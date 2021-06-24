/**
 * Copyright © 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "pldm.hpp"

#include <phosphor-logging/log.hpp>

#include "fru.h"
#include "pldm_types.h"

namespace pldm
{
namespace fru
{

using FRUMetadata = std::map<std::string, uint32_t>;
using FRUVariantType = std::variant<uint8_t, uint32_t, std::string>;
using FRUProperties = std::map<std::string, FRUVariantType>;

static constexpr uint16_t timeout = 100;
static constexpr size_t retryCount = 3;
constexpr uint8_t timeStamp104Size = 13;

static inline const std::map<uint8_t, const char*> fruEncodingType{
    {PLDM_FRU_ENCODING_UNSPECIFIED, "Unspecified"},
    {PLDM_FRU_ENCODING_ASCII, "ASCII"},
    {PLDM_FRU_ENCODING_UTF8, "UTF8"},
    {PLDM_FRU_ENCODING_UTF16, "UTF16"},
    {PLDM_FRU_ENCODING_UTF16LE, "UTF16LE"},
    {PLDM_FRU_ENCODING_UTF16BE, "UTF16BE"}};

static inline const std::map<uint8_t, const char*> fruRecordTypes{
    {PLDM_FRU_RECORD_TYPE_GENERAL, "General"},
    {PLDM_FRU_RECORD_TYPE_OEM, "OEM"}};

static void removeInterface(
    std::string& interfacePath,
    std::vector<std::shared_ptr<sdbusplus::asio::dbus_interface>>& interfaces);

/** @brief run SetFRURecordTable command
 *
 * @return PLDM_SUCCESS on success and corresponding error completion code
 * on failure
 */
int setFruRecordTableCmd(boost::asio::yield_context yield, const pldm_tid_t tid,
                         const std::vector<uint8_t>& setFruData);

class GetPLDMFRU
{
  public:
    GetPLDMFRU() = delete;
    GetPLDMFRU(boost::asio::yield_context yieldVal, const pldm_tid_t tidVal);
    ~GetPLDMFRU();

    /** @brief runs supported FRU commands
     *
     * @return true on success; false otherwise
     * on failure
     */
    bool runGetFRUCommands();

    /** @brief returns the FruRecord table
     *
     * @return FruRecord table on success; empty table otherwise
     * on failure
     * This is used for validation.
     */
    std::optional<std::vector<uint8_t>> getPLDMFruRecordData();

  private:
    /** @brief run GetFRURecordTableMetadata command
     *
     * @return PLDM_SUCCESS on success and corresponding error completion code
     * on failure
     */
    int getFRURecordTableMetadataCmd();

    /** @brief run GetFRURecordTable command
     *
     * @return PLDM_SUCCESS on success and corresponding error completion code
     * on failure
     */
    int getFRURecordTableCmd(FRUProperties& fruProperties);

    /** @brief verify Integrity checksum on the FRU Table Data with metadata
     * checksum value
     *
     * @return true on success and false on checksum match failure
     */
    bool verifyCRC(std::vector<uint8_t>& fruTable);

    boost::asio::yield_context yield;
    pldm_tid_t tid;
    FRUMetadata fruMetadata;
};

class PLDMFRUTable
{
  public:
    PLDMFRUTable() = delete;
    PLDMFRUTable(const std::vector<uint8_t> tableVal, const pldm_tid_t tidVal);
    ~PLDMFRUTable();

    std::optional<FRUProperties> parseTable();

  private:
    using FRUFieldParser =
        std::function<std::string(const uint8_t* value, uint8_t length)>;

    using FieldType = uint8_t;
    using RecordType = uint8_t;
    using FieldName = std::string;
    using FRUFieldTypes =
        std::map<FieldType, std::pair<FieldName, FRUFieldParser>>;

    bool isTableEnd(const uint8_t* pTable);

    std::string typeToString(std::map<uint8_t, const char*> typeMap,
                             uint8_t type)
    {
        auto typeString = std::to_string(type);
        auto typeFound = typeMap.find(type);
        if (typeFound != typeMap.end())
        {
            return typeString + "(" + typeFound->second + ")";
        }
        return typeString;
    }

    static std::string fruFieldParserString(const uint8_t* value,
                                            uint8_t length)
    {
        assert(value != NULL);
        if (length < 1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid FRU field length");
            return std::string("");
        }
        std::string strVal(reinterpret_cast<const char*>(value), length);
        // non printable characters cause sdbusplus exceptions, so better to
        // handle it by replacing with space
        std::replace_if(
            strVal.begin(), strVal.end(),
            [](const char& c) { return !isprint(c); }, ' ');
        return strVal;
    }

    static std::string fruFieldParserTimestamp(const uint8_t* value,
                                               uint8_t length)
    {
        assert(value != NULL);
        timestamp104_t fruStamp;
        std::string timeStampStr;

        if (length != timeStamp104Size)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid time stamp length");
            return std::string("");
        }

        try
        {
            std::copy_n(value, timeStamp104Size,
                        reinterpret_cast<uint8_t*>(&fruStamp));
        }
        catch (std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("Exception Received FRU timestamp parsing error" +
                 std::string(e.what()))
                    .c_str());
            return std::string("");
        }
        catch (...)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Exception Occured FRU timestamp parsing error");
            return std::string("");
        }

        if ((fruStamp.month >= 1 && fruStamp.month <= 12) ||
            (fruStamp.day >= 1 && fruStamp.day <= 31) || (fruStamp.hour < 24) ||
            (fruStamp.minute < 60) || (fruStamp.second < 60))
        {
            timeStampStr.assign(std::to_string(fruStamp.year) + "-" +
                                std::to_string(fruStamp.month) + "-" +
                                std::to_string(fruStamp.day));
            timeStampStr.append(" " + std::to_string(fruStamp.hour) + ":" +
                                std::to_string(fruStamp.minute) + ":" +
                                std::to_string(fruStamp.second));

            // TODO: Need to handle CIM conversions and UTC offset
        }
        return timeStampStr;
    }

    static std::string fruFieldParserU32(const uint8_t* value, uint8_t length)
    {
        assert(value != NULL);
        if (length == 4)
        {
            uint32_t v;
            std::memcpy(&v, value, length);
            return std::to_string(le32toh(*reinterpret_cast<uint32_t*>(v)));
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Vendor IANA should be of length 4");
            return std::string("");
        }
    }

    static inline const FRUFieldTypes fruGeneralFieldTypes = {
        {PLDM_FRU_FIELD_TYPE_CHASSIS, {"ChassisType", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_MODEL, {"Model", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_PN, {"PN", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_SN, {"SN", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_MANUFAC, {"Manufacturer", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_MANUFAC_DATE,
         {"ManufacturerDate", fruFieldParserTimestamp}},
        {PLDM_FRU_FIELD_TYPE_VENDOR, {"Vendor", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_NAME, {"Name", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_SKU, {"SKU", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_VERSION, {"Version", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_ASSET_TAG, {"AssetTag", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_DESC, {"Description", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_EC_LVL, {"ECLevel", fruFieldParserString}},
        {PLDM_FRU_FIELD_TYPE_IANA, {"IANA", fruFieldParserU32}},
    };

    static inline const FRUFieldTypes fruOEMFieldTypes = {
        {1, {"Vendor IANA", fruFieldParserU32}},

    };

    static inline const std::map<RecordType, FRUFieldTypes> fruFieldTypes{
        {PLDM_FRU_RECORD_TYPE_GENERAL, fruGeneralFieldTypes},
        {PLDM_FRU_RECORD_TYPE_OEM, fruOEMFieldTypes}};

    bool parseFRUField(uint8_t recordType, uint8_t type, uint8_t length,
                       const uint8_t* value);

    const std::vector<uint8_t> table;
    pldm_tid_t tid;
    FRUProperties fruProperties;
};

} // namespace fru
} // namespace pldm
