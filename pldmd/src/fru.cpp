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
#include "fru.hpp"

#include "fru_support.hpp"

#include <string>
#include <xyz/openbmc_project/Inventory/Source/PLDM/FRU/server.hpp>

namespace pldm
{
namespace fru
{

using FRU =
    sdbusplus::xyz::openbmc_project::Inventory::Source::PLDM::server::FRU;

std::string fruPath = "/xyz/openbmc_project/pldm/fru/";

std::shared_ptr<sdbusplus::asio::dbus_interface> setFRUIface;
std::shared_ptr<sdbusplus::asio::dbus_interface> getFRUIface;
std::vector<std::shared_ptr<sdbusplus::asio::dbus_interface>> fruInterface;

static std::map<pldm_tid_t, FRUMetadata> terminusFRUMetadata;
static std::map<pldm_tid_t, FRUProperties> terminusFRUProperties;

// Fru record data is saved in byte format as it is received. This data is
// used by GetPldmFRU method
using FRUData = std::unordered_map<pldm_tid_t, std::vector<uint8_t>>;
static FRUData fruData;

constexpr size_t pldmHdrSize = sizeof(pldm_msg_hdr);

// Fru Support object is used to covert PLDM FRU to IPMI Format
FruSupport ipmiFru;

std::optional<FRUProperties> getProperties(const pldm_tid_t tid)
{
    auto it = terminusFRUProperties.find(tid);
    if (it != terminusFRUProperties.end())
    {
        return it->second;
    }
    return std::nullopt;
}

bool PLDMFRUTable::parseFRUField(uint8_t recordType, uint8_t type,
                                 uint8_t length, const uint8_t* value)
{
    if (value == NULL)
    {
        return false;
    }
    try
    {
        auto& [typeString, parser] = fruFieldTypes.at(recordType).at(type);
        fruProperties[typeString] = parser(value, length);
    }
    catch (const std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "fruFieldTypes key not available in map",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }

    return true;
}

bool PLDMFRUTable::isTableEnd(const uint8_t* pTable)
{
    if (pTable == NULL)
    {
        return false;
    }
    constexpr size_t fixedFRUBytes = 7;
    if (pTable < table.data())
    {
        return false;
    }
    auto offset = pTable - table.data();
    return (table.size() - offset) <= fixedFRUBytes;
}

std::optional<FRUProperties> PLDMFRUTable::parseTable()
{
    const uint8_t* pTable = table.data();
    while (!isTableEnd(pTable))
    {
        auto record =
            reinterpret_cast<const pldm_fru_record_data_format*>(pTable);
        uint16_t recordSetID = le16toh(record->record_set_id);
        std::string recordType =
            typeToString(fruRecordTypes, record->record_type);
        uint8_t fruFieldNum = static_cast<uint8_t>(record->num_fru_fields);
        std::string encodeType =
            typeToString(fruEncodingType, record->encoding_type);

        phosphor::logging::log<phosphor::logging::level::INFO>(
            "FRU Record Set Identifier",
            phosphor::logging::entry("REC_SET_ID=%d", recordSetID));
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "FRU Record Type",
            phosphor::logging::entry("REC_TYPE=%s", recordType.c_str()));
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "FRU field number",
            phosphor::logging::entry("FRU_FIELD_NUM=%d", fruFieldNum));
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "FRU Encode Type",
            phosphor::logging::entry("FRU_ENCODE_TYPE=%s", encodeType.c_str()));

        if (fruFieldNum < 1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Number of FRU fields cannot be 0.");
            return std::nullopt;
        }

        auto isGeneralRec = false;
        if (record->record_type == PLDM_FRU_RECORD_TYPE_GENERAL)
        {
            isGeneralRec = true;
        }

        pTable +=
            sizeof(pldm_fru_record_data_format) - sizeof(pldm_fru_record_tlv);
        for (int i = 0; i < record->num_fru_fields; i++)
        {
            auto tlv = reinterpret_cast<const pldm_fru_record_tlv*>(pTable);
            if (isGeneralRec)
            {
                if (!parseFRUField(record->record_type, tlv->type, tlv->length,
                                   tlv->value))
                {
                    phosphor::logging::log<phosphor::logging::level::WARNING>(
                        "Failed to parse fru fields",
                        phosphor::logging::entry("TID=%d", tid));
                }
            }
            pTable += sizeof(pldm_fru_record_tlv) - 1 + tlv->length;
        }
    }
    return fruProperties;
}

PLDMFRUTable::PLDMFRUTable(const std::vector<uint8_t> tableVal,
                           const pldm_tid_t tidVal) :
    table(tableVal),
    tid(tidVal)
{
}

PLDMFRUTable::~PLDMFRUTable()
{
}

bool GetPLDMFRU::verifyCRC(std::vector<uint8_t>& fruTable)
{
    auto crcFound = fruMetadata.find("Checksum");
    if (crcFound == fruMetadata.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetFruRecordTable: No CRC-32 available in metadata",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }

    constexpr size_t mod = 4;
    size_t numPadBytes = 0;
    if (fruTable.size() % mod)
    {
        numPadBytes = mod - (fruTable.size() % mod);
    }

    // fill padding with zeros
    fruTable.resize(fruTable.size() + numPadBytes);

    uint32_t checksum = crc32(fruTable.data(), fruTable.size());

    if (crcFound->second != checksum)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetFruRecordTable: CRC match failure with metadata "
            "CRC value",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>("CRC Match Done");
    return true;
}

static bool addFRUObjectToDbus(const std::string& fruObjPath,
                               const pldm_tid_t tid,
                               FRUProperties& fruProperties)
{
    auto objServer = getObjServer();
    std::shared_ptr<sdbusplus::asio::dbus_interface> fruIface =
        objServer->add_interface(fruObjPath, FRU::interface);

    std::string propertyVal = "";
    for (auto i : fruProperties)
    {
        try
        {
            propertyVal = std::get<std::string>(i.second);
        }
        catch (const std::bad_variant_access&)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to register FRU property",
                phosphor::logging::entry("TID=%d", tid));
            continue;
        }
        fruIface->register_property(i.first, propertyVal);
    }

    fruIface->initialize();
    fruInterface.push_back(fruIface);

    return true;
}

int GetPLDMFRU::getFRURecordTableCmd(FRUProperties& fruProperties)
{
    uint32_t dataTransferHandle = 0;
    uint8_t transferOperationFlag = PLDM_GET_FIRSTPART;
    size_t multipartTransferLimit = 100;

    uint8_t cc = PLDM_ERROR;
    uint8_t transferFlag = 0;
    uint32_t nextDataTransferHandle = 0;
    size_t fruRecordTableLen = 0;
    std::vector<uint8_t> fruRecordTableData = {};

    while (transferFlag != PLDM_END && transferFlag != PLDM_START_AND_END)
    {
        auto fruTableLen = fruMetadata.find("FRUTableLength");
        if (fruTableLen == fruMetadata.end())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetFruRecordTable: No FRUTableLength available in "
                "metadata",
                phosphor::logging::entry("TID=%d", tid));
            return PLDM_ERROR;
        }
        if (fruRecordTableData.size() > fruTableLen->second ||
            !(--multipartTransferLimit))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Max FRU record table length limit reached. Discarding the "
                "record",
                phosphor::logging::entry("TID=%d", tid));
            return PLDM_ERROR;
        }

        uint8_t instanceID = createInstanceId(tid);

        std::vector<uint8_t> requestMsg(pldmHdrSize +
                                        PLDM_GET_FRU_RECORD_TABLE_REQ_BYTES);
        auto request = reinterpret_cast<pldm_msg*>(requestMsg.data());

        int rc = encode_get_fru_record_table_req(
            instanceID, dataTransferHandle, transferOperationFlag, request,
            requestMsg.size() - pldmHdrSize);

        if (!validatePLDMReqEncode(tid, rc, "GetFruRecordTable"))
        {
            return PLDM_ERROR;
        }

        std::vector<uint8_t> responseMsg;

        if (!sendReceivePldmMessage(yield, tid, timeout, retryCount, requestMsg,
                                    responseMsg))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetFruRecordTable: Failed to send or receive PLDM message",
                phosphor::logging::entry("TID=%d", tid));
            return PLDM_ERROR;
        }

        auto responsePtr = reinterpret_cast<pldm_msg*>(responseMsg.data());
        size_t payloadLen = responseMsg.size() - pldmHdrSize;

        if (payloadLen < PLDM_GET_FRU_RECORD_TABLE_MIN_RESP_BYTES)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetFruRecordTable: payloadLen cannot be less than 6",
                phosphor::logging::entry("TID=%d", tid));
            return PLDM_ERROR;
        }

        std::vector<uint8_t> partialFRURecordTableData(
            payloadLen - PLDM_GET_FRU_RECORD_TABLE_MIN_RESP_BYTES);

        rc = decode_get_fru_record_table_resp(
            responsePtr, payloadLen, &cc, &nextDataTransferHandle,
            &transferFlag, partialFRURecordTableData.data(),
            &fruRecordTableLen);

        if (!validatePLDMRespDecode(tid, rc, cc, "GetFruRecordTable"))
        {
            return PLDM_ERROR;
        }
        dataTransferHandle = nextDataTransferHandle;
        transferOperationFlag = PLDM_GET_NEXTPART;

        // Copy multipart fru data into fruRecordTableData to create
        // final fru
        std::copy(partialFRURecordTableData.begin(),
                  partialFRURecordTableData.end(),
                  std::back_inserter(fruRecordTableData));
    }

    if (!verifyCRC(fruRecordTableData))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed at CRC Match", phosphor::logging::entry("TID=%d", tid));
        return PLDM_ERROR;
    }

    auto it = fruData.find(tid);
    if (it != fruData.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("PLDM FRU device already exist for TID " + std::to_string(tid))
                .c_str());
        fruData.erase(it);
    }
    // Fru record data is saved in byte format as it is received. This data is
    // used by GetPldmFRU method
    fruData.emplace(tid, fruRecordTableData);

    PLDMFRUTable tableParse(std::move(fruRecordTableData), tid);

    std::optional<FRUProperties> fruProp = tableParse.parseTable();
    if (!fruProp.has_value())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to parse fru table data",
            phosphor::logging::entry("TID=%d", tid));
        return PLDM_ERROR_INVALID_DATA;
    }
    fruProperties = std::move(fruProp.value());

    std::string tidFRUObjPath = fruPath + std::to_string(tid);
    addFRUObjectToDbus(tidFRUObjPath, tid, fruProperties);

    return PLDM_SUCCESS;
}

int GetPLDMFRU::getFRURecordTableMetadataCmd()
{
    uint8_t instanceID = createInstanceId(tid);

    std::vector<uint8_t> requestMsg(sizeof(PLDMEmptyRequest));
    struct pldm_msg* request = reinterpret_cast<pldm_msg*>(requestMsg.data());

    int rc = encode_get_fru_record_table_metadata_req(
        instanceID, request, PLDM_GET_FRU_RECORD_TABLE_METADATA_REQ_BYTES);

    if (!validatePLDMReqEncode(tid, rc, "GetFRURecordTableMetadata"))
    {
        return PLDM_ERROR;
    }

    std::vector<uint8_t> responseMsg;

    if (!sendReceivePldmMessage(yield, tid, timeout, retryCount, requestMsg,
                                responseMsg))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetFRURecordTableMetadata: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", tid));
        return PLDM_ERROR;
    }

    auto responsePtr = reinterpret_cast<pldm_msg*>(responseMsg.data());
    size_t payloadLen = responseMsg.size() - pldmHdrSize;

    // parse response
    uint8_t cc = PLDM_ERROR;
    uint8_t fruDataMajorVersion;
    uint8_t fruDataMinorVersion;
    uint16_t totalRecordSetIdentifiers;
    uint16_t totalTableRecords;
    uint32_t fruTableMaximumSize;
    uint32_t fruTableLength;
    uint32_t checksum;

    rc = decode_get_fru_record_table_metadata_resp(
        responsePtr, payloadLen, &cc, &fruDataMajorVersion,
        &fruDataMinorVersion, &fruTableMaximumSize, &fruTableLength,
        &totalRecordSetIdentifiers, &totalTableRecords, &checksum);

    if (!validatePLDMRespDecode(tid, rc, cc, "GetFRURecordTableMetadata"))
    {
        return PLDM_ERROR;
    }

    fruMetadata["FRUTableMaximumSize"] = fruTableMaximumSize;
    fruMetadata["FRUTableLength"] = fruTableLength;
    fruMetadata["Checksum"] = checksum;

    return PLDM_SUCCESS;
}

GetPLDMFRU::GetPLDMFRU(boost::asio::yield_context yieldVal,
                       const pldm_tid_t tidVal) :
    yield(yieldVal),
    tid(tidVal)
{
}

GetPLDMFRU::~GetPLDMFRU()
{
}

bool GetPLDMFRU::runGetFRUCommands()
{
    int retVal = getFRURecordTableMetadataCmd();
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run GetFRURecordTableMetadata command",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }

    FRUProperties fruProperties;
    retVal = getFRURecordTableCmd(fruProperties);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run GetFruRecordTable command",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }

    terminusFRUMetadata.insert_or_assign(tid, fruMetadata);
    terminusFRUProperties.insert_or_assign(tid, std::move(fruProperties));
    return true;
}

static void removeInterface(
    std::string& interfacePath,
    std::vector<std::shared_ptr<sdbusplus::asio::dbus_interface>>& interfaces)
{
    auto objServer = getObjServer();
    for (auto dbusInterface = interfaces.begin();
         dbusInterface != interfaces.end(); dbusInterface++)
    {
        if ((*dbusInterface)->get_object_path() == interfacePath)
        {
            std::shared_ptr<sdbusplus::asio::dbus_interface> tmpIf =
                *dbusInterface;
            objServer->remove_interface(tmpIf);
            interfaces.erase(dbusInterface);
            break;
        }
    }
}

/** @brief API that deletes PLDM fru device resorces. This API should be
 * called when PLDM fru capable devide is removed from the platform.
 */
bool deleteFRUDevice(const pldm_tid_t tid)
{
    auto it = terminusFRUMetadata.find(tid);
    if (it == terminusFRUMetadata.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("PLDM FRU device not matched for TID " + std::to_string(tid))
                .c_str());
        // If terminusFRUMetadata[tid] is not present, then it is safe to return
        // as terminusFRUProperties / fruInterface will not be there.
        return false;
    }
    terminusFRUMetadata.erase(it);

    auto itr = terminusFRUProperties.find(tid);
    if (itr == terminusFRUProperties.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("PLDM FRU device properties not matched for TID " +
             std::to_string(tid))
                .c_str());
        // Only terminusFRUMeta[tid] is present, which is cleared. No
        // terminusFRUProperties[tid] is present meaning terminusFRUProperties /
        // fruInterface will not be there to clear. So return true.
        return true;
    }
    terminusFRUProperties.erase(itr);

    auto itData = fruData.find(tid);
    if (itData == fruData.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("PLDM FRU device not available for TID " + std::to_string(tid))
                .c_str());
        // terminusFRUMeta[tid] is present, which is cleared.
        // terminusFRUProperties[tid] is cleared .NO fruData present meaning
        // terminusFRUProperties / fruInterface will not be there to clear. So
        // return true.
        return true;
    }
    fruData.erase(itData);

    std::string tidFRUObjPath = fruPath + std::to_string(tid);
    removeInterface(tidFRUObjPath, fruInterface);
    ipmiFru.removeInterfaces(tid);

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("PLDM FRU device resource deleted for TID " + std::to_string(tid))
            .c_str());
    return true;
}

std::optional<std::vector<uint8_t>> GetPLDMFRU::getPLDMFruRecordData()
{
    auto it = terminusFRUMetadata.find(tid);
    auto itr = fruData.find(tid);
    if (it == terminusFRUMetadata.end() || itr == fruData.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("PLDM FRU device not matched for TID " + std::to_string(tid))
                .c_str());
        return std::nullopt;
    }

    return itr->second;
}

int setFruRecordTableCmd(boost::asio::yield_context yield, const pldm_tid_t tid,
                         const std::vector<uint8_t>& setFruData)
{
    auto it = terminusFRUMetadata.find(tid);
    if (it != terminusFRUMetadata.end())
    {
        // In case of empty FRU, Metadata won't be present, so still proceeed.
        FRUMetadata& tmpMap = it->second;
        auto fruTableMaxSize = tmpMap.find("FRUTableMaximumSize");
        if (fruTableMaxSize == tmpMap.end())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "SetFruRecordTable: No FRUTableMaximumSize available in "
                "metadata",
                phosphor::logging::entry("TID=%d", tid));
            return PLDM_ERROR;
        }
        if (setFruData.size() > fruTableMaxSize->second)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "SetFruRecordTable: FRU Data Size cannot be greater "
                "than FRUTableMaximumSize",
                phosphor::logging::entry("TID=%d", tid));
            return PLDM_ERROR;
        }
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Fru Data Size Check Done");
    }

    // TODO: Multipart transfer

    uint32_t dataTransferHandle = 1;
    uint8_t transferFlag = PLDM_START_AND_END;

    struct variable_field fruRecordTableData;
    fruRecordTableData.ptr = setFruData.data();
    fruRecordTableData.length = setFruData.size();

    std::vector<uint8_t> requestMsg(pldmHdrSize +
                                    sizeof(pldm_set_fru_record_table_req) +
                                    setFruData.size());
    struct pldm_msg* request = reinterpret_cast<pldm_msg*>(requestMsg.data());

    uint8_t instanceId = createInstanceId(tid);

    int rc = encode_set_fru_record_table_req(
        instanceId, dataTransferHandle, transferFlag, &fruRecordTableData,
        request, requestMsg.size() - pldmHdrSize);

    if (!validatePLDMReqEncode(tid, rc, "SetFruRecordTable"))
    {
        return PLDM_ERROR;
    }

    std::vector<uint8_t> responseMsg;

    if (!sendReceivePldmMessage(yield, tid, timeout, retryCount, requestMsg,
                                responseMsg))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SetFruRecordTable: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", tid));
        return PLDM_ERROR;
    }

    auto responsePtr = reinterpret_cast<pldm_msg*>(responseMsg.data());
    size_t payloadLen = responseMsg.size() - pldmHdrSize;

    // parse response
    uint8_t cc = PLDM_ERROR;
    uint32_t nextDataTransferHandle = 0;

    rc = decode_set_fru_record_table_resp(responsePtr, payloadLen, &cc,
                                          &nextDataTransferHandle);

    if (!validatePLDMRespDecode(tid, rc, cc, "SetFruRecordTable"))
    {
        return PLDM_ERROR;
    }

    auto itr = terminusFRUMetadata.find(tid);
    if (itr != terminusFRUMetadata.end())
    {
        // If terminusFRUMetadata[tid] not found, then continue with get
        // commands and add fru interface for first time setFRU.
        // If terminusFRUMetadata[tid] found, then clearing all tid info in maps
        // and removing interface.

        if (!deleteFRUDevice(tid))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to to remove interface",
                phosphor::logging::entry("TID=%d", tid));
            return PLDM_ERROR;
        }
    }

    // Re-query FRU data via get commands and update the FRU fields accordingly.
    GetPLDMFRU getFRUCommands(yield, tid);
    if (!getFRUCommands.runGetFRUCommands())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run FRU commands",
            phosphor::logging::entry("TID=%d", tid));
        return PLDM_ERROR;
    }

    return PLDM_SUCCESS;
}

static void initializeGetFruIntf()
{
    auto objServer = getObjServer();
    getFRUIface = objServer->add_interface("/xyz/openbmc_project/pldm/fru",
                                           "xyz.openbmc_project.PLDM.GetFRU");
    getFRUIface->register_method(
        "GetPldmFRU",
        [](boost::asio::yield_context yieldVal, const pldm_tid_t tidVal) {
            GetPLDMFRU fruManager(yieldVal, tidVal);
            std::optional<std::vector<uint8_t>> retVal =
                fruManager.getPLDMFruRecordData();

            if (!retVal)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to get GetFruRecordTable details");
                throw std::system_error(
                    std::make_error_code(std::errc::no_message_available));
            }
            return std::move(retVal).value();
        });
    getFRUIface->initialize();
}

static void initializeFRUBase()
{
    auto objServer = getObjServer();
    setFRUIface = objServer->add_interface("/xyz/openbmc_project/pldm/fru",
                                           "xyz.openbmc_project.PLDM.SetFRU");
    setFRUIface->register_method(
        "SetFRU",
        [](boost::asio::yield_context yieldVal, const pldm_tid_t tidVal,
           const std::vector<uint8_t>& data) {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "SetFRURecordTable is called");
            int retVal = setFruRecordTableCmd(yieldVal, tidVal, data);

            if (retVal != PLDM_SUCCESS)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to run SetFruRecordTable command");
            }
            return retVal;
        });
    setFRUIface->initialize();

    if (auto envPtr = std::getenv("PLDM_DEBUG"))
    {
        std::string value(envPtr);
        if (value == "1")
        {
            initializeGetFruIntf();
        }
    }
}

bool fruInit(boost::asio::yield_context yield, const pldm_tid_t tid)
{
    bool retVal = true;
    if (!setFRUIface || !setFRUIface->is_initialized())
    {
        initializeFRUBase();
        ipmiFru.initializeFRUSupport();
    }

    GetPLDMFRU getFRUCommands(yield, tid);
    if (!getFRUCommands.runGetFRUCommands())
    {
        retVal = false;
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run FRU commands",
            phosphor::logging::entry("TID=%d", tid));
        return retVal;
    }

    try
    {
        ipmiFru.convertFRUToIpmiFRU(tid, terminusFRUProperties.at(tid));
    }
    catch (const std::out_of_range&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to map PLDM Fru to IPMI fru",
            phosphor::logging::entry("TID=%d", tid));
    }

    return retVal;
}
} // namespace fru
} // namespace pldm
