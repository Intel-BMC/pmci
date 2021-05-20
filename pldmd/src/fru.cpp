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
std::shared_ptr<sdbusplus::asio::dbus_interface> fruIface;
std::vector<std::shared_ptr<sdbusplus::asio::dbus_interface>> fruInterface;

using FRUMetadata = std::map<std::string, uint32_t>;
static FRUMetadata fruMetadata;
static std::map<pldm_tid_t, FRUMetadata> terminusFRUMetadata;

using FRUVariantType = std::variant<uint8_t, uint32_t, std::string>;
using FRUProperties = std::map<std::string, FRUVariantType>;
static FRUProperties fruProperties;
static std::map<pldm_tid_t, FRUProperties> terminusFRUProperties;

constexpr size_t pldmHdrSize = sizeof(pldm_msg_hdr);

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

bool PLDMFRUTable::parseTable()
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
            return false;
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
        terminusFRUProperties[tid] = fruProperties;
    }
    return true;
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
    auto it = terminusFRUMetadata.find(tid);
    if (it == terminusFRUMetadata.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetFruRecordTable: no TID match found for CRC check",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }

    FRUMetadata& tmpMap = it->second;
    auto crcFound = tmpMap.find("Checksum");
    if (crcFound == tmpMap.end())
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

int GetPLDMFRU::getFRURecordTableCmd()
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
        // Check for fruRecordTableLen from metadata FRUTableLength and
        // multipartTransferLimit
        auto it = terminusFRUMetadata.find(tid);
        if (it != terminusFRUMetadata.end())
        {
            FRUMetadata& tmpMap = it->second;
            auto fruTableLen = tmpMap.find("FRUTableLength");
            if (fruTableLen == tmpMap.end())
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

    PLDMFRUTable tableParse(std::move(fruRecordTableData), tid);

    if (!tableParse.parseTable())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to parse fru table data",
            phosphor::logging::entry("TID=%d", tid));
        return PLDM_ERROR_INVALID_DATA;
    }

    std::string tidFRUObjPath = fruPath + std::to_string(tid);
    addFRUObjectToDbus(tidFRUObjPath, tid);

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
    terminusFRUMetadata[tid] = fruMetadata;

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

    retVal = getFRURecordTableCmd();

    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run GetFruRecordTable command",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }

    return true;
}

static bool addFRUObjectToDbus(const std::string& fruObjPath,
                               const pldm_tid_t tid)
{
    auto objServer = getObjServer();
    fruIface = objServer->add_interface(fruObjPath, FRU::interface);

    auto it = terminusFRUProperties.find(tid);
    if (it == terminusFRUProperties.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No TID match found to populate FRU",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }
    FRUProperties& tmpMap = it->second;

    std::string propertyVal = "";
    for (auto i : tmpMap)
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

    std::string tidFRUObjPath = fruPath + std::to_string(tid);
    removeInterface(tidFRUObjPath, fruInterface);

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("PLDM FRU device resource deleted for TID " + std::to_string(tid))
            .c_str());
    return true;
}

int setFruRecordTableCmd(boost::asio::yield_context& yield,
                         const pldm_tid_t tid,
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
}

bool fruInit(boost::asio::yield_context yield, const pldm_tid_t tid)
{
    bool retVal = true;
    if (!setFRUIface || !setFRUIface->is_initialized())
    {
        initializeFRUBase();
    }

    GetPLDMFRU getFRUCommands(yield, tid);
    if (!getFRUCommands.runGetFRUCommands())
    {
        retVal = false;
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run FRU commands",
            phosphor::logging::entry("TID=%d", tid));
    }

    fruMetadata.clear();
    fruProperties.clear();
    return retVal;
}
} // namespace fru
} // namespace pldm
