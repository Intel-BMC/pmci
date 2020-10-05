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

#include <phosphor-logging/log.hpp>
#include <string>
#include <xyz/openbmc_project/Inventory/Source/PLDM/FRU/server.hpp>

namespace pldm
{
namespace fru
{

using FRU =
    sdbusplus::xyz::openbmc_project::Inventory::Source::PLDM::server::FRU;

constexpr size_t hdrSize = sizeof(pldm_msg_hdr);

int PLDMFRUCmd::getFRURecordTableMetadataCmd()
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
    size_t payloadLen = responseMsg.size() - hdrSize;

    // parse response
    uint8_t cc = 0;
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

    // TODO: Add needed response to map for further use

    return PLDM_SUCCESS;
}

PLDMFRUCmd::PLDMFRUCmd(boost::asio::yield_context yieldVal,
                       const pldm_tid_t tidVal) :
    yield(yieldVal),
    tid(tidVal)
{
}

PLDMFRUCmd::~PLDMFRUCmd()
{
}

bool PLDMFRUCmd::runFRUCommands()
{
    int retVal = getFRURecordTableMetadataCmd();

    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run GetFRURecordTableMetadata command",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }

    // TODO: Perform other FRU commands

    return true;
}

bool fruInit(boost::asio::yield_context yield, const pldm_tid_t tid)
{
    std::string fruObjPath =
        "/xyz/openbmc_project/pldm/fru/" + std::to_string(tid);
    auto objServer = getObjServer();
    auto fruIface = objServer->add_interface(fruObjPath, FRU::interface);
    fruIface->register_method(
        "SetFRU", []([[maybe_unused]] const pldm_tid_t tidVal,
                     [[maybe_unused]] const std::vector<uint8_t>& data) {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "SetFRURecordTable is called");
        });
    fruIface->initialize();

    PLDMFRUCmd fruCommands(yield, tid);

    if (!fruCommands.runFRUCommands())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run FRU commands",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }

    return true;
}
} // namespace fru
} // namespace pldm
