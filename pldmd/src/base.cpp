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
#include <unordered_map>

namespace pldm
{
namespace base
{

constexpr uint16_t timeOut = 100;
constexpr size_t retryCount = 3;
constexpr size_t hdrSize = sizeof(pldm_msg_hdr);

using SupportedPLDMTypes = std::array<bitfield8_t, 8>;

static bool validateBaseReqEncode(const mctpw_eid_t eid, const int rc,
                                  const std::string& commandString)
{
    if (rc != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (commandString + ": Request encode failed").c_str(),
            phosphor::logging::entry("EID=%d", eid),
            phosphor::logging::entry("RC=%d", rc));
        return false;
    }
    return true;
}

static bool validateBaseRespDecode(const mctpw_eid_t eid, const int rc,
                                   const uint8_t completionCode,
                                   const std::string& commandString)
{
    if (rc != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (commandString + ": Response decode failed").c_str(),
            phosphor::logging::entry("EID=%d", eid),
            phosphor::logging::entry("RC=%d", rc));
        return false;
    }

    // Completion code value is considered as valid only if decode is success(rc
    // = PLDM_SUCCESS)
    if (completionCode != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (commandString + ": Invalid completion code").c_str(),
            phosphor::logging::entry("EID=%d", eid),
            phosphor::logging::entry("CC=%d", completionCode));
        return false;
    }
    return true;
}

bool getSupportedPLDMTypes(boost::asio::yield_context yield,
                           const mctpw_eid_t eid,
                           SupportedPLDMTypes& supportedTypes)
{
    // A special TID is used in cases where TID is not assigned
    constexpr uint8_t specialTID = 0x00;

    uint8_t instanceID = createInstanceId(specialTID);
    std::vector<uint8_t> getSupportedPLDMTypesRequest(sizeof(PLDMEmptyRequest),
                                                      0x00);
    auto msg = reinterpret_cast<pldm_msg*>(getSupportedPLDMTypesRequest.data());
    std::vector<uint8_t> getSupportedPLDMTypesResponse;

    int rc = encode_get_types_req(instanceID, msg);
    if (!validateBaseReqEncode(eid, rc, "GetTypes"))
    {
        return false;
    }

    // TID passed as 0 will be ignored since EID is present.
    if (!sendReceivePldmMessage(yield, specialTID, timeOut, retryCount,
                                getSupportedPLDMTypesRequest,
                                getSupportedPLDMTypesResponse, eid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send receive error while getting supported PLDM Types",
            phosphor::logging::entry("EID=%d", eid));
        return false;
    }

    uint8_t completionCode;
    rc = decode_get_types_resp(
        reinterpret_cast<pldm_msg*>(getSupportedPLDMTypesResponse.data()),
        getSupportedPLDMTypesResponse.size() - hdrSize, &completionCode,
        supportedTypes.data());
    if (!validateBaseRespDecode(eid, rc, completionCode, "GetTypes"))
    {
        return false;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "GetTypes processed successfully",
        phosphor::logging::entry("EID=%d", eid));
    return true;
}

bool baseInit(boost::asio::yield_context yield, const mctpw_eid_t eid,
              pldm_tid_t& /*tid*/)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Running Base initialisation", phosphor::logging::entry("EID=%d", eid));

    SupportedPLDMTypes pldmTypes;
    if (!getSupportedPLDMTypes(yield, eid, pldmTypes))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error getting supported PLDM Types",
            phosphor::logging::entry("EID=%d", eid));
        return false;
    }
    // TODO Get PLDM Version
    // TODO Get PLDM COmmands
    // TODO Get or Assign TID
    return true;
}

} // namespace base
} // namespace pldm
