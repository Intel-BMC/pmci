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
#include <unordered_set>

#include "utils.h"

namespace pldm
{
namespace base
{

constexpr uint16_t timeOut = 100;
constexpr size_t retryCount = 3;
constexpr size_t hdrSize = sizeof(pldm_msg_hdr);
constexpr uint8_t defaultTID = 0x00;

using SupportedPLDMTypes = std::array<bitfield8_t, 8>;
using PLDMVersions = std::vector<ver32_t>;
using VersionSupportTable = std::unordered_map<uint8_t, PLDMVersions>;

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

    uint8_t instanceID = createInstanceId(defaultTID);
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
    if (!sendReceivePldmMessage(yield, defaultTID, timeOut, retryCount,
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
    return true;
}

bool getPLDMVersions(boost::asio::yield_context yield, const mctpw_eid_t eid,
                     const uint8_t pldmType, PLDMVersions& supportedVersions)
{
    int8_t maxTransfers = 16;
    uint8_t instanceID = createInstanceId(defaultTID);
    std::vector<uint8_t> getPLDMVersionsRequest(
        sizeof(pldm_get_version_req) + hdrSize, 0x00);
    std::vector<uint8_t> getPLDMVersionsResponse;
    uint32_t transferHandle = 0;
    uint8_t transferOpFlag = PLDM_GET_FIRSTPART;
    uint8_t completionCode = PLDM_ERROR;
    uint8_t transferFlag = PLDM_START;
    variable_field responseVersion;
    auto msg = reinterpret_cast<pldm_msg*>(getPLDMVersionsRequest.data());
    std::vector<uint8_t> versionDataBuffer;

    supportedVersions.clear();
    while (PLDM_END != transferFlag && PLDM_START_AND_END != transferFlag)
    {
        if (maxTransfers-- < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Maximum number of packets limit reached for GetVersion "
                "request");
            return false;
        }
        int rc = encode_get_version_req(instanceID, transferHandle,
                                        transferOpFlag, pldmType, msg);
        if (!validateBaseReqEncode(eid, rc, "GetVersion"))
        {
            return false;
        }

        // TID passed as 0 will be ignored since EID is present.
        if (!sendReceivePldmMessage(yield, defaultTID, timeOut, retryCount,
                                    getPLDMVersionsRequest,
                                    getPLDMVersionsResponse, eid))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send receive error while getting supported PLDM Versions",
                phosphor::logging::entry("EID=0x%X", eid));
            return false;
        }

        // For multipart response next transfer handle will be updated in
        // transferHandle variable and it will be used in subsequent iterations
        rc = decode_get_version_resp(
            reinterpret_cast<pldm_msg*>(getPLDMVersionsResponse.data()),
            getPLDMVersionsResponse.size() - hdrSize, &completionCode,
            &transferHandle, &transferFlag, &responseVersion);
        if (!validateBaseRespDecode(eid, rc, completionCode, "GetVersion"))
        {
            return false;
        }
        versionDataBuffer.insert(versionDataBuffer.end(), responseVersion.ptr,
                                 responseVersion.ptr + responseVersion.length);

        transferOpFlag = PLDM_GET_NEXTPART;
    }

    // Version response should contain at least one version and its CRC32
    // checksum. So minimum 8 bytes.
    if (versionDataBuffer.size() < sizeof(uint64_t))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Version response length is less than expected",
            phosphor::logging::entry("LEN=%d", versionDataBuffer.size()),
            phosphor::logging::entry("EID=0x%X", eid));
        return false;
    }

    // Last 4 bytes is CRC
    size_t versionDataSize = versionDataBuffer.size() - sizeof(uint32_t);
    if ((versionDataSize % sizeof(uint32_t)) != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Version data size must be a multiple of 4",
            phosphor::logging::entry("LEN=%d", versionDataSize),
            phosphor::logging::entry("EID=0x%X", eid));
        return false;
    }

    auto versionPtr = reinterpret_cast<uint32_t*>(versionDataBuffer.data());
    size_t versionCount = versionDataSize / sizeof(uint32_t);
    for (size_t i = 0; i < versionCount; i++)
    {
        uint32_t encodedVersion = le32toh(versionPtr[i]);
        encodedVersion = htobe32(encodedVersion);
        auto version = reinterpret_cast<ver32_t*>(&encodedVersion);
        supportedVersions.emplace_back(*version);
    }

    uint32_t* crcPacket =
        reinterpret_cast<uint32_t*>(versionDataBuffer.data() + versionDataSize);
    uint32_t crcCalculated = crc32(versionDataBuffer.data(), versionDataSize);

    if (le32toh(*crcPacket) != crcCalculated)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "CRC Mismatch in version response",
            phosphor::logging::entry("CRC1=0x%X", *crcPacket),
            phosphor::logging::entry("CRC2=0x%X", crcCalculated),
            phosphor::logging::entry("Type=0x%X", pldmType),
            phosphor::logging::entry("EID=0x%X", eid));
        return false;
    }

    return true;
}

static std::unordered_set<uint8_t>
    getTypeCodesFromSupportedTypes(const SupportedPLDMTypes& supportedTypes)
{
    constexpr uint8_t byteWidth = 8;
    constexpr uint8_t rightMostBitMask = 0x01;
    std::unordered_set<uint8_t> types;
    for (uint8_t i = 0; i < supportedTypes.size(); i++)
    {
        uint8_t supportByte = supportedTypes[i].byte;
        for (uint8_t j = 0; j < byteWidth; j++)
        {
            // Checking rightmost bit is set
            if (supportByte & rightMostBitMask)
            {
                types.emplace(static_cast<uint8_t>((i * byteWidth) + j));
            }
            supportByte = supportByte >> 1;
        }
    }
    return types;
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
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "GetTypes processed successfully",
        phosphor::logging::entry("EID=%d", eid));

    VersionSupportTable versionSupportTable;
    auto typeCodes = getTypeCodesFromSupportedTypes(pldmTypes);
    for (auto pldmType : typeCodes)
    {
        PLDMVersions versions;
        if (getPLDMVersions(yield, eid, pldmType, versions))
        {
            versionSupportTable.emplace(pldmType, versions);
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error getting supported PLDM Versions",
                phosphor::logging::entry("EID=0x%X", eid),
                phosphor::logging::entry("TYPE=0x%X", pldmType));
            // Continue scanning next PLDM type
        }
    }
    // TODO Get PLDM Commands
    // TODO Get or Assign TID
    return true;
}

} // namespace base
} // namespace pldm
