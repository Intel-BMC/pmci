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
#include "base.hpp"

#include "platform.hpp"
#include "pldm.hpp"

#include <numeric>
#include <phosphor-logging/log.hpp>
#include <unordered_map>
#include <unordered_set>

#include "platform.h"
#include "utils.h"

namespace std
{
template <>
struct hash<pldm::platform::UUID>
{
    std::size_t operator()(const pldm::platform::UUID& uuid) const
    {
        return std::accumulate(std::begin(uuid), std::end(uuid), 0,
                               [](size_t prevHash, uint8_t byte) {
                                   return prevHash ^ std::hash<uint8_t>{}(byte);
                               });
    }
};
} // namespace std

namespace pldm
{
namespace base
{

constexpr uint16_t timeOut = 100;
constexpr size_t retryCount = 3;
constexpr size_t hdrSize = sizeof(pldm_msg_hdr);
constexpr uint8_t defaultTID = 0x00;
constexpr size_t maxTIDPoolSize = 254;
constexpr std::chrono::minutes tidReclaimWindow{3};

using SupportedPLDMTypes = std::array<bitfield8_t, 8>;
using PLDMVersions = std::vector<ver32_t>;
using VersionSupportTable = std::unordered_map<uint8_t, PLDMVersions>;

struct DiscoveryData
{
    CommandSupportTable cmdSupportTable;
};

// FIFO TID pool to
// 1) Support a flag to mark TID as used or unused
// 2) Avoid chances of TIDs getting exhausted when freed TIDs are not reused
// 3) Support to re-assign the same TID if a PLDM terminus lost its TID after
// reset
struct TIDPool
{
    using FIFOTIDPool = std::vector<std::pair<uint8_t, bool>>;

  public:
    TIDPool(const size_t tidRange)
    {
        for (pldm_tid_t tid = 1; tid <= tidRange; tid++)
        {
            pool.push_back(std::make_pair(tid, false));
        }
    }

    std::optional<pldm_tid_t> getFreeTID()
    {
        for (auto& [tid, flag] : pool)
        {
            if (!flag)
            {
                flag = true;
                return tid;
            }
        }
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No free TID available");
        return std::nullopt;
    }

    void pushFrontUnusedTID(const pldm_tid_t unusedTID)
    {
        auto itr = findUsedTID(unusedTID);
        if (itr != pool.end())
        {
            auto& [tid, flag] = *itr;
            flag = false;
        }
    }

    void pushBackFreedTID(const pldm_tid_t freedTID)
    {
        auto itr = findUsedTID(freedTID);
        if (itr != pool.end())
        {
            pool.erase(itr);
            pool.push_back(std::make_pair(freedTID, false));
        }
    }

  private:
    FIFOTIDPool::iterator findUsedTID(const pldm_tid_t tid)
    {
        return std::find_if(
            pool.begin(), pool.end(), [&tid](const auto& mappedTIDAndFlag) {
                auto const& [mappedTID, flag] = mappedTIDAndFlag;
                return mappedTID == tid && flag == true;
            });
    }

    FIFOTIDPool pool;
};

static std::unordered_map<pldm_tid_t, DiscoveryData> discoveryDataTable;
static std::unordered_map<pldm::platform::UUID, pldm_tid_t> uuidMapping;
static TIDPool tidPool(maxTIDPoolSize);
static std::unordered_map<pldm_tid_t,
                          std::unique_ptr<boost::asio::steady_timer>>
    tidReclaimWindowTimers;

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
            "Send or receive error while getting supported PLDM Types",
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
                "Send or receive error while getting supported PLDM Versions",
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

std::optional<SupportedCommands>
    getPLDMCommands(boost::asio::yield_context yield, const mctpw_eid_t eid,
                    const uint8_t pldmType, const ver32_t& version)
{
    uint8_t instanceID = createInstanceId(defaultTID);
    std::vector<uint8_t> getCommandsRequest(
        sizeof(pldm_get_commands_req) + hdrSize, 0x00);
    auto msg = reinterpret_cast<pldm_msg*>(getCommandsRequest.data());
    std::vector<uint8_t> getCommandsResponse;

    int rc = encode_get_commands_req(instanceID, pldmType, version, msg);
    if (!validateBaseReqEncode(eid, rc, "GetPLDMCommands"))
    {
        return std::nullopt;
    }

    if (!sendReceivePldmMessage(yield, defaultTID, timeOut, retryCount,
                                getCommandsRequest, getCommandsResponse, eid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send or receive error during GetPLDMCommands request",
            phosphor::logging::entry("EID=0x%X", eid));
        return std::nullopt;
    }

    uint8_t completionCode;
    SupportedCommands commands;
    rc = decode_get_commands_resp(
        reinterpret_cast<pldm_msg*>(getCommandsResponse.data()),
        getCommandsResponse.size() - hdrSize, &completionCode, commands.data());
    if (!validateBaseRespDecode(eid, rc, completionCode, "GetPLDMCommands"))
    {
        return std::nullopt;
    }
    return commands;
}

std::optional<pldm_tid_t> getTID(boost::asio::yield_context yield,
                                 const mctpw_eid_t eid)
{
    uint8_t instanceID = createInstanceId(defaultTID);
    std::vector<uint8_t> getTIDRequest(hdrSize, 0x00);
    auto msg = reinterpret_cast<pldm_msg*>(getTIDRequest.data());
    std::vector<uint8_t> getTIDResponse;

    int rc = encode_get_tid_req(instanceID, msg);
    if (!validateBaseReqEncode(eid, rc, "GetTID"))
    {
        return std::nullopt;
    }

    if (!sendReceivePldmMessage(yield, defaultTID, timeOut, retryCount,
                                getTIDRequest, getTIDResponse, eid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send or receive error during GetTID request");
        return std::nullopt;
    }

    uint8_t completionCode;
    uint8_t tID;
    rc = decode_get_tid_resp(reinterpret_cast<pldm_msg*>(getTIDResponse.data()),
                             getTIDResponse.size() - hdrSize, &completionCode,
                             &tID);
    if (!validateBaseRespDecode(eid, rc, completionCode, "GetTID"))
    {
        return std::nullopt;
    }
    return tID;
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

bool setTID(boost::asio::yield_context yield, const mctpw_eid_t eid,
            const pldm_tid_t tid)
{
    uint8_t instanceID = createInstanceId(defaultTID);
    std::vector<uint8_t> setTIDRequest(hdrSize + sizeof(pldm_set_tid_req),
                                       0x00);
    auto msg = reinterpret_cast<pldm_msg*>(setTIDRequest.data());
    std::vector<uint8_t> setTIDResponse;

    int rc = encode_set_tid_req(instanceID, tid, msg);
    if (!validateBaseReqEncode(eid, rc, "SetTID"))
    {
        return false;
    }

    if (!sendReceivePldmMessage(yield, defaultTID, timeOut, retryCount,
                                setTIDRequest, setTIDResponse, eid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send or receive error during SetTID request");
        return false;
    }

    uint8_t completionCode;
    rc = decode_set_tid_resp(reinterpret_cast<pldm_msg*>(setTIDResponse.data()),
                             setTIDResponse.size() - hdrSize, &completionCode);
    if (!validateBaseRespDecode(eid, rc, completionCode, "SetTID"))
    {
        return false;
    }
    return true;
}
VersionSupportTable
    createVersionSupportTable(boost::asio::yield_context yield,
                              const mctpw_eid_t eid,
                              const SupportedPLDMTypes& pldmTypes)
{
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
    return versionSupportTable;
}

CommandSupportTable
    createCommandSupportTable(boost::asio::yield_context yield,
                              const mctpw_eid_t eid,
                              const VersionSupportTable& versionSupportTable)
{
    CommandSupportTable cmdSupportTable;
    for (const auto& versionTable : versionSupportTable)
    {
        if (versionTable.second.size() == 0)
        {
            // No versions supported for this type
            continue;
        }
        // Only the first PLDM version type given out for the type is
        // processed
        ver32_t firstVersion = versionTable.second.front();
        auto supportedCommands =
            getPLDMCommands(yield, eid, versionTable.first, firstVersion);
        if (supportedCommands)
        {
            cmdSupportTable[versionTable.first].emplace(
                firstVersion, supportedCommands.value());
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetPLDMCommands failed",
                phosphor::logging::entry("TYPE=0x%X", versionTable.first),
                phosphor::logging::entry("EID=0x%X", eid));
        }
    }
    return cmdSupportTable;
}

bool isSupported(const CommandSupportTable& cmdSupportTable,
                 const pldm_type_t type, const uint8_t cmd)
{
    auto itCmd = cmdSupportTable.find(type);
    if (cmdSupportTable.end() == itCmd)
    {
        return false;
    }

    using VersionCommandTable = CommandSupportTable::mapped_type::value_type;
    // To check if any version support cmd
    auto checkCmdBit = [cmd](const VersionCommandTable& table) {
        // table.second will be 32 byte array representing support for each
        // command. First [] operator will fetch the support byte for the
        // command. [0..7] => 0;[8..15] -> 1 etc. & operator checks if bit
        // for the command is set. counting bits from right to left.
        return table.second[cmd / 8].byte & (0x01 << (cmd % 8));
    };
    return std::any_of(std::begin(itCmd->second), std::end(itCmd->second),
                       checkCmdBit);
}

void cancelTIDReclaimTimerIfExists(const pldm_tid_t tid)
{
    auto itr = std::find_if(tidReclaimWindowTimers.begin(),
                            tidReclaimWindowTimers.end(),
                            [&tid](const auto& tidTimer) {
                                auto const& [tidInMap, reclaimTimer] = tidTimer;
                                if (tidInMap == tid)
                                {
                                    reclaimTimer->cancel();
                                    return true;
                                }
                                return false;
                            });
    if (itr != tidReclaimWindowTimers.end())
    {
        tidReclaimWindowTimers.erase(itr);
    }
}

void releaseTIDAfterReclaimInterval(const pldm_tid_t tid)
{
    std::unique_ptr<boost::asio::steady_timer> tidReclaimTimer =
        std::make_unique<boost::asio::steady_timer>(
            *getIoContext(),
            std::chrono::steady_clock::now() + tidReclaimWindow);
    tidReclaimTimer->async_wait([tid](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("TID:" + std::to_string(tid) + " reclaim timer aborted")
                    .c_str());
            return;
        }
        else if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("TID:" + std::to_string(tid) + " reclaim timer failed")
                    .c_str());
        }
        auto itr = std::find_if(uuidMapping.begin(), uuidMapping.end(),
                                [&tid](const auto& uuidTID) {
                                    auto const& [uuid, mappedTID] = uuidTID;
                                    return mappedTID == tid;
                                });
        if (itr != uuidMapping.end())
        {
            uuidMapping.erase(itr);
        }
        tidPool.pushBackFreedTID(tid);
        tidReclaimWindowTimers.erase(tid);
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("TID:" + std::to_string(tid) + " released from UUID-TID table")
                .c_str());
    });
    tidReclaimWindowTimers.emplace(tid, std::move(tidReclaimTimer));
}

bool isTerminusUnregistered(const pldm_tid_t tid)
{
    return tidReclaimWindowTimers.count(tid) == 1;
}

bool baseInit(boost::asio::yield_context yield, const mctpw_eid_t eid,
              pldm_tid_t& tid, CommandSupportTable& cmdSupportTable)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Running Base initialisation", phosphor::logging::entry("EID=%d", eid));

    if (auto mappedTID = tidMapper.getMappedTID(eid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("EID: " + std::to_string(static_cast<int>(eid)) +
             " is already mapped with another TID: " +
             std::to_string(static_cast<int>(mappedTID.value())))
                .c_str());
        return false;
    }

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

    auto versionSupportTable = createVersionSupportTable(yield, eid, pldmTypes);

    cmdSupportTable =
        createCommandSupportTable(yield, eid, versionSupportTable);

    auto assignedTID = getTID(yield, eid);
    if (!assignedTID)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Terminus doesn't have a TID assigned"),
            phosphor::logging::entry("EID=0x%X", eid);
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Terminus has TID assigned",
            phosphor::logging::entry("TID=0x%X", assignedTID.value()));
    }

    bool prevTIDExists = false;
    std::optional<pldm::platform::UUID> uuid;
    tid = 0x00;
    if (isSupported(cmdSupportTable, PLDM_PLATFORM, PLDM_GET_TERMINUS_UID))
    {
        uuid = pldm::platform::getTerminusUID(yield, tid, eid);
        if (uuid)
        {
            auto itTID = uuidMapping.find(uuid.value());
            if (uuidMapping.end() != itTID)
            {
                tid = itTID->second;
                prevTIDExists = true;
            }
        }
    }

    if (prevTIDExists && assignedTID && !isTerminusUnregistered(tid))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Device already registered");
        return false;
    }

    // device doesn't support GetTerminusUID or didnt respond correctly to
    // GetTerminusUID request or its UUID is appearing for the first time
    if (tid == 0x00)
    {
        auto newTID = tidPool.getFreeTID();
        if (!newTID)
        {
            return false;
        }
        tid = newTID.value();
    }
    else
    {
        if (uuid)
        {
            cancelTIDReclaimTimerIfExists(tid);
        }
    }

    if (isSupported(cmdSupportTable, PLDM_BASE, PLDM_SET_TID) &&
        !setTID(yield, eid, tid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SetTID failed", phosphor::logging::entry("EID=0x%X", eid));
        tidPool.pushFrontUnusedTID(tid);
        return false;
    }

    if (!tidMapper.addEntry(tid, eid))
    {
        tidPool.pushFrontUnusedTID(tid);
        return false;
    }
    if (uuid)
    {
        uuidMapping.emplace(uuid.value(), tid);
    }
    discoveryDataTable.insert_or_assign(tid, DiscoveryData({cmdSupportTable}));
    return true;
}

bool deleteDeviceBaseInfo(const pldm_tid_t tid)
{
    auto itr = std::find_if(uuidMapping.begin(), uuidMapping.end(),
                            [&tid](const auto& uuidTID) {
                                auto const& [uuid, mappedTID] = uuidTID;
                                return mappedTID == tid;
                            });
    if (itr != uuidMapping.end())
    {
        auto const& [uuid, mappedTID] = *itr;
        releaseTIDAfterReclaimInterval(mappedTID);
    }
    tidMapper.removeEntry(tid);
    return discoveryDataTable.erase(tid) == 1;
}

bool isSupported(pldm_tid_t tid, const uint8_t type, const uint8_t cmd)
{
    try
    {
        DiscoveryData& discoveryData = discoveryDataTable.at(tid);
        return isSupported(discoveryData.cmdSupportTable, type, cmd);
    }
    catch (std::out_of_range&)
    {
        return false;
    }
}

bool isSupported(pldm_tid_t tid, const uint8_t type)
{
    try
    {
        DiscoveryData& discoveryData = discoveryDataTable.at(tid);
        return discoveryData.cmdSupportTable.find(type) !=
               discoveryData.cmdSupportTable.end();
    }
    catch (std::out_of_range&)
    {
        return false;
    }
}

} // namespace base
} // namespace pldm
