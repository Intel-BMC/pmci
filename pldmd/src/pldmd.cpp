/*
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "base.hpp"
#include "mctp_wrapper.hpp"
#include "platform.hpp"
#include "pldm.hpp"
#include "utils.hpp"

#include <phosphor-logging/log.hpp>

static constexpr const char* pldmService = "xyz.openbmc_project.pldm";
static constexpr const char* pldmPath = "/xyz/openbmc_project/pldm";
bool debug = false;

namespace pldm
{

// Mapper will have 1:1 mapping between TID and EID
using Mapper = std::unordered_map<
    pldm_tid_t, /*TID as key*/
    mctpw_eid_t /*TODO: Update to std::variant<MCTP_EID, RBT for NCSI) etc.*/>;
static Mapper tidMapper;

static bool rsvBWActive = false;
static pldm_tid_t reservedTID = pldmInvalidTid;
static uint8_t reservedPLDMType = pldmInvalidType;

static bool validateReserveBW(const pldm_tid_t tid, const uint8_t pldmType)
{
    return rsvBWActive && !(tid == reservedTID && pldmType == reservedPLDMType);
}

bool reserveBandwidth(const boost::asio::yield_context& yield,
                      const pldm_tid_t tid, const uint8_t pldmType,
                      const uint16_t timeout)
{
    if (validateReserveBW(tid, pldmType))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Reserve bandwidth is active for TID: " +
             std::to_string(reservedTID) +
             ". RESERVED_PLDM_TYPE: " + std::to_string(reservedPLDMType))
                .c_str());
        return false;
    }
    mctpw_eid_t eid = 0;
    if (auto eidPtr = getEidFromMapper(tid))
    {
        eid = *eidPtr;
    }
    else
    {
        return false;
    }
    boost::system::error_code ec;
    auto bus = getSdBus();
    int rc = bus->yield_method_call<int>(
        yield, ec, "xyz.openbmc_project.MCTP_SMBus_PCIe_slot",
        "/xyz/openbmc_project/mctp", "xyz.openbmc_project.MCTP.Base",
        "ReserveBandwidth", eid, timeout);

    if (ec || rc < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (("ReserveBandwidth: failed for EID: ") + std::to_string(eid))
                .c_str());
        return false;
    }
    rsvBWActive = true;
    reservedTID = tid;
    reservedPLDMType = pldmType;
    return true;
}

bool releaseBandwidth(const boost::asio::yield_context& yield,
                      const pldm_tid_t tid, const uint8_t pldmType)
{
    if (!rsvBWActive)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "releaseBandwidth: Reserve bandwidth is not active.");
        return false;
    }
    if (tid != reservedTID || pldmType != reservedPLDMType)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "releaseBandwidth: Invalid TID or pldm type");
        return false;
    }
    std::optional<mctpw_eid_t> eid = getEidFromMapper(tid);
    if (eid == std::nullopt)
    {
        return false;
    }
    boost::system::error_code ec;
    auto bus = getSdBus();
    int rc = bus->yield_method_call<int>(
        yield, ec, "xyz.openbmc_project.MCTP_SMBus_PCIe_slot",
        "/xyz/openbmc_project/mctp", "xyz.openbmc_project.MCTP.Base",
        "ReleaseBandwidth", *eid);

    if (ec || rc < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (("releaseBandwidth: failed for EID: ") + std::to_string(*eid))
                .c_str());
        return false;
    }
    rsvBWActive = false;
    reservedTID = pldmInvalidTid;
    reservedPLDMType = pldmInvalidType;
    return true;
}
std::unique_ptr<mctpw::MCTPWrapper> mctpWrapper;

std::optional<pldm_tid_t> getTidFromMapper(const mctpw_eid_t eid)
{
    for (auto& eidMap : tidMapper)
    {
        if (eidMap.second == eid)
        {
            return eidMap.first;
        }
    }
    phosphor::logging::log<phosphor::logging::level::WARNING>(
        "EID not found in the mapper");
    return std::nullopt;
}

void addToMapper(const pldm_tid_t tid, const mctpw_eid_t eid)
{
    tidMapper[tid] = eid;
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Mapper: TID " + std::to_string(static_cast<int>(tid)) +
         " mapped to EID " + std::to_string(static_cast<int>(eid)))
            .c_str());
}

std::optional<pldm_tid_t> getFreeTid()
{
    static pldm_tid_t tid = 0x00;
    if (tid < PLDM_TID_MAX)
    {
        tid += 1;
        return tid;
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "No free TID available");
    return std::nullopt;
}

std::optional<mctpw_eid_t> getEidFromMapper(const pldm_tid_t tid)
{
    auto mapperPtr = tidMapper.find(tid);
    if (mapperPtr != tidMapper.end())
    {
        return mapperPtr->second;
    }
    phosphor::logging::log<phosphor::logging::level::WARNING>(
        "TID not found in the mapper");
    return std::nullopt;
}

std::optional<uint8_t> getInstanceId(std::vector<uint8_t>& message)
{
    if (message.empty())
    {
        return std::nullopt;
    }
    return message[0] & PLDM_INSTANCE_ID_MASK;
}

std::optional<uint8_t> getPldmMessageType(std::vector<uint8_t>& message)
{
    constexpr int msgTypeIndex = 1;
    if (message.size() < 2)
    {
        return std::nullopt;
    }
    return message[msgTypeIndex] & PLDM_MSG_TYPE_MASK;
}

// Returns type of message(response,request, Reserved or Unacknowledged PLDM
// request messages)
std::optional<MessageType> getPldmPacketType(std::vector<uint8_t>& message)
{
    constexpr int rqD = 0;
    if (message.size() < 1)
    {
        return std::nullopt;
    }

    uint8_t rqDValue = (message[rqD] & PLDM_RQ_D_MASK) >> PLDM_RQ_D_SHIFT;
    return static_cast<MessageType>(rqDValue);
}

bool validatePLDMReqEncode(const pldm_tid_t tid, const int rc,
                           const std::string& commandString)
{
    if (rc != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (commandString + ": Request encode failed").c_str(),
            phosphor::logging::entry("TID=%d", tid),
            phosphor::logging::entry("RC=%d", rc));
        return false;
    }
    return true;
}

bool validatePLDMRespDecode(const pldm_tid_t tid, const int rc,
                            const uint8_t completionCode,
                            const std::string& commandString)
{
    if (rc != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (commandString + ": Response decode failed").c_str(),
            phosphor::logging::entry("TID=%d", tid),
            phosphor::logging::entry("RC=%d", rc));
        return false;
    }

    // Completion code value is considered as valid only if decode is success(rc
    // = PLDM_SUCCESS)
    if (completionCode != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (commandString + ": Invalid completion code").c_str(),
            phosphor::logging::entry("TID=%d", tid),
            phosphor::logging::entry("CC=%d", completionCode));
        return false;
    }
    return true;
}

static bool doSendReceievePldmMessage(boost::asio::yield_context yield,
                                      const mctpw_eid_t dstEid,
                                      const uint16_t timeout,
                                      std::vector<uint8_t>& pldmReq,
                                      std::vector<uint8_t>& pldmResp)
{
    auto sendStatus = mctpWrapper->sendReceiveYield(
        yield, dstEid, pldmReq, std::chrono::milliseconds(timeout));
    pldmResp = sendStatus.second;
    utils::printVect("Request(MCTP payload):", pldmReq);
    utils::printVect("Response(MCTP payload):", pldmResp);
    return sendStatus.first ? false : true;
}

bool sendReceivePldmMessage(boost::asio::yield_context yield,
                            const pldm_tid_t tid, const uint16_t timeout,
                            size_t retryCount, std::vector<uint8_t> pldmReq,
                            std::vector<uint8_t>& pldmResp,
                            std::optional<mctpw_eid_t> eid)
{
    pldm_msg_hdr* hdr = reinterpret_cast<pldm_msg_hdr*>(pldmReq.data());
    if (validateReserveBW(tid, hdr->type))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("sendReceivePldmMessage is not allowed. Reserve bandwidth is "
             "active for TID: " +
             std::to_string(reservedTID) +
             " RESERVED_PLDM_TYPE: " + std::to_string(reservedPLDMType))
                .c_str());
        return false;
    }
    // Retry the request if
    //  1) No response
    //  2) payload.size() < 4
    //  3) If response bit is not set in PLDM header
    //  4) Invalid message type
    //  5) Invalid instance id

    // Upper cap of retryCount = 5
    constexpr size_t maxRetryCount = 5;
    if (retryCount > maxRetryCount)
    {
        retryCount = maxRetryCount;
    }

    for (size_t retry = 0; retry < retryCount; retry++)
    {
        mctpw_eid_t dstEid;

        // Input EID takes precedence over TID
        // Usecase: TID reassignment
        if (eid)
        {
            dstEid = eid.value();
        }
        else
        {
            // A PLDM device removal can cause an update to TID mapper. In such
            // case the retry should be aborted immediately.
            if (auto eidPtr = getEidFromMapper(tid))
            {
                dstEid = *eidPtr;
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "PLDM message send failed. Invalid TID/EID");
                return false;
            }
        }

        // Insert MCTP Message Type to start of the payload
        if (retry == 0)
        {
            pldmReq.insert(pldmReq.begin(), PLDM);
        }

        // Clear the resp vector each time before a retry
        pldmResp.clear();
        if (doSendReceievePldmMessage(yield, dstEid, timeout, pldmReq,
                                      pldmResp))
        {
            constexpr size_t minPldmMsgSize = 4;
            if (pldmResp.size() < minPldmMsgSize)
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    "Invalid response length");
                continue;
            }

            // Verify the message received is a response
            if (auto msgTypePtr = getPldmPacketType(pldmResp))
            {
                if (*msgTypePtr != PLDM_RESPONSE)
                {
                    phosphor::logging::log<phosphor::logging::level::WARNING>(
                        "PLDM message received is not response");
                    continue;
                }
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    "Unable to get message type");
                continue;
            }

            // Verify the response received is of type PLDM
            constexpr int mctpMsgType = 0;
            if (pldmResp.at(mctpMsgType) == PLDM)
            {
                // Remove the MCTP message type and IC bit from req and resp
                // payload.
                // Why: Upper layer handlers(PLDM message type handlers)
                // are not intrested in MCTP message type information and
                // integrity check fields.
                pldmResp.erase(pldmResp.begin());
                pldmReq.erase(pldmReq.begin());
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    "Response received is not of message type PLDM");
                continue;
            }

            // Verify request and response instance ID matches
            if (auto reqInstanceId = getInstanceId(pldmReq))
            {
                if (auto respInstanceId = getInstanceId(pldmResp))
                {
                    if (*reqInstanceId == *respInstanceId)
                    {
                        return true;
                    }
                }
            }
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Instance ID check failed");
            continue;
        }
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Retry count exceeded. No response");
    return false;
}

bool sendPldmMessage(const pldm_tid_t tid, const uint8_t msgTag,
                     const bool tagOwner, std::vector<uint8_t> payload)
{
    pldm_msg_hdr* hdr = reinterpret_cast<pldm_msg_hdr*>(payload.data());
    if (validateReserveBW(tid, hdr->type))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("sendPldmMessage is not allowed. Reserve bandwidth is active for "
             "TID: " +
             std::to_string(reservedTID) +
             " RESERVED_PLDM_TYPE: " + std::to_string(reservedPLDMType))
                .c_str());
        return false;
    }

    mctpw_eid_t dstEid;
    if (auto eidPtr = getEidFromMapper(tid))
    {
        dstEid = *eidPtr;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PLDM message send failed. Invalid TID");
        return false;
    }

    // Insert MCTP Message Type to start of the payload
    payload.insert(payload.begin(), PLDM);
    utils::printVect("Send PLDM message(MCTP payload):", payload);

    auto sendCallback = [](boost::system::error_code ec, int status) {
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                (std::string("Send error ") + ec.message()).c_str());
        }
        if (status == -1)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "SendMCTPPayload returned -1");
        }
    };
    mctpWrapper->sendAsync(sendCallback, dstEid, msgTag, tagOwner, payload);
    return true;
}

auto msgRecvCallback = [](void*, mctpw::eid_t srcEid, bool tagOwner,
                          uint8_t msgTag, const std::vector<uint8_t>& data,
                          int) {
    // Intentional copy. MCTPWrapper provides const reference in callback
    auto payload = data;
    // Verify the response received is of type PLDM
    if (!payload.empty() && payload.at(0) == PLDM)
    {
        // Discard the packet if no matching TID is found
        // Why: We do not have to process packets from uninitialised Termini
        if (auto tid = getTidFromMapper(srcEid))
        {
            utils::printVect("PLDM message received(MCTP payload):", payload);
            payload.erase(payload.begin());
            if (auto pldmMsgType = getPldmMessageType(payload))
            {
                switch (*pldmMsgType)
                {
                    case PLDM_FWU:
                        pldm::fwu::pldmMsgRecvFwUpdCallback(*tid, msgTag,
                                                            tagOwner, payload);
                        break;
                        // No use case for other PLDM message types
                    default:
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            "Unsupported PLDM message received",
                            phosphor::logging::entry("TID=%d", *tid),
                            phosphor::logging::entry("EID=%d", srcEid),
                            phosphor::logging::entry("MSG_TYPE=%d",
                                                     *pldmMsgType));
                        break;
                }
            }
        }
    }
};

uint8_t createInstanceId(pldm_tid_t tid)
{
    static std::unordered_map<pldm_tid_t, uint8_t> instanceMap;

    auto& instanceId = instanceMap[tid];

    instanceId = (instanceId + 1) & PLDM_INSTANCE_ID_MASK;
    return instanceId;
}
} // namespace pldm

void initDevice(const mctpw_eid_t eid, boost::asio::yield_context& yield)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Initializing MCTP EID " + std::to_string(eid)).c_str());

    pldm_tid_t assignedTID = 0x00;
    pldm::base::CommandSupportTable cmdSupportTable;
    if (!pldm::base::baseInit(yield, eid, assignedTID, cmdSupportTable))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PLDM base init failed", phosphor::logging::entry("EID=%d", eid));
        return;
    }

    auto isSupported = [&cmdSupportTable](pldm_type_t type) {
        return cmdSupportTable.end() != cmdSupportTable.find(type);
    };

    if (isSupported(PLDM_PLATFORM) &&
        !pldm::platform::platformInit(yield, assignedTID, {}))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PLDM platform init failed",
            phosphor::logging::entry("TID=%d", assignedTID));
    }
    if (isSupported(PLDM_FRU) && !pldm::fru::fruInit(yield, assignedTID))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PLDM fru init failed",
            phosphor::logging::entry("TID=%d", assignedTID));
    }
    if (isSupported(PLDM_FWU) && !pldm::fwu::fwuInit(yield, assignedTID))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PLDM firmware update init failed",
            phosphor::logging::entry("TID=%d", assignedTID));
    }
}

void deleteDevice(const pldm_tid_t tid)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Delete PLDM device with TID " + std::to_string(tid)).c_str());

    // Delete the resources in reverse order of init to avoid errors due to
    // dependency if any
    if (pldm::base::isSupported(tid, PLDM_FWU))
    {
        pldm::fwu::deleteFWDevice(tid);
    }
    if (pldm::base::isSupported(tid, PLDM_FRU))
    {
        pldm::fru::deleteFRUDevice(tid);
    }
    if (pldm::base::isSupported(tid, PLDM_PLATFORM))
    {
        pldm::platform::deleteMnCTerminus(tid);
    }
    pldm::base::deleteDeviceBaseInfo(tid);
}

// These are expected to be used only here, so declare them here
extern void setIoContext(const std::shared_ptr<boost::asio::io_context>& newIo);
extern void
    setSdBus(const std::shared_ptr<sdbusplus::asio::connection>& newBus);
extern void setObjServer(
    const std::shared_ptr<sdbusplus::asio::object_server>& newServer);

void onDeviceUpdate(void*, const mctpw::Event& evt,
                    boost::asio::yield_context& yield)
{
    switch (evt.type)
    {
        case mctpw::Event::EventType::deviceAdded: {
            pldm::platform::pauseSensorPolling();
            initDevice(evt.eid, yield);
            pldm::platform::resumeSensorPolling();
            break;
        }
        case mctpw::Event::EventType::deviceRemoved: {
            auto tid = pldm::getTidFromMapper(evt.eid);
            if (tid)
            {
                deleteDevice(tid.value());
            }
            break;
        }
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unsupported event type in onDeviceUpdate",
                phosphor::logging::entry("TYPE=%d",
                                         static_cast<int>(evt.type)));
            break;
    }
    return;
}

void enableDebug()
{
    if (auto envPtr = std::getenv("PLDM_DEBUG"))
    {
        std::string value(envPtr);
        if (value == "1")
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "PLDM debug enabled");
            debug = true;
        }
    }
}

int main(void)
{
    auto ioc = std::make_shared<boost::asio::io_context>();
    setIoContext(ioc);
    boost::asio::signal_set signals(*ioc, SIGINT, SIGTERM);
    signals.async_wait([&ioc](const boost::system::error_code&, const int&) {
        pldm::platform::pauseSensorPolling();
        for (auto& [tid, eid] : pldm::tidMapper)
        {
            deleteDevice(tid);
        }
        ioc->stop();
    });

    auto conn = std::make_shared<sdbusplus::asio::connection>(*ioc);

    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(conn);
    conn->request_name(pldmService);
    setSdBus(conn);
    setObjServer(objectServer);

    auto objManager =
        std::make_shared<sdbusplus::server::manager::manager>(*conn, pldmPath);

    enableDebug();

    // TODO - Read from entity manager about the transport bindings to be
    // supported by PLDM
    mctpw::MCTPConfiguration config(mctpw::MessageType::pldm,
                                    mctpw::BindingType::mctpOverSmBus);

    pldm::mctpWrapper = std::make_unique<mctpw::MCTPWrapper>(
        conn, config, onDeviceUpdate, pldm::msgRecvCallback);

    boost::asio::spawn(*ioc, [](boost::asio::yield_context yield) {
        pldm::mctpWrapper->detectMctpEndpoints(yield);
        auto& eidMap = pldm::mctpWrapper->getEndpointMap();
        for (auto& [eid, service] : eidMap)
        {
            pldm::platform::pauseSensorPolling();
            initDevice(eid, yield);
            pldm::platform::resumeSensorPolling();
        }
    });

    ioc->run();

    return 0;
}
