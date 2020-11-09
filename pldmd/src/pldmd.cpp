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

#include "pldm.hpp"

#include <phosphor-logging/log.hpp>

static constexpr const char* pldmService = "xyz.openbmc_project.pldm";
static constexpr const char* pldmPath = "/xyz/openbmc_project/pldm";

namespace pldm
{
// Mapper will have 1:1 mapping between TID and EID
using Mapper = std::unordered_map<
    pldm_tid_t, /*TID as key*/
    mctpw_eid_t /*TODO: Update to std::variant<MCTP_EID, RBT for NCSI) etc.*/>;
static Mapper tidMapper;

std::optional<pldm_tid_t> getTidFromMapper(const mctpw_eid_t eid)
{
    for (auto& eidMap : tidMapper)
    {
        if (eidMap.second == eid)
        {
            return eidMap.second;
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
    // TODO: Use mctp-wrapper provided api to send/receive PLDM message
    boost::system::error_code ec;
    auto bus = getSdBus();
    pldmResp = bus->yield_method_call<std::vector<uint8_t>>(
        yield, ec, "xyz.openbmc_project.mctp-emulator",
        "/xyz/openbmc_project/mctp", "xyz.openbmc_project.MCTP.Base",
        "SendReceiveMctpMessagePayload", dstEid, pldmReq, timeout);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "PLDM message send/receive failed");
        return false;
    }
    return true;
}

bool sendReceivePldmMessage(boost::asio::yield_context yield,
                            const pldm_tid_t tid, const uint16_t timeout,
                            size_t retryCount, std::vector<uint8_t> pldmReq,
                            std::vector<uint8_t>& pldmResp,
                            std::optional<mctpw_eid_t> eid)
{
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

    // TODO: Use mctp-wrapper provided api to send PLDM message
    auto bus = getSdBus();
    bus->async_method_call(
        [tid](const boost::system::error_code ec) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error sending PLDM message",
                    phosphor::logging::entry("TID=%d", tid));
                return;
            }
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "PLDM message send Success",
                phosphor::logging::entry("TID=%d", tid));
        },
        "xyz.openbmc_project.mctp-emulator", "/xyz/openbmc_project/mctp",
        "xyz.openbmc_project.MCTP.Base", "SendMctpMessagePayload", dstEid,
        msgTag, tagOwner, payload);
    return true;
}

auto msgRecvCallback = [](sdbusplus::message::message& message) {
    uint8_t messageType;
    mctpw_eid_t srcEid;
    uint8_t msgTag;
    bool tagOwner;
    std::vector<uint8_t> payload;

    message.read(messageType, srcEid, msgTag, tagOwner, payload);

    // Verify the response received is of type PLDM
    if (messageType == PLDM && !payload.empty() && payload.at(0) == PLDM)
    {

        // Discard the packet if no matching TID is found
        // Why: We do not have to process packets from uninitialised Termini
        if (auto tid = getTidFromMapper(srcEid))
        {

            payload.erase(payload.begin());
            if (auto pldmMsgType = getPldmMessageType(payload))
            {
                switch (*pldmMsgType)
                {
                    case PLDM_FWU:
                        pldm::fwu::pldmMsgRecvCallback(*tid, msgTag, tagOwner,
                                                       payload);
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

std::unique_ptr<sdbusplus::bus::match::match> pldmMsgRecvMatch;
void pldmMsgRecvCallbackInit()
{
    // TODO: Use mctp-wrapper provided api to receive PLDM message signals
    const std::string filterMsgRecvdSignal =
        sdbusplus::bus::match::rules::type::signal() +
        sdbusplus::bus::match::rules::member("MessageReceivedSignal") +
        sdbusplus::bus::match::rules::interface(
            "xyz.openbmc_project.MCTP.Base");

    auto bus = getSdBus();
    pldmMsgRecvMatch = std::make_unique<sdbusplus::bus::match::match>(
        *bus, filterMsgRecvdSignal, msgRecvCallback);
}

uint8_t createInstanceId(pldm_tid_t tid)
{
    static std::unordered_map<pldm_tid_t, uint8_t> instanceMap;

    auto& instanceId = instanceMap[tid];

    instanceId = (instanceId + 1) & PLDM_INSTANCE_ID_MASK;
    return instanceId;
}
} // namespace pldm

// These are expected to be used only here, so declare them here
extern void setIoContext(const std::shared_ptr<boost::asio::io_context>& newIo);
extern void
    setSdBus(const std::shared_ptr<sdbusplus::asio::connection>& newBus);
extern void setObjServer(
    const std::shared_ptr<sdbusplus::asio::object_server>& newServer);

int main(void)
{
    auto ioc = std::make_shared<boost::asio::io_context>();
    setIoContext(ioc);
    boost::asio::signal_set signals(*ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc](const boost::system::error_code&, const int&) { ioc->stop(); });

    auto conn = std::make_shared<sdbusplus::asio::connection>(*ioc);

    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(conn);
    conn->request_name(pldmService);
    setSdBus(conn);
    setObjServer(objectServer);

    auto objManager =
        std::make_shared<sdbusplus::server::manager::manager>(*conn, pldmPath);

    // Register for PLDM message signals
    pldm::pldmMsgRecvCallbackInit();

    // TODO: List Endpoints that support registered PLDM message type

    // Using dummy EID exposed by emulator until the discovery is implemented
    mctpw_eid_t dummyEid = 8;
    if (auto tid = pldm::getFreeTid())
    {
        // TODO: Add TID to mapper only if setTID/getTID success
        pldm::addToMapper(*tid, dummyEid);

        // TODO: Assign TID and find supported PLDM type and execute
        // corresponding init methods

        // Create yield context for each new TID and pass to the Init methods
        boost::asio::spawn(*ioc, [&tid](boost::asio::yield_context yield) {
            // Dummy init method invocation
            if (pldm::platform::platformInit(yield, *tid, {}))
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "PLDM platform init success",
                    phosphor::logging::entry("TID=%d", *tid));
            }
        });
    }
    ioc->run();

    return 0;
}
