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

#include "mctpw.h"

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

bool sendReceivePldmMessage(boost::asio::yield_context yield,
                            const pldm_tid_t tid, const uint16_t timeout,
                            std::vector<uint8_t> pldmReq,
                            std::vector<uint8_t>& pldmResp,
                            std::optional<mctpw_eid_t> eid)
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
    pldmReq.insert(pldmReq.begin(), PLDM);

    // TODO: Use mctp-wrapper provided api to send/receive PLDM message
    boost::system::error_code ec;
    auto bus = getSdBus();
    pldmResp = bus->yield_method_call<std::vector<uint8_t>>(
        yield, ec, "xyz.openbmc_project.mctp-emulator",
        "/xyz/openbmc_project/mctp", "xyz.openbmc_project.MCTP.Base",
        "SendReceiveMctpMessagePayload", dstEid, pldmReq, timeout);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PLDM message send/receive failed");
        return false;
    }

    if (pldmResp.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Empty response received");
        return false;
    }

    // Verify the response received is of type PLDM
    if (pldmResp.at(0) == PLDM)
    {
        pldmResp.erase(pldmResp.begin());
        pldmReq.erase(pldmReq.begin());
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Response received is not of message type PLDM");
        return false;
    }

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
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Instance ID check failed");
    return false;
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

    // TODO: List Endpoints that support registered PLDM message type

    // Using dummy EID till the discovery is implemented
    mctpw_eid_t dummyEid = 1;
    if (auto tid = pldm::getFreeTid())
    {
        // TODO: Add TID to mapper only if setTID/getTID success
        pldm::addToMapper(*tid, dummyEid);

        // TODO: Assign TID and find supported PLDM type and execute
        // corresponding methods Dummy init method invocation
        if (pldm::platform::platformInit(*tid))
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "PLDM platform init success",
                phosphor::logging::entry("TID=%d", *tid));
        }
    }
    ioc->run();

    return 0;
}
