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

    // TODO: Assign TID and find supported PLDM type and execute corresponding
    // methods
    // Dummy init method invocation
    pldm_tid_t dummyTid = 1;
    if (PLDM_SUCCESS == pldm::platform::platformInit(dummyTid))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "PLDM platform init success",
            phosphor::logging::entry("TID=%d", dummyTid));
    }

    ioc->run();

    return 0;
}
