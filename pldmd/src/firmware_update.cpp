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
#include <xyz/openbmc_project/PLDM/FWU/FWUBase/server.hpp>

namespace pldm
{
namespace fwu
{
using FWUBase = sdbusplus::xyz::openbmc_project::PLDM::FWU::server::FWUBase;

void pldmMsgRecvCallback(const pldm_tid_t tid, const uint8_t /*msgTag*/,
                         const bool /*tagOwner*/,
                         std::vector<uint8_t>& /*message*/)
{
    // TODO: Perform the actual init operations needed
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "PLDM Firmware update message received",
        phosphor::logging::entry("EID=0x%X", tid));

    return;
}

static bool fwuBaseInitialized = false;

static void initializeFWUBase()
{
    std::string objPath = "/xyz/openbmc_project/pldm/fwu";
    auto objServer = getObjServer();
    auto fwuBaseIface = objServer->add_interface(objPath, FWUBase::interface);
    fwuBaseIface->register_method(
        "StartFWUpdate", []([[maybe_unused]] std::string filePath) {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "StartFWUpdate is called");
        });
    fwuBaseIface->initialize();
    fwuBaseInitialized = true;
}

bool fwuInit(boost::asio::yield_context /*yield*/, const pldm_tid_t /*tid*/)
{
    if (!fwuBaseInitialized)
    {
        initializeFWUBase();
    }

    return true;
}
} // namespace fwu
} // namespace pldm
