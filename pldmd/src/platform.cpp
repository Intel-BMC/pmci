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
#include "platform.hpp"

#include "pldm.hpp"

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace platform
{
// Holds platform monitoring and control resources for each termini
static std::map<pldm_tid_t, PlatformMonitoringControl> platforms{};

bool platformInit(boost::asio::yield_context yield, const pldm_tid_t tid,
                  const PLDMCommandTable& /*commandTable*/)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Running Platform Monitoring and Control initialisation",
        phosphor::logging::entry("TID=0x%X", tid));

    // Destroy previous resources if any
    platformDestroy(tid);

    auto& platformMC = platforms[tid];
    platformMC.pdrManager = std::make_unique<PDRManager>(yield, tid);

    if (!platformMC.pdrManager->pdrManagerInit())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PDR Manager Init failed",
            phosphor::logging::entry("TID=0x%X", tid));
        return false;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "PDR Manager Init Success", phosphor::logging::entry("TID=0x%X", tid));

    return true;
}

bool platformDestroy(const pldm_tid_t tid)
{
    auto entry = platforms.find(tid);
    if (entry == platforms.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("No Platform Monitoring and Control resources related to TID " +
             std::to_string(tid))
                .c_str());
        return false;
    }
    platforms.erase(entry);
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Platform Monitoring and Control resources destroyed for TID " +
         std::to_string(tid))
            .c_str());

    return true;
}
} // namespace platform
} // namespace pldm
