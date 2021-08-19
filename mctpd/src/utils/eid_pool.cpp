/*
// Copyright (c) 2021 Intel Corporation
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

#include "utils/eid_pool.hpp"

#include <phosphor-logging/log.hpp>
#include <system_error>

namespace mctpd
{

void EidPool::initializeEidPool(const std::set<mctp_eid_t>& pool)
{
    for (auto const& epId : pool)
    {
        eidPool.push_back(std::make_pair(epId, false));
    }
}

void EidPool::updateEidStatus(const mctp_eid_t endpointId, const bool assigned)
{
    bool eidPresent = false;
    size_t prevSize = eidPool.size();
    // To implement EID pool in FIFO: The eid entry in the pool is removed and
    // inserted at the end, so that the older EID from the pool is picked for
    // registering the endpoint.

    eidPool.erase(std::remove_if(eidPool.begin(), eidPool.end(),
                                 [endpointId](auto const& eidPair) {
                                     return (eidPair.first == endpointId);
                                 }),
                  eidPool.end());
    eidPresent = (prevSize > eidPool.size());

    if (eidPresent)
    {
        eidPool.push_back(std::make_pair(endpointId, assigned));

        if (assigned)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("EID " + std::to_string(endpointId) + " is assigned").c_str());
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("EID " + std::to_string(endpointId) + " added to pool")
                    .c_str());
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Unable to find EID " + std::to_string(endpointId) +
             " in the pool")
                .c_str());
    }
}

mctp_eid_t EidPool::getAvailableEidFromPool()
{
    // Note:- No need to check for busowner role explicitly when accessing EID
    // pool since getAvailableEidFromPool will be called only in busowner mode.

    for (auto& [eid, eidAssignedStatus] : eidPool)
    {
        if (!eidAssignedStatus)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Allocated EID: " + std::to_string(eid)).c_str());
            eidAssignedStatus = true;
            return eid;
        }
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "No free EID in the pool");
    throw std::system_error(
        std::make_error_code(std::errc::address_not_available));
}

} // namespace mctpd
