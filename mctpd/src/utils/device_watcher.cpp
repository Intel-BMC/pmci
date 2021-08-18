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

#include "utils/device_watcher.hpp"

#include <iomanip>
#include <phosphor-logging/log.hpp>
#include <sstream>

using DeviceWatcher = mctpd::DeviceWatcher;

void DeviceWatcher::deviceDiscoveryInit()
{
    previousInitList = std::move(currentInitList);
    for (auto itr = successiveInitCount.begin();
         itr != successiveInitCount.end();)
    {
        if (previousInitList.count(itr->first) == 0)
        {
            itr = successiveInitCount.erase(itr);
        }
        else
        {
            ++itr;
        }
    }
}

bool DeviceWatcher::isDeviceGoodForInit(const BindingPrivateVect& bindingPvt)
{
    return ignoreList.count(bindingPvt) == 0;
}

bool DeviceWatcher::checkDeviceInitThreshold(
    const BindingPrivateVect& bindingPvt)
{
    constexpr int successiveDeviceInitThold = 10;

    currentInitList.emplace(bindingPvt);
    if (previousInitList.count(bindingPvt) == 0)
    {
        successiveInitCount.insert_or_assign(bindingPvt, 0);
        return true;
    }

    auto search = successiveInitCount.find(bindingPvt);
    if (search != successiveInitCount.end())
    {
        if (search->second > successiveDeviceInitThold)
        {
            return false;
        }

        search->second += 1;
        if (search->second == successiveDeviceInitThold)
        {
            ignoreList.emplace(bindingPvt);

            std::stringstream bindingPvtStr;
            for (auto re : bindingPvt)
            {
                bindingPvtStr << " 0x" << std::hex << std::setfill('0')
                              << std::setw(2) << static_cast<int>(re);
            }
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("Device discovery failed successively for device having "
                 "binding private:" +
                 bindingPvtStr.str() + "; Placing the device into ignore list.")
                    .c_str());
            return false;
        }
    }
    return true;
}