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

#pragma once

#include <cstdint>
#include <numeric>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mctpd
{
using BindingPrivateVect = std::vector<uint8_t>;
}

namespace std
{
template <>
struct hash<mctpd::BindingPrivateVect>
{
    size_t operator()(const mctpd::BindingPrivateVect& bindingPrivate) const
    {
        size_t init = 0;
        return std::accumulate(std::begin(bindingPrivate),
                               std::end(bindingPrivate), init,
                               [](size_t prevHash, uint8_t byte) {
                                   return prevHash ^ std::hash<uint8_t>{}(byte);
                               });
    }
};
} // namespace std

namespace mctpd
{
struct DeviceWatcher
{
  public:
    void deviceDiscoveryInit();
    bool isDeviceGoodForInit(const BindingPrivateVect& bindingPvt);
    bool checkDeviceInitThreshold(const BindingPrivateVect& bindingPvt);

  private:
    std::unordered_set<BindingPrivateVect> ignoreList;
    std::unordered_set<BindingPrivateVect> previousInitList;
    std::unordered_set<BindingPrivateVect> currentInitList;
    std::unordered_map<BindingPrivateVect, int> successiveInitCount;
};
} // namespace mctpd