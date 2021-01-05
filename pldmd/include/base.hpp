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

#pragma once

#include <boost/asio/spawn.hpp>
#include <functional>

#include "base.h"

namespace std
{
template <>
struct hash<ver32_t>
{
    std::size_t operator()(const ver32_t& ver) const
    {
        return std::hash<uint8_t>{}(ver.major) ^
               std::hash<uint8_t>{}(ver.minor) ^
               std::hash<uint8_t>{}(ver.update) ^
               std::hash<uint8_t>{}(ver.alpha);
    }
};
inline bool operator==(const ver32_t& v1, const ver32_t& v2)
{
    return v1.major == v2.major && v1.minor == v2.minor &&
           v1.update == v2.update && v1.alpha == v2.alpha;
}
} // namespace std

namespace pldm
{
namespace base
{
// For bitfield8[N], where N = 0 to 31;
// (bit M is set) => PLDM Command (N*8+M) Supported
using SupportedCommands = std::array<bitfield8_t, 32>;
// [PLDMType -> [PLDMVersion -> SupportedCommands]] Mapping
using CommandSupportTable =
    std::unordered_map<uint8_t, std::unordered_map<ver32_t, SupportedCommands>>;

// TODO. Use eid_type for eid
bool baseInit(boost::asio::yield_context yield, const uint8_t eid,
              pldm_tid_t& tid, CommandSupportTable& cmdSupportTable);
bool baseDestroy(pldm_tid_t tid);

bool isSupported(const CommandSupportTable& cmdSupportTable, const uint8_t type,
                 const uint8_t cmd);
bool isSupported(pldm_tid_t tid, const uint8_t type, const uint8_t cmd);

} // namespace base
} // namespace pldm
