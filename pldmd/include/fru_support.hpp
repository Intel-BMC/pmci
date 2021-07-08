/**
 * Copyright © 2021 Intel Corporation
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

#include <map>
#include <sdbusplus/asio/object_server.hpp>

#include "fru.h"

using FRUVariantType = std::variant<uint8_t, uint32_t, std::string>;
using FRUProperties = std::map<std::string, FRUVariantType>;

class FruSupport
{
  public:
    /** @brief Converts PLDM FRU to IPMI FRU
     *  @param tid - TID of the PLDM device
     *  @param fruProperties - Properties of PLDM device
     *  @return void
     */
    void convertFRUToIpmiFRU(const pldm_tid_t& tid,
                             const FRUProperties& fruProperties);

    /** @brief Removes the IPMI interfaces
     *  @param tid - TID of the PLDM device
     *  @return void
     */
    void removeInterfaces(const pldm_tid_t& tid);

  private:
    std::unordered_map<pldm_tid_t,
                       std::shared_ptr<sdbusplus::asio::dbus_interface>>
        ipmiFruInterface;
};
