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
    /** @brief Add IPMI Fru interfaces, Add GetRawFru method
     *
     * @return void
     */
    void initializeFRUSupport();

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
    std::shared_ptr<sdbusplus::asio::dbus_interface> fruIface;
    std::map<pldm_tid_t, FRUProperties> ipmiFRUProperties;

    /** @brief returns the FRUData in IPMI format
     *
     * @return FRURecord in IPMI format on success; empty table otherwise
     * on failure
     */
    std::optional<std::vector<uint8_t>>
        getRawFRURecordData(const pldm_tid_t tid);

    /** @brief Returns checksum
     */
    uint8_t calculateChecksum(std::vector<uint8_t>::const_iterator iter,
                              std::vector<uint8_t>::const_iterator end);

    /** @brief Set the Common Header of IPMI FRU
     */
    void setCommonHeader(const uint8_t internalAreaLen,
                         const uint8_t chassisAreaLen,
                         const uint8_t boardAreaLen,
                         const uint8_t productAreaLen,
                         std::vector<uint8_t>& ipmiFruData);

    uint8_t setInternalArea(std::vector<uint8_t>& fruData);

    uint8_t setChassisArea(std::vector<uint8_t>& fruData);

    uint8_t setBoardArea(std::vector<uint8_t>& fruData);

    uint8_t setProductArea(const FRUProperties& properties,
                           std::vector<uint8_t>& fruData);

    uint8_t setHeaderAreaOffset(uint8_t& fruOffset, const uint8_t areaOffset);
};
