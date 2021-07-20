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

#include "fwu_utils.hpp"

#include "firmware_update.h"

namespace pldm
{
namespace fwu
{

class FWInventoryInfo
{
  public:
    FWInventoryInfo() = delete;
    explicit FWInventoryInfo(const pldm_tid_t _tid);

    /** @brief runs inventory commands
     */
    std::optional<FDProperties>
        runInventoryCommands(boost::asio::yield_context yield);
    /** @brief API that adds inventory info to D-Bus
     */
    void addInventoryInfoToDBus();

    std::vector<std::unique_ptr<sdbusplus::asio::dbus_interface>>&
        getInterfaces()
    {
        return interfaceList;
    }

    std::string getInventoryPath()
    {
        return inventoryPath;
    }

  private:
    std::vector<std::unique_ptr<sdbusplus::asio::dbus_interface>> interfaceList;

    /** @brief run query device identifiers command
     * @return PLDM_SUCCESS on success and corresponding error completion code
     * on failure
     */
    int runQueryDeviceIdentifiers(boost::asio::yield_context yield);

    /** @brief run get firmware parameters command
     * @return PLDM_SUCCESS on success and corresponding error completion code
     * on failure
     */
    int runGetFirmwareParameters(boost::asio::yield_context yield);

    /** @brief API that unpacks get firmware parameters component data.
     */
    int unpackCompData(const uint16_t count,
                       const std::vector<uint8_t>& compData);

    /** @brief API that copies get firmware parameters component image set data
     * to fwuProperties map.
     */
    void copyCompImgSetData(
        const struct get_firmware_parameters_resp& respData,
        const struct variable_field& activeCompImgSetVerStr,
        const struct variable_field& pendingCompImgSetVerStr);

    /** @brief API that copies get firmware parameters component data to
     * fwuProperties map.
     */
    void copyCompData(const uint16_t count,
                      const struct component_parameter_table* componentData,
                      struct variable_field* activeCompVerStr,
                      struct variable_field* pendingCompVerStr);
    /** @brief API that adds component image set info to D-Bus
     */
    void addCompImgSetDataToDBus();

    /** @brief API that adds descriptor data to D-Bus
     */
    void addDescriptorsToDBus();

    /** @brief API that adds component info to D-Bus
     */
    void addCompDataToDBus();

    /** @brief API that adds pci descriptors to D-Bus
     */
    void addPCIDescriptorsToDBus(const std::string& objPath);

    /** @brief API that gets auto apply property
     */
    bool getCompAutoApply(const uint32_t capabilitiesDuringUpdate);

    /** @brief API that adds firmware inventory to dbus
     */
    void addFirmwareInventoryToDBus();

    pldm_tid_t tid;
    std::shared_ptr<sdbusplus::asio::object_server> objServer;
    // map that holds the component properties of a terminus
    CompPropertiesMap compPropertiesMap;
    std::string pendingCompImgSetVerStr;
    std::string activeCompImgSetVerStr;
    uint16_t initialDescriptorType;
    const uint16_t timeout = 100;
    const size_t retryCount = 3;
    // map that holds the general properties of a terminus
    FWUProperties fwuProperties;
    // map that holds the descriptors of a terminus
    DescriptorsMap descriptors;
    std::string inventoryPath;
};
} // namespace fwu
} // namespace pldm
