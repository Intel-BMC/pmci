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

#include "numeric_effecter_manager.hpp"
#include "pdr_manager.hpp"
#include "pldm.hpp"
#include "sensor_manager.hpp"
#include "state_effecter.hpp"
#include "state_sensor.hpp"

#include "platform.h"

namespace pldm
{
namespace platform
{

constexpr uint16_t commandTimeout = 100;
constexpr size_t commandRetryCount = 3;

using UUID = std::array<uint8_t, 16>;

std::optional<UUID> getTerminusUID(boost::asio::yield_context yield,
                                   const mctpw_eid_t eid);

struct PlatformMonitoringControl
{
    std::unique_ptr<PDRManager> pdrManager;
    std::unordered_map<SensorID, std::unique_ptr<SensorManager>>
        sensorManagerMap;
    std::unordered_map<SensorID, std::unique_ptr<StateSensor>> stateSensorMap;
    // TODO: Rename above maps as NumericSensors and StateSensors
    std::unordered_map<EffecterID, std::unique_ptr<NumericEffecterManager>>
        numericEffecters;
    std::unordered_map<EffecterID, std::unique_ptr<StateEffecter>>
        stateEffecters;
};

/** @brief Pause sensor polling
 *
 *  Caller should resume the sensor polling manually using resumeSensorPolling()
 */
void pauseSensorPolling();

/** @brief Resume sensor polling if it is paused*/
void resumeSensorPolling();
} // namespace platform
} // namespace pldm
