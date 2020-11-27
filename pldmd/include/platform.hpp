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

#include "pdr_manager.hpp"
#include "pldm.hpp"
#include "sensor_manager.hpp"

#include "platform.h"

namespace pldm
{
namespace platform
{

constexpr uint16_t commandTimeout = 100;
constexpr size_t commandRetryCount = 3;

struct PlatformMonitoringControl
{
    std::unique_ptr<PDRManager> pdrManager;
    std::unordered_map<SensorID, std::shared_ptr<SensorManager>>
        sensorManagerMap;
    // TODO: Add effecter resources
};

} // namespace platform
} // namespace pldm
