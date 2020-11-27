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

#include "sensor.hpp"

#include "platform.h"

namespace pdr
{

namespace sensor
{

/** @brief Calculate sensor value*/
double calculateSensorValue(const pldm_numeric_sensor_value_pdr& pdr,
                            const double& sensorReading);

/** @brief Fetch the sensor value as per data size*/
std::optional<double> fetchSensorValue(const pldm_numeric_sensor_value_pdr& pdr,
                                       const union_sensor_data_size& data);

/** @brief Get sensor unit as per D-Bus representation*/
std::optional<SensorUnit>
    getSensorUnit(const pldm_numeric_sensor_value_pdr& pdr);

/** @brief Fetch range field value as per range field format*/
std::optional<double>
    fetchRangeFieldValue(const pldm_numeric_sensor_value_pdr& pdr,
                         const union_range_field_format& data);

} // namespace sensor
} // namespace pdr
