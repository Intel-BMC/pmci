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

#include "numeric_sensor.hpp"

#include "platform.h"

namespace pdr
{

namespace sensor
{

/** @brief Calculate sensor value*/
double calculateSensorValue(const pldm_numeric_sensor_value_pdr& pdr,
                            const float& sensorReading);

/** @brief Fetch the sensor value as per data size*/
std::optional<float> fetchSensorValue(const pldm_numeric_sensor_value_pdr& pdr,
                                      const union_sensor_data_size& data);

/** @brief Get sensor unit as per D-Bus representation*/
std::optional<SensorUnit>
    getSensorUnit(const pldm_numeric_sensor_value_pdr& pdr);

/** @brief Fetch range field value as per range field format*/
std::optional<float>
    fetchRangeFieldValue(const pldm_numeric_sensor_value_pdr& pdr,
                         const union_range_field_format& data);

} // namespace sensor

namespace effecter
{

/** @brief Calculate effecter value*/
double calculateEffecterValue(const pldm_numeric_effecter_value_pdr& pdr,
                              const float& value);

/** @brief Calculate setable effecter value*/
std::optional<double>
    calculateSettableEffecterValue(const pldm_numeric_effecter_value_pdr& pdr,
                                   const double& value);

/** @brief Fetch the effecter value as per data size*/
std::optional<float>
    fetchEffecterValue(const pldm_numeric_effecter_value_pdr& pdr,
                       const union_effecter_data_size& data);

/** @brief Fetch range field value as per range field format*/
std::optional<float>
    fetchRangeFieldValue(const pldm_numeric_effecter_value_pdr& pdr,
                         const union_range_field_format& data);

} // namespace effecter

} // namespace pdr
