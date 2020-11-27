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
#include "sensor.hpp"

#include <boost/asio.hpp>

#include "platform.h"

namespace pldm
{
namespace platform
{

// TODO:Move pldm_sensor_init to libpldm. Keeping here temporarily to unblock
// further development activity
/** @brief PLDM sensor initialization schemes
 */
enum pldm_sensor_init
{
    PLDM_NO_INIT,
    PLDM_USE_INIT_PDR,
    PLDM_ENABLE_SENSOR,
    PLDM_DISABLE_SENSOR
};

class SensorManager
{
  public:
    SensorManager() = delete;
    SensorManager(const SensorManager&) = delete;
    SensorManager(SensorManager&&) = delete;
    SensorManager& operator=(const SensorManager&) = delete;
    SensorManager& operator=(SensorManager&&) = delete;
    ~SensorManager() = default;

    SensorManager(const pldm_tid_t tid, const SensorID sensorID,
                  const std::string& name,
                  const pldm_numeric_sensor_value_pdr& pdr);

    /** @brief Init Sensor Manager*/
    bool sensorManagerInit(boost::asio::yield_context& yield);

  private:
    /** @brief  Enable sensor*/
    bool setNumericSensorEnable(boost::asio::yield_context& yield);

    /** @brief  Get supported thresholds from PDR*/
    void getSupportedThresholds(
        std::vector<thresholds::Threshold>& thresholdData);

    /** @brief Init sensor*/
    bool initSensor();

    /** @brief Terminus ID*/
    pldm_tid_t _tid;

    /** @brief Sensor ID*/
    SensorID _sensorID;

    /** @brief Sensor name*/
    std::string _name;

    /** @brief Sensor PDR*/
    pldm_numeric_sensor_value_pdr _pdr;

    /** @brief Sensor*/
    std::shared_ptr<Sensor> _sensor;
};

} // namespace platform
} // namespace pldm
