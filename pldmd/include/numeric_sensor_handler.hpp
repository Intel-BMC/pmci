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
#include "pdr_manager.hpp"

#include <boost/asio.hpp>

#include "platform.h"

namespace pldm
{
namespace platform
{

class NumericSensorHandler
{
  public:
    NumericSensorHandler() = delete;
    NumericSensorHandler(const NumericSensorHandler&) = delete;
    NumericSensorHandler(NumericSensorHandler&&) = delete;
    NumericSensorHandler& operator=(const NumericSensorHandler&) = delete;
    NumericSensorHandler& operator=(NumericSensorHandler&&) = delete;
    ~NumericSensorHandler() = default;

    NumericSensorHandler(
        const pldm_tid_t tid, const SensorID sensorID, const std::string& name,
        const std::shared_ptr<pldm_numeric_sensor_value_pdr>& pdr);

    /** @brief Init NumericSensorHandler*/
    bool sensorHandlerInit(boost::asio::yield_context& yield);

    /** @brief Read sensor value and update interfaces*/
    bool populateSensorValue(boost::asio::yield_context& yield);

    /**@brief Check sensor is disabled or not*/
    bool isSensorDisabled()
    {
        return sensorDisabled;
    }

  private:
    /** @brief  Enable sensor*/
    bool setNumericSensorEnable(boost::asio::yield_context& yield);

    /** @brief  Get supported thresholds from PDR*/
    void getSupportedThresholds(
        std::vector<thresholds::Threshold>& thresholdData);

    /** @brief Init sensor*/
    bool initSensor();

    /** @brief fetch the sensor value*/
    bool getSensorReading(boost::asio::yield_context& yield);

    /** @brief Decode sensor value and D-Bus interfaces*/
    bool handleSensorReading(uint8_t sensorOperationalState,
                             uint8_t sensorDataSize,
                             union_sensor_data_size& presentReading);

    /** @brief Terminus ID*/
    pldm_tid_t _tid;

    /** @brief Sensor ID*/
    SensorID _sensorID;

    /** @brief Sensor name*/
    std::string _name;

    /** @brief Sensor PDR*/
    std::shared_ptr<pldm_numeric_sensor_value_pdr> _pdr;

    /** @brief Sensor*/
    std::shared_ptr<NumericSensor> _sensor;

    /** @brief Sensor disabled flag*/
    bool sensorDisabled = false;
};

} // namespace platform
} // namespace pldm
