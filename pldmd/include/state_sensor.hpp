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

#include <boost/asio.hpp>

#include "platform.h"

namespace pldm
{
namespace platform
{

class StateSensor
{
  public:
    StateSensor() = delete;
    StateSensor(const StateSensor&) = delete;
    StateSensor(StateSensor&&) = delete;
    StateSensor& operator=(const StateSensor&) = delete;
    StateSensor& operator=(StateSensor&&) = delete;
    ~StateSensor() = default;

    StateSensor(const pldm_tid_t tid, const SensorID sensorID,
                const std::string& name,
                const std::shared_ptr<StateSensorPDR>& pdr);

    /** @brief Init StateSensor*/
    bool stateSensorInit(boost::asio::yield_context& yield);

    /** @brief Read sensor value and update interfaces*/
    bool populateSensorValue(boost::asio::yield_context& yield);

    /**@brief Check sensor is disabled or not*/
    bool isSensorDisabled()
    {
        return sensorDisabled;
    }

  private:
    /** @brief Enable/Disable sensor*/
    bool setStateSensorEnables(boost::asio::yield_context& yield);

    /** @brief fetch the sensor value*/
    bool getStateSensorReadings(boost::asio::yield_context& yield);

    /** @brief Set initial D-Bus interfaces and properties*/
    void setInitialProperties();

    /** @brief Initialize D-Bus interfaces*/
    void initializeInterface();

    /** @brief Update the sensor functionality*/
    void markFunctional(bool isFunctional);

    /** @brief Update the sensor availability*/
    void markAvailable(bool isAvailable);

    /** @brief Increment the error count in case of failure*/
    void incrementError();

    /** @brief Update sensor state*/
    void updateState(const uint8_t currentState, const uint8_t previousState);

    /** @brief Handle sensor reading*/
    bool handleSensorReading(get_sensor_state_field& stateReading);

    /** @brief Terminus ID*/
    pldm_tid_t _tid;

    /** @brief Sensor ID*/
    SensorID _sensorID;

    /** @brief Sensor name*/
    std::string _name;

    /** @brief Sensor PDR*/
    std::shared_ptr<StateSensorPDR> _pdr;

    /** @brief Error counter*/
    size_t errCount;

    /** @brief Sensor disabled flag*/
    bool sensorDisabled = false;

    /** @brief Cache readings for later use*/
    bool isAvailableReading = std::numeric_limits<bool>::min();
    bool isFuntionalReading = std::numeric_limits<bool>::min();
    uint8_t previousStateReading = std::numeric_limits<uint8_t>::max();
    uint8_t currentStateReading = std::numeric_limits<uint8_t>::max();

    /** @brief Sensor Interfaces*/
    std::unique_ptr<sdbusplus::asio::dbus_interface> sensorInterface = nullptr;
    std::unique_ptr<sdbusplus::asio::dbus_interface> availableInterface =
        nullptr;
    std::unique_ptr<sdbusplus::asio::dbus_interface> operationalInterface =
        nullptr;
};

} // namespace platform
} // namespace pldm
