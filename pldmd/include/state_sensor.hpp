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
    bool StateSensorInit(boost::asio::yield_context& yield);

  private:
    /** @brief Enable/Disable sensor*/
    bool setStateSensorEnables(boost::asio::yield_context& yield);

    /** @brief Terminus ID*/
    pldm_tid_t _tid;

    /** @brief Sensor ID*/
    SensorID _sensorID;

    /** @brief Sensor name*/
    std::string _name;

    /** @brief Sensor PDR*/
    std::shared_ptr<StateSensorPDR> _pdr;
};

} // namespace platform
} // namespace pldm
