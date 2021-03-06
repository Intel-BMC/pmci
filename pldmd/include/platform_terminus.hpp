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

#include "numeric_effecter_handler.hpp"
#include "numeric_sensor_handler.hpp"
#include "pdr_manager.hpp"
#include "state_effecter_handler.hpp"
#include "state_sensor_handler.hpp"

namespace pldm
{
namespace platform
{
struct PlatformTerminus
{
  public:
    PlatformTerminus(boost::asio::yield_context yield, const pldm_tid_t tid);

    std::unique_ptr<PDRManager> pdrManager;
    std::unordered_map<SensorID, std::unique_ptr<NumericSensorHandler>>
        numericSensors;
    std::unordered_map<SensorID, std::unique_ptr<StateSensorHandler>>
        stateSensors;
    std::unordered_map<EffecterID, std::unique_ptr<NumericEffecterHandler>>
        numericEffecters;
    std::unordered_map<EffecterID, std::unique_ptr<StateEffecterHandler>>
        stateEffecters;

  private:
    void initSensors(boost::asio::yield_context yield);
    void initEffecters(boost::asio::yield_context yield);
    bool initPDRs(boost::asio::yield_context yield);

    pldm_tid_t _tid;
};
} // namespace platform
} // namespace pldm