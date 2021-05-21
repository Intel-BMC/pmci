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
#include "platform_terminus.hpp"

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace platform
{

PlatformTerminus::PlatformTerminus(boost::asio::yield_context yield,
                                   const pldm_tid_t tid) :
    _tid(tid)
{
    if (!initPDRs(yield))
    {
        throw std::runtime_error("Platform terminus initialization failed");
    }

    initSensors(yield);

    initEffecters(yield);
}

void PlatformTerminus::initSensors(boost::asio::yield_context yield)
{
    std::unordered_map<SensorID, std::string> sensorList =
        pdrManager->getSensors();

    for (auto const& [sensorID, sensorName] : sensorList)
    {
        if (auto pdr = pdrManager->getNumericSensorPDR(sensorID))
        {
            std::unique_ptr<NumericSensorHandler> numericSensorHandler =
                std::make_unique<NumericSensorHandler>(_tid, sensorID,
                                                       sensorName, *pdr);
            if (!numericSensorHandler->sensorHandlerInit(yield))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Sensor Handler Init failed",
                    phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                    phosphor::logging::entry("TID=%d", _tid));
                continue;
            }

            numericSensors.emplace(sensorID, std::move(numericSensorHandler));
        }

        if (auto pdr = pdrManager->getStateSensorPDR(sensorID))
        {
            std::unique_ptr<StateSensorHandler> stateSensorHandler;
            try
            {
                stateSensorHandler = std::make_unique<StateSensorHandler>(
                    _tid, sensorID, sensorName, *pdr);
            }
            catch (const std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    e.what(),
                    phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                    phosphor::logging::entry("TID=%d", _tid));
                continue;
            }

            if (!stateSensorHandler->sensorHandlerInit(yield))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "State Sensor Init failed",
                    phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                    phosphor::logging::entry("TID=%d", _tid));
                continue;
            }

            stateSensors.emplace(sensorID, std::move(stateSensorHandler));
        }
    }
}

void PlatformTerminus::initEffecters(boost::asio::yield_context yield)
{
    std::unordered_map<EffecterID, std::string> effecterList =
        pdrManager->getEffecters();

    for (auto const& [effecterID, effecterName] : effecterList)
    {
        if (auto pdr = pdrManager->getNumericEffecterPDR(effecterID))
        {
            std::unique_ptr<NumericEffecterHandler> numericEffecterHandler =
                std::make_unique<NumericEffecterHandler>(_tid, effecterID,
                                                         effecterName, *pdr);
            if (!numericEffecterHandler->effecterHandlerInit(yield))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Numeric Effecter Handler Init failed",
                    phosphor::logging::entry("EFFECTER_ID=0x%0X", effecterID),
                    phosphor::logging::entry("TID=%d", _tid));
                continue;
            }

            numericEffecters.emplace(effecterID,
                                     std::move(numericEffecterHandler));
        }

        if (auto pdr = pdrManager->getStateEffecterPDR(effecterID))
        {
            std::unique_ptr<StateEffecterHandler> stateEffecterHandler =
                std::make_unique<StateEffecterHandler>(_tid, effecterID,
                                                       effecterName, pdr);
            if (!stateEffecterHandler->effecterHandlerInit(yield))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "State Effecter Init failed",
                    phosphor::logging::entry("EFFECTER_ID=0x%0X", effecterID),
                    phosphor::logging::entry("TID=%d", _tid));
                continue;
            }

            stateEffecters.emplace(effecterID, std::move(stateEffecterHandler));
        }
    }
}

bool PlatformTerminus::initPDRs(boost::asio::yield_context yield)
{
    pdrManager = std::make_unique<PDRManager>(_tid);
    if (!pdrManager->pdrManagerInit(yield))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PDR Manager Init failed",
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "PDR Manager Init Success", phosphor::logging::entry("TID=%d", _tid));

    return true;
}
} // namespace platform
} // namespace pldm