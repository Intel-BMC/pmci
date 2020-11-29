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
#include "platform.hpp"

#include "pldm.hpp"

#include <boost/asio/steady_timer.hpp>
#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace platform
{
// Holds platform monitoring and control resources for each termini
static std::map<pldm_tid_t, PlatformMonitoringControl> platforms{};
// TODO: Optimize poll interval
static constexpr const int pollIntervalMillisec = 10;
std::shared_ptr<boost::asio::steady_timer> sensorTimer;
static bool isSensorPollRunning = false;

bool introduceDelayInPolling(boost::asio::yield_context& yield)
{
    boost::system::error_code ec;
    sensorTimer->expires_after(
        boost::asio::chrono::milliseconds(pollIntervalMillisec));
    sensorTimer->async_wait(yield[ec]);
    if (ec == boost::asio::error::operation_aborted)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Sensor poll timer aborted");
        return false;
    }
    else if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Sensor poll timer failed");
        return false;
    }
    return true;
}

// TODO: Dynamic sensor scanning
// As of today, PLDM is majorly used in Add-on-cards which is behind mux.
// There can be M number of Add-on-cards and each one can have N
// associated sensors. Which will result in higher number(M*N) of PLDM
// message traffic through mux. In this case mux switching is a constraint.
// Thus poll sensors sequentially.
void pollAllSensors(boost::asio::yield_context& yield)
{
    for (auto const& [tid, platformMC] : platforms)
    {
        for (auto const& [sensorID, sensorManager] :
             platformMC.sensorManagerMap)
        {
            sensorManager->populateSensorValue(yield);
            if (!introduceDelayInPolling(yield))
            {
                isSensorPollRunning = false;
                return;
            }
            isSensorPollRunning = true;
        }
        for (auto const& [sensorID, stateSensor] : platformMC.stateSensorMap)
        {
            stateSensor->populateSensorValue(yield);
            if (!introduceDelayInPolling(yield))
            {
                isSensorPollRunning = false;
                return;
            }
            isSensorPollRunning = true;
        }
    }
    if (isSensorPollRunning)
    {
        pollAllSensors(yield);
    }
}

void initSensorPoll()
{
    if (isSensorPollRunning)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Sensor poll already running");
        return;
    }
    sensorTimer = std::make_shared<boost::asio::steady_timer>(*getIoContext());
    boost::asio::spawn(*getIoContext(), [](boost::asio::yield_context yield) {
        pollAllSensors(yield);
    });
}

void initSensors(boost::asio::yield_context& yield, const pldm_tid_t tid)
{
    PlatformMonitoringControl& platformMC = platforms[tid];
    std::unordered_map<SensorID, std::string> sensorList =
        platformMC.pdrManager->getSensors();

    for (auto const& [sensorID, sensorName] : sensorList)
    {
        if (auto pdr = platformMC.pdrManager->getNumericSensorPDR(sensorID))
        {
            std::unique_ptr<SensorManager> sensorManager =
                std::make_unique<SensorManager>(tid, sensorID, sensorName,
                                                *pdr);
            if (!sensorManager->sensorManagerInit(yield))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Sensor Manager Init failed",
                    phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                    phosphor::logging::entry("TID=%d", tid));
                continue;
            }

            platformMC.sensorManagerMap[sensorID] = std::move(sensorManager);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Sensor Manager Init Success",
                phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                phosphor::logging::entry("TID=%d", tid));
        }

        if (auto pdr = platformMC.pdrManager->getStateSensorPDR(sensorID))
        {
            std::unique_ptr<StateSensor> stateSensor;
            try
            {
                stateSensor = std::make_unique<StateSensor>(tid, sensorID,
                                                            sensorName, *pdr);
            }
            catch (const std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    e.what(),
                    phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                    phosphor::logging::entry("TID=%d", tid));
                continue;
            }

            if (!stateSensor->stateSensorInit(yield))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "State Sensor Init failed",
                    phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                    phosphor::logging::entry("TID=%d", tid));
                continue;
            }

            platformMC.stateSensorMap[sensorID] = std::move(stateSensor);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "State Sensor Init Success",
                phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                phosphor::logging::entry("TID=%d", tid));
        }
    }
}

bool initPDRs(boost::asio::yield_context& yield, const pldm_tid_t tid)
{
    std::unique_ptr<PDRManager> pdrManager = std::make_unique<PDRManager>(tid);
    if (!pdrManager->pdrManagerInit(yield))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "PDR Manager Init failed", phosphor::logging::entry("TID=%d", tid));
        return false;
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "PDR Manager Init Success", phosphor::logging::entry("TID=%d", tid));

    PlatformMonitoringControl& platformMC = platforms[tid];
    platformMC.pdrManager = std::move(pdrManager);

    return true;
}

bool platformInit(boost::asio::yield_context yield, const pldm_tid_t tid,
                  const PLDMCommandTable& /*commandTable*/)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Running Platform Monitoring and Control initialisation",
        phosphor::logging::entry("TID=%d", tid));

    // Destroy previous resources if any
    platformDestroy(tid);

    if (!initPDRs(yield, tid))
    {
        return false;
    }

    initSensors(yield, tid);

    initSensorPoll();

    phosphor::logging::log<phosphor::logging::level::INFO>(
        " Platform Monitoring and Control initialisation success",
        phosphor::logging::entry("TID=%d", tid));

    return true;
}

bool platformDestroy(const pldm_tid_t tid)
{
    auto entry = platforms.find(tid);
    if (entry == platforms.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("No Platform Monitoring and Control resources related to TID " +
             std::to_string(tid))
                .c_str());
        return false;
    }
    platforms.erase(entry);
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Platform Monitoring and Control resources destroyed for TID " +
         std::to_string(tid))
            .c_str());

    return true;
}
} // namespace platform
} // namespace pldm
