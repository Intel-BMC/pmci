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
static std::map<pldm_tid_t, PlatformTerminus> platforms{};
// TODO: Optimize poll interval
static constexpr const int pollIntervalMillisec = 10;
std::unique_ptr<boost::asio::steady_timer> sensorTimer = nullptr;
static bool isSensorPollRunning = false;

bool introduceDelayInPolling(boost::asio::yield_context& yield)
{
    if (!sensorTimer)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Sensor poll timer not active");
        return false;
    }

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
    for (auto const& [tid, platformTerminus] : platforms)
    {
        for (auto const& [sensorID, numericSensorHandler] :
             platformTerminus.numericSensors)
        {
            if (numericSensorHandler->isSensorDisabled())
            {
                continue;
            }
            numericSensorHandler->populateSensorValue(yield);
            if (!introduceDelayInPolling(yield))
            {
                isSensorPollRunning = false;
                return;
            }
            isSensorPollRunning = true;
        }
        for (auto const& [sensorID, stateSensorHandler] :
             platformTerminus.stateSensors)
        {
            if (stateSensorHandler->isSensorDisabled())
            {
                continue;
            }
            stateSensorHandler->populateSensorValue(yield);
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
    sensorTimer = std::make_unique<boost::asio::steady_timer>(*getIoContext());
    boost::asio::spawn(*getIoContext(), [](boost::asio::yield_context yield) {
        pollAllSensors(yield);
    });
}

void initSensors(boost::asio::yield_context& yield, const pldm_tid_t tid)
{
    PlatformTerminus& platformTerminus = platforms[tid];
    std::unordered_map<SensorID, std::string> sensorList =
        platformTerminus.pdrManager->getSensors();

    for (auto const& [sensorID, sensorName] : sensorList)
    {
        if (auto pdr =
                platformTerminus.pdrManager->getNumericSensorPDR(sensorID))
        {
            std::unique_ptr<NumericSensorHandler> numericSensorHandler =
                std::make_unique<NumericSensorHandler>(tid, sensorID,
                                                       sensorName, *pdr);
            if (!numericSensorHandler->sensorHandlerInit(yield))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Sensor Handler Init failed",
                    phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                    phosphor::logging::entry("TID=%d", tid));
                continue;
            }

            platformTerminus.numericSensors[sensorID] =
                std::move(numericSensorHandler);
        }

        if (auto pdr = platformTerminus.pdrManager->getStateSensorPDR(sensorID))
        {
            std::unique_ptr<StateSensorHandler> stateSensorHandler;
            try
            {
                stateSensorHandler = std::make_unique<StateSensorHandler>(
                    tid, sensorID, sensorName, *pdr);
            }
            catch (const std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    e.what(),
                    phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                    phosphor::logging::entry("TID=%d", tid));
                continue;
            }

            if (!stateSensorHandler->sensorHandlerInit(yield))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "State Sensor Init failed",
                    phosphor::logging::entry("SENSOR_ID=0x%0X", sensorID),
                    phosphor::logging::entry("TID=%d", tid));
                continue;
            }

            platformTerminus.stateSensors[sensorID] =
                std::move(stateSensorHandler);
        }
    }
}

void initEffecters(boost::asio::yield_context& yield, const pldm_tid_t tid)
{
    PlatformTerminus& platformTerminus = platforms[tid];
    std::unordered_map<EffecterID, std::string> effecterList =
        platformTerminus.pdrManager->getEffecters();

    for (auto const& [effecterID, effecterName] : effecterList)
    {
        if (auto pdr =
                platformTerminus.pdrManager->getNumericEffecterPDR(effecterID))
        {
            std::unique_ptr<NumericEffecterHandler> numericEffecterHandler =
                std::make_unique<NumericEffecterHandler>(tid, effecterID,
                                                         effecterName, *pdr);
            if (!numericEffecterHandler->effecterHandlerInit(yield))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Numeric Effecter Handler Init failed",
                    phosphor::logging::entry("EFFECTER_ID=0x%0X", effecterID),
                    phosphor::logging::entry("TID=%d", tid));
                continue;
            }

            platformTerminus.numericEffecters[effecterID] =
                std::move(numericEffecterHandler);
        }

        if (auto pdr =
                platformTerminus.pdrManager->getStateEffecterPDR(effecterID))
        {
            std::unique_ptr<StateEffecterHandler> stateEffecterHandler =
                std::make_unique<StateEffecterHandler>(tid, effecterID,
                                                       effecterName, pdr);
            if (!stateEffecterHandler->effecterHandlerInit(yield))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "State Effecter Init failed",
                    phosphor::logging::entry("EFFECTER_ID=0x%0X", effecterID),
                    phosphor::logging::entry("TID=%d", tid));
                continue;
            }

            platformTerminus.stateEffecters[effecterID] =
                std::move(stateEffecterHandler);
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

    PlatformTerminus& platformTerminus = platforms[tid];
    platformTerminus.pdrManager = std::move(pdrManager);

    return true;
}

// TODO Add support to accept eid or tid.
std::optional<UUID> getTerminusUID(boost::asio::yield_context yield,
                                   const mctpw_eid_t eid)
{
    static constexpr pldm_tid_t defaultTID = 0x00;
    static constexpr size_t hdrSize = sizeof(PLDMEmptyRequest);
    uint8_t instanceID = createInstanceId(defaultTID);
    std::vector<uint8_t> getUIDRequest(hdrSize, 0x00);
    auto msg = reinterpret_cast<pldm_msg*>(getUIDRequest.data());

    int rc = encode_get_terminus_uid_req(instanceID, msg);
    if (!validatePLDMReqEncode(eid, rc, "GetTerminusUUID"))
    {
        return std::nullopt;
    }

    std::vector<uint8_t> getUIDResponse;
    if (!sendReceivePldmMessage(yield, defaultTID, commandTimeout,
                                commandRetryCount, getUIDRequest,
                                getUIDResponse, eid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send receive error during GetTerminusUUID request");
        return std::nullopt;
    }

    uint8_t completionCode;
    UUID uuid;
    rc = decode_get_terminus_uid_resp(
        reinterpret_cast<pldm_msg*>(getUIDResponse.data()),
        getUIDResponse.size() - hdrSize, &completionCode, uuid.data());
    if (!validatePLDMRespDecode(eid, rc, completionCode, "GetTerminusUUID"))
    {
        return std::nullopt;
    }
    return uuid;
}

void pauseSensorPolling()
{
    if (!sensorTimer)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Sensor polling timer not yet active");
        return;
    }
    sensorTimer->cancel();
    sensorTimer.reset();
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Sensor polling paused");
}

void resumeSensorPolling()
{
    initSensorPoll();
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Sensor polling resumed");
}

bool platformInit(boost::asio::yield_context yield, const pldm_tid_t tid,
                  const pldm::base::CommandSupportTable& /*commandTable*/)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Running Platform Monitoring and Control initialisation",
        phosphor::logging::entry("TID=%d", tid));

    // Delete previous resources if any
    deleteMnCTerminus(tid);

    if (!initPDRs(yield, tid))
    {
        return false;
    }

    initSensors(yield, tid);

    initEffecters(yield, tid);

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Platform Monitoring and Control initialisation success",
        phosphor::logging::entry("TID=%d", tid));

    return true;
}

bool deleteMnCTerminus(const pldm_tid_t tid)
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
        ("Platform Monitoring and Control resources deleted for TID " +
         std::to_string(tid))
            .c_str());

    return true;
}
} // namespace platform
} // namespace pldm
