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

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace platform
{
// TODO: Optimize poll interval
static constexpr const int pollIntervalMillisec = 500;
static Platform platform;

bool Platform::introduceDelayInPolling(boost::asio::yield_context yield)
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
void Platform::pollAllSensors()
{
    auto doPoll = [this](boost::asio::yield_context yield) {
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
            pollAllSensors();
        }
    };

    boost::asio::spawn(*getIoContext(), doPoll);
}

void Platform::initSensorPoll()
{
    if (isSensorPollRunning)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Sensor poll already running");
        return;
    }
    sensorTimer = std::make_unique<boost::asio::steady_timer>(*getIoContext());
    pollAllSensors();
}

std::optional<UUID> getTerminusUID(boost::asio::yield_context yield,
                                   const pldm_tid_t tid,
                                   std::optional<mctpw_eid_t> eid)
{

    static constexpr size_t hdrSize = sizeof(PLDMEmptyRequest);
    uint8_t instanceID = createInstanceId(tid);
    std::vector<uint8_t> getUIDRequest(hdrSize, 0x00);
    auto msg = reinterpret_cast<pldm_msg*>(getUIDRequest.data());

    int rc = encode_get_terminus_uid_req(instanceID, msg);
    if (!validatePLDMReqEncode(tid, rc, "GetTerminusUUID"))
    {
        return std::nullopt;
    }

    std::vector<uint8_t> getUIDResponse;
    if (!sendReceivePldmMessage(yield, tid, commandTimeout, commandRetryCount,
                                getUIDRequest, getUIDResponse, eid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send or receive error during GetTerminusUUID request");
        return std::nullopt;
    }

    uint8_t completionCode;
    UUID uuid;
    rc = decode_get_terminus_uid_resp(
        reinterpret_cast<pldm_msg*>(getUIDResponse.data()),
        getUIDResponse.size() - hdrSize, &completionCode, uuid.data());
    if (!validatePLDMRespDecode(tid, rc, completionCode, "GetTerminusUUID"))
    {
        return std::nullopt;
    }
    return uuid;
}

void Platform::stopSensorPolling()
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

void Platform::startSensorPolling()
{
    initSensorPoll();
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Sensor polling resumed");
}

void Platform::initializeSensorPollIntf()
{
    static std::unique_ptr<sdbusplus::asio::dbus_interface> pausePollInterface =
        nullptr;
    if (pausePollInterface != nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "pausePollInterface already initialized");
        return;
    }

    const char* objPath = "/xyz/openbmc_project/sensors";
    pausePollInterface =
        addUniqueInterface(objPath, "xyz.openbmc_project.PLDM.SensorPoll");
    pausePollInterface->register_method("PauseSensorPoll",
                                        [](const bool pause) {
                                            if (pause)
                                            {
                                                pauseSensorPolling();
                                            }
                                            else
                                            {
                                                resumeSensorPolling();
                                            }
                                        });
    pausePollInterface->initialize();
}

void Platform::initializePlatformIntf()
{
    static std::unique_ptr<sdbusplus::asio::dbus_interface> platformInterface =
        nullptr;
    if (platformInterface != nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "platformInterface already initialized");
        return;
    }

    const char* objPath = "/xyz/openbmc_project/system";
    platformInterface =
        addUniqueInterface(objPath, "xyz.openbmc_project.PLDM.Platform");
    platformInterface->register_method(
        "RefreshPDR",
        [](boost::asio::yield_context yield, const pldm_tid_t tid) {
            pauseSensorPolling();
            platformInit(yield, tid, {});
            resumeSensorPolling();
        });
    platformInterface->initialize();
}

bool Platform::isTerminusRemoved(const pldm_tid_t tid)
{
    return tidsUnderInitialization.count(tid) == 0;
}

void Platform::removeTIDFromInitializationList(const pldm_tid_t tid)
{
    auto search = tidsUnderInitialization.find(tid);
    if (search != tidsUnderInitialization.end())
    {
        tidsUnderInitialization.erase(search);
    }
}

bool Platform::initTerminus(
    boost::asio::yield_context yield, const pldm_tid_t tid,
    const pldm::base::CommandSupportTable& /*commandTable*/)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Running Platform Monitoring and Control initialisation",
        phosphor::logging::entry("TID=%d", tid));

    // Delete previous resources if any
    deleteMnCTerminus(tid);
    tidsUnderInitialization.emplace(tid);

    if (debug)
    {
        initializeSensorPollIntf();
        initializePlatformIntf();
    }

    try
    {
        PlatformTerminus platformTerminus(yield, tid);
        if (isTerminusRemoved(tid))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Terminus removed before Platform Monitoring and Control "
                "initialisation completes",
                phosphor::logging::entry("TID=%d", tid));
            return false;
        }
        platforms.insert_or_assign(tid, std::move(platformTerminus));
    }
    catch (const std::exception& e)
    {
        removeTIDFromInitializationList(tid);
        phosphor::logging::log<phosphor::logging::level::ERR>(
            e.what(), phosphor::logging::entry("TID=%d", tid));
        return false;
    }

    removeTIDFromInitializationList(tid);
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Platform Monitoring and Control initialisation success",
        phosphor::logging::entry("TID=%d", tid));

    return true;
}

bool Platform::deleteTerminus(const pldm_tid_t tid)
{
    removeTIDFromInitializationList(tid);

    auto entry = platforms.find(tid);
    if (entry == platforms.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("No Platform Monitoring and Control resources related to "
             "TID " +
             std::to_string(tid))
                .c_str());
        return false;
    }
    pauseSensorPolling();
    platforms.erase(entry);
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Platform Monitoring and Control resources deleted for TID " +
         std::to_string(tid))
            .c_str());
    resumeSensorPolling();

    return true;
}

void pauseSensorPolling()
{
    platform.stopSensorPolling();
}

void resumeSensorPolling()
{
    platform.startSensorPolling();
}

bool platformInit(boost::asio::yield_context yield, const pldm_tid_t tid,
                  const pldm::base::CommandSupportTable& commandTable)
{
    return platform.initTerminus(yield, tid, commandTable);
}

bool deleteMnCTerminus(const pldm_tid_t tid)
{
    return platform.deleteTerminus(tid);
}

} // namespace platform
} // namespace pldm
