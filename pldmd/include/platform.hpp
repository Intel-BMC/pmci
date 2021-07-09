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

#include "platform_terminus.hpp"
#include "pldm.hpp"

#include <boost/asio/steady_timer.hpp>

#include "platform.h"

namespace pldm
{
namespace platform
{

constexpr uint16_t commandTimeout = 100;
constexpr size_t commandRetryCount = 3;

using UUID = std::array<uint8_t, 16>;

std::optional<UUID>
    getTerminusUID(boost::asio::yield_context yield, const pldm_tid_t tid,
                   std::optional<mctpw_eid_t> eid = std::nullopt);

class Platform
{
  public:
    void stopSensorPolling();
    void startSensorPolling();
    bool initTerminus(boost::asio::yield_context yield, const pldm_tid_t tid,
                      const pldm::base::CommandSupportTable& commandTable);
    bool deleteTerminus(const pldm_tid_t tid);

  private:
    bool induceAsyncDelay(boost::asio::yield_context yield, int delay);
    void doPoll(boost::asio::yield_context yield);
    void pollAllSensors();
    void initializeSensorPollIntf();
    void initializePlatformIntf();
    bool isTerminusRemoved(const pldm_tid_t tid);
    void removeTIDFromInitializationList(const pldm_tid_t tid);

    std::map<pldm_tid_t, PlatformTerminus> platforms{};
    std::unique_ptr<boost::asio::steady_timer> sensorTimer = nullptr;
    bool isSensorPollRunning = false;
    bool startSensorPoll = false;
    bool stopSensorPoll = false;
    std::set<pldm_tid_t> tidsUnderInitialization{};
};

/** @brief Pause sensor polling
 *
 *  Caller should resume the sensor polling manually using resumeSensorPolling()
 */
void pauseSensorPolling();

/** @brief Resume sensor polling if it is paused*/
void resumeSensorPolling();
} // namespace platform
} // namespace pldm
