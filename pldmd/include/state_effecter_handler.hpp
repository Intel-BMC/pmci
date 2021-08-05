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

class StateEffecterHandler
{
  public:
    StateEffecterHandler() = delete;
    StateEffecterHandler(const StateEffecterHandler&) = delete;
    StateEffecterHandler(StateEffecterHandler&&) = delete;
    StateEffecterHandler& operator=(const StateEffecterHandler&) = delete;
    StateEffecterHandler& operator=(StateEffecterHandler&&) = delete;
    ~StateEffecterHandler() = default;

    StateEffecterHandler(const pldm_tid_t tid, const EffecterID effecterID,
                         const std::string& name,
                         const std::shared_ptr<StateEffecterPDR>& pdr);

    /** @brief Init StateEffecterHandler*/
    bool effecterHandlerInit(boost::asio::yield_context yield);

  private:
    /** @brief Initialize initial D-Bus interfaces and properties*/
    void setInitialProperties();

    /** @brief Initialize D-Bus interfaces*/
    void initializeInterface();

    /** @brief Update the effecter functionality*/
    void markFunctional(bool isFunctional);

    /** @brief Update the effecter availability*/
    void markAvailable(bool isAvailable);

    /** @brief Increment the error count in case of failure*/
    void incrementError();

    /** @brief Update effecter state*/
    void updateState(const uint8_t currentState, const uint8_t pendingState);

    /** @brief  Enable effecter*/
    bool enableStateEffecter(boost::asio::yield_context yield);

    /** @brief Handle effecter reading*/
    bool handleStateEffecterState(boost::asio::yield_context yield,
                                  get_effecter_state_field& stateReading);

    /** @brief fetch the effecter value*/
    bool getStateEffecterStates(boost::asio::yield_context yield);

    /** @brief Read effecter value and update interfaces*/
    bool populateEffecterValue(boost::asio::yield_context yield);

    /** @brief Validate the effecter value is supported*/
    bool isEffecterStateSettable(const uint8_t state);

    /** @brief Set effecter value*/
    bool setEffecter(boost::asio::yield_context yield, const uint8_t value);

    /** @brief Register D-Bus interfaces for SetEffecterValue*/
    void registerSetEffecter();

    /** @brief Terminus ID*/
    pldm_tid_t _tid;

    /** @brief Effecter ID*/
    EffecterID _effecterID;

    /** @brief Effecter name*/
    std::string _name;

    /** @brief Effecter PDR*/
    std::shared_ptr<StateEffecterPDR> _pdr;

    /** @brief Error counter*/
    size_t errCount = 0;

    /** @brief Cache readings for later use*/
    bool isAvailableReading = false;
    bool isFuntionalReading = false;
    uint8_t pendingStateReading = std::numeric_limits<uint8_t>::max();
    uint8_t currentStateReading = std::numeric_limits<uint8_t>::max();

    /** @brief Flags which indicate interfaces are ready*/
    bool effecterIntfReady = false;
    bool availableIntfReady = false;
    bool operationalIntfReady = false;
    bool interfaceInitialized = false;

    /** @brief Effecter Interfaces*/
    std::unique_ptr<sdbusplus::asio::dbus_interface> effecterInterface =
        nullptr;
    std::unique_ptr<sdbusplus::asio::dbus_interface> availableInterface =
        nullptr;
    std::unique_ptr<sdbusplus::asio::dbus_interface> operationalInterface =
        nullptr;
    std::unique_ptr<sdbusplus::asio::dbus_interface> setEffecterInterface =
        nullptr;

    /** @brief Timer to wait for trasition interval after setStateEffecter*/
    std::unique_ptr<boost::asio::steady_timer> transitionIntervalTimer;

    uint8_t stateCmdRetryCount{};
};

} // namespace platform
} // namespace pldm
