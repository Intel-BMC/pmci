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

class StateEffecter
{
  public:
    StateEffecter() = delete;
    StateEffecter(const StateEffecter&) = delete;
    StateEffecter(StateEffecter&&) = delete;
    StateEffecter& operator=(const StateEffecter&) = delete;
    StateEffecter& operator=(StateEffecter&&) = delete;
    ~StateEffecter() = default;

    StateEffecter(const pldm_tid_t tid, const EffecterID effecterID,
                  const std::string& name,
                  const std::shared_ptr<StateEffecterPDR>& pdr);

    /** @brief Init StateEffecter*/
    bool stateEffecterInit(boost::asio::yield_context& yield);

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
    bool enableStateEffecter(boost::asio::yield_context& yield);

    /** @brief Terminus ID*/
    pldm_tid_t _tid;

    /** @brief Effecter ID*/
    EffecterID _effecterID;

    /** @brief Effecter name*/
    std::string _name;

    /** @brief Effecter PDR*/
    std::shared_ptr<StateEffecterPDR> _pdr;

    /** @brief Error counter*/
    size_t errCount;

    /** @brief Cache readings for later use*/
    bool isAvailableReading = false;
    bool isFuntionalReading = false;
    uint8_t pendingStateReading = std::numeric_limits<uint8_t>::max();
    uint8_t currentStateReading = std::numeric_limits<uint8_t>::max();

    /** @brief Effecter Interfaces*/
    std::unique_ptr<sdbusplus::asio::dbus_interface> effecterInterface =
        nullptr;
    std::unique_ptr<sdbusplus::asio::dbus_interface> availableInterface =
        nullptr;
    std::unique_ptr<sdbusplus::asio::dbus_interface> operationalInterface =
        nullptr;
};

} // namespace platform
} // namespace pldm
