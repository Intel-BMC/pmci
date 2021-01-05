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

#include "numeric_effecter.hpp"
#include "pdr_manager.hpp"

#include <boost/asio.hpp>

#include "platform.h"

namespace pldm
{
namespace platform
{

class NumericEffecterManager
{
  public:
    NumericEffecterManager() = delete;
    NumericEffecterManager(const NumericEffecterManager&) = delete;
    NumericEffecterManager(NumericEffecterManager&&) = delete;
    NumericEffecterManager& operator=(const NumericEffecterManager&) = delete;
    NumericEffecterManager& operator=(NumericEffecterManager&&) = delete;
    ~NumericEffecterManager();

    NumericEffecterManager(const pldm_tid_t tid, const EffecterID effecterID,
                           const std::string& name,
                           const pldm_numeric_effecter_value_pdr& pdr);

    /** @brief Init Effecter Manager*/
    bool effecterManagerInit(boost::asio::yield_context& yield);

  private:
    /** @brief  Enable effecter*/
    bool enableNumericEffecter(boost::asio::yield_context& yield);

    /** @brief Init effecter*/
    bool initEffecter();

    /** @brief fetch the effecter value*/
    bool getEffecterReading(boost::asio::yield_context& yield);

    /** @brief Decode effecter value and update D-Bus interfaces*/
    bool handleEffecterReading(uint8_t effecterOperationalState,
                               uint8_t effecterDataSize,
                               union_effecter_data_size& presentReading);

    /** @brief Read effecter value and update interfaces*/
    bool populateEffecterValue(boost::asio::yield_context& yield);

    /** @brief Set effecter value*/
    bool setEffecter(boost::asio::yield_context& yield, double& value);

    /** @brief Register D-Bus interfaces for SetEffecterValue*/
    void registerSetEffecter();

    /** @brief Terminus ID*/
    pldm_tid_t _tid;

    /** @brief Effecter ID*/
    EffecterID _effecterID;

    /** @brief Effecter name*/
    std::string _name;

    /** @brief Effecter PDR*/
    pldm_numeric_effecter_value_pdr _pdr;

    /** @brief Effecter*/
    std::shared_ptr<NumericEffecter> _effecter;

    /** @brief Set Effecter interface*/
    std::shared_ptr<sdbusplus::asio::dbus_interface> setEffecterInterface;

    /** @brief Timer to wait for trasition interval after
     * SetNumericEffecterValue*/
    std::unique_ptr<boost::asio::steady_timer> transitionIntervalTimer;

    /** @brief Maximum settable Effecter value*/
    double maxSettable;

    /** @brief Minimum settable Effecter value*/
    double minSettable;
};

} // namespace platform
} // namespace pldm
