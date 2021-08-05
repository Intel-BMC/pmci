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

#include "pldm.hpp"

#include <limits>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

using EffecterUnit = uint8_t;

struct NumericEffecter
{
    NumericEffecter(const std::string& effecterName, pldm_tid_t tid,
                    const double max, const double min,
                    const EffecterUnit effecterUnit);

    ~NumericEffecter();

    std::string name;
    double maxValue;
    double minValue;
    std::shared_ptr<sdbusplus::asio::dbus_interface> effecterInterface =
        nullptr;
    std::shared_ptr<sdbusplus::asio::dbus_interface> availableInterface =
        nullptr;
    std::shared_ptr<sdbusplus::asio::dbus_interface> operationalInterface =
        nullptr;
    double value = std::numeric_limits<double>::quiet_NaN();
    size_t errCount = 0;
    EffecterUnit unit;

    /** @brief Update the effecter functionality*/
    void markFunctional(bool isFunctional);

    /** @brief Update the effecter availability*/
    void markAvailable(bool isAvailable);

    /** @brief Increment the error count in case of failure*/
    void incrementError();

    /** @brief Update effecter value*/
    void updateValue(const double& newValue);

  private:
    void updateProperty(
        const std::shared_ptr<sdbusplus::asio::dbus_interface>& interface,
        double& oldValue, const double& newValue, const char* dbusPropertyName);

    void setInitialProperties();
};
