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

#include "numeric_effecter.hpp"

#include "pldm.hpp"

#include <phosphor-logging/log.hpp>
#include <regex>

#include "platform.h"

constexpr const size_t effecterErrorThreshold = 5;

NumericEffecter::NumericEffecter(const std::string& effecterName,
                                 pldm_tid_t tid, const double max,
                                 const double min,
                                 const EffecterUnit effecterUnit) :
    name(std::regex_replace(effecterName, std::regex("[^a-zA-Z0-9_/]+"), "_")),
    maxValue(max), minValue(min), unit(effecterUnit), errCount(0)
{
    std::string path;
    switch (unit)
    {
        case PLDM_SENSOR_UNIT_SECONDS:
            path = "/xyz/openbmc_project/pldm/" + std::to_string(tid) +
                   "/effecter/time/";
            break;
        case PLDM_SENSOR_UNIT_VOLTS:
            path = "/xyz/openbmc_project/pldm/" + std::to_string(tid) +
                   "/effecter/voltage/";
            break;
        case PLDM_SENSOR_UNIT_AMPS:
            path = "/xyz/openbmc_project/pldm/" + std::to_string(tid) +
                   "/effecter/current/";
            break;
        case PLDM_SENSOR_UNIT_WATTS:
            path = "/xyz/openbmc_project/pldm/" + std::to_string(tid) +
                   "/effecter/power/";
            break;
        default:
            throw std::runtime_error("State effecter unit not supported");
            break;
    }

    auto objectServer = getObjServer();

    effecterInterface = objectServer->add_interface(
        path + name, "xyz.openbmc_project.Effecter.Value");
    operationalInterface = objectServer->add_interface(
        path + name, "xyz.openbmc_project.State.Decorator.OperationalStatus");

    setInitialProperties();
}

NumericEffecter::~NumericEffecter()
{
    auto objectServer = getObjServer();
    if (effecterInterface)
    {
        objectServer->remove_interface(effecterInterface);
    }
    if (operationalInterface)
    {
        objectServer->remove_interface(operationalInterface);
    }
    if (availableInterface)
    {
        objectServer->remove_interface(availableInterface);
    }
}

std::string name;
double maxValue;
double minValue;
std::shared_ptr<sdbusplus::asio::dbus_interface> effecterInterface;
std::shared_ptr<sdbusplus::asio::dbus_interface> availableInterface;
std::shared_ptr<sdbusplus::asio::dbus_interface> operationalInterface;
double value = std::numeric_limits<double>::quiet_NaN();
size_t errCount;
EffecterUnit unit;

void NumericEffecter::setInitialProperties()
{
    effecterInterface->register_property("MaxValue", maxValue);
    effecterInterface->register_property("MinValue", minValue);
    effecterInterface->register_property("Value", value);
    effecterInterface->initialize();

    operationalInterface->register_property("Functional", true);
    operationalInterface->initialize();

    std::shared_ptr<sdbusplus::asio::connection> conn = getSdBus();

    availableInterface = std::make_shared<sdbusplus::asio::dbus_interface>(
        conn, effecterInterface->get_object_path(),
        "xyz.openbmc_project.State.Decorator.Availability");
    availableInterface->register_property(
        "Available", true, [this](const bool propIn, bool& old) {
            if (propIn == old)
            {
                return 1;
            }
            old = propIn;
            if (!propIn)
            {
                updateValue(std::numeric_limits<double>::quiet_NaN());
            }
            return 1;
        });
    availableInterface->initialize();
}

void NumericEffecter::markFunctional(bool isFunctional)
{
    if (operationalInterface)
    {
        operationalInterface->set_property("Functional", isFunctional);
    }
    if (isFunctional)
    {
        errCount = 0;
    }
    else
    {
        updateValue(std::numeric_limits<double>::quiet_NaN());
    }
}

void NumericEffecter::markAvailable(bool isAvailable)
{
    if (availableInterface)
    {
        availableInterface->set_property("Available", isAvailable);
        errCount = 0;
    }
}

void NumericEffecter::incrementError()
{
    if (errCount >= effecterErrorThreshold)
    {
        return;
    }

    errCount++;
    if (errCount == effecterErrorThreshold)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Effecter " + name + " reading error").c_str());
        markFunctional(false);
    }
}

void NumericEffecter::updateValue(const double& currentValue)
{
    updateProperty(effecterInterface, value, currentValue, "Value");

    if (!std::isnan(currentValue))
    {
        markFunctional(true);
        markAvailable(true);
    }
}

void NumericEffecter::updateProperty(
    const std::shared_ptr<sdbusplus::asio::dbus_interface>& interface,
    double& previousValue, const double& currentValue,
    const char* dbusPropertyName)
{
    previousValue = currentValue;
    if (interface && !(interface->set_property(dbusPropertyName, currentValue)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Error setting property " + std::string(dbusPropertyName)).c_str(),
            phosphor::logging::entry("VALUE=%l", currentValue));
    }
}
