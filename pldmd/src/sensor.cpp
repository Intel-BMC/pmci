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

#include "sensor.hpp"

#include <limits>
#include <phosphor-logging/log.hpp>
#include <regex>

constexpr const char* availableInterfaceName =
    "xyz.openbmc_project.State.Decorator.Availability";
constexpr const char* operationalInterfaceName =
    "xyz.openbmc_project.State.Decorator.OperationalStatus";
constexpr const size_t errorThreshold = 5;

NumericSensor::NumericSensor(const std::string& sensorName,
                             std::vector<thresholds::Threshold>& thresholdData,
                             const double max, const double min,
                             const SensorUnit sensorUnit,
                             const bool sensorDisabled) :
    name(std::regex_replace(sensorName, std::regex("[^a-zA-Z0-9_/]+"), "_")),
    maxValue(max), minValue(min), thresholds(thresholdData), unit(sensorUnit),
    hysteresisTrigger((max - min) * 0.01),
    hysteresisPublish((max - min) * 0.0001), errCount(0)
{
    std::string path;
    switch (unit)
    {
        case SensorUnit::DegreesC:
            path = "/xyz/openbmc_project/sensors/temperature/";
            break;
        case SensorUnit::Volts:
            path = "/xyz/openbmc_project/sensors/voltage/";
            break;
        case SensorUnit::Amperes:
            path = "/xyz/openbmc_project/sensors/current/";
            break;
        case SensorUnit::RPMS:
            path = "/xyz/openbmc_project/sensors/fan_pwm/";
            break;
        case SensorUnit::Watts:
            path = "/xyz/openbmc_project/sensors/power/";
            break;
        default:
            throw std::runtime_error("Sensor " + name +
                                     " is not of supported type");
            break;
    }

    auto objectServer = getObjServer();

    sensorInterface = objectServer->add_interface(
        path + name, "xyz.openbmc_project.Sensor.Value");
    if (thresholds::hasWarningInterface(thresholds))
    {
        thresholdInterfaceWarning = objectServer->add_interface(
            path + name, "xyz.openbmc_project.Sensor.Threshold.Warning");
    }
    if (thresholds::hasCriticalInterface(thresholds))
    {
        thresholdInterfaceCritical = objectServer->add_interface(
            path + name, "xyz.openbmc_project.Sensor.Threshold.Critical");
    }

    // TODO: Support to update associations

    setInitialProperties(sensorDisabled);
}

NumericSensor::~NumericSensor()
{
    auto objectServer = getObjServer();
    if (thresholdInterfaceWarning)
    {
        objectServer->remove_interface(thresholdInterfaceWarning);
    }
    if (thresholdInterfaceCritical)
    {
        objectServer->remove_interface(thresholdInterfaceCritical);
    }
    if (sensorInterface)
    {
        objectServer->remove_interface(sensorInterface);
    }
}

std::optional<ThresholdInterface> NumericSensor::selectThresholdInterface(
    const thresholds::Threshold& threshold)
{
    ThresholdInterface thresholdIntf;
    if (threshold.level == thresholds::Level::critical)
    {
        thresholdIntf.iface = thresholdInterfaceCritical;
        if (threshold.direction == thresholds::Direction::high)
        {
            thresholdIntf.level = "CriticalHigh";
            thresholdIntf.alarm = "CriticalAlarmHigh";
        }
        else
        {
            thresholdIntf.level = "CriticalLow";
            thresholdIntf.alarm = "CriticalAlarmLow";
        }
    }
    else if (threshold.level == thresholds::Level::warning)
    {
        thresholdIntf.iface = thresholdInterfaceWarning;
        if (threshold.direction == thresholds::Direction::high)
        {
            thresholdIntf.level = "WarningHigh";
            thresholdIntf.alarm = "WarningAlarmHigh";
        }
        else
        {
            thresholdIntf.level = "WarningLow";
            thresholdIntf.alarm = "WarningAlarmLow";
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown threshold level",
            phosphor::logging::entry("THRESHOLD_LEVEL=%d", threshold.level));
        return std::nullopt;
    }

    if (!thresholdIntf.iface)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Threshold interface not initialized");
        return std::nullopt;
    }
    return thresholdIntf;
}

void NumericSensor::setInitialProperties(bool sensorDisabled)
{
    sensorInterface->register_property("MaxValue", maxValue);
    sensorInterface->register_property("MinValue", minValue);
    sensorInterface->register_property("Value", value);

    for (thresholds::Threshold& threshold : thresholds)
    {
        std::optional<ThresholdInterface> thresholdIntf =
            selectThresholdInterface(threshold);
        if (!thresholdIntf)
        {
            continue;
        }

        thresholdIntf->iface->register_property(thresholdIntf->level,
                                                threshold.value);
        thresholdIntf->iface->register_property(thresholdIntf->alarm, false);
    }

    if (!sensorInterface->initialize())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error initializing value interface");
    }
    if (thresholdInterfaceWarning &&
        !thresholdInterfaceWarning->initialize(true))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error initializing warning threshold interface");
    }

    if (thresholdInterfaceCritical &&
        !thresholdInterfaceCritical->initialize(true))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error initializing critical threshold interface");
    }

    std::shared_ptr<sdbusplus::asio::connection> conn = getSdBus();

    availableInterface = std::make_shared<sdbusplus::asio::dbus_interface>(
        conn, sensorInterface->get_object_path(), availableInterfaceName);
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

    operationalInterface = std::make_shared<sdbusplus::asio::dbus_interface>(
        conn, sensorInterface->get_object_path(), operationalInterfaceName);
    operationalInterface->register_property("Functional", !sensorDisabled);
    operationalInterface->initialize();
}

void NumericSensor::markFunctional(bool isFunctional)
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

void NumericSensor::markAvailable(bool isAvailable)
{
    if (availableInterface)
    {
        availableInterface->set_property("Available", isAvailable);
        errCount = 0;
    }
}

void NumericSensor::incrementError()
{
    if (errCount >= errorThreshold)
    {
        return;
    }

    errCount++;
    if (errCount == errorThreshold)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Sensor " + name + " reading error").c_str());
        markFunctional(false);
    }
}

void NumericSensor::updateValue(const double& newValue)
{
    updateProperty(sensorInterface, value, newValue, "Value");

    // Always check thresholds after changing the value,
    // as the test against hysteresisTrigger now takes place in
    // the thresholds::checkThresholds() method,
    // which is called by checkThresholds() below,
    // in all current implementations of sensors that have thresholds.
    checkThresholds();
    if (!std::isnan(newValue))
    {
        markFunctional(true);
        markAvailable(true);
    }
}

void NumericSensor::updateProperty(
    std::shared_ptr<sdbusplus::asio::dbus_interface>& interface,
    double& oldValue, const double& newValue, const char* dbusPropertyName)
{
    if (requiresUpdate(oldValue, newValue))
    {
        oldValue = newValue;
        if (interface && !(interface->set_property(dbusPropertyName, newValue)))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("Error setting property " + std::string(dbusPropertyName))
                    .c_str(),
                phosphor::logging::entry("VALUE=%l", newValue));
        }
    }
}

bool NumericSensor::requiresUpdate(const double& lVal, const double& rVal)
{
    if (std::isnan(lVal) || std::isnan(rVal))
    {
        return true;
    }
    double diff = std::abs(lVal - rVal);
    return diff > hysteresisPublish;
}

void NumericSensor::checkThresholds(void)
{
    thresholds::checkThresholds(*(this));
}
