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

#include "thresholds.hpp"

#include "sensor.hpp"

#include <phosphor-logging/log.hpp>

static constexpr bool debug = false;

namespace thresholds
{

void updateThresholds(Sensor& sensor)
{
    if (sensor.thresholds.empty())
    {
        return;
    }

    for (const Threshold& threshold : sensor.thresholds)
    {
        std::optional<ThresholdInterface> thresholdIntf =
            sensor.selectThresholdInterface(threshold);
        if (!thresholdIntf)
        {
            continue;
        }
        thresholdIntf->iface->set_property(thresholdIntf->level,
                                           threshold.value);
    }
}

// Debugging counters
static int cHiTrue = 0;
static int cHiFalse = 0;
static int cHiMidstate = 0;
static int cLoTrue = 0;
static int cLoFalse = 0;
static int cLoMidstate = 0;
static int cDebugThrottle = 0;
static constexpr int assertLogCount = 10;

struct ChangeParam
{
    ChangeParam(Threshold whichThreshold, bool status, double value) :
        threshold(whichThreshold), asserted(status), assertValue(value)
    {
    }

    Threshold threshold;
    bool asserted;
    double assertValue;
};

static std::vector<ChangeParam> checkThresholds(Sensor& sensor, double value)
{
    std::vector<ChangeParam> thresholdChanges;
    if (sensor.thresholds.empty())
    {
        return thresholdChanges;
    }

    for (const Threshold& threshold : sensor.thresholds)
    {
        // Use "Schmitt trigger" logic to avoid threshold trigger spam,
        // if value is noisy while hovering very close to a threshold.
        // When a threshold is crossed, indicate true immediately,
        // but require more distance to be crossed the other direction,
        // before resetting the indicator back to false.
        if (threshold.direction == Direction::high)
        {
            if (value >= threshold.value)
            {
                thresholdChanges.emplace_back(threshold, true, value);
                if (++cHiTrue < assertLogCount)
                {
                    std::stringstream assertLog;
                    assertLog << "Sensor " << sensor.name << " high threshold "
                              << threshold.value << " assert: value " << value
                              << " raw data " << sensor.rawValue;
                    phosphor::logging::log<phosphor::logging::level::DEBUG>(
                        assertLog.str().c_str());
                }
            }
            else if (value < (threshold.value - sensor.hysteresisTrigger))
            {
                thresholdChanges.emplace_back(threshold, false, value);
                ++cHiFalse;
            }
            else
            {
                ++cHiMidstate;
            }
        }
        else if (threshold.direction == Direction::low)
        {
            if (value <= threshold.value)
            {
                thresholdChanges.emplace_back(threshold, true, value);
                if (++cLoTrue < assertLogCount)
                {
                    std::stringstream assertLog;
                    assertLog << "Sensor " << sensor.name << " low threshold "
                              << threshold.value << " assert: value "
                              << sensor.value << " raw data " << sensor.rawValue
                              << "\n";
                    phosphor::logging::log<phosphor::logging::level::DEBUG>(
                        assertLog.str().c_str());
                }
            }
            else if (value > (threshold.value + sensor.hysteresisTrigger))
            {
                thresholdChanges.emplace_back(threshold, false, value);
                ++cLoFalse;
            }
            else
            {
                ++cLoMidstate;
            }
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error determining threshold direction");
        }
    }

    if constexpr (debug)
    {
        // Throttle debug output, so that it does not continuously spam
        ++cDebugThrottle;
        if (cDebugThrottle >= 1000)
        {
            cDebugThrottle = 0;
            std::stringstream throttleLog;
            throttleLog << "checkThresholds: High T=" << cHiTrue
                        << " F=" << cHiFalse << " M=" << cHiMidstate
                        << ", Low T=" << cLoTrue << " F=" << cLoFalse
                        << " M=" << cLoMidstate << "\n";
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                throttleLog.str().c_str());
        }
    }

    return thresholdChanges;
}

bool checkThresholds(Sensor& sensor)
{
    bool status = true;
    std::vector<ChangeParam> changes = checkThresholds(sensor, sensor.value);
    for (const ChangeParam& change : changes)
    {
        assertThresholds(sensor, change.assertValue, change.threshold.level,
                         change.threshold.direction, change.asserted);
        if (change.threshold.level == Level::critical && change.asserted)
        {
            status = false;
        }
    }

    return status;
}

void assertThresholds(Sensor& sensor, double assertValue, Level level,
                      Direction direction, bool assert)
{
    Threshold threshold = {level, direction, assertValue};

    std::optional<ThresholdInterface> thresholdIntf =
        sensor.selectThresholdInterface(threshold);
    if (!thresholdIntf)
    {
        return;
    }

    if (thresholdIntf->iface->set_property<bool, true>(thresholdIntf->alarm,
                                                       assert))
    {
        try
        {
            // msg.get_path() is interface->get_object_path()
            sdbusplus::message::message msg =
                thresholdIntf->iface->new_signal("ThresholdAsserted");

            msg.append(sensor.name, thresholdIntf->iface->get_interface_name(),
                       thresholdIntf->alarm, assert, assertValue);
            msg.signal_send();
        }
        catch (const sdbusplus::exception::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to send thresholdAsserted signal with assertValue");
        }
    }
}

bool hasCriticalInterface(const std::vector<Threshold>& thresholdVector)
{
    return std::any_of(thresholdVector.begin(), thresholdVector.end(),
                       [](const Threshold& threshold) {
                           return threshold.level == Level::critical;
                       });
}

bool hasWarningInterface(const std::vector<Threshold>& thresholdVector)
{
    return std::any_of(thresholdVector.begin(), thresholdVector.end(),
                       [](const Threshold& threshold) {
                           return threshold.level == Level::warning;
                       });
}
} // namespace thresholds
