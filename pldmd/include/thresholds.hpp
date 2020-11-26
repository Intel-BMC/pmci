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

#include <cstdint>
#include <vector>

struct Sensor;
namespace thresholds
{
enum Level : uint8_t
{
    warning,
    critical
};
enum Direction : uint8_t
{
    high,
    low
};
struct Threshold
{
    Threshold(const Level lev, const Direction dir, const double& val) :
        level(lev), direction(dir), value(val)
    {
    }
    Level level;
    Direction direction;
    double value;
};

/** @brief Assert the threshold interface of Sensor*/
void assertThresholds(Sensor& sensor, double assertValue, Level level,
                      Direction direction, bool assert);

/** @brief Verify Critical interface is present*/
bool hasCriticalInterface(const std::vector<Threshold>& thresholdVector);

/** @brief Verify Warning interface is present*/
bool hasWarningInterface(const std::vector<Threshold>& thresholdVector);

/** @brief Update threshold values. Will be useful in case of a PDR update*/
void updateThresholds(Sensor& sensor);

/** @brief Update Thresholds. Returns false if a critical threshold has been
 * crossed, true otherwise*/
bool checkThresholds(Sensor& sensor);
} // namespace thresholds
