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

#include "pdr_utils.hpp"

#include <cmath>
#include <phosphor-logging/log.hpp>

namespace pdr
{

namespace sensor
{

// Calculate sensor reading in baseUnit(Eg: Volts, Watts) defined in DSP0248
// Table 74. Returned value can be directly used for D-Bus representation
double applyUnitModifiers(const pldm_numeric_sensor_value_pdr& pdr,
                          const double& sensorValue)
{
    // Sensor/Effecter Units = baseUnit * 10^unitModifier rateUnit
    return sensorValue * std::pow(10, pdr.unit_modifier);

    // TODO: Handle auxUnitModifier
}

double calculateSensorValue(const pldm_numeric_sensor_value_pdr& pdr,
                            const float& sensorReading)
{
    // Reference: DSP0248 sec 27.7
    // Reading Conversion formula: Y = (m * X + B)
    //  Where:
    //  Y = converted reading in Units
    //  X = reading from sensor
    //  m = resolution from PDR in Units
    //  B = offset from PDR in Units
    //  Units = sensor/effecter Units, based on the Units and auxUnits fields
    // from the PDR for the numeric sensor(Eg: millivolt, kilowatt)
    float resolution =
        std::isnan(pdr.resolution) ? 1 : static_cast<float>(pdr.resolution);
    float offset = std::isnan(pdr.offset) ? 0 : static_cast<float>(pdr.offset);
    return applyUnitModifiers(pdr, resolution * sensorReading + offset);
    // Note:- Accuracy and Tolerance is not handled
}

std::optional<float> fetchSensorValue(const pldm_numeric_sensor_value_pdr& pdr,
                                      const union_sensor_data_size& data)
{
    switch (pdr.sensor_data_size)
    {
        case PLDM_SENSOR_DATA_SIZE_UINT8:
            return static_cast<float>(data.value_u8);
        case PLDM_SENSOR_DATA_SIZE_SINT8:
            return static_cast<float>(data.value_s8);
        case PLDM_SENSOR_DATA_SIZE_UINT16:
            return static_cast<float>(data.value_u16);
        case PLDM_SENSOR_DATA_SIZE_SINT16:
            return static_cast<float>(data.value_s16);
        case PLDM_SENSOR_DATA_SIZE_UINT32:
            return static_cast<float>(data.value_u32);
        case PLDM_SENSOR_DATA_SIZE_SINT32:
            return static_cast<float>(data.value_s32);
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Sensor data size not recognized");
            return std::nullopt;
    }
}

std::optional<SensorUnit>
    getSensorUnit(const pldm_numeric_sensor_value_pdr& pdr)
{
    switch (pdr.base_unit)
    {
        case PLDM_SENSOR_UNIT_DEGREES_C:
            return SensorUnit::DegreesC;
        case PLDM_SENSOR_UNIT_VOLTS:
            return SensorUnit::Volts;
        case PLDM_SENSOR_UNIT_AMPS:
            return SensorUnit::Amperes;
        case PLDM_SENSOR_UNIT_WATTS:
            return SensorUnit::Watts;
        case PLDM_SENSOR_UNIT_RPM:
            return SensorUnit::RPMS;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Sensor unit not recognized");
            return std::nullopt;
    }
}

std::optional<float>
    fetchRangeFieldValue(const pldm_numeric_sensor_value_pdr& pdr,
                         const union_range_field_format& data)
{
    switch (pdr.range_field_format)
    {
        case PLDM_RANGE_FIELD_FORMAT_UINT8:
            return static_cast<float>(data.value_u8);
        case PLDM_RANGE_FIELD_FORMAT_SINT8:
            return static_cast<float>(data.value_s8);
        case PLDM_RANGE_FIELD_FORMAT_UINT16:
            return static_cast<float>(data.value_u16);
        case PLDM_RANGE_FIELD_FORMAT_SINT16:
            return static_cast<float>(data.value_s16);
        case PLDM_RANGE_FIELD_FORMAT_UINT32:
            return static_cast<float>(data.value_u32);
        case PLDM_RANGE_FIELD_FORMAT_SINT32:
            return static_cast<float>(data.value_s32);
        case PLDM_RANGE_FIELD_FORMAT_REAL32:
            return static_cast<float>(data.value_f32);
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Sensor range field size not recognized");
            return std::nullopt;
    }
}
} // namespace sensor

namespace effecter
{

// Calculate sensor reading in baseUnit(Eg: Volts, Watts) defined in DSP0248
// Table 74. Returned value can be directly used for D-Bus representation
static double applyUnitModifiers(const pldm_numeric_effecter_value_pdr& pdr,
                                 const double& effecterValue)
{
    // Sensor/Effecter Units = baseUnit * 10^unitModifier rateUnit
    return effecterValue * std::pow(10, pdr.unit_modifier);

    // TODO: Handle auxUnitModifier
}

double calculateEffecterValue(const pldm_numeric_effecter_value_pdr& pdr,
                              const float& effecterReading)
{
    // Reference: DSP0248 sec 27.7
    // Reading Conversion formula: Y = (m * X + B)
    //  Where:
    //  Y = converted reading in Units
    //  X = reading from sensor
    //  m = resolution from PDR in Units
    //  B = offset from PDR in Units
    //  Units = sensor/effecter Units, based on the Units and auxUnits fields
    // from the PDR for the numeric sensor(Eg: millivolt, kilowatt)
    float resolution =
        std::isnan(pdr.resolution) ? 1 : static_cast<float>(pdr.resolution);
    float offset = std::isnan(pdr.offset) ? 0 : static_cast<float>(pdr.offset);
    return applyUnitModifiers(pdr, resolution * effecterReading + offset);
    // Note:- Accuracy and Tolerance is not handled
}

// Decode the value in Units(eg: V, mV)
static double extractUnitModifiers(const pldm_numeric_effecter_value_pdr& pdr,
                                   const double& value)
{
    // Sensor/Effecter Units = baseUnit * 10^unitModifier rateUnit
    return value / std::pow(10, pdr.unit_modifier);

    // TODO: Handle auxUnitModifier
}

std::optional<double>
    calculateSettableEffecterValue(const pldm_numeric_effecter_value_pdr& pdr,
                                   const double& value)
{
    // Reading Conversion formula: Y = (m * X + B)
    //  Where:
    //  Y = converted reading in Units
    //  X = reading from effecter
    //  m = resolution from PDR in Units
    //  B = offset from PDR in Units
    //  Units = effecter/effecter Units, based on the Units and auxUnits fields
    // from the PDR for the numeric effecter
    //  There for: m = (Y - B) / m

    double resolution =
        std::isnan(pdr.resolution) ? 1 : static_cast<double>(pdr.resolution);
    double offset =
        std::isnan(pdr.offset) ? 0 : static_cast<double>(pdr.offset);
    double effecterReading =
        std::round((extractUnitModifiers(pdr, value) - offset) / resolution);
    return effecterReading;

    // Note:- Accuracy and Tolerance is not handled
}

template <class T>
T verifiedCast(const double value)
{
    if (value < std::numeric_limits<T>::min() ||
        value > std::numeric_limits<T>::max())
    {
        throw std::runtime_error("Value out of range");
    }
    return static_cast<T>(value);
}

std::optional<union_effecter_data_size>
    formatSettableEffecterValue(const pldm_numeric_effecter_value_pdr& pdr,
                                const double value)
{
    union_effecter_data_size formattedValue;
    try
    {
        switch (pdr.effecter_data_size)
        {
            case PLDM_EFFECTER_DATA_SIZE_UINT8:
                formattedValue.value_u8 = verifiedCast<uint8_t>(value);
                break;
            case PLDM_EFFECTER_DATA_SIZE_SINT8:
                formattedValue.value_s8 = verifiedCast<int8_t>(value);
                break;
            case PLDM_EFFECTER_DATA_SIZE_UINT16:
                formattedValue.value_u16 = verifiedCast<uint16_t>(value);
                break;
            case PLDM_EFFECTER_DATA_SIZE_SINT16:
                formattedValue.value_s16 = verifiedCast<int16_t>(value);
                break;
            case PLDM_EFFECTER_DATA_SIZE_UINT32:
                formattedValue.value_u32 = verifiedCast<uint32_t>(value);
                break;
            case PLDM_EFFECTER_DATA_SIZE_SINT32:
                formattedValue.value_s32 = verifiedCast<int32_t>(value);
                break;
            default:
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Effecter data size not recognized");
                return std::nullopt;
        }
        return formattedValue;
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return std::nullopt;
    }
}

// Fetch the effecter value as per data size
std::optional<float>
    fetchEffecterValue(const pldm_numeric_effecter_value_pdr& pdr,
                       const union_effecter_data_size& data)
{
    switch (pdr.effecter_data_size)
    {
        case PLDM_SENSOR_DATA_SIZE_UINT8:
            return static_cast<float>(data.value_u8);
        case PLDM_SENSOR_DATA_SIZE_SINT8:
            return static_cast<float>(data.value_s8);
        case PLDM_SENSOR_DATA_SIZE_UINT16:
            return static_cast<float>(data.value_u16);
        case PLDM_SENSOR_DATA_SIZE_SINT16:
            return static_cast<float>(data.value_s16);
        case PLDM_SENSOR_DATA_SIZE_UINT32:
            return static_cast<float>(data.value_u32);
        case PLDM_SENSOR_DATA_SIZE_SINT32:
            return static_cast<float>(data.value_s32);
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Effecter data size not recognized");
            return std::nullopt;
    }
}

std::optional<float>
    fetchRangeFieldValue(const pldm_numeric_effecter_value_pdr& pdr,
                         const union_range_field_format& data)
{
    switch (pdr.range_field_format)
    {
        case PLDM_RANGE_FIELD_FORMAT_UINT8:
            return static_cast<float>(data.value_u8);
        case PLDM_RANGE_FIELD_FORMAT_SINT8:
            return static_cast<float>(data.value_s8);
        case PLDM_RANGE_FIELD_FORMAT_UINT16:
            return static_cast<float>(data.value_u16);
        case PLDM_RANGE_FIELD_FORMAT_SINT16:
            return static_cast<float>(data.value_s16);
        case PLDM_RANGE_FIELD_FORMAT_UINT32:
            return static_cast<float>(data.value_u32);
        case PLDM_RANGE_FIELD_FORMAT_SINT32:
            return static_cast<float>(data.value_s32);
        case PLDM_RANGE_FIELD_FORMAT_REAL32:
            return static_cast<float>(data.value_f32);
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Effecter range field size not recognized");
            return std::nullopt;
    }
}
} // namespace effecter

} // namespace pdr
