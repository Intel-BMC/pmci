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

#include "sensor_manager.hpp"

#include "pdr_utils.hpp"
#include "platform.hpp"

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace platform
{

SensorManager::SensorManager(const pldm_tid_t tid, const SensorID sensorID,
                             const std::string& name,
                             const pldm_numeric_sensor_value_pdr& pdr) :
    _tid(tid),
    _sensorID(sensorID), _name(name), _pdr(pdr)
{
}

bool SensorManager::setNumericSensorEnable(boost::asio::yield_context& yield)
{
    uint8_t sensorOpState;
    switch (_pdr.sensor_init)
    {
        case PLDM_NO_INIT:
            sensorOpState = PLDM_SENSOR_ENABLED;
            break;
        case PLDM_USE_INIT_PDR:
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Numeric Sensor Initialization PDR not supported",
                phosphor::logging::entry("TID=%d", _tid),
                phosphor::logging::entry("SENSOR_ID=%d", _sensorID));
            return false;
        case PLDM_ENABLE_SENSOR:
            sensorOpState = PLDM_SENSOR_ENABLED;
            break;
        case PLDM_DISABLE_SENSOR:
            sensorOpState = PLDM_SENSOR_DISABLED;
            break;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid sensorInit value in PDR",
                phosphor::logging::entry("TID=%d", _tid),
                phosphor::logging::entry("SENSOR_ID=%d", _sensorID));
            return false;
    }

    int rc;
    std::vector<uint8_t> req(pldmMsgHdrSize +
                             sizeof(pldm_set_numeric_sensor_enable_req));
    pldm_msg* reqMsg = reinterpret_cast<pldm_msg*>(req.data());

    // PLDM events are not supported
    // TODO: create another method to support disableNumericSensor
    // TODO: Support for Event Generation flag
    rc = encode_set_numeric_sensor_enable_req(createInstanceId(_tid), _sensorID,
                                              sensorOpState,
                                              PLDM_NO_EVENT_GENERATION, reqMsg);
    if (!validatePLDMReqEncode(_tid, rc, "SetNumericSensorEnable"))
    {
        return false;
    }

    std::vector<uint8_t> resp;
    if (!sendReceivePldmMessage(yield, _tid, commandTimeout, commandRetryCount,
                                req, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send SetNumericSensorEnable request",
            phosphor::logging::entry("TID=%d", _tid),
            phosphor::logging::entry("SENSOR_ID=%d", _sensorID));
        return false;
    }

    uint8_t completionCode;
    auto rspMsg = reinterpret_cast<pldm_msg*>(resp.data());

    rc = decode_cc_only_resp(rspMsg, resp.size() - pldmMsgHdrSize,
                             &completionCode);
    if (!validatePLDMRespDecode(_tid, rc, completionCode,
                                "SetNumericSensorEnable"))
    {
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "SetNumericSensorEnable success",
        phosphor::logging::entry("TID=%d", _tid),
        phosphor::logging::entry("SENSOR_ID=%d", _sensorID));
    return true;
}

void SensorManager::getSupportedThresholds(
    std::vector<thresholds::Threshold>& thresholdData)
{
    if (_pdr.supported_thresholds.bits.bit0)
    {
        if (auto rangeFieldValue =
                pdr::sensor::fetchRangeFieldValue(_pdr, _pdr.warning_high))
        {
            thresholdData.emplace_back(
                thresholds::Level::warning, thresholds::Direction::high,
                pdr::sensor::calculateSensorValue(_pdr, *rangeFieldValue));
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "WarningHigh Supported",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID));
        }
    }

    if (_pdr.supported_thresholds.bits.bit1 &&
        _pdr.range_field_support.bits.bit3)
    {
        if (auto rangeFieldValue =
                pdr::sensor::fetchRangeFieldValue(_pdr, _pdr.critical_high))
        {
            thresholdData.emplace_back(
                thresholds::Level::critical, thresholds::Direction::high,
                pdr::sensor::calculateSensorValue(_pdr, *rangeFieldValue));
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "CriticalHigh Supported",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID));
        }
    }

    if (_pdr.supported_thresholds.bits.bit3 &&
        _pdr.range_field_support.bits.bit3)
    {
        if (auto rangeFieldValue =
                pdr::sensor::fetchRangeFieldValue(_pdr, _pdr.warning_low))
        {
            thresholdData.emplace_back(
                thresholds::Level::warning, thresholds::Direction::low,
                pdr::sensor::calculateSensorValue(_pdr, *rangeFieldValue));
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "WarningLow Supported",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID));
        }
    }

    if (_pdr.supported_thresholds.bits.bit4 &&
        _pdr.range_field_support.bits.bit4)
    {
        if (auto rangeFieldValue =
                pdr::sensor::fetchRangeFieldValue(_pdr, _pdr.critical_low))
        {
            thresholdData.emplace_back(
                thresholds::Level::critical, thresholds::Direction::low,
                pdr::sensor::calculateSensorValue(_pdr, *rangeFieldValue));
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "CriticalLow Supported",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID));
        }
    }
    // Note:- Fatal values are not supported
}

bool SensorManager::initSensor()
{
    std::optional<float> maxVal =
        pdr::sensor::fetchSensorValue(_pdr, _pdr.max_readable);
    if (maxVal == std::nullopt)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to decode maxReadable",
            phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    std::optional<float> minVal =
        pdr::sensor::fetchSensorValue(_pdr, _pdr.min_readable);
    if (minVal == std::nullopt)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to decode minReadable",
            phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    std::optional<SensorUnit> baseUnit = pdr::sensor::getSensorUnit(_pdr);
    if (baseUnit == std::nullopt)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to decode sensor unit",
            phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    std::vector<thresholds::Threshold> thresholdData;
    getSupportedThresholds(thresholdData);

    if (_pdr.sensor_init == PLDM_DISABLE_SENSOR)
    {
        sensorDisabled = true;
    }
    try
    {
        _sensor = std::make_shared<Sensor>(
            _name, thresholdData,
            pdr::sensor::calculateSensorValue(_pdr, *maxVal),
            pdr::sensor::calculateSensorValue(_pdr, *minVal), *baseUnit,
            sensorDisabled);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            e.what(), phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Sensor Init success",
        phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

bool SensorManager::handleSensorReading(uint8_t sensorOperationalState,
                                        uint8_t sensorDataSize,
                                        union_sensor_data_size& presentReading)
{
    switch (sensorOperationalState)
    {
        case PLDM_SENSOR_DISABLED: {
            _sensor->markFunctional(false);
            _sensor->markAvailable(true);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Numeric sensor disabled",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
                phosphor::logging::entry("TID=%d", _tid));
            break;
        }
        case PLDM_SENSOR_UNAVAILABLE: {
            _sensor->markFunctional(false);
            _sensor->markAvailable(false);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Numeric sensor unavailable",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
                phosphor::logging::entry("TID=%d", _tid));
            return false;
        }
        case PLDM_SENSOR_ENABLED: {
            if (_pdr.sensor_data_size != sensorDataSize)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Invalid sensor reading. Sensor data size missmatch",
                    phosphor::logging::entry("TID=%d", _tid),
                    phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
                    phosphor::logging::entry("DATA_SIZE=%d", sensorDataSize));
                return false;
            }

            std::optional<float> sensorReading =
                pdr::sensor::fetchSensorValue(_pdr, presentReading);
            if (sensorReading == std::nullopt)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Numeric sensor value decode failed",
                    phosphor::logging::entry("TID=%d", _tid),
                    phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
                    phosphor::logging::entry("DATA_SIZE=%d", sensorDataSize));
                return false;
            }

            _sensor->updateValue(
                pdr::sensor::calculateSensorValue(_pdr, *sensorReading));

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "GetSensorReading success",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
                phosphor::logging::entry("TID=%d", _tid),
                phosphor::logging::entry("VALUE=%lf", *sensorReading));
            break;
        }
        default: {
            // TODO: Handle other sensor operational states like statusUnknown,
            // initializing etc.
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Numeric sensor operational status unknown",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
                phosphor::logging::entry("TID=%d", _tid));
            return false;
        }
    }
    return true;
}

bool SensorManager::getSensorReading(boost::asio::yield_context& yield)
{
    int rc;
    std::vector<uint8_t> req(pldmMsgHdrSize +
                             sizeof(pldm_get_sensor_reading_req));
    pldm_msg* reqMsg = reinterpret_cast<pldm_msg*>(req.data());

    // PLDM events are not supported
    constexpr uint8_t rearmEventState = 0x00;
    rc = encode_get_sensor_reading_req(createInstanceId(_tid), _sensorID,
                                       rearmEventState, reqMsg);
    if (!validatePLDMReqEncode(_tid, rc, "GetSensorReading"))
    {
        return false;
    }

    std::vector<uint8_t> resp;
    if (!sendReceivePldmMessage(yield, _tid, commandTimeout, commandRetryCount,
                                req, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send GetSensorReading request",
            phosphor::logging::entry("TID=%d", _tid),
            phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID));
        return false;
    }

    uint8_t completionCode;
    uint8_t sensorDataSize = _pdr.sensor_data_size;
    uint8_t sensorOperationalState;
    uint8_t sensorEventMessageEnable;
    uint8_t presentState;
    uint8_t previousState;
    uint8_t eventState;
    union_sensor_data_size presentReading;
    auto rspMsg = reinterpret_cast<pldm_msg*>(resp.data());

    rc = decode_get_sensor_reading_resp(
        rspMsg, resp.size() - pldmMsgHdrSize, &completionCode, &sensorDataSize,
        &sensorOperationalState, &sensorEventMessageEnable, &presentState,
        &previousState, &eventState,
        reinterpret_cast<uint8_t*>(&presentReading));
    if (!validatePLDMRespDecode(_tid, rc, completionCode, "GetSensorReading"))
    {
        return false;
    }

    return handleSensorReading(sensorOperationalState, sensorDataSize,
                               presentReading);
}

bool SensorManager::populateSensorValue(boost::asio::yield_context& yield)
{
    // No need to read the sensor if it is disabled
    if (_pdr.sensor_init == PLDM_DISABLE_SENSOR)
    {
        return false;
    }
    if (!getSensorReading(yield))
    {
        _sensor->incrementError();
        return false;
    }
    return true;
}

bool SensorManager::sensorManagerInit(boost::asio::yield_context& yield)
{
    if (!setNumericSensorEnable(yield))
    {
        return false;
    }

    if (!initSensor())
    {
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Sensor Manager Init Success", phosphor::logging::entry("TID=%d", _tid),
        phosphor::logging::entry("SENSOR_ID=%d", _sensorID));
    return true;
}

} // namespace platform
} // namespace pldm
