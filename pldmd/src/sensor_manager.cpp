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
            return true;
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

bool SensorManager::sensorManagerInit(boost::asio::yield_context& yield)
{
    if (!setNumericSensorEnable(yield))
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
