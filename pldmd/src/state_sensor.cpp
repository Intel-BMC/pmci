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

#include "state_sensor.hpp"

#include "platform.hpp"
#include "sensor_manager.hpp"

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace platform
{

StateSensor::StateSensor(const pldm_tid_t tid, const SensorID sensorID,
                         const std::string& name,
                         const std::shared_ptr<StateSensorPDR>& pdr) :
    _tid(tid),
    _sensorID(sensorID), _name(name), _pdr(pdr)
{
}

bool StateSensor::setStateSensorEnables(boost::asio::yield_context& yield)
{
    uint8_t sensorOpState;
    switch (_pdr->stateSensorData.sensor_init)
    {
        case PLDM_NO_INIT:
            return true;
        case PLDM_USE_INIT_PDR:
            // TODO: State Sensor Initialization PDR support
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "State Sensor Initialization PDR not supported",
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
                "Invalid sensorInit value in StateSensorPDR",
                phosphor::logging::entry("TID=%d", _tid),
                phosphor::logging::entry("SENSOR_ID=%d", _sensorID));
            return false;
    }

    int rc;
    // TODO: PLDM events and composite sensor support
    constexpr uint8_t compositeSensorCount = 1;
    std::array<state_sensor_op_field, compositeSensorCount> opFields = {
        {sensorOpState, PLDM_NO_EVENT_GENERATION}};
    std::vector<uint8_t> req(pldmMsgHdrSize +
                             sizeof(pldm_set_state_sensor_enable_req));
    pldm_msg* reqMsg = reinterpret_cast<pldm_msg*>(req.data());

    // TODO: Init state as per State Sensor Initialization PDR
    rc = encode_set_state_sensor_enable_req(createInstanceId(_tid), _sensorID,
                                            compositeSensorCount,
                                            opFields.data(), reqMsg);
    if (!validatePLDMReqEncode(_tid, rc, "SetStateSensorEnables"))
    {
        return false;
    }

    std::vector<uint8_t> resp;
    if (!sendReceivePldmMessage(yield, _tid, commandTimeout, commandRetryCount,
                                req, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send SetStateSensorEnables request",
            phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    uint8_t completionCode;
    auto rspMsg = reinterpret_cast<pldm_msg*>(resp.data());

    rc = decode_cc_only_resp(rspMsg, resp.size() - pldmMsgHdrSize,
                             &completionCode);
    if (!validatePLDMRespDecode(_tid, rc, completionCode,
                                "SetStateSensorEnables"))
    {
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "SetStateSensorEnables success",
        phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

bool StateSensor::StateSensorInit(boost::asio::yield_context& yield)
{
    if (!setStateSensorEnables(yield))
    {
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "State Sensor Init Success",
        phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

} // namespace platform
} // namespace pldm
