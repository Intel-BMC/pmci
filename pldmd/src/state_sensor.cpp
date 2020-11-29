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
const static constexpr char* pldmPath = "/xyz/openbmc_project/pldm/";
constexpr const size_t errorThreshold = 5;

StateSensor::StateSensor(const pldm_tid_t tid, const SensorID sensorID,
                         const std::string& name,
                         const std::shared_ptr<StateSensorPDR>& pdr) :
    _tid(tid),
    _sensorID(sensorID), _name(name), _pdr(pdr)
{
    if (_pdr->possibleStates.empty())
    {
        throw std::runtime_error("State sensor PDR data invalid");
    }

    setInitialProperties();
}

void StateSensor::setInitialProperties()
{
    std::string path =
        pldmPath + std::to_string(_tid) + "/state_sensor/" + _name;

    auto objectServer = getObjServer();
    sensorInterface = objectServer->add_unique_interface(
        path, "xyz.openbmc_project.Sensor.State");
    // Composite sensors are not supported. Thus extract only first sensor
    // states
    sensorInterface->register_property_r(
        "StateSetId", _pdr->possibleStates[0].stateSetID,
        sdbusplus::vtable::property_::const_, [](const auto& r) { return r; });
    sensorInterface->register_property_r(
        "PossibleStates", _pdr->possibleStates[0].possibleStateSetValues,
        sdbusplus::vtable::property_::const_, [](const auto& r) { return r; });

    availableInterface = objectServer->add_unique_interface(
        path, "xyz.openbmc_project.State.Decorator.Availability");

    operationalInterface = objectServer->add_unique_interface(
        path, "xyz.openbmc_project.State.Decorator.OperationalStatus");
}

void StateSensor::initializeInterface()
{
    static bool interfaceInitialized = false;
    if (interfaceInitialized)
    {
        return;
    }

    if (!sensorInterface->is_initialized())
    {
        sensorInterface->initialize();
    }
    if (!availableInterface->is_initialized())
    {
        availableInterface->initialize();
    }
    if (!operationalInterface->is_initialized())
    {
        operationalInterface->initialize();
    }
    interfaceInitialized = true;
}

void StateSensor::markFunctional(bool isFunctional)
{
    if (!operationalInterface)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Operational interface not initialized",
            phosphor::logging::entry("TID=%d", _tid),
            phosphor::logging::entry("SENSOR_ID=%d", _sensorID));
        return;
    }

    if (!operationalInterface->is_initialized())
    {
        operationalInterface->register_property("Functional", isFunctional);
    }
    else
    {
        if (isFuntionalReading == isFunctional)
        {
            return;
        }
        operationalInterface->set_property("Functional", isFunctional);
    }
    isFuntionalReading = isFunctional;

    if (isFunctional)
    {
        errCount = 0;
    }
    else
    {
        updateState(std::numeric_limits<uint8_t>::max(),
                    std::numeric_limits<uint8_t>::max());
    }
}

void StateSensor::markAvailable(bool isAvailable)
{
    if (!availableInterface)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Avaliable interface not initialized",
            phosphor::logging::entry("TID=%d", _tid),
            phosphor::logging::entry("SENSOR_ID=%d", _sensorID));
        return;
    }

    if (!availableInterface->is_initialized())
    {
        availableInterface->register_property("Available", isAvailable);
    }
    else
    {
        if (isAvailableReading == isAvailable)
        {
            return;
        }
        availableInterface->set_property("Available", isAvailable);
    }
    isAvailableReading = isAvailable;
    errCount = 0;
}

void StateSensor::incrementError()
{
    if (errCount >= errorThreshold)
    {
        return;
    }

    errCount++;
    if (errCount == errorThreshold)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "State sensor reading failed",
            phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
            phosphor::logging::entry("TID=%d", _tid));
        markFunctional(false);
    }
}

void StateSensor::updateState(const uint8_t currentState,
                              const uint8_t previousState)
{
    if (!sensorInterface)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Sensor interface not initialized");
        return;
    }
    if (!sensorInterface->is_initialized())
    {
        sensorInterface->register_property("PreviousState", previousState);
        sensorInterface->register_property("CurrentState", currentState);
    }
    else
    {
        if (currentStateReading == currentState &&
            previousStateReading == previousState)
        {
            return;
        }
        sensorInterface->set_property("PreviousState", previousState);
        sensorInterface->set_property("CurrentState", currentState);
    }
    // cache the last read state value from the sensor
    currentStateReading = currentState;
    previousStateReading = previousState;

    if (!isFuntionalReading)
    {
        markFunctional(true);
    }
    if (!isAvailableReading)
    {
        markAvailable(true);
    }
}

void StateSensor::handleStateSensorReading(get_sensor_state_field& stateReading)
{
    if (stateReading.sensor_op_state != PLDM_SENSOR_ENABLED)
    {
        markAvailable(true);
        markFunctional(false);
        initializeInterface();
        return;
    }
    updateState(stateReading.present_state, stateReading.previous_state);
    initializeInterface();
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
            markAvailable(false);
            markFunctional(false);
            initializeInterface();
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

bool StateSensor::getStateSensorReadings(boost::asio::yield_context& yield)
{
    int rc;
    std::vector<uint8_t> req(pldmMsgHdrSize +
                             PLDM_GET_STATE_SENSOR_READINGS_REQ_BYTES);
    pldm_msg* reqMsg = reinterpret_cast<pldm_msg*>(req.data());
    // PLDM events and composite sensor are not supported
    constexpr bitfield8_t sensorRearm = {0x00};
    constexpr uint8_t reserved = 0x00;

    rc = encode_get_state_sensor_readings_req(createInstanceId(_tid), _sensorID,
                                              sensorRearm, reserved, reqMsg);
    if (!validatePLDMReqEncode(_tid, rc, "GetStateSensorReadings"))
    {
        return false;
    }

    std::vector<uint8_t> resp;
    if (!sendReceivePldmMessage(yield, _tid, commandTimeout, commandRetryCount,
                                req, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send GetStateSensorReadings request",
            phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    uint8_t completionCode;
    uint8_t compositeSensorCount;
    constexpr size_t maxCompositeSensorCount = 0x08;
    std::array<get_sensor_state_field, maxCompositeSensorCount> stateField{};
    auto rspMsg = reinterpret_cast<pldm_msg*>(resp.data());

    rc = decode_get_state_sensor_readings_resp(
        rspMsg, resp.size() - pldmMsgHdrSize, &completionCode,
        &compositeSensorCount, stateField.data());
    if (!validatePLDMRespDecode(_tid, rc, completionCode,
                                "GetStateSensorReadings"))
    {
        return false;
    }

    // Handle only first value. Composite sensor not supported.
    handleStateSensorReading(stateField[0]);

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "GetStateSensorReadings success",
        phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

bool StateSensor::populateSensorValue(boost::asio::yield_context& yield)
{
    // No need to read the sensor if it is disabled
    if (_pdr->stateSensorData.sensor_init == PLDM_DISABLE_SENSOR)
    {
        return false;
    }
    if (!getStateSensorReadings(yield))
    {
        incrementError();
        return false;
    }
    return true;
}

bool StateSensor::stateSensorInit(boost::asio::yield_context& yield)
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
