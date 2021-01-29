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

StateSensorHandler::StateSensorHandler(
    const pldm_tid_t tid, const SensorID sensorID, const std::string& name,
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

void StateSensorHandler::setInitialProperties()
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

void StateSensorHandler::initializeInterface()
{
    if (!interfaceInitialized && sensorIntfReady && availableIntfReady &&
        operationalIntfReady)
    {
        sensorInterface->register_property("PreviousState",
                                           previousStateReading);
        sensorInterface->register_property("CurrentState", currentStateReading);
        sensorInterface->initialize();

        availableInterface->register_property("Available", isAvailableReading);
        availableInterface->initialize();

        operationalInterface->register_property("Functional",
                                                isFuntionalReading);
        operationalInterface->initialize();
        interfaceInitialized = true;
    }
}

void StateSensorHandler::markFunctional(bool isFunctional)
{
    if (!operationalInterface)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Operational interface not initialized",
            phosphor::logging::entry("TID=%d", _tid),
            phosphor::logging::entry("SENSOR_ID=%d", _sensorID));
        return;
    }

    if (!interfaceInitialized)
    {
        isFuntionalReading = isFunctional;
        operationalIntfReady = true;
        initializeInterface();
    }
    else
    {
        operationalInterface->set_property("Functional", isFunctional);
    }

    if (isFunctional)
    {
        errCount = 0;
    }
    else
    {
        updateState(PLDM_INVALID_VALUE, PLDM_INVALID_VALUE);
    }
}

void StateSensorHandler::markAvailable(bool isAvailable)
{
    if (!availableInterface)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Avaliable interface not initialized",
            phosphor::logging::entry("TID=%d", _tid),
            phosphor::logging::entry("SENSOR_ID=%d", _sensorID));
        return;
    }

    if (!interfaceInitialized)
    {
        isAvailableReading = isAvailable;
        availableIntfReady = true;
        initializeInterface();
    }
    else
    {
        availableInterface->set_property("Available", isAvailable);
    }
}

void StateSensorHandler::incrementError()
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

void StateSensorHandler::updateState(const uint8_t currentState,
                                     const uint8_t previousState)
{
    if (!sensorInterface)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Sensor interface not initialized");
        return;
    }

    if (!interfaceInitialized)
    {
        currentStateReading = currentState;
        previousStateReading = previousState;
        sensorIntfReady = true;
        initializeInterface();
    }
    else
    {
        sensorInterface->set_property("CurrentState", currentState);
        sensorInterface->set_property("PreviousState", previousState);
    }

    if (currentState != PLDM_INVALID_VALUE &&
        previousState != PLDM_INVALID_VALUE)
    {
        markFunctional(true);
        markAvailable(true);
    }
}

bool StateSensorHandler::handleSensorReading(
    get_sensor_state_field& stateReading)
{
    switch (stateReading.sensor_op_state)
    {
        case PLDM_SENSOR_DISABLED: {
            markFunctional(false);
            markAvailable(true);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "State sensor disabled",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
                phosphor::logging::entry("TID=%d", _tid));
            break;
        }
        case PLDM_SENSOR_UNAVAILABLE: {
            markFunctional(false);
            markAvailable(false);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "State sensor unavailable",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
                phosphor::logging::entry("TID=%d", _tid));
            return false;
        }
        case PLDM_SENSOR_ENABLED: {
            updateState(stateReading.present_state,
                        stateReading.previous_state);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "GetStateSensorReadings success",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
                phosphor::logging::entry("TID=%d", _tid));
            break;
        }
        default: {
            // TODO: Handle other sensor operational states like statusUnknown,
            // initializing etc.
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "State sensor operational status unknown",
                phosphor::logging::entry("SENSOR_ID=0x%0X", _sensorID),
                phosphor::logging::entry("TID=%d", _tid));
            return false;
        }
    }
    return true;
}

bool StateSensorHandler::setStateSensorEnables(
    boost::asio::yield_context& yield)
{
    uint8_t sensorOpState;
    switch (_pdr->stateSensorData.sensor_init)
    {
        case PLDM_NO_INIT:
            sensorOpState = PLDM_SENSOR_ENABLED;
            break;
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
            /** @brief Sensor disabled flag*/
            sensorDisabled = true;
            markAvailable(true);
            markFunctional(false);
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

bool StateSensorHandler::getStateSensorReadings(
    boost::asio::yield_context& yield)
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
    // Pass compositeSensorCount as 1 to indicate that only one sensor instance
    // is supported
    uint8_t compositeSensorCount = 1;
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
    return handleSensorReading(stateField[0]);
}

bool StateSensorHandler::populateSensorValue(boost::asio::yield_context& yield)
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

bool StateSensorHandler::sensorHandlerInit(boost::asio::yield_context& yield)
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
