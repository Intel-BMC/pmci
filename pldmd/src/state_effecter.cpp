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

#include "state_effecter.hpp"

#include "platform.hpp"

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace platform
{
static const char* pldmPath = "/xyz/openbmc_project/pldm/";
constexpr const size_t errorThreshold = 5;

static bool effecterIntfReady = false;
static bool availableIntfReady = false;
static bool operationalIntfReady = false;
static bool interfaceInitialized = false;

StateEffecter::StateEffecter(const pldm_tid_t tid, const EffecterID effecterID,
                             const std::string& name,
                             const std::shared_ptr<StateEffecterPDR>& pdr) :
    _tid(tid),
    _effecterID(effecterID), _name(name), _pdr(pdr)
{
    if (_pdr->possibleStates.empty())
    {
        throw std::runtime_error("State effecter PDR data invalid");
    }

    setInitialProperties();
}

void StateEffecter::setInitialProperties()
{
    static const std::string path =
        pldmPath + std::to_string(_tid) + "/state_effecter/" + _name;

    auto objectServer = getObjServer();
    effecterInterface = objectServer->add_unique_interface(
        path, "xyz.openbmc_project.Effecter.State");
    // Composite effecters are not supported. Thus extract only first effecter
    // state
    effecterInterface->register_property_r(
        "StateSetID", _pdr->possibleStates[0].stateSetID,
        sdbusplus::vtable::property_::const_, [](const auto& r) { return r; });
    effecterInterface->register_property_r(
        "PossibleStates", _pdr->possibleStates[0].possibleStateSetValues,
        sdbusplus::vtable::property_::const_, [](const auto& r) { return r; });

    availableInterface = objectServer->add_unique_interface(
        path, "xyz.openbmc_project.State.Decorator.Availability");

    operationalInterface = objectServer->add_unique_interface(
        path, "xyz.openbmc_project.State.Decorator.OperationalStatus");
}

void StateEffecter::initializeInterface()
{
    if (!interfaceInitialized && effecterIntfReady && availableIntfReady &&
        operationalIntfReady)
    {
        effecterInterface->register_property("PendingState",
                                             pendingStateReading);
        effecterInterface->register_property("CurrentState",
                                             currentStateReading);
        effecterInterface->initialize();

        availableInterface->register_property("Available", isAvailableReading);
        availableInterface->initialize();

        operationalInterface->register_property("Functional",
                                                isFuntionalReading);
        operationalInterface->initialize();
        interfaceInitialized = true;
    }
}

void StateEffecter::markFunctional(bool isFunctional)
{
    if (!operationalInterface)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Operational interface not initialized",
            phosphor::logging::entry("TID=%d", _tid),
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID));
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

void StateEffecter::markAvailable(bool isAvailable)
{
    if (!availableInterface)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Avaliable interface not initialized",
            phosphor::logging::entry("TID=%d", _tid),
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID));
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

void StateEffecter::incrementError()
{
    if (errCount >= errorThreshold)
    {
        return;
    }

    errCount++;
    if (errCount == errorThreshold)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "State effecter reading failed",
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
            phosphor::logging::entry("TID=%d", _tid));
        markFunctional(false);
    }
}

void StateEffecter::updateState(const uint8_t currentState,
                                const uint8_t pendingState)
{
    if (!effecterInterface)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Effecter interface not initialized");
        return;
    }

    if (!interfaceInitialized)
    {
        currentStateReading = currentState;
        pendingStateReading = pendingState;
        effecterIntfReady = true;
        initializeInterface();
    }
    else
    {
        effecterInterface->set_property("CurrentState", currentState);
        effecterInterface->set_property("PendingState", pendingState);
    }

    if (currentState != PLDM_INVALID_VALUE &&
        pendingState != PLDM_INVALID_VALUE)
    {

        markFunctional(true);
        markAvailable(true);
    }
}

bool StateEffecter::enableStateEffecter(boost::asio::yield_context& yield)
{
    uint8_t effecterOpState;
    switch (_pdr->stateEffecterData.effecter_init)
    {
        case PLDM_NO_INIT:
            effecterOpState = EFFECTER_OPER_STATE_ENABLED_NOUPDATEPENDING;
            break;
        case PLDM_USE_INIT_PDR:
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "State Effecter Initialization PDR not supported",
                phosphor::logging::entry("TID=%d", _tid),
                phosphor::logging::entry("EFFECTER_ID=%d", _effecterID));
            return false;
        case PLDM_ENABLE_EFFECTER:
            effecterOpState = EFFECTER_OPER_STATE_ENABLED_NOUPDATEPENDING;
            break;
        case PLDM_DISABLE_EFECTER:
            effecterOpState = EFFECTER_OPER_STATE_DISABLED;
            break;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid effecterInit value in PDR",
                phosphor::logging::entry("TID=%d", _tid),
                phosphor::logging::entry("EFFECTER_ID=%d", _effecterID));
            return false;
    }

    int rc;
    // TODO: PLDM events and composite effecter supported
    constexpr uint8_t compositeEffecterCount = 1;
    std::array<state_effecter_op_field, compositeEffecterCount> opFields = {
        {effecterOpState, PLDM_DISABLE_EVENTS}};
    std::vector<uint8_t> req(pldmMsgHdrSize +
                             sizeof(pldm_set_state_effecter_enable_req));
    pldm_msg* reqMsg = reinterpret_cast<pldm_msg*>(req.data());

    rc = encode_set_state_effecter_enable_req(
        createInstanceId(_tid), _effecterID, compositeEffecterCount,
        opFields.data(), reqMsg);
    if (!validatePLDMReqEncode(_tid, rc, "SetStateEffecterEnable"))
    {
        return false;
    }

    std::vector<uint8_t> resp;
    if (!sendReceivePldmMessage(yield, _tid, commandTimeout, commandRetryCount,
                                req, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send SetStateEffecterEnable request",
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    uint8_t completionCode;
    auto rspMsg = reinterpret_cast<pldm_msg*>(resp.data());

    rc = decode_cc_only_resp(rspMsg, resp.size() - pldmMsgHdrSize,
                             &completionCode);
    if (!validatePLDMRespDecode(_tid, rc, completionCode,
                                "SetStateEffecterEnable"))
    {
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "SetStateEffecterEnable success",
        phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

bool StateEffecter::handleStateEffecterState(
    get_effecter_state_field& stateReading)
{
    switch (stateReading.effecter_op_state)
    {
        case EFFECTER_OPER_STATE_ENABLED_UPDATEPENDING:
        // TODO: Read again after transition interval before setting value
        case EFFECTER_OPER_STATE_ENABLED_NOUPDATEPENDING: {
            updateState(stateReading.present_state, stateReading.pending_state);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "GetStateEffecterStates success",
                phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                phosphor::logging::entry("TID=%d", _tid));
            break;
        }
        case EFFECTER_OPER_STATE_DISABLED: {
            markFunctional(false);
            markAvailable(true);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "State effecter disabled",
                phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                phosphor::logging::entry("TID=%d", _tid));
            break;
        }
        case EFFECTER_OPER_STATE_UNAVAILABLE: {
            markFunctional(false);
            markAvailable(false);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "State effecter unavailable",
                phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                phosphor::logging::entry("TID=%d", _tid));
            return false;
        }
        default:
            // TODO: Handle other effecter operational states like
            // statusUnknown, initializing etc.
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "State effecter operational status unknown",
                phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                phosphor::logging::entry("TID=%d", _tid));
            return false;
    }
    return true;
}

bool StateEffecter::getStateEffecterStates(boost::asio::yield_context& yield)
{
    int rc;
    std::vector<uint8_t> req(pldmMsgHdrSize +
                             sizeof(pldm_get_state_effecter_states_req));
    pldm_msg* reqMsg = reinterpret_cast<pldm_msg*>(req.data());

    rc = encode_get_state_effecter_states_req(createInstanceId(_tid),
                                              _effecterID, reqMsg);
    if (!validatePLDMReqEncode(_tid, rc, "GetStateEffecterStates"))
    {
        return false;
    }

    std::vector<uint8_t> resp;
    if (!sendReceivePldmMessage(yield, _tid, commandTimeout, commandRetryCount,
                                req, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send GetStateEffecterStates request",
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    uint8_t completionCode;
    // Pass compositeEffecterCount as 1 to indicate that only one effecter
    // instance is supported
    uint8_t compositeEffecterCount = PLDM_COMPOSITE_EFFECTER_COUNT_MIN;
    std::array<get_effecter_state_field, PLDM_COMPOSITE_EFFECTER_COUNT_MAX>
        stateField{};
    auto rspMsg = reinterpret_cast<pldm_msg*>(resp.data());

    rc = decode_get_state_effecter_states_resp(
        rspMsg, resp.size() - pldmMsgHdrSize, &completionCode,
        &compositeEffecterCount, stateField.data());
    if (!validatePLDMRespDecode(_tid, rc, completionCode,
                                "GetStateEffecterStates"))
    {
        return false;
    }

    if (!compositeEffecterCount)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetStateEffecterStates: Invalid composite effecter count",
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }
    // Handle only first value.
    // TODO: Composite effecter support.
    return handleStateEffecterState(stateField[0]);
}

bool StateEffecter::populateEffecterValue(boost::asio::yield_context& yield)
{
    if (!getStateEffecterStates(yield))
    {
        incrementError();
        return false;
    }
    return true;
}

bool StateEffecter::isEffecterStateSettable(const uint8_t state)
{
    // Note:- possibleStates will never be empty
    auto itr =
        std::find(_pdr->possibleStates[0].possibleStateSetValues.begin(),
                  _pdr->possibleStates[0].possibleStateSetValues.end(), state);
    if (itr != _pdr->possibleStates[0].possibleStateSetValues.end())
    {
        return true;
    }
    phosphor::logging::log<phosphor::logging::level::WARNING>(
        "State not supported by effecter",
        phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
        phosphor::logging::entry("TID=%d", _tid));
    return false;
}

bool StateEffecter::setEffecter(boost::asio::yield_context& yield,
                                const uint8_t state)
{
    int rc;

    // Composite effecters not spported
    constexpr size_t minSetStateEffecterStatesSize = 5;
    std::vector<uint8_t> req(pldmMsgHdrSize + minSetStateEffecterStatesSize);
    pldm_msg* reqMsg = reinterpret_cast<pldm_msg*>(req.data());
    set_effecter_state_field stateField = {PLDM_REQUEST_SET, state};

    constexpr size_t compositeEffecterCount = 1;
    rc = encode_set_state_effecter_states_req(
        createInstanceId(_tid), _effecterID, compositeEffecterCount,
        &stateField, reqMsg);
    if (!validatePLDMReqEncode(_tid, rc, "SetStateEffecterStates"))
    {
        return false;
    }

    std::vector<uint8_t> resp;
    if (!sendReceivePldmMessage(yield, _tid, commandTimeout, commandRetryCount,
                                req, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send SetStateEffecterStates request",
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    uint8_t completionCode;
    auto rspMsg = reinterpret_cast<pldm_msg*>(resp.data());

    rc = decode_cc_only_resp(rspMsg, resp.size() - pldmMsgHdrSize,
                             &completionCode);
    if (!validatePLDMRespDecode(_tid, rc, completionCode,
                                "SetStateEffecterStates"))
    {
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "SetStateEffecterStates success",
        phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

void StateEffecter::registerSetEffecter()
{
    static const std::string path =
        pldmPath + std::to_string(_tid) + "/state_effecter/" + _name;
    auto objServer = getObjServer();
    setEffecterInterface = objServer->add_unique_interface(
        path, "xyz.openbmc_project.Effecter.SetEffecter");
    setEffecterInterface->register_method(
        "SetStateEffecter",
        [this](boost::asio::yield_context yield, uint8_t effecterState) {
            if (!isEffecterStateSettable(effecterState))
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    "Unsupported effecter data state received",
                    phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                    phosphor::logging::entry("TID=%d", _tid),
                    phosphor::logging::entry("STATE=%d", effecterState));

                throw sdbusplus::exception::SdBusError(
                    -EINVAL, "Unsupported effecter state");
            }
            if (!setEffecter(yield, effecterState))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to SetStateEffecterStates",
                    phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                    phosphor::logging::entry("TID=%d", _tid));

                throw sdbusplus::exception::SdBusError(
                    -EINVAL, "SetStateEffecterStates failed");
            }

            auto refreshEffecterInterfaces = [this]() {
                boost::system::error_code ec;
                uint8_t transitionIntervalSec = 3;
                transitionIntervalTimer =
                    std::make_unique<boost::asio::steady_timer>(
                        *getIoContext());
                transitionIntervalTimer->expires_after(
                    boost::asio::chrono::seconds(transitionIntervalSec));
                transitionIntervalTimer->async_wait(
                    [this](const boost::system::error_code& e) {
                        if (e)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(
                                "SetStateEffecter: async_wait error");
                        }
                        boost::asio::spawn(
                            *getIoContext(),
                            [this](boost::asio::yield_context yieldCtx) {
                                if (!populateEffecterValue(yieldCtx))
                                {
                                    phosphor::logging::log<
                                        phosphor::logging::level::ERR>(
                                        "Read state effecter failed",
                                        phosphor::logging::entry(
                                            "EFFECTER_ID=0x%0X", _effecterID),
                                        phosphor::logging::entry("TID=%d",
                                                                 _tid));
                                }
                            });
                    });
            };

            // Refresh the value on D-Bus
            getIoContext()->post(refreshEffecterInterfaces);
        });
    setEffecterInterface->initialize();
}

bool StateEffecter::stateEffecterInit(boost::asio::yield_context& yield)
{
    if (!enableStateEffecter(yield))
    {
        return false;
    }

    if (!populateEffecterValue(yield))
    {
        return false;
    }

    registerSetEffecter();

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "State Effecter Init Success",
        phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

} // namespace platform
} // namespace pldm
