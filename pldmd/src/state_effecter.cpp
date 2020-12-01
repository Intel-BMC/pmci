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
    static bool interfaceInitialized = false;
    if (interfaceInitialized)
    {
        return;
    }

    if (!effecterInterface->is_initialized())
    {
        effecterInterface->initialize();
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
    if (!effecterInterface->is_initialized())
    {
        effecterInterface->register_property("PendingState", pendingState);
        effecterInterface->register_property("CurrentState", currentState);
    }
    else
    {
        if (currentStateReading != currentState)
        {
            effecterInterface->set_property("CurrentState", currentState);
        }
        if (pendingStateReading != pendingState)
        {
            effecterInterface->set_property("PendingState", pendingState);
        }
    }
    // cache the last read state value from the effecter
    currentStateReading = currentState;
    pendingStateReading = pendingState;

    if (!isFuntionalReading)
    {
        markFunctional(true);
    }
    if (!isAvailableReading)
    {
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

bool StateEffecter::stateEffecterInit(boost::asio::yield_context& yield)
{
    if (!enableStateEffecter(yield))
    {
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "State Effecter Init Success",
        phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

} // namespace platform
} // namespace pldm