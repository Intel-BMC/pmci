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

#include "numeric_effecter_manager.hpp"

#include "pdr_utils.hpp"
#include "platform.hpp"

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace platform
{

NumericEffecterManager::NumericEffecterManager(
    const pldm_tid_t tid, const EffecterID effecterID, const std::string& name,
    const pldm_numeric_effecter_value_pdr& pdr) :
    _tid(tid),
    _effecterID(effecterID), _name(name), _pdr(pdr)
{
}

bool NumericEffecterManager::enableNumericEffecter(
    boost::asio::yield_context& yield)
{
    uint8_t effecterOpState;
    switch (_pdr.effecter_init)
    {
        case PLDM_NO_INIT:
            effecterOpState = EFFECTER_OPER_STATE_ENABLED_NOUPDATEPENDING;
            break;
        case PLDM_USE_INIT_PDR:
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Numeric Effecter Initialization PDR not supported",
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
    std::vector<uint8_t> req(pldmMsgHdrSize +
                             sizeof(pldm_set_numeric_effecter_enable_req));
    pldm_msg* reqMsg = reinterpret_cast<pldm_msg*>(req.data());

    rc = encode_set_numeric_effecter_enable_req(
        createInstanceId(_tid), _effecterID, effecterOpState, reqMsg);
    if (!validatePLDMReqEncode(_tid, rc, "SetNumericEffecterEnable"))
    {
        return false;
    }

    std::vector<uint8_t> resp;
    if (!sendReceivePldmMessage(yield, _tid, commandTimeout, commandRetryCount,
                                req, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send SetNumericEffecterEnable request",
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    uint8_t completionCode;
    auto rspMsg = reinterpret_cast<pldm_msg*>(resp.data());

    rc = decode_cc_only_resp(rspMsg, resp.size() - pldmMsgHdrSize,
                             &completionCode);
    if (!validatePLDMRespDecode(_tid, rc, completionCode,
                                "SetNumericEffecterEnable"))
    {
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "SetNumericEffecterEnable success",
        phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

bool NumericEffecterManager::initEffecter()
{
    std::optional<double> maxVal =
        pdr::effecter::fetchEffecterValue(_pdr, _pdr.max_set_table);
    if (maxVal == std::nullopt)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to decode maxSetable",
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    std::optional<double> minVal =
        pdr::effecter::fetchEffecterValue(_pdr, _pdr.min_set_table);
    if (minVal == std::nullopt)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to decode minReadable",
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    try
    {
        _effecter = std::make_shared<NumericEffecter>(
            _name, _tid, pdr::effecter::calculateEffecterValue(_pdr, *maxVal),
            pdr::effecter::calculateEffecterValue(_pdr, *minVal),
            _pdr.base_unit);
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            e.what(),
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Effecter Init success",
        phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

bool NumericEffecterManager::handleEffecterReading(
    uint8_t effecterOperationalState, uint8_t effecterDataSize,
    union_effecter_data_size& presentReading)
{
    switch (effecterOperationalState)
    {
        case EFFECTER_OPER_STATE_ENABLED_UPDATEPENDING:
        // TODO: Read again after transition interval before setting value
        case EFFECTER_OPER_STATE_ENABLED_NOUPDATEPENDING: {
            if (_pdr.effecter_data_size != effecterDataSize)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Invalid effecter reading. Effecter data size missmatch",
                    phosphor::logging::entry("TID=%d", _tid),
                    phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                    phosphor::logging::entry("DATA_SIZE=%d", effecterDataSize));
                return false;
            }

            std::optional<double> effecterReading =
                pdr::effecter::fetchEffecterValue(_pdr, presentReading);
            if (effecterReading == std::nullopt)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Numeric effecter value decode failed",
                    phosphor::logging::entry("TID=%d", _tid),
                    phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                    phosphor::logging::entry("DATA_SIZE=%d", effecterDataSize));
                return false;
            }

            double value =
                pdr::effecter::calculateEffecterValue(_pdr, *effecterReading);
            _effecter->updateValue(value);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "GetNumericEffecterValue success",
                phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                phosphor::logging::entry("TID=%d", _tid),
                phosphor::logging::entry("VALUE=%lf", value));
            break;
        }
        case EFFECTER_OPER_STATE_DISABLED: {
            _effecter->markFunctional(false);
            _effecter->markAvailable(true);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Numeric effecter disabled",
                phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                phosphor::logging::entry("TID=%d", _tid));
            break;
        }
        case EFFECTER_OPER_STATE_UNAVAILABLE: {
            _effecter->markFunctional(false);
            _effecter->markAvailable(false);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Numeric effecter unavailable",
                phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                phosphor::logging::entry("TID=%d", _tid));
            return false;
        }
        default:
            // TODO: Handle other effecter operational states like
            // statusUnknown, initializing etc.
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Numeric effecter operational status unknown",
                phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
                phosphor::logging::entry("TID=%d", _tid));
            return false;
    }
    return true;
}

bool NumericEffecterManager::getEffecterReading(
    boost::asio::yield_context& yield)
{
    int rc;
    std::vector<uint8_t> req(pldmMsgHdrSize +
                             sizeof(pldm_get_numeric_effecter_value_req));
    pldm_msg* reqMsg = reinterpret_cast<pldm_msg*>(req.data());

    rc = encode_get_numeric_effecter_value_req(createInstanceId(_tid),
                                               _effecterID, reqMsg);
    if (!validatePLDMReqEncode(_tid, rc, "GetNumericEffecterValue"))
    {
        return false;
    }

    std::vector<uint8_t> resp;
    if (!sendReceivePldmMessage(yield, _tid, commandTimeout, commandRetryCount,
                                req, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send GetNumericEffecterValue request",
            phosphor::logging::entry("TID=%d", _tid),
            phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID));
        return false;
    }

    uint8_t completionCode;
    uint8_t effecterDataSize;
    uint8_t effecterOperationalState;
    union_effecter_data_size pendingValue;
    union_effecter_data_size presentValue;
    auto rspMsg = reinterpret_cast<pldm_msg*>(resp.data());

    rc = decode_get_numeric_effecter_value_resp(
        rspMsg, resp.size() - pldmMsgHdrSize, &completionCode,
        &effecterDataSize, &effecterOperationalState,
        reinterpret_cast<uint8_t*>(&pendingValue),
        reinterpret_cast<uint8_t*>(&presentValue));
    if (!validatePLDMRespDecode(_tid, rc, completionCode,
                                "GetNumericEffecterValue"))
    {
        return false;
    }

    return handleEffecterReading(effecterOperationalState, effecterDataSize,
                                 presentValue);
}

bool NumericEffecterManager::populateEffecterValue(
    boost::asio::yield_context& yield)
{
    if (!getEffecterReading(yield))
    {
        _effecter->incrementError();
        return false;
    }
    return true;
}

bool NumericEffecterManager::effecterManagerInit(
    boost::asio::yield_context& yield)
{
    if (!enableNumericEffecter(yield))
    {
        return false;
    }

    if (!initEffecter())
    {
        return false;
    }

    // Read and populate the effecter initial value
    if (!populateEffecterValue(yield))
    {
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Effecter Manager Init Success",
        phosphor::logging::entry("EFFECTER_ID=0x%0X", _effecterID),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
}

} // namespace platform
} // namespace pldm
