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
#include "firmware_update.h"

#include "firmware_update.hpp"
#include "pldm.hpp"

#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/PLDM/FWU/FWUBase/server.hpp>

namespace pldm
{
namespace fwu
{
// map that holds the properties of all terminus
std::map<pldm_tid_t, FDProperties> terminusFwuProperties;
// map that holds the general properties of a terminus
FWUProperties fwuProperties;

using FWUBase = sdbusplus::xyz::openbmc_project::PLDM::FWU::server::FWUBase;
constexpr size_t hdrSize = sizeof(pldm_msg_hdr);

void pldmMsgRecvCallback(const pldm_tid_t tid, const uint8_t /*msgTag*/,
                         const bool /*tagOwner*/,
                         std::vector<uint8_t>& /*message*/)
{
    // TODO: Perform the actual init operations needed
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "PLDM Firmware update message received",
        phosphor::logging::entry("EID=0x%X", tid));

    return;
}

template <typename T>
static void
    processDescriptor(const DescriptorHeader& header, const T& data,
                      std::map<std::string, FWUVariantType>& descriptorData)

{
    std::string value;
    try
    {
        value = std::to_string(data);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return;
    }

    switch (header.type)
    {
        case pldm::fwu::DescriptorIdentifierType::pciVendorID: {
            descriptorData["PCIVendorID"] = value;
            break;
        }
        case pldm::fwu::DescriptorIdentifierType::pciDeviceID: {
            descriptorData["PCIDeviceID"] = value;
            break;
        }
        case pldm::fwu::DescriptorIdentifierType::pciSubsystemVendorID: {
            descriptorData["PCISubsystemVendorID"] = value;
            break;
        }
        case pldm::fwu::DescriptorIdentifierType::pciSubsystemID: {
            descriptorData["PCISubsystemID"] = value;
            break;
        }
        case pldm::fwu::DescriptorIdentifierType::pciRevisionID: {
            descriptorData["PCIRevisionID"] = value;
            break;
        }
        // TODO Add cases for other Descriptor Identifier Types
        default: {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Descriptor identifier type not matched");
            break;
        }
    }
}

static void
    processDescriptor(const DescriptorHeader& /*header*/,
                      const std::vector<uint8_t>& /*data*/,
                      std::map<std::string, FWUVariantType>& /*descriptorData*/)
{

    // TODO process non-standard descriptor sizes(Eg: PnP 3 byes) and bigger
    // sizes(Eg: UUID 16 bytes)
}

static void
    unpackDescriptors(const uint8_t count, const std::vector<uint8_t>& data,
                      std::map<std::string, FWUVariantType>& descriptorData)
{
    size_t found = 0;
    auto it = std::begin(data);

    while (it != std::end(data) && found != count)
    {
        size_t bytesLeft = std::distance(it, std::end(data));
        // Check header size
        if (bytesLeft <= sizeof(DescriptorHeader))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "No headers left");
            break;
        }

        // Unpack header
        const auto hdr = reinterpret_cast<const DescriptorHeader*>(&*it);
        std::advance(it, sizeof(*hdr));
        bytesLeft = std::distance(it, std::end(data));

        // Check data size
        if (bytesLeft < hdr->size)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid descriptor data size");
            break;
        }

        // Unpack data
        if (hdr->size == sizeof(uint8_t))
        {
            processDescriptor(*hdr, *it, descriptorData);
        }
        else if (hdr->size == sizeof(uint16_t))
        {
            processDescriptor(*hdr, *reinterpret_cast<const uint16_t*>(&*it),
                              descriptorData);
        }
        else if (hdr->size == sizeof(uint32_t))
        {
            processDescriptor(*hdr, *reinterpret_cast<const uint32_t*>(&*it),
                              descriptorData);
        }
        else
        {
            std::vector<uint8_t> descriptorDataVect;
            std::copy(it, std::next(it, hdr->size),
                      std::back_inserter(descriptorDataVect));
            processDescriptor(*hdr, descriptorDataVect, descriptorData);
        }
        std::advance(it, hdr->size);

        found++;
    }

    if (found != count)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Descriptor count not matched",
            phosphor::logging::entry("ACTUAL_DESCRIPTOR_COUNT=%d", found),
            phosphor::logging::entry("EXPECTED_DESCRIPTOR_COUNT=%d", count));
    }
}

int FWInventoryInfo::runQueryDeviceIdentifiers(boost::asio::yield_context yield)
{
    uint8_t instanceID = createInstanceId(tid);
    std::vector<uint8_t> pldmReq(sizeof(struct PLDMEmptyRequest));

    struct pldm_msg* msgReq = reinterpret_cast<pldm_msg*>(pldmReq.data());

    int retVal = encode_query_device_identifiers_req(
        instanceID, msgReq, PLDM_QUERY_DEVICE_IDENTIFIERS_REQ_BYTES);

    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "QueryDeviceIdentifiers: encode request failed",
            phosphor::logging::entry("TID=%d", tid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        return retVal;
    }

    std::vector<uint8_t> pldmResp;

    if (!sendReceivePldmMessage(yield, tid, timeout, retryCount, pldmReq,
                                pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "QueryDeviceIdentifiers: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", tid));
        return PLDM_ERROR;
    }

    auto msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());

    size_t payloadLen = pldmResp.size() - hdrSize;

    uint8_t completionCode = PLDM_SUCCESS;
    uint32_t deviceIdentifiersLen = 0;
    uint8_t descriptorCount = 0;
    constexpr size_t maxDescriptorDataLen = 255;
    std::vector<uint8_t> descriptorDataVect(maxDescriptorDataLen);

    struct variable_field descriptorData;
    descriptorData.length = descriptorDataVect.size();
    descriptorData.ptr = descriptorDataVect.data();

    retVal = decode_query_device_identifiers_resp(
        msgResp, payloadLen, &completionCode, &deviceIdentifiersLen,
        &descriptorCount, &descriptorData);

    if (retVal != PLDM_SUCCESS)
    {

        phosphor::logging::log<phosphor::logging::level::ERR>(
            "QueryDeviceIdentifiers: decode response failed",
            phosphor::logging::entry("TID=%d", tid),
            phosphor::logging::entry("RETVAL=%d", retVal));

        return retVal;
    }

    unpackDescriptors(descriptorCount, descriptorDataVect, fwuProperties);

    return PLDM_SUCCESS;
}

void FWInventoryInfo::copyCompImgSetData(
    const struct get_firmware_parameters_resp& respData,
    const struct variable_field& activeCompImgSetVerData,
    const struct variable_field& pendingCompImgSetVerData)
{
    fwuProperties["CapabilitiesDuringUpdate"] =
        htole32(respData.capabilities_during_update);
    fwuProperties["ComponentCount"] = htole16(respData.comp_count);
    std::string activeCompImgSetVerStr(
        reinterpret_cast<const char*>(activeCompImgSetVerData.ptr),
        activeCompImgSetVerData.length);
    fwuProperties["ActiveCompImgSetVerStr"] = activeCompImgSetVerStr;

    if (pendingCompImgSetVerData.length != 0)
    {
        std::string pendingCompImgSetVerStr(
            reinterpret_cast<const char*>(pendingCompImgSetVerData.ptr),
            pendingCompImgSetVerData.length);
        fwuProperties["PendingCompImgSetVerStr"] = pendingCompImgSetVerStr;
    }
}

void FWInventoryInfo::copyCompData(
    const uint16_t count, const struct component_parameter_table* componentData,
    struct variable_field* activeCompVerData,
    struct variable_field* pendingCompVerData)
{
    std::map<std::string, FWUVariantType> compProperties;
    compProperties["ComponentClassification"] =
        componentData->comp_classification;
    compProperties["ComponentIdentifier"] = componentData->comp_identifier;
    compProperties["ComponentClassificationIndex"] =
        componentData->comp_classification_index;
    compProperties["ActiveComponentComparisonStamp"] =
        componentData->active_comp_comparison_stamp;
    compProperties["ActiveComponentReleaseDate"] =
        componentData->active_comp_release_date;
    std::string activeCompVerStr(
        reinterpret_cast<const char*>(activeCompVerData->ptr),
        activeCompVerData->length);
    compProperties["ActiveComponentVersionString"] = activeCompVerStr;

    compProperties["PendingComponentComparisonStamp"] =
        componentData->pending_comp_comparison_stamp;
    compProperties["PendingComponentReleaseDate"] =
        componentData->pending_comp_release_date;
    std::string pendingCompVerStr(
        reinterpret_cast<const char*>(pendingCompVerData->ptr),
        pendingCompVerData->length);
    compProperties["PendingComponentVersionString"] = pendingCompVerStr;

    compProperties["ComponentActivationMethods"] =
        componentData->comp_activation_methods;
    compProperties["CapabilitiesDuringUpdate"] =
        componentData->capabilities_during_update;
    compPropertiesMap[count] = compProperties;
}

void FWInventoryInfo::unpackCompData(const uint16_t count,
                                     const std::vector<uint8_t>& compData)
{
    struct component_parameter_table compDataObj;
    struct variable_field activeCompVerStr;
    struct variable_field pendingCompVerStr;

    uint16_t found = 0;
    size_t bytesLeft = 0;
    auto it = std::begin(compData);

    while (it < std::end(compData) && found != count)
    {
        bytesLeft = std::distance(it, std::end(compData));

        if (bytesLeft < sizeof(compDataObj))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetFirmwareParameters: invalid component data");
            break;
        }

        int retVal = decode_get_firmware_parameters_comp_resp(
            &it[0], bytesLeft, &compDataObj, &activeCompVerStr,
            &pendingCompVerStr);

        if (retVal != PLDM_SUCCESS)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetFirmwareParameters: decode response of component data "
                "failed",
                phosphor::logging::entry("TID=%d", tid),
                phosphor::logging::entry("RETVAL=%d", retVal));
            break;
        }

        size_t offSet = sizeof(struct component_parameter_table) +
                        compDataObj.active_comp_ver_str_len +
                        compDataObj.pending_comp_ver_str_len;

        if (offSet > bytesLeft)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetFirmwareParameters: invalid component data");
            break;
        }
        std::advance(it, offSet);
        found++;
        copyCompData(found, &compDataObj, &activeCompVerStr,
                     &pendingCompVerStr);
    }

    if (found != count)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Component count not matched",
            phosphor::logging::entry("ACTUAL_COMP_COUNT=%d", found),
            phosphor::logging::entry("EXPECTED_COMP_COUNT=%d", count));
    }
}

int FWInventoryInfo::runGetFirmwareParameters(boost::asio::yield_context yield)
{
    uint8_t instanceID = createInstanceId(tid);
    std::vector<uint8_t> pldmReq(sizeof(struct PLDMEmptyRequest));

    struct pldm_msg* msgReq = reinterpret_cast<pldm_msg*>(pldmReq.data());

    int retVal = encode_get_firmware_parameters_req(
        instanceID, msgReq, PLDM_QUERY_DEVICE_IDENTIFIERS_REQ_BYTES);

    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetFirmwareParameters: encode response failed",
            phosphor::logging::entry("TID=%d", tid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        return retVal;
    }

    std::vector<uint8_t> pldmResp;

    if (!sendReceivePldmMessage(yield, tid, timeout, retryCount, pldmReq,
                                pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetFirmwareParameters: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", tid));
        return PLDM_ERROR;
    }

    if (pldmResp.size() < hdrSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetFirmwareParameters: Response lenght is invalid");
        return PLDM_ERROR_INVALID_LENGTH;
    }
    auto respMsg = reinterpret_cast<pldm_msg*>(pldmResp.data());
    size_t payloadLen = pldmResp.size() - hdrSize;

    struct get_firmware_parameters_resp resp;
    struct variable_field activeCompImageSetVerStr;
    struct variable_field pendingCompImageSetVerStr;

    retVal = decode_get_firmware_parameters_comp_img_set_resp(
        respMsg, payloadLen, &resp, &activeCompImageSetVerStr,
        &pendingCompImageSetVerStr);

    if (retVal != PLDM_SUCCESS)
    {

        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetFirmwareParameters: decode response failed",
            phosphor::logging::entry("TID=%d", tid),
            phosphor::logging::entry("RETVAL=%d", retVal));

        return retVal;
    }

    copyCompImgSetData(resp, activeCompImageSetVerStr,
                       pendingCompImageSetVerStr);

    size_t compDataOffset = hdrSize + sizeof(get_firmware_parameters_resp) +
                            resp.active_comp_image_set_ver_str_len +
                            resp.pending_comp_image_set_ver_str_len;

    if (pldmResp.size() < compDataOffset)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetFirmwareParameters: Response lenght is invalid");
        return PLDM_ERROR_INVALID_LENGTH;
    }

    std::vector<uint8_t> compData(pldmResp.begin() + compDataOffset,
                                  pldmResp.end());
    unpackCompData(resp.comp_count, compData);

    return PLDM_SUCCESS;
}

FWInventoryInfo::FWInventoryInfo(const pldm_tid_t _tid) : tid(_tid)
{
}

FWInventoryInfo::~FWInventoryInfo()
{
}

static bool fwuBaseInitialized = false;

static void initializeFWUBase()
{
    std::string objPath = "/xyz/openbmc_project/pldm/fwu";
    auto objServer = getObjServer();
    auto fwuBaseIface = objServer->add_interface(objPath, FWUBase::interface);
    fwuBaseIface->register_method(
        "StartFWUpdate", []([[maybe_unused]] std::string filePath) {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "StartFWUpdate is called");
        });
    fwuBaseIface->initialize();
    fwuBaseInitialized = true;
}

std::optional<FDProperties>
    FWInventoryInfo::runInventoryCommands(boost::asio::yield_context yield)
{
    int retVal = runQueryDeviceIdentifiers(yield);

    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run QueryDeviceIdentifiers command");
        return std::nullopt;
    }

    retVal = runGetFirmwareParameters(yield);

    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run GetFirmwareParameters command");
        return std::nullopt;
    }
    FDProperties fdProperties(fwuProperties, compPropertiesMap);
    return fdProperties;
}

bool fwuInit(boost::asio::yield_context yield, const pldm_tid_t tid)
{
    if (!fwuBaseInitialized)
    {
        initializeFWUBase();
    }
    FWInventoryInfo inventoryInfo(tid);

    if (auto properties = inventoryInfo.runInventoryCommands(yield))
    {
        terminusFwuProperties[tid] = *properties;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run runInventory commands",
            phosphor::logging::entry("TID=%d", tid));
        return false;
    }

    fwuProperties.clear();
    return true;
}
} // namespace fwu
} // namespace pldm
