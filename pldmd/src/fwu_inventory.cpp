/**
 * Copyright © 2021 Intel Corporation
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
#include "fwu_inventory.hpp"

#include "pldm.hpp"
#include "utils.hpp"

#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>

namespace pldm
{
namespace fwu
{
// map that holds the properties of all terminus
std::map<pldm_tid_t, FDProperties> terminusFwuProperties;

FWInventoryInfo::FWInventoryInfo(const pldm_tid_t _tid) :
    tid(_tid), objServer(getObjServer())
{
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
    uint8_t* descriptorData = NULL;

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

    if (descriptorData == NULL)
    {
        return PLDM_ERROR;
    }
    std::vector<uint8_t> descriptorDataVect(deviceIdentifiersLen);

    std::copy(descriptorData, descriptorData + deviceIdentifiersLen,
              descriptorDataVect.begin());
    unpackDescriptors(descriptorCount, descriptorDataVect,
                      initialDescriptorType, descriptors);
    return PLDM_SUCCESS;
}

void FWInventoryInfo::copyCompImgSetData(
    const struct get_firmware_parameters_resp& respData,
    const struct variable_field& activeCompImgSetVerData,
    const struct variable_field& pendingCompImgSetVerData)
{
    fwuProperties["CapabilitiesDuringUpdate"] =
        htole32(respData.capabilities_during_update.value);
    fwuProperties["ComponentCount"] = htole16(respData.comp_count);
    activeCompImgSetVerStr = toString(activeCompImgSetVerData);
    fwuProperties["ActiveCompImgSetVerStr"] = activeCompImgSetVerStr;

    if (pendingCompImgSetVerData.length != 0)
    {
        pendingCompImgSetVerStr = toString(pendingCompImgSetVerData);
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
        le64toh(*reinterpret_cast<const uint64_t*>(
            componentData->active_comp_release_date));
    std::string activeCompVerStr(
        reinterpret_cast<const char*>(activeCompVerData->ptr),
        activeCompVerData->length);
    compProperties["ActiveComponentVersionString"] = activeCompVerStr;

    compProperties["PendingComponentComparisonStamp"] =
        componentData->pending_comp_comparison_stamp;
    compProperties["PendingComponentReleaseDate"] =
        le64toh(*reinterpret_cast<const uint64_t*>(
            componentData->pending_comp_release_date));
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

int FWInventoryInfo::unpackCompData(const uint16_t count,
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
                ("GetFirmwareParameters: decode response of component data "
                 "failed, TID: " +
                 utils::changeToString(tid) +
                 " RETVAL: " + utils::changeToString(retVal))
                    .c_str());
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
            ("Component count not matched,actual component count: " +
             utils::changeToString(found) +
             " expected component count: " + utils::changeToString(count))
                .c_str());
        return PLDM_ERROR;
    }

    return PLDM_SUCCESS;
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
            "GetFirmwareParameters: Response length is invalid");
        return PLDM_ERROR_INVALID_LENGTH;
    }

    std::vector<uint8_t> compData(pldmResp.begin() + compDataOffset,
                                  pldmResp.end());

    return unpackCompData(resp.comp_count, compData);
}

void FWInventoryInfo::addPCIDescriptorsToDBus(const std::string& objPath)
{
    auto pciDevIntf = objServer->add_unique_interface(
        objPath, "xyz.openbmc_project.PLDM.FWU.PCIDescriptor");
    for (auto& it : descriptors)
    {
        std::replace_if(
            it.second.begin(), it.second.end(),
            [](const char& c) { return !isprint(c); }, ' ');
        pciDevIntf->register_property(it.first, it.second);
    }
    pciDevIntf->initialize();
    interfaceList.push_back(std::move(pciDevIntf));
}

void FWInventoryInfo::addDescriptorsToDBus()
{
    const std::string objPath = "/xyz/openbmc_project/pldm/fwu/" +
                                utils::changeToString(tid) +
                                "/deviceDescriptors";

    switch (
        static_cast<pldm::fwu::DescriptorIdentifierType>(initialDescriptorType))
    {
        case pldm::fwu::DescriptorIdentifierType::pciVendorID: {
            addPCIDescriptorsToDBus(objPath);
            break;
        }
        // TODO Add cases for other Descriptor Identifier Types
        default: {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "addDescriptorsToDBus: Descriptor identifier type not matched",
                phosphor::logging::entry("TID=%d", tid));
            break;
        }
    }
}

void FWInventoryInfo::addCompImgSetDataToDBus()
{
    const std::string compImgSetPath = "/xyz/openbmc_project/pldm/fwu/" +
                                       utils::changeToString(tid) +
                                       "/componentImageSetInfo";
    auto activeCompImgSetInfoIntf = objServer->add_unique_interface(
        compImgSetPath,
        "xyz.openbmc_project.PLDM.FWU.ActiveComponentImageSetInfo");
    activeCompImgSetInfoIntf->register_property(
        "ActiveComponentImageSetVersionString", activeCompImgSetVerStr);
    activeCompImgSetInfoIntf->initialize();

    auto pendingCompImgSetInfoIntf = objServer->add_unique_interface(
        compImgSetPath,
        "xyz.openbmc_project.PLDM.FWU.PendingComponentImageSetInfo");
    pendingCompImgSetInfoIntf->register_property(
        "PendingComponentImageSetVersionString", pendingCompImgSetVerStr);
    pendingCompImgSetInfoIntf->initialize();

    interfaceList.push_back(std::move(activeCompImgSetInfoIntf));
    interfaceList.push_back(std::move(pendingCompImgSetInfoIntf));
}

void FWInventoryInfo::addFirmwareInventoryToDBus()
{
    std::string inventoryName = getInventoryName();
    inventoryPath = "/xyz/openbmc_project/software/" + inventoryName + "_" +
                    std::to_string(tid);
    std::string activation(
        "xyz.openbmc_project.Software.Activation.Activations.Active");
    auto activationIntf = objServer->add_unique_interface(
        inventoryPath, "xyz.openbmc_project.Software.Activation");
    if (!activationIntf)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Failed to add activation interface");
    }
    else
    {
        activationIntf->register_property("Activation", activation);
        activationIntf->initialize();
        interfaceList.push_back(std::move(activationIntf));
    }
    auto versionIntf = objServer->add_unique_interface(
        inventoryPath, "xyz.openbmc_project.Software.Version");
    if (!versionIntf)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Failed to add version interface");
    }
    else
    {
        versionIntf->register_property("Version", activeCompImgSetVerStr);
        std::string purpose(
            "xyz.openbmc_project.Software.Version.VersionPurpose.PLDM");
        versionIntf->register_property("Purpose", purpose);
        versionIntf->initialize();
        interfaceList.push_back(std::move(versionIntf));
    }
}

std::string FWInventoryInfo::getInventoryName()
{
    if (auto name = utils::getFruProperty(tid, "Name"))
    {
        std::string inventoryName = std::get<std::string>(*name);

        inventoryName.erase(
            std::remove(inventoryName.begin(), inventoryName.end(), ' '),
            inventoryName.end());
        return inventoryName;
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Setting default Inventory Name ");
    return "pldm_fd";
}

void FWInventoryInfo::addInventoryInfoToDBus()
{
    try
    {
        addCompImgSetDataToDBus();
    }
    catch (const std::exception&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to add component image set info to D-Bus",
            phosphor::logging::entry("TID=%d", tid));
    }
    try
    {
        addDescriptorsToDBus();
    }
    catch (const std::exception&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to add descriptor data to D-Bus",
            phosphor::logging::entry("TID=%d", tid));
    }
    try
    {
        addCompDataToDBus();
    }
    catch (const std::exception&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to add component info to D-Bus",
            phosphor::logging::entry("TID=%d", tid));
    }
    addFirmwareInventoryToDBus();
}

void FWInventoryInfo::addCompDataToDBus()
{
    const std::string objPath = "/xyz/openbmc_project/pldm/fwu/" +
                                utils::changeToString(tid) +
                                "/componentImageSetInfo/component_";
    for (auto& itr : compPropertiesMap)
    {
        const std::string compPath = objPath + utils::changeToString(itr.first);
        auto compProps = itr.second;
        auto activeCompInfoIntf = objServer->add_unique_interface(
            compPath, "xyz.openbmc_project.PLDM.FWU.ActiveComponentInfo");
        activeCompInfoIntf->register_property(
            "ComponentClassification",
            std::get<uint16_t>(compProps["ComponentClassification"]));
        activeCompInfoIntf->register_property(
            "ComponentIdentifier",
            std::get<uint16_t>(compProps["ComponentIdentifier"]));
        activeCompInfoIntf->register_property(
            "ComponentClassificationIndex",
            std::get<uint8_t>(compProps["ComponentClassificationIndex"]));
        activeCompInfoIntf->register_property(
            "ActiveComponentComparisonStamp",
            std::get<uint32_t>(compProps["ActiveComponentComparisonStamp"]));
        activeCompInfoIntf->register_property(
            "ActiveComponentReleaseDate",
            std::get<uint64_t>(compProps["ActiveComponentReleaseDate"]));
        activeCompInfoIntf->register_property(
            "ComponentAutoApply",
            getCompAutoApply(
                (std::get<bitfield32_t>(compProps["CapabilitiesDuringUpdate"]))
                    .value));
        std::string activeCompStr =
            std::get<std::string>(compProps["ActiveComponentVersionString"]);
        std::replace_if(
            activeCompStr.begin(), activeCompStr.end(),
            [](const char& c) { return !isprint(c); }, ' ');
        activeCompInfoIntf->register_property("ActiveComponentVersionString",
                                              activeCompStr);
        // TODO expose ComponentActivationMethods and CapabilitiesDuringUpdate
        // to separate interfaces.
        activeCompInfoIntf->register_property(
            "ComponentActivationMethods",
            (std::get<bitfield16_t>(compProps["ComponentActivationMethods"]))
                .value);
        activeCompInfoIntf->register_property(
            "CapabilitiesDuringUpdate",
            (std::get<bitfield32_t>(compProps["CapabilitiesDuringUpdate"]))
                .value);
        activeCompInfoIntf->initialize();

        auto pendingCompInfoIntf = objServer->add_unique_interface(
            compPath, "xyz.openbmc_project.PLDM.FWU.PendingComponentInfo");
        pendingCompInfoIntf->register_property(
            "PendingComponentComparisonStamp",
            std::get<uint32_t>(compProps["PendingComponentComparisonStamp"]));
        pendingCompInfoIntf->register_property(
            "PendingComponentReleaseDate",
            std::get<uint64_t>(compProps["PendingComponentReleaseDate"]));
        std::string pendingCompSrt =
            std::get<std::string>(compProps["PendingComponentVersionString"]);
        std::replace_if(
            pendingCompSrt.begin(), pendingCompSrt.end(),
            [](const char& c) { return !isprint(c); }, ' ');
        pendingCompInfoIntf->register_property("PendingComponentVersionString",
                                               pendingCompSrt);
        pendingCompInfoIntf->initialize();
        interfaceList.push_back(std::move(activeCompInfoIntf));
        interfaceList.push_back(std::move(pendingCompInfoIntf));
    }
}

bool FWInventoryInfo::getCompAutoApply(const uint32_t capabilitiesDuringUpdate)
{
    constexpr size_t capabilitiesDuringUpdateMask = 0xFFFE;
    return capabilitiesDuringUpdate & capabilitiesDuringUpdateMask;
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
    FDProperties fdProperties =
        std::make_tuple(fwuProperties, descriptors, compPropertiesMap);
    return fdProperties;
}
} // namespace fwu
} // namespace pldm
