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

#include "utils.h"

namespace pldm
{
namespace fwu
{
// map that holds the properties of all terminus
std::map<pldm_tid_t, FDProperties> terminusFwuProperties;

const std::array<uint8_t, pkgHeaderIdentifierSize> pkgHdrIdentifier = {
    0xF0, 0x18, 0x87, 0x8C, 0xCB, 0x7D, 0x49, 0x43,
    0x98, 0x00, 0xA0, 0x2F, 0x05, 0x9A, 0xCA, 0x02};

using FWUBase = sdbusplus::xyz::openbmc_project::PLDM::FWU::server::FWUBase;
constexpr size_t PLDMCCOnlyResponse = sizeof(struct PLDMEmptyRequest) + 1;
constexpr size_t hdrSize = sizeof(pldm_msg_hdr);
std::unique_ptr<PLDMImg> pldmImg = nullptr;

void FWUpdate::validateReqForFWUpdCmd(const pldm_tid_t tid,
                                      const uint8_t messageTag,
                                      const bool _tagOwner,
                                      const std::vector<uint8_t>& req)
{
    if (req.size() < hdrSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid FW request");
        return;
    }
    const struct pldm_msg_hdr* msgHdr =
        reinterpret_cast<const pldm_msg_hdr*>(req.data());
    if (tid != currentTid || msgHdr->command != expectedCmd)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Firmware update in progress for TID: " +
             std::to_string(currentTid))
                .c_str());
        return;
    }
    msgTag = messageTag;
    tagOwner = _tagOwner;
    fdReq = req;
    timer.cancel();
    return;
}

void pldmMsgRecvFwUpdCallback(const pldm_tid_t tid, const uint8_t msgTag,
                              const bool tagOwner,
                              std::vector<uint8_t>& message)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "PLDM Firmware update message received",
        phosphor::logging::entry("TID=0x%X", tid));
    // pldmImg points to null if FW update is not in progress at this point
    // firmware device should not send any firmware update commands
    if (!pldmImg)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Firmware update is not in process, command not excepted");
        return;
    }
    pldmImg->fwUpdate->validateReqForFWUpdCmd(tid, msgTag, tagOwner, message);
    return;
}

/** @brief API that deletes PLDM firmware device resorces. This API should be
 * called when PLDM firmware update capable device is removed from the platform.
 */
bool deleteFWDevice(const pldm_tid_t tid)
{
    auto itr = terminusFwuProperties.find(tid);
    if (itr == terminusFwuProperties.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("PLDM firmware update device not matched for TID " +
             std::to_string(tid))
                .c_str());
        return false;
    }
    terminusFwuProperties.erase(itr);
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("PLDM firmware update device resources deleted for TID " +
         std::to_string(tid))
            .c_str());
    return true;
}

template <typename T>
static void processDescriptor(const DescriptorHeader& header, const T& data,
                              DescriptorsMap& descriptorData)

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

static void processDescriptor(const DescriptorHeader& /*header*/,
                              const std::vector<uint8_t>& /*data*/,
                              DescriptorsMap& /*descriptorData*/)
{
    // TODO process non-standard descriptor sizes(Eg: PnP 3 byes) and bigger
    // sizes(Eg: UUID 16 bytes)
}

static void createAsyncDelay(boost::asio::yield_context yield,
                             const uint16_t delay)
{
    boost::asio::steady_timer timer(*getIoContext());
    boost::system::error_code ec;

    timer.expires_after(std::chrono::milliseconds(delay));
    timer.async_wait(yield[ec]);
}

static void unpackDescriptors(const uint8_t count,
                              const std::vector<uint8_t>& data,
                              uint16_t& initialDescriptorType,
                              DescriptorsMap& descriptorData)
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
        if (!found)
        {
            initialDescriptorType = static_cast<uint16_t>(hdr->type);
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

    unpackDescriptors(descriptorCount, descriptorDataVect,
                      initialDescriptorType, descriptors);
    return PLDM_SUCCESS;
}

static std::string toString(const struct variable_field& var)
{
    if (var.ptr == NULL || var.length == 0)
    {
        return "";
    }
    std::string str(reinterpret_cast<const char*>(var.ptr), var.length);
    std::replace_if(
        str.begin(), str.end(), [](const char& c) { return !isprint(c); }, ' ');
    return str;
}

void FWInventoryInfo::copyCompImgSetData(
    const struct get_firmware_parameters_resp& respData,
    const struct variable_field& activeCompImgSetVerData,
    const struct variable_field& pendingCompImgSetVerData)
{
    fwuProperties["CapabilitiesDuringUpdate"] =
        htole32(respData.capabilities_during_update);
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
    unpackCompData(resp.comp_count, compData);

    return PLDM_SUCCESS;
}

FWInventoryInfo::FWInventoryInfo(const pldm_tid_t _tid) :
    tid(_tid), objServer(getObjServer())
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
        "StartFWUpdate",
        [](const boost::asio::yield_context yield, const std::string filePath) {
            int rc = -1;
            if (pldmImg)
            {
                return rc;
            }
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "StartFWUpdate is called");
            try
            {
                pldmImg = std::make_unique<PLDMImg>(filePath);
                if (!pldmImg->processPkgHdr())
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "processPkgHdr: Failed");
                }
                else
                {
                    rc = 0;
                }
            }
            catch (const std::exception&)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to process pldm image",
                    phosphor::logging::entry("PLDM_IMAGE=%s",
                                             filePath.c_str()));
            }
            pldmImg->runPkgUpdate(yield);
            pldmImg = nullptr;
            return rc;
        });
    fwuBaseIface->initialize();
    fwuBaseInitialized = true;
}

void FWInventoryInfo::addPCIDescriptorsToDBus(const std::string& objPath)
{
    auto pciDevIntf = objServer->add_interface(
        objPath, "xyz.openbmc_project.PLDM.FWU.PCIDescriptor");
    for (auto& it : descriptors)
    {
        std::replace_if(
            it.second.begin(), it.second.end(),
            [](const char& c) { return !isprint(c); }, ' ');
        pciDevIntf->register_property(it.first, it.second);
    }
    pciDevIntf->initialize();
}

void FWInventoryInfo::addDescriptorsToDBus()
{
    const std::string objPath = "/xyz/openbmc_project/pldm/fwu/" +
                                std::to_string(tid) + "/deviceDescriptors";

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
                                       std::to_string(tid) +
                                       "/componentImageSetInfo";
    auto activeCompImgSetInfoIntf = objServer->add_interface(
        compImgSetPath,
        "xyz.openbmc_project.PLDM.FWU.ActiveComponentImageSetInfo");
    activeCompImgSetInfoIntf->register_property(
        "ActiveComponentImageSetVersionString", activeCompImgSetVerStr);
    activeCompImgSetInfoIntf->initialize();

    auto pendingCompImgSetInfoIntf = objServer->add_interface(
        compImgSetPath,
        "xyz.openbmc_project.PLDM.FWU.PendingComponentImageSetInfo");
    pendingCompImgSetInfoIntf->register_property(
        "PendingComponentImageSetVersionString", pendingCompImgSetVerStr);
    pendingCompImgSetInfoIntf->initialize();
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
}

void FWInventoryInfo::addCompDataToDBus()
{
    const std::string objPath = "/xyz/openbmc_project/pldm/fwu/" +
                                std::to_string(tid) +
                                "/componentImageSetInfo/component_";
    for (auto& itr : compPropertiesMap)
    {
        const std::string compPath = objPath + std::to_string(itr.first);
        auto compProps = itr.second;
        auto activeCompInfoIntf = objServer->add_interface(
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
            "ComponentAutoApply", getCompAutoApply(std::get<uint32_t>(
                                      compProps["CapabilitiesDuringUpdate"])));
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
            std::get<uint16_t>(compProps["ComponentActivationMethods"]));
        activeCompInfoIntf->register_property(
            "CapabilitiesDuringUpdate",
            std::get<uint32_t>(compProps["CapabilitiesDuringUpdate"]));
        activeCompInfoIntf->initialize();

        auto pendingCompInfoIntf = objServer->add_interface(
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

PLDMImg::PLDMImg(const std::string& pldmImgPath)
{
    pldmImg.open(pldmImgPath, std::ios::in | std::ios::binary | std::ios::ate);
    if (!pldmImg.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to open pldm image");
        throw std::errc::no_such_file_or_directory;
    }
    pldmImg.seekg(0, pldmImg.end);
    pldmImgSize = pldmImg.tellg();
    pldmImg.seekg(0, pldmImg.beg);
}

PLDMImg::~PLDMImg()
{
}

bool PLDMImg::readData(const size_t startAddr, std::vector<uint8_t>& data,
                       const size_t dataLen)
{
    if (startAddr + dataLen > pldmImgSize + PLDM_FWU_BASELINE_TRANSFER_SIZE)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "readData: invalid start address or bytes to read is out of range");
        return false;
    }
    pldmImg.seekg(startAddr, pldmImg.beg);
    if (!pldmImg.good())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "readData: Failed to seek on pldm image.");
        return false;
    }

    pldmImg.read(reinterpret_cast<char*>(&data[0]), dataLen);
    if (!pldmImg.good())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "readData: Failed to read on pldm image.");
        return false;
    }

    return true;
}

uint16_t PLDMImg::getHdrLen()
{
    constexpr size_t pkgHdroffSet = 17;
    pldmImg.seekg(pkgHdroffSet, pldmImg.beg);
    if (!pldmImg.good())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getHdrLen: Failed to seek on pldm image.");

        return 0;
    }
    pldmImg.read(reinterpret_cast<char*>(&pkgHdrLen), sizeof(pkgHdrLen));
    if (!pldmImg.good())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getHdrLen: Failed to read on pldm image.");
        return 0;
    }
    return htole16(pkgHdrLen);
}

bool PLDMImg::matchPkgHdrIdentifier(const uint8_t* packageHeaderIdentifier)
{
    if (!packageHeaderIdentifier)
    {
        return false;
    }

    if (std::memcmp(packageHeaderIdentifier, pkgHdrIdentifier.data(),
                    pkgHdrIdentifier.size()))
    {
        return false;
    }
    // TODO: return version number from this api.
    return true;
}

inline bool PLDMImg::validateHdrDataLen(const size_t bytesLeft,
                                        const size_t nextDataSize)
{
    return !(bytesLeft < nextDataSize);
}

bool PLDMImg::advanceHdrItr(const size_t dataSize, const size_t nextDataSize)
{
    std::advance(hdrItr, dataSize);
    size_t bytesLeft = std::distance(hdrItr, std::end(hdrData));
    return validateHdrDataLen(bytesLeft, nextDataSize);
}

void PLDMImg::copyPkgHdrInfoToMap(const struct PLDMPkgHeaderInfo* headerInfo,
                                  const std::string& pkgVersionString)
{
    pkgFWUProperties["PkgHeaderFormatRevision"] =
        headerInfo->pkgHeaderFormatRevision;
    pkgFWUProperties["PkgHeaderSize"] = htole16(headerInfo->pkgHeaderSize);
    compBitmapBitLength = htole16(headerInfo->compBitmapBitLength);
    pkgFWUProperties["CompBitmapBitLength"] = compBitmapBitLength;
    pkgFWUProperties["PkgVersionStringType"] = headerInfo->pkgVersionStringType;
    pkgFWUProperties["PkgVersionStringLen"] = headerInfo->pkgVersionStringLen;
    pkgFWUProperties["PkgVersionString"] = pkgVersionString;
}

bool PLDMImg::processPkgHdrInfo()
{
    hdrItr = std::begin(hdrData);
    if (hdrItr == std::end(hdrData))
    {
        return false;
    }
    size_t bytesLeft = std::distance(hdrItr, std::end(hdrData));
    if (bytesLeft < sizeof(PLDMPkgHeaderInfo))
    {
        return false;
    }
    PLDMPkgHeaderInfo* headerInfo =
        reinterpret_cast<PLDMPkgHeaderInfo*>(&*hdrItr);

    if (!matchPkgHdrIdentifier(headerInfo->packageHeaderIdentifier))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "packageHeaderIdentifier not matched");
        return false;
    }

    if (!advanceHdrItr(sizeof(PLDMPkgHeaderInfo),
                       static_cast<size_t>(headerInfo->pkgVersionStringLen)))
    {
        return false;
    }
    pkgVersionStringLen = headerInfo->pkgVersionStringLen;
    std::string pkgVersionString(hdrItr,
                                 hdrItr + headerInfo->pkgVersionStringLen);
    copyPkgHdrInfoToMap(headerInfo, pkgVersionString);
    return true;
}

static bool updateMode = false;
int PLDMImg::runPkgUpdate(const boost::asio::yield_context& yield)
{
    for (const auto& it : matchedTermini)
    {
        pldm_tid_t matchedTid = it.second;
        uint8_t matchedDevIdRecord = it.first;
        fwUpdate = std::make_unique<FWUpdate>(matchedTid, matchedDevIdRecord);
        if (!fwUpdate->setMatchedFDDescriptors())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("runPkgUpdate: Failed to set TargetFDProperties for "
                 "TID: " +
                 std::to_string(matchedTid))
                    .c_str());
            continue;
        }
        if (fwUpdate->runUpdate(yield) != PLDM_SUCCESS)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("runUpdate failed for TID: " + std::to_string(matchedTid))
                    .c_str());
            updateMode = false;
            // TODO call cancelUpdate command
        }
    }
    return PLDM_SUCCESS;
}

bool PLDMImg::verifyPkgHdrChecksum()
{
    constexpr size_t pkgHdrChecksumSize = 4;
    uint32_t pkgHdrChecksum = 0;
    std::vector<uint8_t> checksum(pkgHdrChecksumSize);

    if (!readData(pkgHdrLen - pkgHdrChecksumSize, checksum, pkgHdrChecksumSize))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "failed to read pkgHdrChecksum");
        return false;
    }
    pkgHdrChecksum = *reinterpret_cast<uint32_t*>(checksum.data());

    if (pkgHdrChecksum !=
        crc32(hdrData.data(), hdrData.size() - pkgHdrChecksumSize))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "verifyPkgHdrChecksum: checksum not macthed");
        return false;
    }
    return true;
}

bool PLDMImg::processPkgHdr()
{
    constexpr size_t minPkgHeaderLen =
        sizeof(PLDMPkgHeaderInfo) + sizeof(FWDevIdRecord) + sizeof(CompImgInfo);
    pkgHdrLen = getHdrLen();
    assert(pkgHdrLen != minPkgHeaderLen);
    hdrData.resize(pkgHdrLen);

    if (!readData(0, hdrData, pkgHdrLen))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("read failed ");
        return false;
    }

    if (!verifyPkgHdrChecksum())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "verifyPkgHdrChecksum: Failed");
        return false;
    }

    if (!processPkgHdrInfo())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "processPkgHdrInfo: Failed");
        return false;
    }

    if (!processDevIdentificationInfo())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "processDevIdentificationInfo: Failed");
        return false;
    }
    if (!processCompImgInfo())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "processCompImgInfo: Failed");
        return false;
    }
    return true;
}

bool PLDMImg::processCompImgInfo()
{
    uint16_t compCount = 0;
    uint16_t found = 0;

    if (!advanceHdrItr(0, sizeof(compCount)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "no bytes left for deviceIDRecordCount");
        return false;
    }
    compCount = *reinterpret_cast<const uint16_t*>(&*hdrItr);
    std::advance(hdrItr, sizeof(compCount));

    while (hdrItr < std::end(hdrData) && found != compCount)
    {
        size_t bytesLeft = std::distance(hdrItr, std::end(hdrData));
        if (bytesLeft <= sizeof(CompImgInfo))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "no bytes left for CompImgInfo");
            break;
        }
        const auto compInfo = reinterpret_cast<const CompImgInfo*>(&*hdrItr);

        if (!advanceHdrItr(sizeof(CompImgInfo), compInfo->compVerStrLen))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "no bytes left for compVerStr");
            break;
        }
        std::string compVerStr(hdrItr, hdrItr + compInfo->compVerStrLen);
        std::advance(hdrItr, compInfo->compVerStrLen);
        copyCompImgInfoToMap(found, compInfo, compVerStr);
        found++;
    }
    if (found != compCount)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Component count not matched",
            phosphor::logging::entry("ACTUAL_COMP_COUNT=%d", found),
            phosphor::logging::entry("EXPECTED_COMP_COUNT=%d", compCount));
        return false;
    }

    return true;
}

bool PLDMImg::findMatchedTerminus(const uint8_t devIdRecord,
                                  const DescriptorsMap& pkgDescriptors)
{
    for (auto const& it : terminusFwuProperties)
    {
        DescriptorsMap fdDescriptors;
        try
        {
            fdDescriptors = std::get<DescriptorsMap>(it.second);
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("findMatchedTerminus: Failed to get DescriptorsMap for "
                 "devIdRecord: " +
                 std::to_string(devIdRecord))
                    .c_str());
            return false;
        }
        if (pkgDescriptors.size() == fdDescriptors.size() &&
            pkgDescriptors == fdDescriptors)
        {
            matchedTermini.emplace_back(std::make_pair(devIdRecord, it.first));
        }
    }
    return !matchedTermini.empty();
}

bool PLDMImg::processDevIdentificationInfo()
{
    uint8_t deviceIDRecordCount = 0;
    if (!advanceHdrItr(pkgVersionStringLen, sizeof(deviceIDRecordCount)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "no bytes left for deviceIDRecordCount");
        return false;
    }

    deviceIDRecordCount = *hdrItr;
    uint8_t foundDescriptorCount = 0;
    constexpr size_t compBitmapBitLengthMultiplier = 8;
    std::advance(hdrItr, sizeof(deviceIDRecordCount));

    while (hdrItr < std::end(hdrData) &&
           foundDescriptorCount < deviceIDRecordCount)
    {
        ssize_t bytesLeft = std::distance(hdrItr, std::end(hdrData));
        if (bytesLeft < static_cast<ssize_t>(sizeof(FWDevIdRecord)))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "no bytes left for FWDevIdRecord");
            break;
        }
        FWDevIdRecord* devIdentificationInfo =
            reinterpret_cast<FWDevIdRecord*>(&*hdrItr);
        size_t applicableComponentsLen =
            compBitmapBitLength / compBitmapBitLengthMultiplier;
        if (!advanceHdrItr(sizeof(FWDevIdRecord), applicableComponentsLen))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "no bytes left for applicableComponentsLen");
            break;
        }

        std::vector<uint8_t> applicableComponents(
            hdrItr, hdrItr + applicableComponentsLen);

        if (!advanceHdrItr(applicableComponentsLen,
                           devIdentificationInfo->comImgSetVerStrLen))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "no bytes left for comImgSetVerStr");
            break;
        }
        std::string compImgSetVerStr(
            hdrItr, hdrItr + devIdentificationInfo->comImgSetVerStrLen);
        size_t descriptorDataLen = getDescriptorDataLen(
            *devIdentificationInfo, applicableComponentsLen);

        if (!advanceHdrItr(compImgSetVerStr.size(), descriptorDataLen))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "no bytes left for descriptorData");
            break;
        }
        std::vector<uint8_t> descriptorData(hdrItr, hdrItr + descriptorDataLen);
        uint16_t initialDescriptorType;
        DescriptorsMap pkgDescriptorRecords;
        unpackDescriptors(devIdentificationInfo->descriptorCount,
                          descriptorData, initialDescriptorType,
                          pkgDescriptorRecords);
        if (!findMatchedTerminus(foundDescriptorCount, pkgDescriptorRecords))
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "processDevIdentificationInfo: descriptors not matched",
                phosphor::logging::entry("DESCRIPTOR=%d",
                                         foundDescriptorCount));
        }
        fwDevPkgDataLen = htole16(devIdentificationInfo->fwDevPkgDataLen);

        if (!advanceHdrItr(descriptorData.size(), fwDevPkgDataLen))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "no bytes left for fwDevPkgData");
            break;
        }
        std::vector<uint8_t> fwDevPkgData(hdrItr, hdrItr + fwDevPkgDataLen);
        std::advance(hdrItr, fwDevPkgDataLen);
        copyDevIdentificationInfoToMap(
            foundDescriptorCount, initialDescriptorType, devIdentificationInfo,
            applicableComponents, compImgSetVerStr, fwDevPkgData,
            pkgDescriptorRecords);
        foundDescriptorCount++;
    }
    if (foundDescriptorCount != deviceIDRecordCount)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Descriptor count not matched",
            phosphor::logging::entry("ACTUAL_DEV_ID_RECORD_COUNT=%d",
                                     foundDescriptorCount),
            phosphor::logging::entry("EXPECTED_DEV_ID_RECORD_COUNT=%d",
                                     deviceIDRecordCount));
        return false;
    }
    if (!matchedTermini.size())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Descriptors not matched with descriptors in device ID records");
        return false;
    }
    return true;
}

void PLDMImg::copyDevIdentificationInfoToMap(
    const uint8_t deviceIDRecord, const uint16_t initialDescriptorType,
    const FWDevIdRecord* devIdentificationInfo,
    const std::vector<uint8_t>& applicableComponents,
    const std::string& compImgSetVerStr,
    const std::vector<uint8_t>& fwDevPkgData,
    DescriptorsMap& pkgDescriptorRecords)
{
    FWUProperties devIdentificationProps;
    devIdentificationProps["InitialDescriptorType"] = initialDescriptorType;
    devIdentificationProps["DeviceIDRecordCount"] = deviceIDRecord;
    devIdentificationProps["RecordLength"] =
        htole16(devIdentificationInfo->recordLength);
    devIdentificationProps["DescriptorCount"] =
        devIdentificationInfo->descriptorCount;
    devIdentificationProps["DeviceUpdateOptionFlags"] =
        htole32(devIdentificationInfo->deviceUpdateOptionFlags);
    devIdentificationProps["ComImgSetVerStrType"] =
        devIdentificationInfo->comImgSetVerStrType;
    devIdentificationProps["ComImgSetVerStrLen"] =
        devIdentificationInfo->comImgSetVerStrLen;
    devIdentificationProps["FWDevPkgDataLen"] =
        htole16(devIdentificationInfo->fwDevPkgDataLen);
    devIdentificationProps["ApplicableComponents"] = applicableComponents;
    devIdentificationProps["CompImgSetVerStr"] = compImgSetVerStr;
    devIdentificationProps["FirmwareDevicePackageData"] = fwDevPkgData;
    pkgDevIDRecords[deviceIDRecord] =
        std::make_pair(devIdentificationProps, pkgDescriptorRecords);
}
void PLDMImg::copyCompImgInfoToMap(const uint16_t count,
                                   const CompImgInfo* compInfo,
                                   const std::string& compVerStr)
{
    std::map<std::string, FWUVariantType> properties;
    properties["CompClassification"] = htole16(compInfo->compClassification);
    properties["CompIdentifier"] = htole16(compInfo->compIdentifier);
    properties["CompComparisonStamp"] = htole32(compInfo->compComparisonStamp);
    properties["CompOptions"] = htole16(compInfo->compOptions);
    properties["RequestedCompActivationMethod"] =
        htole16(compInfo->requestedCompActivationMethod);
    properties["CompLocationOffset"] = htole32(compInfo->compLocationOffset);
    properties["CompSize"] = htole32(compInfo->compSize);
    properties["CmpVerStrType"] = compInfo->compVerStrType;
    properties["CompVerStrLen"] = compInfo->compVerStrLen;
    properties["CompVerStr"] = compVerStr;
    pkgCompProperties[count] = properties;
}
size_t PLDMImg::getDescriptorDataLen(const FWDevIdRecord& data,
                                     const size_t applicableComponentsLen)
{
    return (htole16(data.recordLength) - sizeof(FWDevIdRecord) -
            applicableComponentsLen - data.comImgSetVerStrLen -
            htole16(data.fwDevPkgDataLen));
}

FWUpdate::FWUpdate(const pldm_tid_t _tid, const uint8_t _deviceIDRecord) :
    currentTid(_tid), deviceIDRecord(_deviceIDRecord), state(FD_IDLE),
    timer(*getIoContext())
{
}

FWUpdate::~FWUpdate()
{
}

bool FWUpdate::setMatchedFDDescriptors()
{
    auto itr = terminusFwuProperties.find(currentTid);
    if (itr == terminusFwuProperties.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("setMatchedFDDescriptors: targetFDProperties not found for "
             "TID: " +
             std::to_string(currentTid))
                .c_str());
        return false;
    }
    targetFDProperties = itr->second;
    return true;
}

template <typename T>
bool PLDMImg::getPkgProperty(T& value, const std::string& name)
{
    auto it = pkgFWUProperties.find(name);
    if (it != pkgFWUProperties.end())
    {
        if (auto itr = std::get_if<T>(&it->second))
        {
            value = *itr;
            return true;
        }
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
        ("getPkgProperty: Failed to property " + name).c_str());
    return false;
}

bool FWUpdate::sendErrorCompletionCode(const uint8_t fdInstanceId,
                                       const uint8_t complCode,
                                       const uint8_t command)
{

    std::vector<uint8_t> pldmResp(PLDMCCOnlyResponse);
    struct pldm_msg* msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    int retVal = encode_cc_only_resp(fdInstanceId, PLDM_FWU, command, complCode,
                                     msgResp);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "sendError: encode response failed",
            phosphor::logging::entry("TID=%d", currentTid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        return false;
    }
    if (!sendPldmMessage(currentTid, msgTag, tagOwner, pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "sendError: Failed to send PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return false;
    }
    return true;
}

int FWUpdate::doRequestUpdate(const boost::asio::yield_context& yield,
                              struct variable_field& compImgSetVerStrn)
{
    if (updateMode)
    {
        return ALREADY_IN_UPDATE_MODE;
    }
    if (fdState != FD_IDLE)
    {
        return NOT_IN_UPDATE_MODE;
    }
    int retVal = requestUpdate(yield, compImgSetVerStrn);
    if (retVal != PLDM_SUCCESS)
    {
        return retVal;
    }
    updateMode = true;
    fdState = FD_LEARN_COMPONENTS;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "FD changed state to LEARN COMPONENTS");
    return PLDM_SUCCESS;
}

int FWUpdate::requestUpdate(const boost::asio::yield_context& yield,
                            struct variable_field& compImgSetVerStrn)
{

    uint8_t instanceID = createInstanceId(currentTid);
    std::vector<uint8_t> pldmReq(sizeof(struct PLDMEmptyRequest) +
                                 sizeof(struct request_update_req) +
                                 compImgSetVerStrn.length);
    struct pldm_msg* msgReq = reinterpret_cast<pldm_msg*>(pldmReq.data());

    int retVal = encode_request_update_req(
        instanceID, msgReq,
        sizeof(struct request_update_req) + compImgSetVerStrn.length,
        &updateProperties, &compImgSetVerStrn);
    if (!validatePLDMReqEncode(currentTid, retVal, "RequestUpdate"))
    {
        return retVal;
    }
    std::vector<uint8_t> pldmResp;
    size_t count = 0;
    do
    {
        if (retVal == RETRY_REQUEST_UPDATE)
        {
            createAsyncDelay(yield, retryRequestForUpdateDelay);
        }
        if (!sendReceivePldmMessage(yield, currentTid, timeout, retryCount,
                                    pldmReq, pldmResp))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "requestUpdate: Failed to send or receive PLDM message",
                phosphor::logging::entry("TID=%d", currentTid));
            return PLDM_ERROR;
        }
        auto msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
        retVal = decode_request_update_resp(
            msgResp, pldmResp.size() - hdrSize, &completionCode,
            &fwDeviceMetaDataLen, &fdWillSendGetPkgDataCmd);
    } while ((retVal == RETRY_REQUEST_UPDATE) && (++count < retryCount));
    if (retVal == RETRY_REQUEST_UPDATE)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "requestUpdate: FD is not able to enter update mode immediately, "
            "requests for retry",
            phosphor::logging::entry("TID=%d", currentTid),
            phosphor::logging::entry("RETRY_COUNT=%d", ++count));
        return retVal;
    }
    if (!validatePLDMRespDecode(currentTid, retVal, completionCode,
                                "RequestUpdate"))
    {
        return retVal;
    }
    return PLDM_SUCCESS;
}

int FWUpdate::doGetDeviceMetaData(const boost::asio::yield_context& yield,
                                  const uint32_t dataTransferHandle,
                                  const uint8_t transferOperationFlag,
                                  uint32_t& nextDataTransferHandle,
                                  uint8_t& transferFlag,
                                  std::vector<uint8_t>& portionOfMetaData)
{

    if (!updateMode)
    {
        return NOT_IN_UPDATE_MODE;
    }
    if (fdState != FD_LEARN_COMPONENTS)
    {
        return COMMAND_NOT_EXPECTED;
    }
    int retVal = getDeviceMetaData(
        yield, dataTransferHandle, transferOperationFlag,
        nextDataTransferHandle, transferFlag, portionOfMetaData);
    if (retVal != PLDM_SUCCESS)
    {
        return retVal;
    }
    return PLDM_SUCCESS;
}

int FWUpdate::getDeviceMetaData(const boost::asio::yield_context& yield,
                                const uint32_t dataTransferHandle,
                                const uint8_t transferOperationFlag,
                                uint32_t& nextDataTransferHandle,
                                uint8_t& transferFlag,
                                std::vector<uint8_t>& portionOfMetaData)
{

    uint8_t instanceID = createInstanceId(currentTid);
    std::vector<uint8_t> pldmReq(sizeof(struct PLDMEmptyRequest) +
                                 sizeof(struct get_device_meta_data_req));
    struct pldm_msg* msgReq = reinterpret_cast<pldm_msg*>(pldmReq.data());

    int retVal = encode_get_device_meta_data_req(
        instanceID, msgReq, sizeof(struct get_device_meta_data_req),
        dataTransferHandle, transferOperationFlag);
    if (!validatePLDMReqEncode(currentTid, retVal, "GetDeviceMetaData"))
    {
        return retVal;
    }
    std::vector<uint8_t> pldmResp;
    if (!sendReceivePldmMessage(yield, currentTid, timeout, retryCount, pldmReq,
                                pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetDeviceMetaData: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return PLDM_ERROR;
    }
    struct variable_field metaData = {};
    auto msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    retVal = decode_get_device_meta_data_resp(
        msgResp, pldmResp.size() - hdrSize, &completionCode,
        &nextDataTransferHandle, &transferFlag, &metaData);
    if (!validatePLDMRespDecode(currentTid, retVal, completionCode,
                                "GetDeviceMetaData"))
    {
        return retVal;
    }
    portionOfMetaData.assign(metaData.ptr, metaData.ptr + metaData.length);
    return PLDM_SUCCESS;
}

int FWUpdate::doPassComponentTable(
    const boost::asio::yield_context& yield,
    const struct pass_component_table_req& componentTable,
    struct variable_field& compImgSetVerStr, uint8_t& compResp,
    uint8_t& compRespCode)
{
    if (!updateMode)
    {
        return NOT_IN_UPDATE_MODE;
    }
    if (fdState != FD_LEARN_COMPONENTS)
    {
        return COMMAND_NOT_EXPECTED;
    }
    int retVal = passComponentTable(yield, componentTable, compImgSetVerStr,
                                    compResp, compRespCode);
    if (retVal != PLDM_SUCCESS)
    {
        return retVal;
    }
    if (componentTable.transfer_flag == PLDM_END ||
        componentTable.transfer_flag == PLDM_START_AND_END)
    {
        fdState = FD_READY_XFER;
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "FD changed state to READY XFER");
    }
    return PLDM_SUCCESS;
}

int FWUpdate::passComponentTable(
    const boost::asio::yield_context& yield,
    const struct pass_component_table_req& componentTable,
    struct variable_field& compImgSetVerStr, uint8_t& compResp,
    uint8_t& compRespCode)
{

    uint8_t instanceID = createInstanceId(currentTid);
    std::vector<uint8_t> pldmReq(sizeof(struct PLDMEmptyRequest) +
                                 sizeof(struct pass_component_table_req) +
                                 compImgSetVerStr.length);
    struct pldm_msg* msgReq = reinterpret_cast<pldm_msg*>(pldmReq.data());

    int retVal = encode_pass_component_table_req(
        instanceID, msgReq,
        sizeof(struct pass_component_table_req) + compImgSetVerStr.length,
        &componentTable, &compImgSetVerStr);
    if (!validatePLDMReqEncode(currentTid, retVal,
                               std::string("PassComponentTable")))
    {
        return retVal;
    }
    std::vector<uint8_t> pldmResp;
    if (!sendReceivePldmMessage(yield, currentTid, timeout, retryCount, pldmReq,
                                pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "passComponentTable: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return PLDM_ERROR;
    }
    auto msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    retVal = decode_pass_component_table_resp(
        msgResp, pldmResp.size() - hdrSize, &completionCode, &compResp,
        &compRespCode);
    if (!validatePLDMRespDecode(currentTid, retVal, completionCode,
                                std::string("PassComponentTable")))
    {
        return retVal;
    }

    return PLDM_SUCCESS;
}

int FWUpdate::doUpdateComponent(const boost::asio::yield_context& yield,
                                const struct update_component_req& component,
                                variable_field& compVerStr,
                                uint8_t& compCompatabilityResp,
                                uint8_t& compCompatabilityRespCode,
                                bitfield32_t& updateOptFlagsEnabled,
                                uint16_t& estimatedTimeReqFd)
{
    if (!updateMode)
    {
        return NOT_IN_UPDATE_MODE;
    }
    if (fdState != FD_READY_XFER)
    {
        return COMMAND_NOT_EXPECTED;
    }
    int retVal = updateComponent(
        yield, component, compVerStr, compCompatabilityResp,
        compCompatabilityRespCode, updateOptFlagsEnabled, estimatedTimeReqFd);
    if (retVal != PLDM_SUCCESS)
    {
        return retVal;
    }
    fdState = FD_DOWNLOAD;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "FD changed state to DOWNLOAD");
    return PLDM_SUCCESS;
}

int FWUpdate::updateComponent(const boost::asio::yield_context& yield,
                              const struct update_component_req& component,
                              variable_field& compVerStr,
                              uint8_t& compCompatabilityResp,
                              uint8_t& compCompatabilityRespCode,
                              bitfield32_t& updateOptFlagsEnabled,
                              uint16_t& estimatedTimeReqFd)
{

    uint8_t instanceID = createInstanceId(currentTid);
    std::vector<uint8_t> pldmReq(sizeof(struct PLDMEmptyRequest) +
                                 sizeof(struct update_component_req) +
                                 compVerStr.length);
    struct pldm_msg* msgReq = reinterpret_cast<pldm_msg*>(pldmReq.data());

    int retVal = encode_update_component_req(
        instanceID, msgReq,
        sizeof(struct update_component_req) + compVerStr.length, &component,
        &compVerStr);
    if (!validatePLDMReqEncode(currentTid, retVal, "UpdateComponent"))
    {
        return retVal;
    }
    std::vector<uint8_t> pldmResp;
    if (!sendReceivePldmMessage(yield, currentTid, timeout, retryCount, pldmReq,
                                pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "updateComponent: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return PLDM_ERROR;
    }
    auto msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    retVal = decode_update_component_resp(
        msgResp, pldmResp.size() - hdrSize, &completionCode,
        &compCompatabilityResp, &compCompatabilityRespCode,
        &updateOptFlagsEnabled, &estimatedTimeReqFd);
    if (!validatePLDMRespDecode(currentTid, retVal, completionCode,
                                "UpdateComponent"))
    {
        return retVal;
    }

    return PLDM_SUCCESS;
}

uint8_t FWUpdate::validateTransferComplete(const uint8_t transferResult)
{
    return (transferResult == PLDM_FWU_TRASFER_SUCCESS)
               ? PLDM_SUCCESS
               : PLDM_ERROR_INVALID_DATA;
}

int FWUpdate::processTransferComplete(const std::vector<uint8_t>& pldmReq,
                                      uint8_t& transferResult)
{
    if (!updateMode || fdState != FD_DOWNLOAD)
    {
        const struct pldm_msg* msgReq =
            reinterpret_cast<const pldm_msg*>(pldmReq.data());
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     COMMAND_NOT_EXPECTED,
                                     PLDM_TRANSFER_COMPLETE))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "TransferComplete: Failed to send PLDM message",
                phosphor::logging::entry("TID=%d", currentTid));
        }
        return COMMAND_NOT_EXPECTED;
    }
    int retVal = transferComplete(pldmReq, transferResult);
    if (retVal != PLDM_SUCCESS)
    {
        return retVal;
    }
    fdState = FD_VERIFY;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "FD changed state to VERIFY");
    return PLDM_SUCCESS;
}

int FWUpdate::transferComplete(const std::vector<uint8_t>& pldmReq,
                               uint8_t& transferResult)
{
    const struct pldm_msg* msgReq =
        reinterpret_cast<const pldm_msg*>(pldmReq.data());
    auto retVal = decode_transfer_complete_req(msgReq, &transferResult);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "TransferComplete: decode request failed",
            phosphor::logging::entry("TID=%d", currentTid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     static_cast<uint8_t>(retVal),
                                     PLDM_TRANSFER_COMPLETE))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "TransferComplete: Failed to send PLDM message",
                phosphor::logging::entry("TID=%d", currentTid));
        }
        return retVal;
    }
    std::vector<uint8_t> pldmResp(PLDMCCOnlyResponse);
    struct pldm_msg* msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    uint8_t compCode = validateTransferComplete(transferResult);
    retVal = encode_transfer_complete_resp(msgReq->hdr.instance_id, compCode,
                                           msgResp);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "TransferComplete: encode response failed",
            phosphor::logging::entry("TID=%d", currentTid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        return retVal;
    }
    if (!sendPldmMessage(currentTid, msgTag, tagOwner, pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "TransferComplete: Failed to send PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return PLDM_ERROR;
    }
    return PLDM_SUCCESS;
}

uint8_t FWUpdate::validateVerifyComplete(const uint8_t verifyResult)
{
    return (verifyResult == PLDM_FWU_VERIFY_SUCCESS) ? PLDM_SUCCESS
                                                     : PLDM_ERROR_INVALID_DATA;
}

int FWUpdate::processVerifyComplete(const std::vector<uint8_t>& pldmReq,
                                    uint8_t& verifyResult)
{
    if (!updateMode || fdState != FD_VERIFY)
    {
        auto msgReq = reinterpret_cast<const pldm_msg*>(pldmReq.data());
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     COMMAND_NOT_EXPECTED,
                                     PLDM_VERIFY_COMPLETE))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "VerifyComplete: Failed to send PLDM message",
                phosphor::logging::entry("TID=%d", currentTid));
        }
        return COMMAND_NOT_EXPECTED;
    }
    int retVal = verifyComplete(pldmReq, verifyResult);
    if (retVal != PLDM_SUCCESS)
    {
        return retVal;
    }
    fdState = FD_APPLY;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "FD changed state to APPLY");
    return PLDM_SUCCESS;
}

int FWUpdate::verifyComplete(const std::vector<uint8_t>& pldmReq,
                             uint8_t& verifyResult)
{

    auto msgReq = reinterpret_cast<const pldm_msg*>(pldmReq.data());
    int retVal = decode_verify_complete_req(msgReq, &verifyResult);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "VerifyComplete: decode request failed",
            phosphor::logging::entry("TID=%d", currentTid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     static_cast<uint8_t>(retVal),
                                     PLDM_VERIFY_COMPLETE))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "VerifyComplete: Failed to send PLDM message",
                phosphor::logging::entry("TID=%d", currentTid));
        }
        return retVal;
    }
    std::vector<uint8_t> pldmResp(PLDMCCOnlyResponse);
    struct pldm_msg* msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    uint8_t compCode = validateVerifyComplete(verifyResult);
    retVal = encode_transfer_complete_resp(msgReq->hdr.instance_id, compCode,
                                           msgResp);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "VerifyComplete: encode response failed",
            phosphor::logging::entry("TID=%d", currentTid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        return retVal;
    }
    if (!sendPldmMessage(currentTid, msgTag, tagOwner, pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "VerifyComplete: Failed to send PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return PLDM_ERROR;
    }
    return PLDM_SUCCESS;
}

int FWUpdate::doActivateFirmware(
    const boost::asio::yield_context& yield, bool8_t selfContainedActivationReq,
    uint16_t& estimatedTimeForSelfContainedActivation)
{
    if (!updateMode)
    {
        return NOT_IN_UPDATE_MODE;
    }
    if (fdState != FD_READY_XFER)
    {
        return COMMAND_NOT_EXPECTED;
    }
    int retVal = activateFirmware(yield, selfContainedActivationReq,
                                  estimatedTimeForSelfContainedActivation);
    if (retVal != PLDM_SUCCESS)
    {
        return retVal;
    }
    fdState = FD_ACTIVATE;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "FD changed state to ACTIVATE");
    return PLDM_SUCCESS;
}

int FWUpdate::activateFirmware(
    const boost::asio::yield_context& yield, bool8_t selfContainedActivationReq,
    uint16_t& estimatedTimeForSelfContainedActivation)
{

    uint8_t instanceID = createInstanceId(currentTid);
    std::vector<uint8_t> pldmReq(sizeof(struct PLDMEmptyRequest) +
                                 sizeof(struct activate_firmware_req));
    struct pldm_msg* msgReq = reinterpret_cast<pldm_msg*>(pldmReq.data());
    int retVal = encode_activate_firmware_req(
        instanceID, msgReq, sizeof(struct activate_firmware_req),
        selfContainedActivationReq);

    if (!validatePLDMReqEncode(currentTid, retVal, "ActivateFirmware"))
    {
        return retVal;
    }
    std::vector<uint8_t> pldmResp;
    if (!sendReceivePldmMessage(yield, currentTid, timeout, retryCount, pldmReq,
                                pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ActivateFirmware: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return PLDM_ERROR;
    }
    auto msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    size_t payloadLen = pldmResp.size() - hdrSize;
    retVal =
        decode_activate_firmware_resp(msgResp, payloadLen, &completionCode,
                                      &estimatedTimeForSelfContainedActivation);

    if (!validatePLDMRespDecode(currentTid, retVal, completionCode,
                                "ActivateFirmware"))
    {
        return retVal;
    }
    return PLDM_SUCCESS;
}

int FWUpdate::getStatus(const boost::asio::yield_context& yield)
{
    uint8_t instanceID = createInstanceId(currentTid);
    std::vector<uint8_t> pldmReq(sizeof(struct PLDMEmptyRequest));
    struct pldm_msg* msgReq = reinterpret_cast<pldm_msg*>(pldmReq.data());
    int retVal = encode_get_status_req(instanceID, msgReq);
    if (!validatePLDMReqEncode(currentTid, retVal, std::string("GetStatus")))
    {
        return retVal;
    }
    std::vector<uint8_t> pldmResp;
    if (!sendReceivePldmMessage(yield, currentTid, timeout, retryCount, pldmReq,
                                pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GetStatus: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return PLDM_ERROR;
    }
    auto msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    size_t payloadLen = pldmResp.size() - hdrSize;
    retVal = decode_get_status_resp(msgResp, payloadLen, &completionCode,
                                    &currentState, &previousState, &auxState,
                                    &auxStateStatus, &progressPercent,
                                    &reasonCode, &updateOptionFlagsEnabled);
    // TODO: need to add the GetStatus response data to D-Bus interface
    if (!validatePLDMRespDecode(currentTid, retVal, completionCode,
                                std::string("GetStatus")))
    {
        return retVal;
    }

    return PLDM_SUCCESS;
}

int FWUpdate::doCancelUpdateComponent(const boost::asio::yield_context& yield)
{
    if (!updateMode)
    {
        return NOT_IN_UPDATE_MODE;
    }
    if (!cancelUpdateComponentState.count(fdState))
    {
        return COMMAND_NOT_EXPECTED;
    }
    int retVal = cancelUpdateComponent(yield);
    if (retVal != PLDM_SUCCESS)
    {
        return retVal;
    }

    fdState = FD_READY_XFER;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "FD changed state to READY XFER");
    return PLDM_SUCCESS;
}

int FWUpdate::cancelUpdateComponent(const boost::asio::yield_context& yield)
{

    uint8_t instanceID = createInstanceId(currentTid);
    std::vector<uint8_t> pldmReq(sizeof(struct PLDMEmptyRequest));
    struct pldm_msg* msgReq = reinterpret_cast<pldm_msg*>(pldmReq.data());
    int retVal = encode_cancel_update_component_req(instanceID, msgReq);
    if (!validatePLDMReqEncode(currentTid, retVal, "CancelUpdateComponent"))
    {
        return retVal;
    }
    std::vector<uint8_t> pldmResp;
    if (!sendReceivePldmMessage(yield, currentTid, timeout, retryCount, pldmReq,
                                pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "CancelUpdateComponent: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return PLDM_ERROR;
    }
    auto msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    size_t payloadLen = pldmResp.size() - hdrSize;
    retVal = decode_cancel_update_component_resp(msgResp, payloadLen,
                                                 &completionCode);
    if (!validatePLDMRespDecode(currentTid, retVal, completionCode,
                                "CancelUpdateComponent"))
    {
        return retVal;
    }
    return PLDM_SUCCESS;
}

int FWUpdate::doCancelUpdate(const boost ::asio ::yield_context& yield,
                             bool8_t& nonFunctioningComponentIndication,
                             bitfield64_t& nonFunctioningComponentBitmap)
{
    if (!updateMode)
    {
        return PLDM_ERROR;
    }
    if ((fdState == FD_IDLE) || (fdState == FD_ACTIVATE))
    {
        return COMMAND_NOT_EXPECTED;
    }
    // TODO:Need to provide D-Bus interface to invoke cancelUpdate
    int retVal = cancelUpdate(yield, nonFunctioningComponentIndication,
                              nonFunctioningComponentBitmap);
    if (retVal != PLDM_SUCCESS)
    {
        return retVal;
    }
    fdState = FD_IDLE;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "FD changed state to IDLE");
    return PLDM_SUCCESS;
}

int FWUpdate::cancelUpdate(const boost::asio::yield_context& yield,
                           bool8_t& nonFunctioningComponentIndication,
                           bitfield64_t& nonFunctioningComponentBitmap)

{

    uint8_t instanceID = createInstanceId(currentTid);
    std::vector<uint8_t> pldmReq(sizeof(struct PLDMEmptyRequest));
    struct pldm_msg* msgReq = reinterpret_cast<pldm_msg*>(pldmReq.data());
    int retVal = encode_cancel_update_req(instanceID, msgReq);
    if (!validatePLDMReqEncode(currentTid, retVal, "CancelUpdate"))
    {
        return retVal;
    }
    std::vector<uint8_t> pldmResp;
    if (!sendReceivePldmMessage(yield, currentTid, timeout, retryCount, pldmReq,
                                pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "CancelUpdate: Failed to send or receive PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return PLDM_ERROR;
    }
    auto msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    size_t payloadLen = pldmResp.size() - hdrSize;
    retVal = decode_cancel_update_resp(msgResp, payloadLen, &completionCode,
                                       &nonFunctioningComponentIndication,
                                       &nonFunctioningComponentBitmap);
    if (!validatePLDMRespDecode(currentTid, retVal, completionCode,
                                std::string("CancelUpdate")))
    {
        return retVal;
    }
    return PLDM_SUCCESS;
}

uint64_t FWUpdate::getApplicableComponents()
{
    // TODO implement actual code.
    return 0;
}

bool FWUpdate::isComponentApplicable()
{
    return (applicableComponentsVal >> currentComp) & 1;
}

constexpr uint32_t convertSecondsToMilliseconds(const uint16_t seconds)
{
    return (seconds * 1000);
}

int FWUpdate::startTimer(const uint16_t interval)
{
    timer.expires_after(
        std::chrono::milliseconds(convertSecondsToMilliseconds(interval)));
    timer.async_wait([this](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted)
        {
            // timer aborted do nothing
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "startTimer: timer operation_aborted");
            fdReqMatched = true;
        }
        else if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Timer error");
            fdReqMatched = false;
            return;
        }
        return;
    });

    return PLDM_SUCCESS;
}

int FWUpdate::runUpdate(const boost::asio::yield_context& yield)
{

    if (updateMode || state != FD_IDLE)
    {
        return ALREADY_IN_UPDATE_MODE;
    }
    // TODO: values need to be filled
    struct variable_field compImgSetVerStrn = {};
    // send requestUpdate command
    int retVal = doRequestUpdate(yield, compImgSetVerStrn);

    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "requestUpdate: Failed to run requestUpdate command",
            phosphor::logging::entry("RETVAL=%d", retVal));
        return retVal;
    }

    // fdWillSendGetPkgDataCmd will be set to 0x01 if there was package data
    // that the FD should obtain
    if (fdWillSendGetPkgDataCmd == 0x01)
    {
        pldmImg->getPkgProperty<uint16_t>(packageDataLength, "FWDevPkgDataLen");
        if (packageDataLength)
        {
            // TODO wait for FD to send GetPackageData and respond back to
            // it.
        }
    }

    if (fwDeviceMetaDataLen)
    {
        // TODO send GetDeviceMetaData command to FD
    }

    pldmImg->getPkgProperty<uint16_t>(compCount, "CompImageCount");

    applicableComponentsVal = getApplicableComponents();

    for (uint16_t i = 0; i < compCount; ++i)
    {

        currentComp = i;
        if (!isComponentApplicable())
        {
            continue;
        }
        // TODO: values need to be filled
        struct pass_component_table_req componentTable = {};
        uint8_t compResp = 0;
        uint8_t compRespCode = 0;
        struct variable_field compImgSetVerStr = {};
        // send PassComponentTable command
        retVal = doPassComponentTable(yield, componentTable, compImgSetVerStr,
                                      compResp, compRespCode);
        if (retVal != PLDM_SUCCESS)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "passComponentTable: Failed to send passComponentTable "
                "command",
                phosphor::logging::entry("RETVAL=%d", retVal),
                phosphor::logging::entry("COMPONENT=%d", currentComp));
            return retVal;
        }
        // TODO: values need to be filled
        struct update_component_req component = {};
        uint8_t compCompatabilityResp = 0;
        uint8_t compCompatabilityRespCode = 0;
        bitfield32_t updateOptFlagsEnabled = {};
        uint16_t estimatedTimeReqFd = 0;
        // send UpdateComponent command
        retVal =
            doUpdateComponent(yield, component, compImgSetVerStr,
                              compCompatabilityResp, compCompatabilityRespCode,
                              updateOptFlagsEnabled, estimatedTimeReqFd);
        if (retVal != PLDM_SUCCESS)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "updateComponent: Failed to run updateComponent command",
                phosphor::logging::entry("RETVAL=%d", retVal),
                phosphor::logging::entry("COMPONENT=%d", currentComp));
            return retVal;
        }
        // TODO wait for FD to send RequestFirmwareData, TransferComplete,
        // VerifyComplete, ApplyComplete commands and respond back to them.
        retVal = getStatus(yield);
        if (retVal != PLDM_SUCCESS)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "getStatus: Failed to run getStatus command",
                phosphor::logging::entry("RETVAL=%d", retVal),
                phosphor::logging::entry("COMPONENT=%d", currentComp));
            return retVal;
        }
    }

    if (fwDeviceMetaDataLen)
    {
        // TODO wait for FD to send GetMetaData command and respond back to
        // it.
    }

    // send ActivateFirmware command
    bool8_t selfContainedActivationReq = true;
    uint16_t estimatedTimeForSelfContainedActivation = 0;
    retVal = doActivateFirmware(yield, selfContainedActivationReq,
                                estimatedTimeForSelfContainedActivation);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "activateFirmware: Failed to send activateFirmware command",
            phosphor::logging::entry("RETVAL=%d", retVal));
        return retVal;
    }
    if (estimatedTimeForSelfContainedActivation)
    {
        // TODO UA should wait until estimatedTimeForSelfContainedActivation
        // is elapsed.
    }
    return PLDM_SUCCESS;
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

    inventoryInfo.addInventoryInfoToDBus();
    return true;
}
} // namespace fwu
} // namespace pldm
