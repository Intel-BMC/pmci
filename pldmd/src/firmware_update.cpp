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
// TODO: The map will be updated for adding Get Firmware Parameters capabilities
std::map<pldm_tid_t, std::map<std::string, FWUVariantType>>
    terminusFwuProperties;

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
void PLDMFWUpdate::processDescriptor(const DescriptorHeader& header,
                                     const T& data)
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
            fwuProperties["PCIVendorID"] = value;
            break;
        }
        case pldm::fwu::DescriptorIdentifierType::pciDeviceID: {
            fwuProperties["PCIDeviceID"] = value;
            break;
        }
        case pldm::fwu::DescriptorIdentifierType::pciSubsystemVendorID: {
            fwuProperties["PCISubsystemVendorID"] = value;
            break;
        }
        case pldm::fwu::DescriptorIdentifierType::pciSubsystemID: {
            fwuProperties["PCISubsystemID"] = value;
            break;
        }
        case pldm::fwu::DescriptorIdentifierType::pciRevisionID: {
            fwuProperties["PCIRevisionID"] = value;
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

void PLDMFWUpdate::processDescriptor(const DescriptorHeader& /*header*/,
                                     const std::vector<uint8_t>& /*data*/)
{

    // TODO process non-standard descriptor sizes(Eg: PnP 3 byes) and bigger
    // sizes(Eg: UUID 16 bytes)
}

void PLDMFWUpdate::unpackDescriptors(const uint8_t count,
                                     const std::vector<uint8_t>& data)
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
            processDescriptor(*hdr, *it);
        }
        else if (hdr->size == sizeof(uint16_t))
        {
            processDescriptor(*hdr, *reinterpret_cast<const uint16_t*>(&*it));
        }
        else if (hdr->size == sizeof(uint32_t))
        {
            processDescriptor(*hdr, *reinterpret_cast<const uint32_t*>(&*it));
        }
        else
        {
            std::vector<uint8_t> descriptorData;
            std::copy(it, std::next(it, hdr->size),
                      std::back_inserter(descriptorData));
            processDescriptor(*hdr, descriptorData);
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

int PLDMFWUpdate::runQueryDeviceIdentifiers()
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

    unpackDescriptors(descriptorCount, descriptorDataVect);

    return PLDM_SUCCESS;
}

PLDMFWUpdate::PLDMFWUpdate(boost::asio::yield_context _yield,
                           const pldm_tid_t _tid) :
    yield(_yield),
    tid(_tid)
{
}

PLDMFWUpdate::~PLDMFWUpdate()
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

std::optional<std::map<std::string, FWUVariantType>>
    PLDMFWUpdate::runInventoryCommands()
{

    int retVal = runQueryDeviceIdentifiers();

    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to run QueryDeviceIdentifiers command");
        return std::nullopt;
    }
    return fwuProperties;
}

bool fwuInit(boost::asio::yield_context yield, const pldm_tid_t tid)
{
    if (!fwuBaseInitialized)
    {
        initializeFWUBase();
    }
    PLDMFWUpdate fwUpdate(yield, tid);

    if (auto properties = fwUpdate.runInventoryCommands())
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

    return true;
}
} // namespace fwu
} // namespace pldm
