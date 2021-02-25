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
#include "fwu_utils.hpp"

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace fwu
{
template <typename T>
static void processDescriptor(const DescriptorHeader& header, const T& data,
                              DescriptorsMap& descriptorData)

{
    if (!std::is_arithmetic_v<T>)
    {
        return;
    }
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

void createAsyncDelay(boost::asio::yield_context yield, const uint16_t delay)
{
    boost::asio::steady_timer timer(*getIoContext());
    boost::system::error_code ec;

    timer.expires_after(std::chrono::milliseconds(delay));
    timer.async_wait(yield[ec]);
}

void unpackDescriptors(const uint8_t count, const std::vector<uint8_t>& data,
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

std::string toString(const struct variable_field& var)
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
} // namespace fwu
} // namespace pldm
