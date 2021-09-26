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
#pragma once

#include "pldm.hpp"

#include <vector>

#include "utils.h"

namespace pldm
{
namespace fwu
{
using DescriptorType = std::variant<uint8_t, uint16_t, uint32_t>;
using DescriptorsMap = std::map<std::string, DescriptorType>;
using FWUVariantType =
    std::variant<uint8_t, uint16_t, uint32_t, uint64_t, bitfield16_t,
                 bitfield32_t, std::string, std::vector<uint8_t>>;
using FWUProperties = std::map<std::string, FWUVariantType>;

using DevIDRecordsMap =
    std::map<uint8_t, std::pair<FWUProperties, DescriptorsMap>>;
using CompPropertiesMap = std::map<uint16_t, FWUProperties>;
using FDProperties =
    std::tuple<FWUProperties, DescriptorsMap, CompPropertiesMap>;

enum class DescriptorIdentifierType : uint16_t
{
    pciVendorID = 0,
    ianaEnterpriseID = 1,
    uuid = 2,
    pnpVendorID = 3,
    acpiVendorID = 4,
    pciDeviceID = 0x0100,
    pciSubsystemVendorID = 0x0101,
    pciSubsystemID = 0x0102,
    pciRevisionID = 0x0103,
    pnpProductIdentifier = 0x0104,
    acpiProductIdentifier = 0x0105
};

struct DescriptorHeader
{
    DescriptorIdentifierType type;
    uint16_t size;
};

constexpr size_t PLDMCCOnlyResponse = sizeof(struct PLDMEmptyRequest) + 1;
constexpr size_t hdrSize = sizeof(pldm_msg_hdr);

void unpackDescriptors(const uint8_t count, const std::vector<uint8_t>& data,
                       uint16_t& initialDescriptorType,
                       DescriptorsMap& descriptorData);
void createAsyncDelay(boost::asio::yield_context yield, const uint16_t delay);
std::string toString(const struct variable_field& var);
} // namespace fwu
} // namespace pldm
