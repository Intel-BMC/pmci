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

#include "fru.hpp"
#include "pldm.hpp"
#include "utils.hpp"

#include <optional>
#include <variant>

using VariantType = std::variant<uint8_t, uint32_t, std::string>;

namespace fruUtils
{

std::optional<VariantType> getFruProperty(const pldm_tid_t tid,
                                          std::string propertyName)
{
    if (auto prop = pldm::fru::getProperties(tid))
    {
        pldm::fru::FRUProperties properties = *prop;
        auto itr = properties.find(propertyName);
        if (itr != properties.end())
        {
            return itr->second;
        }
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("PLDM FRU property " + propertyName + " does not exist for TID " +
         std::to_string(tid))
            .c_str());

    return std::nullopt;
}

} // namespace fruUtils
