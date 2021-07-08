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
#include "fru_support.hpp"

#include "fru.hpp"

#include <boost/algorithm/string.hpp>
#include <vector>
#include <xyz/openbmc_project/Inventory/Source/PLDM/FRU/server.hpp>

const static std::unordered_map<std::string, std::string> mappedIpmiProperties{
    {"PN", "PRODUCT_PART_NUMBER"},     {"Manufacturer", "PRODUCT_MANUFACTURER"},
    {"SN", "PRODUCT_SERIAL_NUMBER"},   {"Name", "PRODUCT_PRODUCT_NAME"},
    {"Version", "PRODUCT_VERSION"},    {"AssetTag", "ASSET_TAG"},
    {"Vendor", "PRODUCT_MANUFACTURER"}};

void FruSupport::convertFRUToIpmiFRU(const pldm_tid_t& tid,
                                     const FRUProperties& fruProperties)
{
    auto objServer = getObjServer();
    auto it = fruProperties.find("Name");

    if (it == fruProperties.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to convert fru data to IPMI data. Couldn't find "
            "productName");
        return;
    }

    std::string productName = std::get<std::string>(it->second);
    if (productName.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Product Name not found");
        return;
    }

    boost::algorithm::trim(productName);
    std::replace(productName.begin(), productName.end(), ' ', '_');

    std::string fruPath = ("/xyz/openbmc_project/FruDevice/") + productName +
                          "_" + std::to_string(tid);

    std::shared_ptr<sdbusplus::asio::dbus_interface> fruIface =
        objServer->add_interface(fruPath, "xyz.openbmc_project.FruDevice");

    std::string propertyVal;
    for (auto& property : fruProperties)
    {
        try
        {
            // Accessing PLDM FRU Properties of type string only
            propertyVal = std::get<std::string>(property.second);
        }
        catch (const std::bad_variant_access&)
        {
            // If the propery value is other than string proceed to next
            // property
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Failed to register FRU property",
                phosphor::logging::entry("TID=%d", tid));
            continue;
        }
        auto itr = mappedIpmiProperties.find(property.first);
        if (itr != mappedIpmiProperties.end())
        {
            if ((property.first.compare("Manufacturer") == 0) &&
                (fruProperties.find("Vendor") != fruProperties.end()))
            {
                // Map Manufacturer with PRODUCT_MANUFACTURER only if Vendor is
                // not available
                continue;
            }
            fruIface->register_property(itr->second, propertyVal);
        }
    }
    // GetRawFru data command(0x11h) internally make use of bus and address to
    // get IPMI based FRU which is present under FruDevice service.
    // To make use of the same command for pldm, we require bus and address
    // for which we are statically picking bus=254 (assuming no hardware
    // currently use this bus number) and address=TID.

    constexpr uint32_t dummybusNumber = 254;
    fruIface->register_property("BUS", dummybusNumber);
    fruIface->register_property("ADDRESS", static_cast<uint32_t>(tid));

    fruIface->initialize();
    ipmiFruInterface.emplace(tid, fruIface);
}

void FruSupport::removeInterfaces(const pldm_tid_t& tid)
{
    auto objServer = getObjServer();

    auto ipmiIface = ipmiFruInterface.find(tid);
    if (ipmiIface != ipmiFruInterface.end())
    {
        objServer->remove_interface(ipmiIface->second);
        ipmiFruInterface.erase(ipmiIface);
        return;
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Interface associated didn't found for ",
        phosphor::logging::entry("TID=%d", tid));
}
