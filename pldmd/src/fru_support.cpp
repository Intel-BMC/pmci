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
#include <numeric>
#include <vector>
#include <xyz/openbmc_project/Inventory/Source/PLDM/FRU/server.hpp>

static std::vector<std::string> ipmiProductProperties = {
    "PRODUCT_MANUFACTURER", "PRODUCT_PRODUCT_NAME",  "PRODUCT_PART_NUMBER",
    "PRODUCT_VERSION",      "PRODUCT_SERIAL_NUMBER", "ASSET_TAG",
    "FRU_FILE_ID"};

const static std::unordered_map<std::string, std::string> mappedIpmiProperties{
    {"PN", "PRODUCT_PART_NUMBER"},     {"Manufacturer", "PRODUCT_MANUFACTURER"},
    {"SN", "PRODUCT_SERIAL_NUMBER"},   {"Name", "PRODUCT_PRODUCT_NAME"},
    {"Version", "PRODUCT_VERSION"},    {"AssetTag", "ASSET_TAG"},
    {"Vendor", "PRODUCT_MANUFACTURER"}};

uint8_t FruSupport::calculateChecksum(std::vector<uint8_t>::const_iterator iter,
                                      std::vector<uint8_t>::const_iterator end)
{
    constexpr int checksumMod = 256;
    constexpr uint8_t modVal = 0xFF;
    int sum = std::accumulate(iter, end, 0);
    int checksum = (checksumMod - sum) & modVal;
    return static_cast<uint8_t>(checksum);
}

void FruSupport::initializeFRUSupport()
{
    auto objServer = getObjServer();
    fruIface = objServer->add_interface("/xyz/openbmc_project/FruDevice",
                                        "xyz.openbmc_project.FruDeviceManager");

    fruIface->register_method("GetRawFru", [this](const uint8_t bus,
                                                  const pldm_tid_t tidVal) {
        std::optional<std::vector<uint8_t>> retVal =
            this->getRawFRURecordData(tidVal);

        if (!retVal)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("Failed to get Raw Fru details for Bus " + std::to_string(bus))
                    .c_str());

            throw std::system_error(
                std::make_error_code(std::errc::no_message_available));
        }

        return retVal.value();
    });

    fruIface->initialize();
}

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

    std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
        objServer->add_interface(fruPath, "xyz.openbmc_project.FruDevice");

    std::string propertyVal;
    FRUProperties ipmiProps;
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
            iface->register_property(itr->second, propertyVal);
            ipmiProps.emplace(itr->second, propertyVal);
        }
    }
    // GetRawFru data command(0x11h) internally make use of bus and address to
    // get IPMI based FRU which is present under FruDevice service.
    // To make use of the same command for pldm, we require bus and address
    // for which we are statically picking bus=254 (assuming no hardware
    // currently use this bus number) and address=TID.

    constexpr uint32_t dummybusNumber = 254;
    iface->register_property("BUS", dummybusNumber);
    iface->register_property("ADDRESS", static_cast<uint32_t>(tid));

    iface->initialize();
    ipmiFruInterface.emplace(tid, iface);
    ipmiFRUProperties.emplace(tid, std::move(ipmiProps));
}

void FruSupport::removeInterfaces(const pldm_tid_t& tid)
{
    auto objServer = getObjServer();

    auto ipmiIface = ipmiFruInterface.find(tid);
    if (ipmiIface != ipmiFruInterface.end())
    {
        objServer->remove_interface(ipmiIface->second);
        ipmiFruInterface.erase(ipmiIface);
        ipmiFRUProperties.erase(tid);
        return;
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Interface associated didn't found for ",
        phosphor::logging::entry("TID=%d", tid));
}

std::optional<std::vector<uint8_t>>
    FruSupport::getRawFRURecordData(const pldm_tid_t tid)
{
    std::vector<uint8_t> ipmiFruData;
    std::vector<uint8_t> rawFruData;

    auto itr = ipmiFRUProperties.find(tid);

    if (itr == ipmiFRUProperties.end())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("IPMI-PLDM FRU device not matched for TID " + std::to_string(tid))
                .c_str());
        return std::nullopt;
    }

    uint8_t internalAreaLen = setInternalArea(rawFruData);

    uint8_t chassisAreaLen = setChassisArea(rawFruData);

    uint8_t boardAreaLen = setBoardArea(rawFruData);

    uint8_t productAreaLen = setProductArea(itr->second, rawFruData);

    setCommonHeader(internalAreaLen, chassisAreaLen, boardAreaLen,
                    productAreaLen, ipmiFruData);
    std::move(rawFruData.begin(), rawFruData.end(),
              std::back_inserter(ipmiFruData));

    return ipmiFruData;
}

uint8_t FruSupport::setHeaderAreaOffset(uint8_t& fruOffset,
                                        const uint8_t areaOffset)
{
    uint8_t offset = fruOffset;
    // Info not present
    if (areaOffset == 0)
    {
        offset = 0;
    }
    // first info to be available
    else if ((fruOffset == 0) && (areaOffset > 0))
    {
        offset = 1;
    }
    // TODO: Add check for overflow
    fruOffset += areaOffset;

    return offset;
}

void FruSupport::setCommonHeader(const uint8_t internalAreaLen,
                                 const uint8_t chassisAreaLen,
                                 const uint8_t boardAreaLen,
                                 const uint8_t productAreaLen,
                                 std::vector<uint8_t>& ipmiFruData)
{
    uint8_t fruAreaOffset = 0;
    // Version
    constexpr uint8_t version = 0x01;
    constexpr uint8_t defaultData = 0;
    ipmiFruData.push_back(version);

    ipmiFruData.push_back(setHeaderAreaOffset(fruAreaOffset, internalAreaLen));
    ipmiFruData.push_back(setHeaderAreaOffset(fruAreaOffset, chassisAreaLen));
    ipmiFruData.push_back(setHeaderAreaOffset(fruAreaOffset, boardAreaLen));
    ipmiFruData.push_back(setHeaderAreaOffset(fruAreaOffset, productAreaLen));

    // MultiRecord Area Offset
    ipmiFruData.push_back(defaultData);
    // Padding
    ipmiFruData.push_back(defaultData);

    ipmiFruData.push_back(
        calculateChecksum(ipmiFruData.begin(), ipmiFruData.end()));
}

uint8_t FruSupport::setInternalArea(std::vector<uint8_t>& fruData)
{
    // IPMI FRU follows specific format from which we need only common header
    // and product info area. So Internal Info area need to be filled with empty
    // fields.
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Size of Internal ",
        phosphor::logging::entry("AREA=%d", fruData.size()));
    return 0;
}

uint8_t FruSupport::setChassisArea(std::vector<uint8_t>& fruData)
{
    // IPMI FRU follows specific format from which we need only common header
    // and product info area. Chassis Info area need to be filled with empty
    // fields.
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Size of Chassis ",
        phosphor::logging::entry("AREA=%d", fruData.size()));
    return 0;
}

uint8_t FruSupport::setBoardArea(std::vector<uint8_t>& fruData)
{
    // IPMI FRU follows specific format from which we need only common header
    // and product info area. Board area need to be filled with empty
    // fields.
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Size of Board ", phosphor::logging::entry("AREA=%d", fruData.size()));
    return 0;
}

uint8_t FruSupport::setProductArea(const FRUProperties& properties,
                                   std::vector<uint8_t>& fruData)
{

    constexpr uint8_t endOfFields = 0xC1;
    // Ascii + Latin 8 bit
    constexpr uint8_t encodingTypeLenByte = 0xC0;
    constexpr uint8_t productAreaVersion = 1;
    // English
    constexpr uint8_t languageCode = 0;
    std::vector<uint8_t> productData;

    // Used to check for the overflow
    constexpr uint8_t maxDataSize = 255;
    constexpr uint8_t initialDataLen = 0;

    productData.push_back(productAreaVersion);
    productData.push_back(initialDataLen);
    productData.push_back(languageCode);

    for (auto prop : ipmiProductProperties)
    {
        try
        {
            std::string data = std::get<std::string>(properties.at(prop));
            // Stripping trailing spaces
            data.erase(std::find_if(data.rbegin(), data.rend(),
                                    [](char ch) { return ch != ' '; })
                           .base(),
                       data.end());

            const size_t length = data.length();
            // IPMI Encoding Type
            // 7:6 - type code
            // 5:0 - number of data bytes
            // 11 - 11b indicates 8-bit ASCII + Latin 1
            // TODO: Encoding type shall be taken from PLDM FRU

            uint8_t typeLenByte =
                static_cast<uint8_t>(length | encodingTypeLenByte);

            productData.push_back(typeLenByte);
            for (size_t i = 0; i < length; ++i)
            {
                unsigned int value = data[i];
                productData.push_back(static_cast<uint8_t>(value));
            }
        }
        catch (std::out_of_range&)
        {
            // Property not provided
            productData.push_back(encodingTypeLenByte);
            continue;
        }
    }

    // No more fields
    productData.push_back(endOfFields);
    productData.push_back(0);

    // Area is multiple of 8 bytes.
    constexpr size_t mod = 8;
    size_t numPadBytes = 0;
    if (productData.size() % mod)
    {
        numPadBytes = mod - (productData.size() % mod);
    }

    // fill padding with zeros
    productData.resize(productData.size() + numPadBytes);

    size_t dataSize = productData.size();
    dataSize = (dataSize % mod) ? dataSize / mod + 1 : dataSize / mod;

    if (dataSize > maxDataSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Size of Product Area is overflowing. ",
            phosphor::logging::entry("SIZE=%d", dataSize));

        return 0;
    }

    // Set Total Length
    productData[1] = static_cast<uint8_t>(dataSize);

    productData.push_back(
        calculateChecksum(productData.begin(), productData.end()));

    std::move(productData.begin(), productData.end(),
              std::back_inserter(fruData));

    return productData[1];
}
