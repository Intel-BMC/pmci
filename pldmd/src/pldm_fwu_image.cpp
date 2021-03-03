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
#include "pldm_fwu_image.hpp"

#include "fwu_inventory.hpp"
#include "platform.hpp"

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace fwu
{
const std::array<uint8_t, pkgHeaderIdentifierSize> pkgHdrIdentifier = {
    0xF0, 0x18, 0x87, 0x8C, 0xCB, 0x7D, 0x49, 0x43,
    0x98, 0x00, 0xA0, 0x2F, 0x05, 0x9A, 0xCA, 0x02};
extern std::map<pldm_tid_t, FDProperties> terminusFwuProperties;

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
    return (pkgHdrLen);
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
    pkgFWUProperties["PkgHeaderSize"] = (headerInfo->pkgHeaderSize);
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
    uint16_t found = 0;

    if (!advanceHdrItr(0, sizeof(totalCompCount)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "no bytes left for deviceIDRecordCount");
        return false;
    }
    totalCompCount = *reinterpret_cast<const uint16_t*>(&*hdrItr);
    std::advance(hdrItr, sizeof(totalCompCount));

    while (hdrItr < std::end(hdrData) && found != totalCompCount)
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
    if (found != totalCompCount)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Component count not matched",
            phosphor::logging::entry("ACTUAL_COMP_COUNT=%d", found),
            phosphor::logging::entry("EXPECTED_COMP_COUNT=%d", totalCompCount));
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
} // namespace fwu
} // namespace pldm
