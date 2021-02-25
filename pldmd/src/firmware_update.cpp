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
#include "firmware_update.hpp"

#include "fwu_inventory.hpp"
#include "platform.hpp"
#include "pldm.hpp"

#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/PLDM/FWU/FWUBase/server.hpp>

#include "firmware_update.h"
#include "utils.h"

namespace pldm
{
namespace fwu
{
using FWUBase = sdbusplus::xyz::openbmc_project::PLDM::FWU::server::FWUBase;
extern std::map<pldm_tid_t, FDProperties> terminusFwuProperties;
std::shared_ptr<boost::asio::steady_timer> expectedCommandTimer = nullptr;
std::unique_ptr<PLDMImg> pldmImg = nullptr;
std::unique_ptr<FWUpdate> fwUpdate = nullptr;

const std::array<uint8_t, pkgHeaderIdentifierSize> pkgHdrIdentifier = {
    0xF0, 0x18, 0x87, 0x8C, 0xCB, 0x7D, 0x49, 0x43,
    0x98, 0x00, 0xA0, 0x2F, 0x05, 0x9A, 0xCA, 0x02};

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

template <typename T>
bool PLDMImg::getCompProperty(T& value, const std::string& name,
                              uint16_t compCount)
{
    auto itr = pkgCompProperties.find(compCount);
    if (itr == pkgCompProperties.end())
    {
        return false;
    }
    auto& compProps = itr->second;
    auto it = compProps.find(name);
    if (compProps.end() != it)
    {
        if (auto itr2 = std::get_if<T>(&it->second))
        {
            value = *itr2;
            return true;
        }
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
        ("getCompProperty: Failed to find " + name).c_str());
    return false;
}

template <typename T>
bool PLDMImg::getDevIdRcrdProperty(T& value, const std::string& name,
                                   uint8_t recordCount)
{
    auto itr = pkgDevIDRecords.find(recordCount);
    if (itr == pkgDevIDRecords.end())
    {
        return false;
    }
    auto& devRcd = itr->second;
    auto& dev = devRcd.first;
    auto it = dev.find(name);
    if (dev.end() != it)
    {
        if (auto itr2 = std::get_if<T>(&it->second))
        {
            value = *itr2;
            return true;
        }
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
        ("getDevIdRcrdProperty: Failed to find " + name).c_str());
    return false;
}

FWUpdate::FWUpdate(const pldm_tid_t _tid, const uint8_t _deviceIDRecord) :
    currentTid(_tid), currentDeviceIDRecord(_deviceIDRecord), state(FD_IDLE)
{
}

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

    if (expectedCmd == PLDM_REQUEST_FIRMWARE_DATA &&
        msgHdr->command == PLDM_TRANSFER_COMPLETE)
    {
        expectedCmd = PLDM_TRANSFER_COMPLETE;
        fdTransferCompleted = true;
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("TransferComplete received from TID: " +
             std::to_string(currentTid))
                .c_str());
    }

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
    fdReqMatched = true;
    fdReq = req;
    expectedCommandTimer->cancel();
    return;
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

void FWUpdate::terminateFwUpdate(const boost::asio::yield_context& yield)
{
    bool8_t nonFunctioningComponentIndication = false;
    bitfield64_t nonFunctioningComponentBitmap = {};
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "unexpected error: firmwareUpdate stopped");
    if (doCancelUpdate(yield, nonFunctioningComponentIndication,
                       nonFunctioningComponentBitmap) != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "unable to send/receive CancelUpdate");
    }
    if (isReserveBandwidthActive)
    {
        isReserveBandwidthActive = false;
        if (!releaseBandwidth(yield, currentTid, PLDM_FWU))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "terminateFwUpdate: releaseBandwidth failed");
        }
    }

    return;
}

bool FWUpdate::prepareRequestUpdateCommand(std::string& vrnStr)
{
    uint16_t tempShort = 0;
    updateProperties.max_transfer_size = PLDM_FWU_BASELINE_TRANSFER_SIZE;
    updateProperties.no_of_comp = compCount;
    updateProperties.max_outstand_transfer_req = 1;
    if (!pldmImg->getDevIdRcrdProperty<uint16_t>(tempShort, "FWDevPkgDataLen",
                                                 currentDeviceIDRecord))
    {
        return false;
    }
    updateProperties.pkg_data_len = tempShort;
    if (!pldmImg->getDevIdRcrdProperty<uint8_t>(
            updateProperties.comp_image_set_ver_str_len, "ComImgSetVerStrLen",
            currentDeviceIDRecord))
    {
        return false;
    }
    if (!pldmImg->getDevIdRcrdProperty<uint8_t>(
            updateProperties.comp_image_set_ver_str_type, "ComImgSetVerStrType",
            currentDeviceIDRecord))
    {
        return false;
    }

    if (!pldmImg->getDevIdRcrdProperty<std::string>(vrnStr, "CompImgSetVerStr",
                                                    currentDeviceIDRecord))
    {
        return false;
    }
    return true;
}

bool FWUpdate::preparePassComponentRequest(
    struct pass_component_table_req& componentTable, const uint16_t compCnt)
{
    uint16_t tempShort = 0;
    uint32_t tempLong = 0;

    if (!pldmImg->getCompProperty<uint16_t>(tempShort, "CompClassification",
                                            compCnt))
    {
        return false;
    }
    componentTable.comp_classification = tempShort;
    componentTable.comp_classification_index = 0;
    if (!pldmImg->getCompProperty<uint32_t>(tempLong, "CompComparisonStamp",
                                            compCnt))
    {
        return false;
    }
    componentTable.comp_comparison_stamp = tempLong;
    if (!pldmImg->getCompProperty<uint16_t>(tempShort, "CompIdentifier",
                                            compCnt))
    {
        return false;
    }
    componentTable.comp_identifier = tempShort;
    if (!pldmImg->getCompProperty<uint8_t>(componentTable.comp_ver_str_len,
                                           "CompVerStrLen", compCnt))
    {
        return false;
    }
    if (!pldmImg->getCompProperty<uint8_t>(componentTable.comp_ver_str_type,
                                           "CmpVerStrType", compCnt))
    {
        return false;
    }

    return initTransferFlag(compCnt, componentTable.transfer_flag);
}

bool FWUpdate::initTransferFlag(const uint16_t compCnt, uint8_t& flag)
{

    if (updateProperties.no_of_comp == 1)
    {
        flag = PLDM_START_AND_END;
        return true;
    }

    if (updateProperties.no_of_comp > 1)
    {
        if (compCnt == 0)
        {
            flag = PLDM_START;
        }
        else if (compCnt + 1 < updateProperties.no_of_comp)
        {
            flag = PLDM_MIDDLE;
        }
        else if (compCnt + 1 == updateProperties.no_of_comp)
        {
            flag = PLDM_END;
        }

        return true;
    }

    return false;
}

bool FWUpdate::prepareUpdateComponentRequest(
    struct update_component_req& component, const uint16_t compCnt)
{
    uint16_t tempShort = 0;
    uint32_t tempLong = 0;

    if (!pldmImg->getCompProperty<uint16_t>(tempShort, "CompClassification",
                                            compCnt))
    {
        return false;
    }
    component.comp_classification = tempShort;
    if (!pldmImg->getCompProperty<uint16_t>(tempShort, "CompIdentifier",
                                            compCnt))
    {
        return false;
    }
    component.comp_identifier = tempShort;
    component.comp_classification_index = 0;
    if (!pldmImg->getCompProperty<uint32_t>(tempLong, "CompComparisonStamp",
                                            compCnt))
    {
        return false;
    }
    component.comp_comparison_stamp = tempLong;
    if (!pldmImg->getCompProperty<uint32_t>(tempLong, "CompSize", compCnt))
    {
        return false;
    }
    component.comp_image_size = tempLong;
    component.update_option_flags = {};
    if (!pldmImg->getCompProperty<uint8_t>(component.comp_ver_str_type,
                                           "CmpVerStrType", compCnt))
    {
        return false;
    }
    if (!pldmImg->getCompProperty<uint8_t>(component.comp_ver_str_len,
                                           "CompVerStrLen", compCnt))
    {
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
    return updateComponent(yield, component, compVerStr, compCompatabilityResp,
                           compCompatabilityRespCode, updateOptFlagsEnabled,
                           estimatedTimeReqFd);
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
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "TransferComplete: sendErrorCompletionCode failed");
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
    int retVal = decode_transfer_complete_req(msgReq, &transferResult);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("transferComplete: decode request failed. RETVAL:" +
             std::to_string(retVal))
                .c_str());
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     static_cast<uint8_t>(retVal),
                                     PLDM_TRANSFER_COMPLETE))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "transferComplete: sendErrorCompletionCode failed.");
        }
        return retVal;
    }
    retVal = validateTransferComplete(transferResult);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("transferComplete: invalid transferResult. transferResult: " +
             std::to_string(transferResult))
                .c_str());
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     static_cast<uint8_t>(retVal),
                                     PLDM_TRANSFER_COMPLETE))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "transferComplete: sendErrorCompletionCode failed");
        }
        return retVal;
    }
    std::vector<uint8_t> pldmResp(PLDMCCOnlyResponse);
    struct pldm_msg* msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    retVal = encode_transfer_complete_resp(
        msgReq->hdr.instance_id, static_cast<uint8_t>(retVal), msgResp);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("transferComplete: encode response failed. RETVAL:" +
             std::to_string(retVal))
                .c_str());
        return retVal;
    }
    if (!sendPldmMessage(currentTid, msgTag, tagOwner, pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "TransferComplete: Failed to send PLDM message");
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
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "VerifyComplete: sendErrorCompletionCode failed");
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
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("verifyComplete: decode request failed. RETVAL:" +
             std::to_string(retVal))
                .c_str());
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     static_cast<uint8_t>(retVal),
                                     PLDM_VERIFY_COMPLETE))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "verifyComplete: sendErrorCompletionCode failed");
        }
        return retVal;
    }
    retVal = validateVerifyComplete(verifyResult);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("verifyComplete: invalid verifyResult. verifyResult: " +
             std::to_string(verifyResult))
                .c_str());
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     static_cast<uint8_t>(retVal),
                                     PLDM_VERIFY_COMPLETE))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "verifyComplete: sendErrorCompletionCode failed.");
        }
        return retVal;
    }
    std::vector<uint8_t> pldmResp(PLDMCCOnlyResponse);
    struct pldm_msg* msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    retVal = encode_verify_complete_resp(msgReq->hdr.instance_id,
                                         static_cast<uint8_t>(retVal), msgResp);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("VerifyComplete: encode response failed. RETVAL:" +
             std::to_string(retVal))
                .c_str());
        return retVal;
    }
    if (!sendPldmMessage(currentTid, msgTag, tagOwner, pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "verifyComplete: sendErrorCompletionCode failed.");
        return PLDM_ERROR;
    }
    return PLDM_SUCCESS;
}

uint8_t FWUpdate::validateApplyComplete(const uint8_t applyResult)
{
    if (applyResult == PLDM_FWU_APPLY_SUCCESS ||
        applyResult == PLDM_FWU_APPLY_SUCCESS_WITH_ACTIVATION_METHOD)
    {
        return PLDM_SUCCESS;
    }
    return PLDM_ERROR_INVALID_DATA;
}

int FWUpdate::processApplyComplete(
    const std::vector<uint8_t>& pldmReq, uint8_t& applyResult,
    bitfield16_t& compActivationMethodsModification)
{
    if (!updateMode || fdState != FD_APPLY)
    {
        auto msgReq = reinterpret_cast<const pldm_msg*>(pldmReq.data());
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     COMMAND_NOT_EXPECTED, PLDM_APPLY_COMPLETE))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ApplyComplete: Failed to send PLDM message",
                phosphor::logging::entry("TID=%d", currentTid));
        }
        return COMMAND_NOT_EXPECTED;
    }
    int retVal =
        applyComplete(pldmReq, applyResult, compActivationMethodsModification);
    if (retVal != PLDM_SUCCESS)
    {
        return retVal;
    }
    fdState = FD_READY_XFER;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "FD changed state to READY XFER");
    return PLDM_SUCCESS;
}

int FWUpdate::applyComplete(const std::vector<uint8_t>& pldmReq,
                            uint8_t& applyResult,
                            bitfield16_t& compActivationMethodsModification)
{

    auto msgReq = reinterpret_cast<const pldm_msg*>(pldmReq.data());
    int retVal = decode_apply_complete_req(msgReq, pldmReq.size() - hdrSize,
                                           &applyResult,
                                           &compActivationMethodsModification);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ApplyComplete: decode request failed",
            phosphor::logging::entry("TID=%d", currentTid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     static_cast<uint8_t>(retVal),
                                     PLDM_APPLY_COMPLETE))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ApplyComplete: Failed to send PLDM message",
                phosphor::logging::entry("TID=%d", currentTid));
        }
        return retVal;
    }

    uint8_t compCode = validateApplyComplete(applyResult);
    std::vector<uint8_t> pldmResp(PLDMCCOnlyResponse);
    struct pldm_msg* msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    retVal =
        encode_apply_complete_resp(msgReq->hdr.instance_id, compCode, msgResp);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ApplyComplete: encode response failed",
            phosphor::logging::entry("TID=%d", currentTid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        return retVal;
    }
    if (!sendPldmMessage(currentTid, msgTag, tagOwner, pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ApplyComplete: Failed to send PLDM message",
            phosphor::logging::entry("TID=%d", currentTid));
        return PLDM_ERROR;
    }

    return PLDM_SUCCESS;
}

int FWUpdate::processRequestFirmwareData(const std ::vector<uint8_t>& pldmReq,
                                         uint32_t& offset, uint32_t& length,
                                         const uint32_t componentSize,
                                         const uint32_t componentOffset)
{
    if (!updateMode || fdState != FD_DOWNLOAD)
    {
        const struct pldm_msg* msgReq =
            reinterpret_cast<const pldm_msg*>(pldmReq.data());
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     COMMAND_NOT_EXPECTED,
                                     PLDM_REQUEST_FIRMWARE_DATA))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "RequestFirmwareData: Failed to send PLDM message",
                phosphor::logging::entry("TID=%d", currentTid));
        }
        return COMMAND_NOT_EXPECTED;
    }
    return requestFirmwareData(pldmReq, offset, length, componentSize,
                               componentOffset);
}

int FWUpdate::requestFirmwareData(const std ::vector<uint8_t>& pldmReq,
                                  uint32_t& offset, uint32_t& length,
                                  const uint32_t componentSize,
                                  const uint32_t componentOffset)
{

    const struct pldm_msg* msgReq =
        reinterpret_cast<const pldm_msg*>(pldmReq.data());
    int retVal = decode_request_firmware_data_req(
        msgReq, pldmReq.size() - hdrSize, &offset, &length);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "requestfirmware: decode request failed",
            phosphor::logging::entry("TID=%d", currentTid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id,
                                     static_cast<uint8_t>(retVal),
                                     PLDM_REQUEST_FIRMWARE_DATA))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "RequestFirmwareData: Failed to send PLDM message",
                phosphor::logging::entry("TID=%d", currentTid));
        }
        return retVal;
    }

    /* completion code plus requested data length */
    size_t payload_length = 1 + length;

    std::vector<uint8_t> pldmResp(PLDMCCOnlyResponse + length);
    std ::vector<uint8_t> data(length);
    if (offset + length > componentSize)
    {
        if (offset < componentSize)
        {
            length = componentSize - offset;
        }
        else
        {
            if (!sendErrorCompletionCode(msgReq->hdr.instance_id, PLDM_ERROR,
                                         PLDM_REQUEST_FIRMWARE_DATA))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "RequestFirmwareData: Failed to send PLDM message",
                    phosphor::logging::entry("TID=%d", currentTid));
            }
            return PLDM_ERROR;
        }
    }

    if (!pldmImg->readData(offset + componentOffset, data, length))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "update image read failed",
            phosphor::logging::entry("TID=%d", currentTid));
        if (!sendErrorCompletionCode(msgReq->hdr.instance_id, PLDM_ERROR,
                                     PLDM_REQUEST_FIRMWARE_DATA))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "RequestFirmwareData: Failed to send PLDM message",
                phosphor::logging::entry("TID=%d", currentTid));
        }
        return PLDM_ERROR;
    }

    struct variable_field componentImagePortion = {};
    componentImagePortion.length = data.size();
    componentImagePortion.ptr = data.data();
    struct pldm_msg* msgResp = reinterpret_cast<pldm_msg*>(pldmResp.data());
    retVal = encode_request_firmware_data_resp(msgReq->hdr.instance_id, msgResp,
                                               payload_length, completionCode,
                                               &componentImagePortion);

    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "requestfirmware: encode request failed",
            phosphor::logging::entry("TID=%d", currentTid),
            phosphor::logging::entry("RETVAL=%d", retVal));
        return retVal;
    }

    if (!sendPldmMessage(currentTid, msgTag, tagOwner, pldmResp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "requestFirmwareData: Failed to send PLDM message",
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
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("CancelUpdateComponent: encode_cancel_update_component_req "
             "failed. RETVAL: " +
             std::to_string(retVal))
                .c_str());
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
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("CancelUpdateComponent: decode_cancel_update_component_resp "
             "failed. RETVAL: " +
             std::to_string(retVal) +
             ". COMPLETION_CODE: " + std::to_string(completionCode))
                .c_str());
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
    return 1;
}

bool FWUpdate::isComponentApplicable()
{
    return (applicableComponentsVal >> currentComp) & 1;
}

constexpr uint32_t convertSecondsToMilliseconds(const uint16_t seconds)
{
    return (seconds * 1000);
}

boost::system::error_code
    FWUpdate::startTimer(const boost::asio::yield_context& yield,
                         const uint32_t interval)
{
    boost::system::error_code ec;
    expectedCommandTimer->expires_after(std::chrono::milliseconds(interval));
    expectedCommandTimer->async_wait(yield[ec]);
    return ec;
}

int FWUpdate::runUpdate(const boost::asio::yield_context& yield)
{
    if (updateMode || state != FD_IDLE)
    {
        return ALREADY_IN_UPDATE_MODE;
    }
    uint32_t compOffset = 0;
    compCount = pldmImg->getTotalCompCount();
    variable_field compImgSetVerStr;
    std::string versionStr;
    if (!prepareRequestUpdateCommand(versionStr))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "RequestUpdateCommand preparation failed");
        return PLDM_ERROR;
    }
    compImgSetVerStr.ptr = reinterpret_cast<const uint8_t*>(versionStr.c_str());
    compImgSetVerStr.length = versionStr.length();

    int retVal = doRequestUpdate(yield, compImgSetVerStr);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Component cannot be put in update mode");
        return PLDM_ERROR;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "RequestUpdate command is success");
    createAsyncDelay(yield, delayBtw);

    // fdWillSendGetPkgDataCmd will be set to 0x01 if there was package data
    // that the FD should obtain
    if (fdWillSendGetPkgDataCmd == 0x01)
    {
        pldmImg->getPkgProperty<uint16_t>(packageDataLength, "FWDevPkgDataLen");
        if (packageDataLength)
        {
            expectedCmd = PLDM_GET_PACKAGE_DATA;
            startTimer(yield, fdCmdTimeout);
            if (fdReqMatched)
            {
                // TODO: need to add getPackageData command call
            }
        }
    }

    if (fwDeviceMetaDataLen)
    {
        // TODO: GetDeviceMetaData command
    }
    applicableComponentsVal = getApplicableComponents();

    for (uint16_t count = 0; count < compCount; ++count)
    {
        struct pass_component_table_req componentTable;
        uint8_t compResp;
        uint8_t compRespCode;

        if (!isComponentApplicable())
        {
            continue;
        }

        if (!preparePassComponentRequest(componentTable, count))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("runUpdate: preparePassComponentRequest failed. COMPONENT: " +
                 std::to_string(count))
                    .c_str());
            return PLDM_ERROR;
        }

        retVal = doPassComponentTable(yield, componentTable, compImgSetVerStr,
                                      compResp, compRespCode);
        if (retVal != PLDM_SUCCESS)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("runUpdate: doPassComponentTable failed. COMPONENT: " +
                 std::to_string(count))
                    .c_str());

            continue;
        }
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("PassComponentTable command is success.COMPONENT: " +
             std::to_string(count))
                .c_str());

        createAsyncDelay(yield, delayBtw);
    }

    compOffset = pldmImg->getHeaderLen();
    for (uint16_t count = 0; count < compCount; ++count)
    {
        struct update_component_req component;
        uint8_t compCompatabilityResp;
        uint8_t compCompatabilityRespCode;
        bitfield32_t updateOptFlagsEnabled;
        uint16_t estimatedTimeReqFd;
        uint32_t compSize;
        pldmImg->getCompProperty<uint32_t>(compSize, "CompSize", count);
        if (!isComponentApplicable())
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "component not applicable");
            compOffset += compSize;
            continue;
        }
        if (!prepareUpdateComponentRequest(component, count))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("runUpdate: prepareUpdateComponentRequest failed. "
                 "COMPONENT: " +
                 std::to_string(count))
                    .c_str());
            compOffset += compSize;
            continue;
        }
        uint32_t maxNumReq = findMaxNumReq(compSize);
        retVal =
            doUpdateComponent(yield, component, compImgSetVerStr,
                              compCompatabilityResp, compCompatabilityRespCode,
                              updateOptFlagsEnabled, estimatedTimeReqFd);
        if (retVal != PLDM_SUCCESS)
        {

            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("runUpdate: doUpdateComponent failed. RETVAL: " +
                 std::to_string(retVal) +
                 ". COMPONENT: " + std::to_string(count))
                    .c_str());
            compOffset += compSize;
            continue;
        }
        if (compCompatabilityResp != COMPONENT_CAN_BE_UPDATED)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("COMPONENT: " + std::to_string(count) +
                 " will not be updated, "
                 "ComponentCompatibilityResponse Code: " +
                 std::to_string(compCompatabilityRespCode))
                    .c_str());
            compOffset += compSize;
            continue;
        }

        fdState = FD_DOWNLOAD;
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "FD changed state to DOWNLOAD");
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("UpdateComponent command is success. COMPONENT: " +
             std::to_string(count))
                .c_str());

        if (!reserveBandwidth(yield, currentTid, PLDM_FWU, reserveEidTimeOut))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("runUpdate: reserveBandwidth failed. TID: " +
                 std::to_string(currentTid))
                    .c_str());
        }
        else
        {
            isReserveBandwidthActive = true;
        }
        uint32_t offset;
        uint32_t length;

        initialize_fw_update(updateProperties.max_transfer_size, compSize);
        uint8_t verifyResult = 0;
        uint8_t transferResult = 0;
        uint8_t applyResult = 0;
        bitfield16_t compActivationMethodsModification = {};
        expectedCmd = PLDM_REQUEST_FIRMWARE_DATA;
        int prevProgress = 0;
        while (--maxNumReq)
        {
            startTimer(yield, requestFirmwareDataIdleTimeoutMs);
            if (!fdReqMatched)
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    "TimeoutWaiting for requestFirmwareData packet");

                break;
            }
            else
            {
                if (fdTransferCompleted)
                {
                    fdTransferCompleted = false;
                    break;
                }
                retVal = processRequestFirmwareData(fdReq, offset, length,
                                                    compSize, compOffset);
                if (retVal != PLDM_SUCCESS)
                {
                    phosphor::logging::log<phosphor::logging::level::WARNING>(
                        ("runUpdate: processRequestFirmwareData failed. "
                         "RETVAL: " +
                         std::to_string(retVal) +
                         ". COMPONENT: " + std::to_string(count))
                            .c_str());
                    break;
                }
                fdReq.clear();

                int progress = ((offset + length) * 100) / compSize;
                if (prevProgress != progress)
                {
                    prevProgress = progress;
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        ("TID: " + std::to_string(currentTid) +
                         " Component: " + std::to_string(count + 1) +
                         " update package transfered: " +
                         std::to_string(progress) + "%")
                            .c_str());
                }

                if (offset + length > compSize)
                {
                    expectedCmd = PLDM_TRANSFER_COMPLETE;
                    break;
                }
            }
        }

        startTimer(yield, fdCmdTimeout);

        if (fdReqMatched)
        {
            retVal = processTransferComplete(fdReq, transferResult);
            if (retVal != PLDM_SUCCESS)
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    ("runUpdate: processTransferComplete failed. RETVAL: " +
                     std::to_string(retVal) +
                     ". COMPONENT: " + std::to_string(count))
                        .c_str());
                retVal = doCancelUpdateComponent(yield);
                if (retVal != PLDM_SUCCESS)
                {
                    phosphor::logging::log<phosphor::logging::level::WARNING>(
                        ("runUpdate: Failed to run CancelUpdateComponent. "
                         "RETVAL: " +
                         std::to_string(retVal) +
                         ". COMPONENT: " + std::to_string(count))
                            .c_str());
                }
                compOffset += compSize;
                continue;
            }
            phosphor::logging::log<phosphor::logging::level::INFO>(
                ("TransferComplete command is success. COMPONENT: " +
                 std::to_string(count))
                    .c_str());
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("Timeout waiting for Transfer complete. COMPONENT: " +
                 std::to_string(count))
                    .c_str());

            compOffset += compSize;
            continue;
        }
        expectedCmd = PLDM_VERIFY_COMPLETE;

        startTimer(yield, fdCmdTimeout);

        if (fdReqMatched)
        {
            retVal = processVerifyComplete(fdReq, verifyResult);
            if (retVal != PLDM_SUCCESS)
            {

                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    ("runUpdate: processVerifyComplete failed for COMPONENT: " +
                     std::to_string(count) +
                     ".RETVAL: " + std::to_string(retVal))
                        .c_str());
                retVal = doCancelUpdateComponent(yield);
                if (retVal != PLDM_SUCCESS)
                {
                    phosphor::logging::log<phosphor::logging::level::WARNING>(
                        ("runUpdate: Failed to run CancelUpdateComponent. "
                         "RETVAL: " +
                         std::to_string(retVal) +
                         ". COMPONENT: " + std::to_string(count))
                            .c_str());
                }
                compOffset += compSize;
                continue;
            }
            phosphor::logging::log<phosphor::logging::level::INFO>(
                ("VerifyComplete command is success. COMPONENT: " +
                 std::to_string(count))
                    .c_str());
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Timeout waiting for Verify complete",
                phosphor::logging::entry("COMPONENT=%d", count));
            compOffset += compSize;
            continue;
        }
        expectedCmd = PLDM_APPLY_COMPLETE;

        startTimer(yield, fdCmdTimeout);

        if (fdReqMatched)
        {
            retVal = processApplyComplete(fdReq, applyResult,
                                          compActivationMethodsModification);
            if (retVal != PLDM_SUCCESS)
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    ("runUpdate: processApplyComplete failed. RETVAL: " +
                     std::to_string(retVal) +
                     ". COMPONENT: " + std::to_string(count))
                        .c_str());

                compOffset += compSize;
                continue;
            }
            isComponentAvailableForUpdate = true;
            phosphor::logging::log<phosphor::logging::level::INFO>(
                ("ApplyComplete command is success. COMPONENT: " +
                 std::to_string(count))
                    .c_str());
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("Timeout waiting for Apply complete. COMPONENT: " +
                 std::to_string(count + 1))
                    .c_str());

            compOffset += compSize;
            continue;
        }
        compOffset += compSize;
    }
    if (isReserveBandwidthActive)
    {
        isReserveBandwidthActive = false;
        if (!releaseBandwidth(yield, currentTid, PLDM_FWU))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "runUpdate: releaseBandwidth failed");
        }
    }

    if (!isComponentAvailableForUpdate)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("firmware update failed. RETVAL: " + std::to_string(retVal))
                .c_str());
        return retVal;
    }

    bool8_t selfContainedActivationReq = true;
    uint16_t estimatedTimeForSelfContainedActivation = 0;
    retVal = doActivateFirmware(yield, selfContainedActivationReq,
                                estimatedTimeForSelfContainedActivation);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("runUpdate: doActivateFirmware failed. RETVAL: " +
             std::to_string(retVal))
                .c_str());
        return retVal;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "ActivateFirmware command is success");

    createAsyncDelay(yield, estimatedTimeForSelfContainedActivation);
    retVal = getStatus(yield);
    if (retVal != PLDM_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("getStatus command  failed. RETVAL: " + std::to_string(retVal))
                .c_str());
        return retVal;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Firmware update completed successfully for TID:" +
         std::to_string(currentTid))
            .c_str());

    return PLDM_SUCCESS;
}

void pldmMsgRecvFwUpdCallback(const pldm_tid_t tid, const uint8_t msgTag,
                              const bool tagOwner,
                              std::vector<uint8_t>& message)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "PLDM Firmware update message received",
        phosphor::logging::entry("TID=0x%X", tid));
    // pldmImg points to null if FW update is not in progress at this point
    // firmware device should not send any firmware update commands
    if (!pldmImg || !fwUpdate)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Firmware update is not in process, command not excepted");
        return;
    }
    fwUpdate->validateReqForFWUpdCmd(tid, msgTag, tagOwner, message);
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

static bool updateMode = false;
static int initUpdate(const boost::asio::yield_context& yield)
{
    if (updateMode)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "initUpdate: Cannot start firmware update. Firmware update is "
            "already in progress");
        return PLDM_ERROR;
    }
    auto matchedTermini = pldmImg->getMatchedTermini();
    for (const auto& it : matchedTermini)
    {
        pldm_tid_t matchedTid = it.second;
        uint8_t matchedDevIdRecord = it.first;
        fwUpdate = std::make_unique<FWUpdate>(matchedTid, matchedDevIdRecord);
        if (!fwUpdate->setMatchedFDDescriptors())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("initUpdate: Failed to set TargetFDProperties for "
                 "TID: " +
                 std::to_string(matchedTid))
                    .c_str());
            continue;
        }
        pldm::platform::pauseSensorPolling();
        int retVal = fwUpdate->runUpdate(yield);
        if (retVal != PLDM_SUCCESS)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("runUpdate failed for TID: " + std::to_string(matchedTid) +
                 ". RETVAL:" + std::to_string(retVal))
                    .c_str());

            fwUpdate->terminateFwUpdate(yield);
        }
        pldm::platform::resumeSensorPolling();
        updateMode = false;
    }
    return PLDM_SUCCESS;
}

static bool fwuBaseInitialized = false;
static void initializeFWUBase()
{
    std::string objPath = "/xyz/openbmc_project/pldm/fwu";
    expectedCommandTimer =
        std::make_shared<boost::asio::steady_timer>(*getIoContext());
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
            rc = initUpdate(yield);
            if (rc != PLDM_SUCCESS)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "StartFWUpdate: initUpdate failed.");
            }
            pldmImg = nullptr;
            return rc;
        });
    fwuBaseIface->initialize();
    fwuBaseInitialized = true;
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
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("fwuInit success for TID:" + std::to_string(tid)).c_str());

    return true;
}
} // namespace fwu
} // namespace pldm
