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

#include "firmware_update.hpp"

#include <fstream>

namespace pldm
{
namespace fwu
{
constexpr size_t pkgHeaderIdentifierSize = 16;

struct PLDMPkgHeaderInfo
{
    uint8_t packageHeaderIdentifier[pkgHeaderIdentifierSize];
    uint8_t pkgHeaderFormatRevision;
    uint16_t pkgHeaderSize;
    uint8_t
        pkgReleaseDateTime[13]; // size of PackageReleaseDateTime is 13 bytes.
    uint16_t compBitmapBitLength;
    uint8_t pkgVersionStringType;
    uint8_t pkgVersionStringLen;
} __attribute__((packed));

// As per spec 1.0.1
struct FWDevIdRecord
{
    uint16_t recordLength;
    uint8_t descriptorCount;
    uint32_t deviceUpdateOptionFlags;
    uint8_t comImgSetVerStrType;
    uint8_t comImgSetVerStrLen;
    uint16_t fwDevPkgDataLen;
} __attribute__((packed));

// As per spec 1.0.1
struct CompImgInfo
{
    uint16_t compClassification;
    uint16_t compIdentifier;
    uint32_t compComparisonStamp;
    uint16_t compOptions;
    uint16_t requestedCompActivationMethod;
    uint32_t compLocationOffset;
    uint32_t compSize;
    uint8_t compVerStrType;
    uint8_t compVerStrLen;
} __attribute__((packed));

class PLDMImg
{
  public:
    PLDMImg() = delete;
    explicit PLDMImg(const std::string& pldmImgPath);
    /** @brief API that process PLDM firmware update package header
     */
    bool processPkgHdr();
    constexpr uint16_t getHeaderLen() const
    {
        return pkgHdrLen;
    }
    constexpr uint16_t getDevIDRecordCount() const
    {
        return deviceIDRecordCount;
    }
    constexpr uint16_t getTotalCompCount() const
    {
        return totalCompCount;
    }

    /** @brief API that gets PLDM firmware update package header property
     */
    template <typename T>
    bool getPkgProperty(T& value, const std::string& name)
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
        return false;
    }

    /** @brief API that gets PLDM firmware update component property
     */
    template <typename T>
    bool getCompProperty(T& value, const std::string& name, uint16_t compCount)
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
        return false;
    }

    /** @brief API that gets PLDM firmware update device record property
     */
    template <typename T>
    bool getDevIdRcrdProperty(T& value, const std::string& name,
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
        return false;
    }

    /** @brief API that is used to read raw bytes from pldm firmware update
     * image
     */
    bool readData(const size_t startAddr, std::vector<uint8_t>& data,
                  const size_t dataLen);

    constexpr uint32_t getImagesize()
    {
        return static_cast<uint32_t>(pldmImgSize);
    };
    std::vector<std::pair<uint8_t, pldm_tid_t>> getMatchedTermini()
    {
        return matchedTermini;
    }

  private:
    /** @brief API that gets descriptor identifiers data length
     */
    size_t getDescriptorDataLen(const FWDevIdRecord& data,
                                const size_t applicableComponentsLen);

    /** @brief API that gets pldm firmware update package header length
     */
    uint16_t getHdrLen();

    /** @brief API that verifys package header checksum
     */
    bool verifyPkgHdrChecksum();

    /** @brief API that validates package header data
     */
    bool validateHdrDataLen(const size_t bytesLeft, const size_t nextDataSize)
    {
        return !(bytesLeft < nextDataSize);
    }

    /** @brief API that matches package header identifier
     */
    bool matchPkgHdrIdentifier(const uint8_t* packageHeaderIdentifier);

    /** @brief API that advance package header iterator
     */
    bool advanceHdrItr(const size_t dataSize, const size_t nextDataSize);

    /** @brief API that process a postion PLDM firmware update package header
     */
    bool processPkgHdrInfo();

    /** @brief API that process device identification info in the pldm package
     * header
     */
    bool processDevIdentificationInfo();

    /** @brief API that finds the matched terminus
     */
    bool findMatchedTerminus(const uint8_t devIdRecord,
                             const DescriptorsMap& pkgDescriptors);

    /** @brief API that process component data from PLDM firmware update package
     * header
     */
    bool processCompImgInfo();

    /** @brief API that copies package header info to firmware update properties
     * map.
     */
    void copyPkgHdrInfoToMap(const struct PLDMPkgHeaderInfo* headerInfo,
                             const std::string& pkgVersionString);

    /** @brief API that copies device identification info to firmware update
     * properties map.
     */
    void copyDevIdentificationInfoToMap(
        const uint8_t deviceIDRecord, const uint16_t initialDescriptorType,
        const FWDevIdRecord* devIdentificationInfo,
        const std::vector<uint8_t>& applicableComponents,
        const std::string& compImgSetVerStr,
        const std::vector<uint8_t>& fwDevPkgData,
        DescriptorsMap& pkgDescriptorRecords);

    /** @brief API that copies component data to firmware update properties map.
     */
    void copyCompImgInfoToMap(const uint16_t count, const CompImgInfo* compInfo,
                              const std::string& compVerStr);

    std::streamoff pldmImgSize;
    std::ifstream pldmImg;
    uint16_t pkgHdrLen = 0;
    std::vector<uint8_t> hdrData;
    std::vector<uint8_t>::iterator hdrItr;
    uint8_t pkgVersionStringLen = 0;
    uint16_t compBitmapBitLength = 0;
    uint16_t fwDevPkgDataLen = 0;
    uint8_t deviceIDRecordCount = 0;
    uint16_t totalCompCount = 0;
    FWUProperties pkgFWUProperties;
    DevIDRecordsMap pkgDevIDRecords;
    CompPropertiesMap pkgCompProperties;
    std::vector<std::pair<uint8_t, pldm_tid_t>> matchedTermini;
};
} // namespace fwu
} // namespace pldm
