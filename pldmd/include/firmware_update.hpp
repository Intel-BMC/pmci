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
#pragma once

#include "fwu_utils.hpp"

#include <boost/asio/steady_timer.hpp>
#include <fstream>
#include <sdbusplus/asio/object_server.hpp>

#include "firmware_update.h"

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

class FWUpdate
{
  public:
    FWUpdate(const pldm_tid_t _tid, const uint8_t _deviceIDRecord);
    int runUpdate(const boost::asio::yield_context& yield);
    void validateReqForFWUpdCmd(const pldm_tid_t tid, const uint8_t messageTag,
                                const bool _tagOwner,
                                const std::vector<uint8_t>& req);
    bool setMatchedFDDescriptors();
    void terminateFwUpdate(const boost::asio::yield_context& yield);

  private:
    bool isComponentApplicable();
    boost::system::error_code
        startTimer(const boost::asio::yield_context& yield,
                   const uint32_t interval);
    uint32_t findMaxNumReq(const uint32_t size)
    {
        return (1 + (size / PLDM_FWU_BASELINE_TRANSFER_SIZE)) * 3;
    }
    uint64_t getApplicableComponents();

    int doRequestUpdate(const boost::asio::yield_context& yield,
                        struct variable_field& compImgSetVerStrn);
    int requestUpdate(const boost::asio::yield_context& yield,
                      struct variable_field& compImgSetVerStrn);
    int sendPackageData(const boost::asio::yield_context& yield);
    int doGetDeviceMetaData(const boost::asio::yield_context& yield,
                            const uint32_t dataTransferHandle,
                            const uint8_t transferOperationFlag,
                            uint32_t& nextDataTransferHandle,
                            uint8_t& transferFlag,
                            std::vector<uint8_t>& portionOfMetaData);
    int getDeviceMetaData(const boost::asio::yield_context& yield,
                          const uint32_t dataTransferHandle,
                          const uint8_t transferOperationFlag,
                          uint32_t& nextDataTransferHandle,
                          uint8_t& transferFlag,
                          std::vector<uint8_t>& portionOfMetaData);
    int doPassComponentTable(
        const boost::asio::yield_context& yield,
        const struct pass_component_table_req& componentTable,
        struct variable_field& compImgSetVerStr, uint8_t& compResp,
        uint8_t& compRespCode);
    int passComponentTable(
        const boost::asio::yield_context& yield,
        const struct pass_component_table_req& componentTable,
        struct variable_field& compImgSetVerStr, uint8_t& compResp,
        uint8_t& compRespCode);
    int doUpdateComponent(const boost::asio::yield_context& yield,
                          const struct update_component_req& component,
                          variable_field& compVerStr,
                          uint8_t& compCompatabilityResp,
                          uint8_t& compCompatabilityRespCode,
                          bitfield32_t& updateOptFlagsEnabled,
                          uint16_t& estimatedTimeReqFd);
    int updateComponent(const boost::asio::yield_context& yield,
                        const struct update_component_req& component,
                        variable_field& compVerStr,
                        uint8_t& compCompatabilityResp,
                        uint8_t& compCompatabilityRespCode,
                        bitfield32_t& updateOptFlagsEnabled,
                        uint16_t& estimatedTimeReqFd);
    int processRequestFirmwareData(const std ::vector<uint8_t>& pldmReq,
                                   uint32_t& offset, uint32_t& length,
                                   const uint32_t componentSize,
                                   const uint32_t componentOffset);
    int requestFirmwareData(const std ::vector<uint8_t>& pldmReq,
                            uint32_t& offset, uint32_t& length,
                            const uint32_t componentSize,
                            const uint32_t componentOffset);
    uint8_t validateTransferComplete(const uint8_t transferResult);
    int processTransferComplete(const std::vector<uint8_t>& pldmReq,
                                uint8_t& transferResult);
    int transferComplete(const std::vector<uint8_t>& pldmReq,
                         uint8_t& transferResult);

    uint8_t validateVerifyComplete(const uint8_t verifyResult);
    int processVerifyComplete(const std::vector<uint8_t>& pldmReq,
                              uint8_t& verifyResult);
    int verifyComplete(const std::vector<uint8_t>& pldmReq,
                       uint8_t& verifyResult);
    uint8_t validateApplyComplete(const uint8_t applyResult);
    int processApplyComplete(const std::vector<uint8_t>& pldmReq,
                             uint8_t& applyResult,
                             bitfield16_t& compActivationMethodsModification);
    int applyComplete(const std::vector<uint8_t>& pldmReq, uint8_t& applyResult,
                      bitfield16_t& compActivationMethodsModification);
    int sendMetaData(const boost::asio::yield_context& yield);
    int doActivateFirmware(const boost::asio::yield_context& yield,
                           bool8_t selfContainedActivationReq,
                           uint16_t& estimatedTimeForSelfContainedActivation);
    int activateFirmware(const boost::asio::yield_context& yield,
                         bool8_t selfContainedActivationReq,
                         uint16_t& estimatedTimeForSelfContainedActivation);
    int getStatus(const boost::asio::yield_context& yield);
    int doCancelUpdateComponent(const boost::asio::yield_context& yield);
    int cancelUpdateComponent(const boost::asio::yield_context& yield);
    int doCancelUpdate(const boost::asio::yield_context& yield,
                       bool8_t& nonFunctioningComponentIndication,
                       bitfield64_t& nonFunctioningComponentBitmap);
    int cancelUpdate(const boost::asio::yield_context& yield,
                     bool8_t& nonFunctioningComponentIndication,
                     bitfield64_t& nonFunctioningComponentBitmap);
    bool sendErrorCompletionCode(const uint8_t fdInstanceId,
                                 const uint8_t complCode,
                                 const uint8_t command);
    bool prepareRequestUpdateCommand(std::string& vrnStr);
    bool preparePassComponentRequest(
        struct pass_component_table_req& componentTable,
        const uint16_t compCnt);
    bool initTransferFlag(const uint16_t compCnt, uint8_t& flag);
    bool prepareUpdateComponentRequest(struct update_component_req& component,
                                       const uint16_t compCnt);

    pldm_tid_t currentTid;
    uint8_t expectedCmd;
    uint8_t msgTag;
    bool tagOwner;
    std::vector<uint8_t> fdReq;
    bool fdReqMatched = false;
    bool isReserveBandwidthActive = false;
    bool isComponentAvailableForUpdate = false;
    uint8_t currentDeviceIDRecord;
    const uint16_t timeout = 100;
    const uint16_t fdCmdTimeout = 5000;
    // Time in milliseconds for the update agent to wait for request firmware
    // data command
    const uint32_t requestFirmwareDataIdleTimeoutMs = 90000;
    const uint16_t reserveEidTimeOut = 900;
    const size_t retryCount = 3;
    const uint16_t delayBtw = 500;
    const uint16_t retryRequestForUpdateDelay = 5000;
    bool updateMode = false;
    uint8_t fdState = FD_IDLE;
    pldm_firmware_update_state state;
    uint16_t packageDataLength = 0;
    uint16_t fwDeviceMetaDataLen = 0;
    uint16_t currentComp = 0;
    uint16_t compCount = 0;
    uint8_t fdWillSendGetPkgDataCmd = 0;
    uint64_t applicableComponentsVal = 0;
    uint8_t currentState = 0;
    uint8_t previousState = 0;
    uint8_t auxState = 0;
    uint8_t auxStateStatus = 0;
    uint8_t progressPercent = 0;
    uint8_t reasonCode = 0;
    bool fdTransferCompleted = false;
    bitfield32_t updateOptionFlagsEnabled = {0};
    uint8_t completionCode = PLDM_SUCCESS;
    struct request_update_req updateProperties = {};
    FDProperties targetFDProperties;
    std::set<uint8_t> cancelUpdateComponentState = {FD_DOWNLOAD, FD_VERIFY,
                                                    FD_APPLY};
};

class PLDMImg
{
  public:
    PLDMImg() = delete;
    PLDMImg(const std::string& pldmImgPath);
    ~PLDMImg();
    /** @brief API that process PLDM firmware update package header
     */
    bool processPkgHdr();
    constexpr uint16_t getHeaderLen()
    {
        return pkgHdrLen;
    }
    constexpr uint16_t getDevIDRecordCount()
    {
        return deviceIDRecordCount;
    }
    constexpr uint16_t getTotalCompCount()
    {
        return totalCompCount;
    }

    /** @brief API that gets PLDM firmware update package header property
     */
    template <typename T>
    bool getPkgProperty(T& value, const std::string& name);

    /** @brief API that gets PLDM firmware update component property
     */
    template <typename T>
    bool getCompProperty(T& value, const std::string& name, uint16_t compCount);

    /** @brief API that gets PLDM firmware update device record property
     */
    template <typename T>
    bool getDevIdRcrdProperty(T& value, const std::string& name,
                              uint8_t recordCount);

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
    inline bool validateHdrDataLen(const size_t bytesLeft,
                                   const size_t nextDataSize);

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
