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
#include <sdbusplus/asio/object_server.hpp>

#include "firmware_update.h"

namespace pldm
{
namespace fwu
{

class FWUpdate
{
  public:
    FWUpdate(const pldm_tid_t _tid, const uint8_t _deviceIDRecord);
    int runUpdate(const boost::asio::yield_context yield);
    void validateReqForFWUpdCmd(const pldm_tid_t tid, const uint8_t messageTag,
                                const std::vector<uint8_t>& req);
    bool setMatchedFDDescriptors();
    void terminateFwUpdate(const boost::asio::yield_context yield);

    template <typename propertyType>
    void updateFWUProperty(const boost::asio::yield_context yield,
                           const std::string& interfaceName,
                           const std::string& propertyName,
                           const propertyType& propertyValue);

  private:
    bool isComponentApplicable();
    boost::system::error_code startTimer(const boost::asio::yield_context yield,
                                         const uint32_t interval);
    uint32_t findMaxNumReq(const uint32_t size)
    {
        return (1 + (size / PLDM_FWU_BASELINE_TRANSFER_SIZE)) * 3;
    }
    uint64_t getApplicableComponents();

    int processRequestUpdate(const boost::asio::yield_context yield);
    int requestUpdate(const boost::asio::yield_context yield,
                      struct variable_field& compImgSetVerStrn);
    int processGetDeviceMetaData(const boost::asio::yield_context yield);
    int getDeviceMetaData(const boost::asio::yield_context yield,
                          const uint32_t dataTransferHandle,
                          const uint8_t transferOperationFlag,
                          uint32_t& nextDataTransferHandle,
                          uint8_t& transferFlag);
    int processSendPackageData(const boost::asio::yield_context yield);
    int sendPackageData(const boost::asio::yield_context yield,
                        uint32_t& offset, uint32_t& length);
    uint8_t setTransferFlag(const uint32_t offset, const uint32_t length,
                            const uint32_t dataSize);
    uint32_t calcMaxNumReq(const uint32_t dataSize);
    int processPassComponentTable(const boost::asio::yield_context yield);
    int passComponentTable(
        const boost::asio::yield_context yield,
        const struct pass_component_table_req& componentTable,
        struct variable_field& compImgSetVerStr, uint8_t& compResp,
        uint8_t& compRespCode);
    int processUpdateComponent(const boost::asio::yield_context yield,
                               uint8_t& compCompatabilityResp,
                               uint8_t& compCompatabilityRespCode,
                               bitfield32_t& updateOptFlagsEnabled,
                               uint16_t& estimatedTimeReqFd);
    int updateComponent(const boost::asio::yield_context yield,
                        const struct update_component_req& component,
                        variable_field& compVerStr,
                        uint8_t& compCompatabilityResp,
                        uint8_t& compCompatabilityRespCode,
                        bitfield32_t& updateOptFlagsEnabled,
                        uint16_t& estimatedTimeReqFd);
    int processRequestFirmwareData(const boost::asio::yield_context yield,
                                   const uint32_t componentSize,
                                   const uint32_t componentOffset);
    int requestFirmwareData(const boost::asio::yield_context yield,
                            const std ::vector<uint8_t>& pldmReq,
                            uint32_t& offset, uint32_t& length,
                            const uint32_t componentSize,
                            const uint32_t componentOffset);
    uint8_t validateTransferComplete(const uint8_t transferResult);
    int processTransferComplete(const boost::asio::yield_context yield,
                                const std::vector<uint8_t>& pldmReq,
                                uint8_t& transferResult);
    int transferComplete(const boost::asio::yield_context yield,
                         const std::vector<uint8_t>& pldmReq,
                         uint8_t& transferResult);

    uint8_t validateVerifyComplete(const uint8_t verifyResult);
    int processVerifyComplete(const boost::asio::yield_context yield,
                              const std::vector<uint8_t>& pldmReq,
                              uint8_t& verifyResult);
    int verifyComplete(const boost::asio::yield_context yield,
                       const std::vector<uint8_t>& pldmReq,
                       uint8_t& verifyResult);
    uint8_t validateApplyComplete(const uint8_t applyResult);
    int processApplyComplete(const boost::asio::yield_context yield,
                             const std::vector<uint8_t>& pldmReq,
                             uint8_t& applyResult,
                             bitfield16_t& compActivationMethodsModification);
    int applyComplete(const boost::asio::yield_context yield,
                      const std::vector<uint8_t>& pldmReq, uint8_t& applyResult,
                      bitfield16_t& compActivationMethodsModification);
    int sendMetaData(const boost::asio::yield_context yield);
    int processActivateFirmware(
        const boost::asio::yield_context yield,
        bool8_t selfContainedActivationReq,
        uint16_t& estimatedTimeForSelfContainedActivation);
    int activateFirmware(const boost::asio::yield_context yield,
                         bool8_t selfContainedActivationReq,
                         uint16_t& estimatedTimeForSelfContainedActivation);
    int getStatus(const boost::asio::yield_context yield);
    int doCancelUpdateComponent(const boost::asio::yield_context yield);
    int cancelUpdateComponent(const boost::asio::yield_context yield);
    int doCancelUpdate(const boost::asio::yield_context yield,
                       bool8_t& nonFunctioningComponentIndication,
                       bitfield64_t& nonFunctioningComponentBitmap);
    int cancelUpdate(const boost::asio::yield_context yield,
                     bool8_t& nonFunctioningComponentIndication,
                     bitfield64_t& nonFunctioningComponentBitmap);
    bool sendErrorCompletionCode(const boost::asio::yield_context yield,
                                 const uint8_t fdInstanceId,
                                 const uint8_t complCode,
                                 const uint8_t command);
    bool prepareRequestUpdateCommand();
    bool preparePassComponentRequest(
        struct pass_component_table_req& componentTable,
        std::string& compVersionString, const uint16_t compCnt);
    bool initTransferFlag(const uint16_t compCnt, uint8_t& flag);
    bool prepareUpdateComponentRequest(struct update_component_req& component);

    void compUpdateProgress(const boost::asio::yield_context yield);

    int processSendMetaData(const boost::asio::yield_context yield);
    int sendMetaData(const boost::asio::yield_context yield, uint32_t& offset,
                     uint32_t& length);

    pldm_tid_t currentTid;
    uint8_t expectedCmd;
    uint8_t msgTag;
    std::vector<uint8_t> fdReq;
    bool fdReqMatched = false;
    bool isReserveBandwidthActive = false;
    bool isComponentAvailableForUpdate = false;
    uint8_t currentDeviceIDRecord;
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
    std::string componentImageSetVersionString;
    bitfield32_t updateOptionFlagsEnabled = {0};
    uint8_t completionCode = PLDM_SUCCESS;
    struct request_update_req updateProperties = {};
    FDProperties targetFDProperties;
    std::set<uint8_t> cancelUpdateComponentState = {FD_DOWNLOAD, FD_VERIFY,
                                                    FD_APPLY};
    uint8_t transferHandle = 0;
    std::vector<uint8_t> packageData;
    std::vector<uint8_t> fwDeviceMetaData;
};
} // namespace fwu
} // namespace pldm
