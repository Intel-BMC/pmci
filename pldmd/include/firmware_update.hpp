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
#include <boost/asio/steady_timer.hpp>
#include <fstream>
#include <sdbusplus/asio/object_server.hpp>
#include <vector>

namespace pldm
{
namespace fwu
{
using FWUVariantType = std::variant<uint8_t, uint16_t, uint32_t, uint64_t,
                                    std::string, std::vector<uint8_t>>;
using FWUProperties = std::map<std::string, FWUVariantType>;
using DescriptorsMap = std::map<std::string, std::string>;
using DevIDRecordsMap =
    std::map<uint8_t, std::pair<FWUProperties, DescriptorsMap>>;
using CompPropertiesMap = std::map<uint16_t, FWUProperties>;
using FDProperties =
    std::tuple<FWUProperties, DescriptorsMap, CompPropertiesMap>;
constexpr size_t pkgHeaderIdentifierSize = 16;

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

class FWInventoryInfo
{
  public:
    FWInventoryInfo() = delete;
    FWInventoryInfo(const pldm_tid_t _tid);
    ~FWInventoryInfo();

    /** @brief runs inventory commands
     */
    std::optional<FDProperties>
        runInventoryCommands(boost::asio::yield_context yield);
    /** @brief API that adds inventory info to D-Bus
     */
    void addInventoryInfoToDBus();

  private:
    /** @brief run query device identifiers command
     * @return PLDM_SUCCESS on success and corresponding error completion code
     * on failure
     */
    int runQueryDeviceIdentifiers(boost::asio::yield_context yield);

    /** @brief run get firmware parameters command
     * @return PLDM_SUCCESS on success and corresponding error completion code
     * on failure
     */
    int runGetFirmwareParameters(boost::asio::yield_context yield);

    /** @brief API that unpacks get firmware parameters component data.
     */
    void unpackCompData(const uint16_t count,
                        const std::vector<uint8_t>& compData);

    /** @brief API that copies get firmware parameters component image set data
     * to fwuProperties map.
     */
    void copyCompImgSetData(
        const struct get_firmware_parameters_resp& respData,
        const struct variable_field& activeCompImgSetVerStr,
        const struct variable_field& pendingCompImgSetVerStr);

    /** @brief API that copies get firmware parameters component data to
     * fwuProperties map.
     */
    void copyCompData(const uint16_t count,
                      const struct component_parameter_table* componentData,
                      struct variable_field* activeCompVerStr,
                      struct variable_field* pendingCompVerStr);
    /** @brief API that adds component image set info to D-Bus
     */
    void addCompImgSetDataToDBus();

    /** @brief API that adds descriptor data to D-Bus
     */
    void addDescriptorsToDBus();

    /** @brief API that adds component info to D-Bus
     */
    void addCompDataToDBus();

    /** @brief API that adds pci descriptors to D-Bus
     */
    void addPCIDescriptorsToDBus(const std::string& objPath);

    /** @brief API that gets auto apply property
     */
    bool getCompAutoApply(const uint32_t capabilitiesDuringUpdate);

    pldm_tid_t tid;
    std::shared_ptr<sdbusplus::asio::object_server> objServer;
    const uint16_t timeout = 100;
    const size_t retryCount = 3;
    // map that holds the component properties of a terminus
    CompPropertiesMap compPropertiesMap;
    // map that holds the general properties of a terminus
    FWUProperties fwuProperties;
    // map that holds the descriptors of a terminus
    DescriptorsMap descriptors;
    uint16_t initialDescriptorType;
    std::string activeCompImgSetVerStr;
    std::string pendingCompImgSetVerStr;
};

class FWUpdate
{
  public:
    FWUpdate(const pldm_tid_t _tid, const uint8_t _deviceIDRecord);
    ~FWUpdate();
    int runUpdate(const boost::asio::yield_context& yield);
    void validateReqForFWUpdCmd(const pldm_tid_t tid, const uint8_t messageTag,
                                const bool _tagOwner,
                                const std::vector<uint8_t>& req);
    bool setMatchedFDDescriptors();

  private:
    bool isComponentApplicable();
    int startTimer(const uint16_t interval);
    uint64_t getApplicableComponents();

    int requestUpdate(const boost::asio::yield_context& yield);
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
    int requestFirmwareData(const boost::asio::yield_context& yield);
    int transferComplete(const boost::asio::yield_context& yield);
    int verifyComplete(const boost::asio::yield_context& yield);
    int applyComplete(const boost::asio::yield_context& yield);
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

    pldm_tid_t currentTid;
    uint8_t expectedCmd;
    uint8_t msgTag;
    bool tagOwner;
    std::vector<uint8_t> fdReq;
    bool fdReqMatched = false;
    uint8_t deviceIDRecord;
    const uint16_t timeout = 100;
    const size_t retryCount = 3;
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
    bitfield32_t updateOptionFlagsEnabled = {0};
    uint8_t completionCode = PLDM_SUCCESS;
    boost::asio::steady_timer timer;
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

    /** @brief API that gets PLDM firmware update package header property
     */
    template <typename T>
    bool getPkgProperty(T& value, const std::string& name);

    /** @brief API that runs PLDM firmware package update
     */
    int runPkgUpdate(const boost::asio::yield_context& yield);
    std::unique_ptr<FWUpdate> fwUpdate;

  private:
    /** @brief API that is used to read raw bytes from pldm firmware update
     * image
     */
    bool readData(const size_t startAddr, std::vector<uint8_t>& data,
                  const size_t dataLen);

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

    FWUProperties pkgFWUProperties;
    DevIDRecordsMap pkgDevIDRecords;
    CompPropertiesMap pkgCompProperties;
    std::vector<std::pair<uint8_t, pldm_tid_t>> matchedTermini;
};
} // namespace fwu
} // namespace pldm
