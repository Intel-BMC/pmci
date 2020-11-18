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

#include "pdr_manager.hpp"

#include "platform.hpp"
#include "pldm.hpp"

#include <codecvt>
#include <phosphor-logging/log.hpp>
#include <queue>

#include "utils.h"

namespace pldm
{
namespace platform
{

PDRManager::PDRManager(const pldm_tid_t tid) : _tid(tid)
{
}

// TODO: remove this API after code complete
static inline void printDebug(const std::string& message)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>(message.c_str());
}

// TODO: remove this API after code complete
static void printPDRInfo(pldm_pdr_repository_info& pdrRepoInfo)
{
    printDebug("GetPDRRepositoryInfo: repositoryState -" +
               std::to_string(pdrRepoInfo.repository_state));
    printDebug("GetPDRRepositoryInfo: recordCount -" +
               std::to_string(pdrRepoInfo.record_count));
    printDebug("GetPDRRepositoryInfo: repositorySize -" +
               std::to_string(pdrRepoInfo.repository_size));
    printDebug("GetPDRRepositoryInfo: largestRecordSize -" +
               std::to_string(pdrRepoInfo.largest_record_size));
    printDebug("GetPDRRepositoryInfo: dataTransferHandleTimeout -" +
               std::to_string(pdrRepoInfo.data_transfer_handle_timeout));
}

// TODO: remove this API after code complete
static void printVector(const std::string& msg, const std::vector<uint8_t>& vec)
{
    printDebug("Length:" + std::to_string(vec.size()));

    std::stringstream ssVec;
    ssVec << msg;
    for (auto re : vec)
    {
        ssVec << " 0x" << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<int>(re);
    }
    printDebug(ssVec.str().c_str());
}

// TODO: remove this API after code complete
static void printPDRResp(const RecordHandle& nextRecordHandle,
                         const transfer_op_flag& transferOpFlag,
                         const uint16_t& recordChangeNumber,
                         const DataTransferHandle& nextDataTransferHandle,
                         const bool& transferComplete,
                         const std::vector<uint8_t>& pdrRecord)
{
    printDebug("GetPDR: nextRecordHandle -" + std::to_string(nextRecordHandle));
    printDebug("GetPDR: transferOpFlag -" + std::to_string(transferOpFlag));
    printDebug("GetPDR: recordChangeNumber -" +
               std::to_string(recordChangeNumber));
    printDebug("GetPDR: nextDataTransferHandle -" +
               std::to_string(nextDataTransferHandle));
    printDebug("GetPDR: transferComplete -" + std::to_string(transferComplete));
    printVector("PDR:", pdrRecord);
}

std::optional<pldm_pdr_repository_info>
    PDRManager::getPDRRepositoryInfo(boost::asio::yield_context& yield)
{
    int rc;
    std::vector<uint8_t> req(sizeof(PLDMEmptyRequest));
    pldm_msg* reqMsg = reinterpret_cast<pldm_msg*>(req.data());

    rc = encode_get_pdr_repository_info_req(createInstanceId(_tid), reqMsg);
    if (!validatePLDMReqEncode(_tid, rc, "GetPDRRepositoryInfo"))
    {
        return std::nullopt;
    }

    std::vector<uint8_t> resp;
    if (!sendReceivePldmMessage(yield, _tid, commandTimeout, commandRetryCount,
                                req, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to send GetPDRRepositoryInfo request",
            phosphor::logging::entry("TID=%d", _tid));
        return std::nullopt;
    }

    pldm_get_pdr_repository_info_resp pdrInfo;
    auto rspMsg = reinterpret_cast<pldm_msg*>(resp.data());

    rc = decode_get_pdr_repository_info_resp(
        rspMsg, resp.size() - pldmMsgHdrSize, &pdrInfo);
    if (!validatePLDMRespDecode(_tid, rc, pdrInfo.completion_code,
                                "GetPDRRepositoryInfo"))
    {
        return std::nullopt;
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "GetPDRRepositoryInfo success",
        phosphor::logging::entry("TID=%d", _tid));
    return pdrInfo.pdr_repo_info;
}

static bool handleGetPDRResp(pldm_tid_t tid, std::vector<uint8_t>& resp,
                             RecordHandle& nextRecordHandle,
                             transfer_op_flag& transferOpFlag,
                             uint16_t& recordChangeNumber,
                             DataTransferHandle& dataTransferHandle,
                             bool& transferComplete,
                             std::vector<uint8_t>& pdrRecord)
{
    int rc;
    uint8_t completionCode{};
    uint8_t transferFlag{};
    uint8_t transferCRC{};
    uint16_t recordDataLen{};
    DataTransferHandle nextDataTransferHandle{};
    auto respMsgPtr = reinterpret_cast<struct pldm_msg*>(resp.data());

    // Get the number of recordData bytes in the response
    rc = decode_get_pdr_resp(respMsgPtr, resp.size() - pldmMsgHdrSize,
                             &completionCode, &nextRecordHandle,
                             &nextDataTransferHandle, &transferFlag,
                             &recordDataLen, nullptr, 0, &transferCRC);
    if (!validatePLDMRespDecode(tid, rc, completionCode, "GetPDR"))
    {
        return false;
    }

    std::vector<uint8_t> pdrData(recordDataLen, 0);
    rc = decode_get_pdr_resp(
        respMsgPtr, resp.size() - pldmMsgHdrSize, &completionCode,
        &nextRecordHandle, &nextDataTransferHandle, &transferFlag,
        &recordDataLen, pdrData.data(), pdrData.size(), &transferCRC);

    if (!validatePLDMRespDecode(tid, rc, completionCode, "GetPDR"))
    {
        return false;
    }

    pdrRecord.insert(pdrRecord.end(), pdrData.begin(), pdrData.end());
    if (transferFlag == PLDM_START)
    {
        auto pdrHdr = reinterpret_cast<pldm_pdr_hdr*>(pdrRecord.data());
        recordChangeNumber = pdrHdr->record_change_num;
    }

    dataTransferHandle = nextDataTransferHandle;
    if ((transferComplete =
             (transferFlag == PLDM_END || transferFlag == PLDM_START_AND_END)))
    {
        if (transferFlag == PLDM_END)
        {
            uint8_t calculatedCRC = crc8(pdrRecord.data(), pdrRecord.size());
            if (calculatedCRC != transferCRC)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "PDR record CRC check failed");
                return false;
            }
        }
    }
    else
    {
        transferOpFlag = PLDM_GET_NEXTPART;
    }
    return true;
}

bool PDRManager::getDevicePDRRecord(boost::asio::yield_context& yield,
                                    const RecordHandle recordHandle,
                                    RecordHandle& nextRecordHandle,
                                    std::vector<uint8_t>& pdrRecord)
{
    std::vector<uint8_t> req(pldmMsgHdrSize + PLDM_GET_PDR_REQ_BYTES);
    auto reqMsgPtr = reinterpret_cast<pldm_msg*>(req.data());
    constexpr size_t requestCount =
        maxPLDMMessageLen - PLDM_GET_PDR_MIN_RESP_BYTES;
    bool transferComplete = false;
    uint16_t recordChangeNumber = 0;
    size_t multipartTransferLimit = 100;
    transfer_op_flag transferOpFlag = PLDM_GET_FIRSTPART;
    DataTransferHandle dataTransferHandle = 0x00;

    // Multipart PDR data transfer
    do
    {
        int rc;
        rc = encode_get_pdr_req(createInstanceId(_tid), recordHandle,
                                dataTransferHandle, transferOpFlag,
                                requestCount, recordChangeNumber, reqMsgPtr,
                                PLDM_GET_PDR_REQ_BYTES);
        if (!validatePLDMReqEncode(_tid, rc, "GetPDR"))
        {
            break;
        }

        std::vector<uint8_t> resp;
        if (!sendReceivePldmMessage(yield, _tid, commandTimeout,
                                    commandRetryCount, req, resp))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to send GetPDR request",
                phosphor::logging::entry("TID=%d", _tid));
            break;
        }

        bool ret = handleGetPDRResp(
            _tid, resp, nextRecordHandle, transferOpFlag, recordChangeNumber,
            dataTransferHandle, transferComplete, pdrRecord);
        if (!ret)
        {
            // Discard the record if decode failed
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "handleGetRecordResp failed");
            // Clear transferComplete if modified
            transferComplete = false;
            break;
        }

        // TODO: remove after code complete
        printPDRResp(nextRecordHandle, transferOpFlag, recordChangeNumber,
                     dataTransferHandle, transferComplete, pdrRecord);

        // Limit the number of middle packets
        // Discard the record if exceeeded.
        if (pdrRecord.size() > pdrRepoInfo.largest_record_size ||
            !(--multipartTransferLimit))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Max PDR record size limit reached",
                phosphor::logging::entry("TID=%d", _tid),
                phosphor::logging::entry("RECORD_HANDLE=%lu", recordHandle));
            break;
        }
    } while (!transferComplete);

    if (!transferComplete)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Multipart PDR data transfer failed. Discarding the record",
            phosphor::logging::entry("TID=%d", _tid),
            phosphor::logging::entry("RECORD_HANDLE=%lu", recordHandle));
        pdrRecord.clear();
        return false;
    }
    return true;
}

bool PDRManager::getDevicePDRRepo(
    boost::asio::yield_context& yield, uint32_t recordCount,
    std::unordered_map<RecordHandle, std::vector<uint8_t>>& devicePDRs)
{
    RecordHandle recordHandle = 0x00;

    do
    {
        std::vector<uint8_t> pdrRecord{};
        RecordHandle nextRecordHandle{};
        if (!getDevicePDRRecord(yield, recordHandle, nextRecordHandle,
                                pdrRecord))
        {
            return false;
        }

        // Discard if an empty record
        if (!pdrRecord.empty())
        {
            devicePDRs.emplace(std::make_pair(recordHandle, pdrRecord));
        }
        recordHandle = nextRecordHandle;

    } while (recordHandle && --recordCount);
    return true;
}

bool PDRManager::addDevicePDRToRepo(
    std::unordered_map<RecordHandle, std::vector<uint8_t>>& devicePDRs)
{
    static bool terminusLPDRFound = false;
    for (auto& pdrRecord : devicePDRs)
    {
        // Update the TID in Terminus Locator PDR before adding to repo
        const pldm_pdr_hdr* pdrHdr =
            reinterpret_cast<const pldm_pdr_hdr*>(pdrRecord.second.data());
        if (pdrHdr->type == PLDM_TERMINUS_LOCATOR_PDR)
        {
            pldm_terminus_locator_pdr* tLocatorPDR =
                reinterpret_cast<pldm_terminus_locator_pdr*>(
                    pdrRecord.second.data());
            if (tLocatorPDR->validity == PLDM_TL_PDR_VALID)
            {
                // Discard the terminus if multiple valid Terminus Locator PDRs
                // are found
                if (terminusLPDRFound)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Multiple valid Terminus Locator PDRs found",
                        phosphor::logging::entry("TID=%d", _tid));
                    return false;
                }
                tLocatorPDR->tid = _tid;
                terminusLPDRFound = true;
                _containerID = tLocatorPDR->container_id;
            }
        }
        pldm_pdr_add(_pdrRepo.get(), pdrRecord.second.data(),
                     pdrRecord.second.size(), pdrRecord.first, true);
    }
    return true;
}

bool PDRManager::constructPDRRepo(boost::asio::yield_context& yield)
{
    uint32_t recordCount = pdrRepoInfo.record_count;

    if (pdrRepoInfo.repository_state != PLDM_PDR_REPOSITORY_STATE_AVAILABLE)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Device PDR record data is unavailable",
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }
    if (!recordCount)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "No PDR records to fetch",
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    std::unordered_map<RecordHandle, std::vector<uint8_t>> devicePDRs{};
    if (!getDevicePDRRepo(yield, recordCount, devicePDRs))
    {
        return false;
    }

    if (!addDevicePDRToRepo(devicePDRs))
    {
        return false;
    }

    uint32_t noOfRecordsFetched = pldm_pdr_get_record_count(_pdrRepo.get());
    if (!noOfRecordsFetched)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No PDR records are added to repo",
            phosphor::logging::entry("TID=%d", _tid));
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::WARNING>(
        ("GetPDR success. " + std::to_string(noOfRecordsFetched) +
         " records fetched out of " + std::to_string(pdrRepoInfo.record_count))
            .c_str(),
        phosphor::logging::entry("TID=%d", _tid));
    return true;
} // namespace platform

static std::optional<std::string> getAuxName(const uint8_t nameStrCount,
                                             const size_t auxNamesLen,
                                             const uint8_t* auxNamesStart)
{
    if (!auxNamesStart)
    {
        return std::nullopt;
    }

    constexpr size_t strASCIInullSize = 1;
    constexpr size_t strUTF16nullSize = 2;
    constexpr size_t codeUnitSize = 2;
    constexpr size_t maxStrLen = 32;
    const std::string supportedLangTag = "en";
    const uint8_t* next = auxNamesStart;
    size_t advanced{};

    for (uint8_t nameCount = 0;
         nameCount < nameStrCount && advanced < auxNamesLen; nameCount++)
    {
        // If the nameLanguageTag and Auxiliary name in the PDR is not null
        // terminated, it will be an issue. Thus limit the string length to
        // maxStrLen. Provided additional one byte buffer to verify if the
        // length is more than maxStrLen. Why: Croping the string will result in
        // incorrect value for subsequent nameLanguageTags and Auxiliary names
        std::string langTag(reinterpret_cast<char const*>(next), 0,
                            maxStrLen + 1);
        // If the nameLanguageTag is not null terminated(Incorrect PDR data -
        // Assuming maximum possible Auxiliary name is of length maxStrLen),
        // further decodings will be erroneous
        if (langTag.size() > maxStrLen)
        {
            return std::nullopt;
        }
        next += langTag.size() + strASCIInullSize;

        std::u16string u16_str(reinterpret_cast<const char16_t*>(next), 0,
                               maxStrLen + 1);
        // If the Auxiliary name is not null terminated(Incorrect PDR data -
        // Assuming maximum possible Auxiliary name is of length maxStrLen),
        // further decodings will be erroneous
        if (u16_str.size() > maxStrLen)
        {
            return std::nullopt;
        }

        // Only supports English
        if (langTag == supportedLangTag)
        {
            std::string auxName =
                std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,
                                     char16_t>{}
                    .to_bytes(u16_str);
            // non printable characters cause sdbusplus exceptions, so better to
            // handle it by replacing with space
            std::replace_if(
                auxName.begin(), auxName.end(),
                [](const char& c) { return !isprint(c); }, ' ');
            return auxName;
        }
        next += (u16_str.size() * codeUnitSize) + strUTF16nullSize;
        advanced = next - auxNamesStart;
    }
    return std::nullopt;
}

void PDRManager::parseEntityAuxNamesPDR()
{
    uint8_t* pdrData = nullptr;
    uint32_t pdrSize{};
    auto record = pldm_pdr_find_record_by_type(_pdrRepo.get(),
                                               PLDM_ENTITY_AUXILIARY_NAMES_PDR,
                                               NULL, &pdrData, &pdrSize);
    while (record)
    {
        constexpr size_t sharedNameCountSize = 1;
        constexpr size_t nameStringCountSize = 1;
        constexpr size_t minEntityAuxNamesPDRLen =
            sizeof(pldm_pdr_hdr) + sizeof(pldm_entity) + sharedNameCountSize +
            nameStringCountSize;

        if (pdrSize >= minEntityAuxNamesPDRLen)
        {
            std::vector<uint8_t> namePDRVec(pdrData, pdrData + pdrSize);
            pldm_pdr_entity_auxiliary_names* namePDR =
                reinterpret_cast<pldm_pdr_entity_auxiliary_names*>(
                    namePDRVec.data());
            LE16TOH(namePDR->entity.entity_type);
            LE16TOH(namePDR->entity.entity_instance_num);
            LE16TOH(namePDR->entity.entity_container_id);

            // TODO: Handle sharedNameCount
            size_t auxNamesLen = pdrSize - minEntityAuxNamesPDRLen;
            if (auto name = getAuxName(namePDR->name_string_count, auxNamesLen,
                                       namePDR->entity_auxiliary_names))
            {
                // Cache the Entity Auxiliary Names
                _entityAuxNames[namePDR->entity] = *name;

                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("Entity Auxiliary Name: " + *name).c_str());
            }
        }
        pdrData = nullptr;
        pdrSize = 0;
        record = pldm_pdr_find_record_by_type(_pdrRepo.get(),
                                              PLDM_ENTITY_AUXILIARY_NAMES_PDR,
                                              record, &pdrData, &pdrSize);
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Entity Auxiliary Names PDR parsing complete");
}

// Create Entity Association node from parsed Entity Association PDR
static bool getEntityAssociation(const std::shared_ptr<pldm_entity[]>& entities,
                                 const size_t numEntities,
                                 EntityNode::NodePtr& entityAssociation)
{
    if (!(0 < numEntities) || !entities)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "No entities in Entity Association PDR");
        return false;
    }
    entityAssociation = std::make_shared<EntityNode>();
    entityAssociation->containerEntity = entities[0];

    for (size_t count = 1; count < numEntities; count++)
    {
        EntityNode::NodePtr containedPtr = std::make_shared<EntityNode>();
        containedPtr->containerEntity = entities[count];

        entityAssociation->containedEntities.emplace_back(
            std::move(containedPtr));
    }
    return true;
}

// Extract root node from the list of Entity Associations parsed by matching
// container ID. Remove the same from list once it is found. Note:- Merge the
// Entity Association PDRs if there is more than one with same root node
// container ID
static EntityNode::NodePtr
    extractRootNode(std::vector<EntityNode::NodePtr>& entityAssociations,
                    ContainerID containerID)
{
    EntityNode::NodePtr entityNode = nullptr;

    entityAssociations.erase(
        std::remove_if(
            entityAssociations.begin(), entityAssociations.end(),
            [&entityNode,
             &containerID](EntityNode::NodePtr& entityAssociation) {
                if (entityAssociation->containerEntity.entity_container_id !=
                    containerID)
                {
                    return false;
                }
                if (!entityNode)
                {
                    entityNode = std::move(entityAssociation);
                }
                else
                {
                    std::move(
                        entityAssociation->containedEntities.begin(),
                        entityAssociation->containedEntities.end(),
                        std::back_inserter(entityNode->containedEntities));
                }
                return true;
            }),
        entityAssociations.end());

    return entityNode;
}

// Get the matching node from Entity Association Tree
static EntityNode::NodePtr getContainedNode(EntityNode::NodePtr& root,
                                            ContainerID containerID)
{
    if (!root)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Root node empty");
        return nullptr;
    }

    std::queue<EntityNode::NodePtr> containedEntityQueue;
    containedEntityQueue.push(root); // Enqueue root
    // Search for EntityNode with matching ContainerID
    while (!containedEntityQueue.empty())
    {
        EntityNode::NodePtr node = containedEntityQueue.front();
        if (node->containerEntity.entity_container_id == containerID)
        {
            return node;
        }

        // Dequeue from queue
        containedEntityQueue.pop();

        // Enqueue all child node of the dequeued entity
        for (EntityNode::NodePtr& entityNode : node->containedEntities)
        {
            containedEntityQueue.push(entityNode);
        }
    }
    phosphor::logging::log<phosphor::logging::level::WARNING>(
        "No matching contained Node found");
    return nullptr;
}

void PDRManager::createEntityAssociationTree(
    std::vector<EntityNode::NodePtr>& entityAssociations)
{
    // Get parent entity association
    EntityNode::NodePtr rootNode =
        extractRootNode(entityAssociations, _containerID);

    if (!rootNode)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to find root node ");
        return;
    }
    _entityAssociationTree = rootNode;

    while (!entityAssociations.empty())
    {
        size_t associationPDRCount = entityAssociations.size();

        entityAssociations.erase(
            std::remove_if(
                entityAssociations.begin(), entityAssociations.end(),
                [&rootNode](EntityNode::NodePtr& entityAssociation) {
                    EntityNode::NodePtr node = getContainedNode(
                        rootNode,
                        entityAssociation->containerEntity.entity_container_id);

                    if (node)
                    {
                        std::move(entityAssociation->containedEntities.begin(),
                                  entityAssociation->containedEntities.end(),
                                  std::back_inserter(node->containedEntities));
                        return true;
                    }
                    return false;
                }),
            entityAssociations.end());

        // Safe check in case there is an invalid PDR
        if (!(entityAssociations.size() < associationPDRCount))
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Invalid Entity Association PDRs found");
            break;
        }
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Successfully created Entity Associaton Tree");
}

void PDRManager::parseEntityAssociationPDR()
{
    uint8_t* pdrData = nullptr;
    uint32_t pdrSize{};
    std::vector<EntityNode::NodePtr> entityAssociations;

    const pldm_pdr_record* record = pldm_pdr_find_record_by_type(
        _pdrRepo.get(), PLDM_PDR_ENTITY_ASSOCIATION, NULL, &pdrData, &pdrSize);

    while (record)
    {
        size_t numEntities{};
        pldm_entity* entitiesPtr = nullptr;
        pldm_entity_association_pdr_extract(pdrData,
                                            static_cast<uint16_t>(pdrSize),
                                            &numEntities, &entitiesPtr);
        std::shared_ptr<pldm_entity[]> entities(entitiesPtr, free);

        EntityNode::NodePtr entityAssociation = nullptr;
        if (getEntityAssociation(entities, numEntities, entityAssociation))
        {
            entityAssociations.emplace_back(std::move(entityAssociation));
        }

        // TODO: Merge the Entity Association PDRs having same containerID

        pdrData = nullptr;
        pdrSize = 0;
        record = pldm_pdr_find_record_by_type(_pdrRepo.get(),
                                              PLDM_PDR_ENTITY_ASSOCIATION,
                                              record, &pdrData, &pdrSize);
    }

    createEntityAssociationTree(entityAssociations);
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Entity Association PDR parsing complete ");
}

void PDRManager::getEntityAssociationPaths(EntityNode::NodePtr& node,
                                           EntityAssociationPath path)
{
    if (node == nullptr)
    {
        return;
    }

    // Append node to the path
    path.emplace_back(node->containerEntity);

    // If it is a leaf add to paths
    if (node->containedEntities.empty())
    {
        _entityObjectPaths.emplace_back(path);
    }
    else
    {
        for (EntityNode::NodePtr& child : node->containedEntities)
        {
            getEntityAssociationPaths(child, path);
        }
    }
}

static void populateEntity(std::shared_ptr<DBusInterface>& entityIntf,
                           const std::string& path, const pldm_entity& entity)
{
    auto objServer = getObjServer();

    entityIntf =
        objServer->add_interface(path, "xyz.openbmc_project.PLDM.Entity");
    entityIntf->register_property("EntityType", entity.entity_type);
    entityIntf->register_property("EntityInstanceNumber",
                                  entity.entity_instance_num);
    entityIntf->register_property("EntityContainerID",
                                  entity.entity_container_id);
    entityIntf->initialize();
    // TODO: expose details from sensor PDR if the entity has a sensor
}

void PDRManager::populateSystemHierarchy()
{
    std::string pldmDevObj =
        "/xyz/openbmc_project/system/" + std::to_string(_tid);

    for (const EntityAssociationPath& path : _entityObjectPaths)
    {
        std::string pathName;
        for (const pldm_entity& entity : path)
        {

            std::string entityAuxName;
            auto itr = _entityAuxNames.find(entity);
            if (itr != _entityAuxNames.end())
            {
                entityAuxName = itr->second;
            }
            else
            {
                // Dummy name if no Auxilary Name found
                entityAuxName = std::to_string(entity.entity_type) + "_" +
                                std::to_string(entity.entity_instance_num) +
                                "_" +
                                std::to_string(entity.entity_container_id);
            }

            // Append entity names for multilevel entity associations
            pathName += "/" + entityAuxName;
            std::string objPath = pldmDevObj + pathName;

            std::shared_ptr<DBusInterface> entityIntf;
            populateEntity(entityIntf, objPath, entity);
            _systemHierarchyIntf[entity] = entityIntf;
        }
    }
    // Clear after usage
    _entityObjectPaths.clear();
}

bool PDRManager::pdrManagerInit(boost::asio::yield_context& yield)
{
    std::optional<pldm_pdr_repository_info> pdrInfo =
        getPDRRepositoryInfo(yield);
    if (!pdrInfo)
    {
        return false;
    }
    pdrRepoInfo = *pdrInfo;
    printPDRInfo(pdrRepoInfo);

    PDRRepo pdrRepo(pldm_pdr_init(), pldm_pdr_destroy);
    _pdrRepo = std::move(pdrRepo);

    if (!constructPDRRepo(yield))
    {
        return false;
    }
    parseEntityAuxNamesPDR();
    parseEntityAssociationPDR();
    getEntityAssociationPaths(_entityAssociationTree, {});
    populateSystemHierarchy();

    return true;
}

} // namespace platform
} // namespace pldm
