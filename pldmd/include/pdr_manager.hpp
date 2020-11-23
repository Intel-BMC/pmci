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

#include "pldm.hpp"

#include <boost/asio.hpp>

#include "platform.h"

namespace pldm
{
namespace platform
{

using ContainerID = uint16_t;
using RecordHandle = uint32_t;
using DataTransferHandle = uint32_t;
using PDRDestroyer = std::function<void(pldm_pdr*)>;
using PDRRepo = std::unique_ptr<pldm_pdr, PDRDestroyer>;
using EntityAssociationPath = std::vector<pldm_entity>;
using SensorID = uint16_t;
using EffecterID = uint16_t;

struct EntityComparator
{
    bool operator()(const pldm_entity& lhsEntity,
                    const pldm_entity& rhsEntity) const
    {
        return std::tie(lhsEntity.entity_type, lhsEntity.entity_instance_num,
                        lhsEntity.entity_container_id) <
               std::tie(rhsEntity.entity_type, rhsEntity.entity_instance_num,
                        rhsEntity.entity_container_id);
    }
};

struct EntityNode
{
    using NodePtr = std::shared_ptr<EntityNode>;
    using ContainedEntities = std::vector<NodePtr>;

    pldm_entity containerEntity;
    ContainedEntities containedEntities;
};

class PDRManager
{
  public:
    PDRManager() = delete;
    PDRManager(const PDRManager&) = delete;
    PDRManager(PDRManager&&) = delete;
    PDRManager& operator=(const PDRManager&) = delete;
    PDRManager& operator=(PDRManager&&) = delete;
    ~PDRManager() = default;

    PDRManager(const pldm_tid_t tid);

    bool pdrManagerInit(boost::asio::yield_context& yield);

  private:
    /** @brief fetch PDR Repository Info from terminus*/
    std::optional<pldm_pdr_repository_info>
        getPDRRepositoryInfo(boost::asio::yield_context& yield);

    /** @brief fetch single PDR record from terminus*/
    bool getDevicePDRRecord(boost::asio::yield_context& yield,
                            const RecordHandle recordHandle,
                            RecordHandle& nextRecordHandle,
                            std::vector<uint8_t>& pdrRecord);

    /** @brief fetch PDR repo from terminus*/
    bool getDevicePDRRepo(
        boost::asio::yield_context& yield, uint32_t recordCount,
        std::unordered_map<RecordHandle, std::vector<uint8_t>>& pdrRepo);

    /** @brief Add Device PDRs to BMC PDR repo*/
    bool addDevicePDRToRepo(
        std::unordered_map<RecordHandle, std::vector<uint8_t>>& pdrRepo);

    /** @brief fetch PDRs from terminus and add to BMC PDR repo*/
    bool constructPDRRepo(boost::asio::yield_context& yield);

    /** @brief Parse the Auxiliary Names PDR */
    void parseEntityAuxNamesPDR();

    /**@brief Create Entity Association Tree from PDRs*/
    void createEntityAssociationTree(
        std::vector<EntityNode::NodePtr>& entityAssociations);

    /**@brief Parse Entity Association PDRs*/
    void parseEntityAssociationPDR();

    /** @brief Get all entity association paths from entity association tree
     * through recursion*/
    void getEntityAssociationPaths(EntityNode::NodePtr& node,
                                   EntityAssociationPath path);

    /** @brief Populate all the PLDM entities on D-Bus to represent system
     * hierarchy*/
    void populateSystemHierarchy();

    /** @brief Parse Sensor Auxiliary Names PDR */
    void parseSensorAuxNamesPDR(std::vector<uint8_t>& pdrData);

    /** @brief Parse Effecter Auxiliary Names PDR */
    void parseEffecterAuxNamesPDR(std::vector<uint8_t>& pdrData);

    /** @brief get Entity D-Bus Object path */
    std::optional<DBusObjectPath>
        getEntityObjectPath(const pldm_entity& entity);

    /** @brief get Sensor Auxiliary name*/
    std::optional<std::string> getSensorAuxNames(const SensorID& sensorID);

    /** @brief Create sensor object path from entity path and sensor name*/
    std::optional<DBusObjectPath> createSensorObjPath(const pldm_entity& entity,
                                                      const SensorID& sensorID,
                                                      const bool8_t auxNamePDR);

    /** @brief Parse Numeric Sensor PDR */
    void parseNumericSensorPDR(std::vector<uint8_t>& pdrData);

    /** @brief Parse State Sensor PDR */
    void parseStateSensorPDR(std::vector<uint8_t>& pdrData);

    /** @brief get Effecter Auxiliary name*/
    std::optional<std::string>
        getEffecterAuxNames(const EffecterID& effecterID);

    /** @brief Create effecter object path from entity path and effecter name*/
    std::optional<DBusObjectPath>
        createEffecterObjPath(const pldm_entity& entity,
                              const EffecterID& effecterID,
                              const bool8_t auxNamePDR);

    /** @brief Parse Numeric Effecter PDR */
    void parseNumericEffecterPDR(std::vector<uint8_t>& pdrData);

    /** @brief Parse State Effecter PDR */
    void parseStateEffecterPDR(std::vector<uint8_t>& pdrData);

    /**@brief General parser to each PDR type*/
    template <pldm_pdr_types pdrType>
    void parsePDR();

    /** @brief PDR Repository Info of this terminus*/
    pldm_pdr_repository_info pdrRepoInfo;

    /** @brief pointer to TID mapped BMC PDR repo*/
    PDRRepo _pdrRepo;

    /** @brief Holds Entity Auxiliary Names*/
    std::map<pldm_entity, std::string, EntityComparator> _entityAuxNames;

    /** @brief Container ID of the parent entity represented by TID*/
    ContainerID _containerID;

    /** @brief Entity Association tree representing system hierarchy*/
    EntityNode::NodePtr _entityAssociationTree;

    /** @brief Temporary storage for Entity Association paths*/
    std::vector<EntityAssociationPath> _entityObjectPaths;

    std::map<pldm_entity, std::pair<DBusInterfacePtr, DBusObjectPath>,
             EntityComparator>
        _systemHierarchyIntf;

    /** @brief Holds Sensor Auxiliary Names.
     * Note:- SensorID is considered as unique within a terminus
     */
    std::unordered_map<SensorID, std::string> _sensorAuxNames;

    /** @brief Holds Effecter Auxiliary Names.
     * Note:- EffecterID is considered as unique within a terminus
     */
    std::unordered_map<EffecterID, std::string> _effecterAuxNames;

    /** @brief Holds Numeric Sensor PDR */
    std::map<SensorID, pldm_numeric_sensor_value_pdr> _numericSensorPDR;

    /** @brief Holds Numeric Sensor D-Bus interfaces and Object paths */
    std::map<SensorID, std::pair<DBusInterfacePtr, DBusObjectPath>> _sensorIntf;

    /** @brief Holds Effecter D-Bus interfaces and Object paths */
    std::map<EffecterID, std::pair<DBusInterfacePtr, DBusObjectPath>>
        _effecterIntf;

    /** @brief Holds Numeric Effecter PDR */
    std::map<EffecterID, pldm_numeric_effecter_value_pdr> _numericEffecterPDR;

    /** @brief Terminus ID*/
    pldm_tid_t _tid;
};

} // namespace platform
} // namespace pldm
