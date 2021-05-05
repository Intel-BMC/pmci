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
using FRURecordSetIdentifier = uint16_t;

struct EntityComparator
{
    bool operator()(const pldm_entity& lhsEntity,
                    const pldm_entity& rhsEntity) const
    {
        return std::tie(lhsEntity.entity_type, lhsEntity.entity_instance_num,
                        lhsEntity.entity_container_id) ==
               std::tie(rhsEntity.entity_type, rhsEntity.entity_instance_num,
                        rhsEntity.entity_container_id);
    }
};

struct EntityHash
{
    std::size_t operator()(const pldm_entity& key) const
    {
        std::hash<uint16_t> hash_function;
        std::size_t returnValue = hash_function(key.entity_type) +
                                  hash_function(key.entity_instance_num) +
                                  hash_function(key.entity_container_id);

        return returnValue;
    }
};

struct EntityNode
{
    using NodePtr = std::shared_ptr<EntityNode>;
    using ContainedEntities = std::vector<NodePtr>;

    pldm_entity containerEntity;
    ContainedEntities containedEntities;
};

struct PossibleStates
{
    uint16_t stateSetID;
    std::set<uint8_t> possibleStateSetValues;
};

struct StateSensorPDR
{
    pldm_state_sensor_pdr stateSensorData;
    std::vector<PossibleStates> possibleStates;
};

struct StateEffecterPDR
{
    pldm_state_effecter_pdr stateEffecterData;
    std::vector<PossibleStates> possibleStates;
};

class PDRManager
{
  public:
    PDRManager() = delete;
    PDRManager(const PDRManager&) = delete;
    PDRManager(PDRManager&&) = delete;
    PDRManager& operator=(const PDRManager&) = delete;
    PDRManager& operator=(PDRManager&&) = delete;
    ~PDRManager();

    PDRManager(const pldm_tid_t tid);

    bool pdrManagerInit(boost::asio::yield_context& yield);

    /** @brief Get Sensors list*/
    const std::unordered_map<SensorID, std::string>& getSensors()
    {
        return _sensorAuxNames;
    };

    /** @brief Get numeric sensor PDR*/
    std::optional<std::shared_ptr<pldm_numeric_sensor_value_pdr>>
        getNumericSensorPDR(const SensorID& sensorID);

    /** @brief Get state sensor PDR*/
    std::optional<std::shared_ptr<StateSensorPDR>>
        getStateSensorPDR(const SensorID& sensorID);

    /** @brief Get Effecter list*/
    std::unordered_map<EffecterID, std::string> getEffecters()
    {
        return _effecterAuxNames;
    };

    /** @brief Get numeric effecter PDR*/
    std::optional<std::shared_ptr<pldm_numeric_effecter_value_pdr>>
        getNumericEffecterPDR(const EffecterID& effecterID);

    /** @brief Get state effecter PDR*/
    std::shared_ptr<StateEffecterPDR>
        getStateEffecterPDR(const EffecterID& effecterID);

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
    void parseEntityAuxNamesPDR(std::vector<uint8_t>& pdrData);

    /**@brief Create Entity Association Tree from PDRs*/
    void createEntityAssociationTree(
        std::vector<EntityNode::NodePtr>& entityAssociations);

    /**@brief Parse Entity Association PDRs*/
    void parseEntityAssociationPDR(std::vector<uint8_t>& pdrData);

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

    /** @brief Parse FRU Record Set PDR */
    void parseFRURecordSetPDR(std::vector<uint8_t>& pdrData);

    /**@brief General parser to each PDR type*/
    template <pldm_pdr_types pdrType>
    void parsePDR();

    /** @brief Create sensor name with sensor ID*/
    std::string createSensorName(const SensorID sensorID);

    /** @brief Create effecter name with effecter ID*/
    std::string createEffecterName(const EffecterID effecterID);

    /** @brief Initialize interface to dump PDR repo*/
    void initializePDRDumpIntf();

    /** @brief PDR Repository Info of this terminus*/
    pldm_pdr_repository_info pdrRepoInfo;

    /** @brief pointer to TID mapped BMC PDR repo*/
    PDRRepo _pdrRepo;

    /** @brief Holds Entity Auxiliary Names*/
    std::unordered_map<pldm_entity, std::string, EntityHash, EntityComparator>
        _entityAuxNames;

    /** @brief Container ID of the parent entity represented by TID*/
    ContainerID _containerID;

    /** @brief Entity Association tree representing system hierarchy*/
    EntityNode::NodePtr _entityAssociationTree;

    /** @brief Temporary storage for Entity Association paths*/
    std::vector<EntityAssociationPath> _entityObjectPaths;

    std::unordered_map<pldm_entity, std::pair<DBusInterfacePtr, DBusObjectPath>,
                       EntityHash, EntityComparator>
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
    std::map<SensorID, std::shared_ptr<pldm_numeric_sensor_value_pdr>>
        _numericSensorPDR;

    /** @brief Holds Numeric Sensor D-Bus interfaces and Object paths */
    std::map<SensorID, std::pair<DBusInterfacePtr, DBusObjectPath>> _sensorIntf;

    /** @brief Holds Effecter D-Bus interfaces and Object paths */
    std::map<EffecterID, std::pair<DBusInterfacePtr, DBusObjectPath>>
        _effecterIntf;

    /** @brief Holds Numeric Effecter PDR */
    std::map<EffecterID, std::shared_ptr<pldm_numeric_effecter_value_pdr>>
        _numericEffecterPDR;

    /** @brief Holds FRU Record Set D-Bus interfaces and Object paths */
    std::map<FRURecordSetIdentifier,
             std::pair<DBusInterfacePtr, DBusObjectPath>>
        _fruRecordSetIntf;

    /** @brief Holds State Sensor PDR */
    std::unordered_map<SensorID, std::shared_ptr<StateSensorPDR>>
        _stateSensorPDR;

    /** @brief D-Bus interfaces to dump PDR */
    DBusInterfacePtr pdrDumpInterface;

    /** @brief Holds State Effecter PDR */
    std::unordered_map<EffecterID, std::shared_ptr<StateEffecterPDR>>
        _stateEffecterPDR;

    /** @brief Terminus ID*/
    pldm_tid_t _tid;

    /** @brief Temporarily holds entity association nodes, used to create entity
     * association tree
     */
    std::vector<EntityNode::NodePtr> entityAssociationNodes;
};

} // namespace platform
} // namespace pldm
