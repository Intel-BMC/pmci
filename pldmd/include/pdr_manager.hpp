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

using RecordHandle = uint32_t;
using DataTransferHandle = uint32_t;
using PDRDestroyer = std::function<void(pldm_pdr*)>;
using PDRRepo = std::unique_ptr<pldm_pdr, PDRDestroyer>;

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

    /** @brief PDR Repository Info of this terminus*/
    pldm_pdr_repository_info pdrRepoInfo;

    /** @brief pointer to TID mapped BMC PDR repo*/
    PDRRepo _pdrRepo;

    /** @brief Holds Entity Auxiliary Names*/
    std::map<pldm_entity, std::string, EntityComparator> _entityAuxNames;

    /** @brief Terminus ID*/
    pldm_tid_t _tid;
};

} // namespace platform
} // namespace pldm
