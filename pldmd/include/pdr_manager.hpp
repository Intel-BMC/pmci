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

    /** @brief PDR Repository Info of this terminus*/
    pldm_pdr_repository_info pdrRepoInfo;

    /** @brief Terminus ID*/
    pldm_tid_t _tid;
};

} // namespace platform
} // namespace pldm
