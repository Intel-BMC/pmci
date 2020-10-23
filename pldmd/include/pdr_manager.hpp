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

    PDRManager(boost::asio::yield_context& yield, const pldm_tid_t tid);

    bool pdrManagerInit();

  private:
    std::optional<pldm_pdr_repository_info> getPDRRepositoryInfo();

    pldm_pdr_repository_info pdrRepoInfo;

    boost::asio::yield_context _yield;

    pldm_tid_t _tid;
};

} // namespace platform
} // namespace pldm
