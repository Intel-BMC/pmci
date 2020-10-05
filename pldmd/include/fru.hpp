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
#include "pldm.hpp"

#include "fru.h"

namespace pldm
{
namespace fru
{

static constexpr uint16_t timeout = 100;
static constexpr size_t retryCount = 3;

class PLDMFRUCmd
{
  public:
    PLDMFRUCmd() = delete;
    PLDMFRUCmd(boost::asio::yield_context yieldVal, const pldm_tid_t tidVal);
    ~PLDMFRUCmd();

    /** @brief runs supported FRU commands
     *
     * @return true on success; false otherwise
     * on failure
     */
    bool runFRUCommands();

  private:
    /** @brief run GetFRURecordTableMetadata command
     *
     * @return PLDM_SUCCESS on success and corresponding error completion code
     * on failure
     */
    int getFRURecordTableMetadataCmd();

    boost::asio::yield_context yield;
    pldm_tid_t tid;
};

} // namespace fru
} // namespace pldm