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

#include <vector>

#include "base.h"

namespace pldm
{

/** @brief Creates new Instance ID for PLDM messages
 *
 * Generated instance ID will be unique for each TID
 *
 * @param tid - TID of the PLDM device
 *
 * @return PLDM Instance ID
 */
uint8_t createInstanceId(pldm_tid_t tid);

namespace platform
{

bool platformInit(const pldm_tid_t tid);
void pldmMsgRecvCallback(const pldm_tid_t tid, std::vector<uint8_t>& message);

} // namespace platform

namespace fru
{

bool fruInit(const pldm_tid_t tid);
void pldmMsgRecvCallback(const pldm_tid_t tid, std::vector<uint8_t>& message);

} // namespace fru

namespace fwu
{

bool fwuInit(const pldm_tid_t tid);
void pldmMsgRecvCallback(const pldm_tid_t tid, std::vector<uint8_t>& message);

} // namespace fwu

} // namespace pldm
