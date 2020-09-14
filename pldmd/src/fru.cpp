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

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace fru
{

bool fruInit(boost::asio::yield_context /*yield*/, const pldm_tid_t tid)
{
    // TODO: Perform the actual init operations needed
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Running FRU initialisation",
        phosphor::logging::entry("TID=0x%X", tid));

    return true;
}
} // namespace fru
} // namespace pldm
