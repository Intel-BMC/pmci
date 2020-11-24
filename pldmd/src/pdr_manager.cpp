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

#include <phosphor-logging/log.hpp>

namespace pldm
{
namespace platform
{

PDRManager::PDRManager(const pldm_tid_t tid) : _tid(tid)
{
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

bool PDRManager::pdrManagerInit(boost::asio::yield_context& yield)
{
    std::optional<pldm_pdr_repository_info> pdrInfo =
        getPDRRepositoryInfo(yield);
    if (!pdrInfo)
    {
        return false;
    }
    pdrRepoInfo = *pdrInfo;

    // TODO: Get the PDR and parse
    return true;
}

} // namespace platform
} // namespace pldm
