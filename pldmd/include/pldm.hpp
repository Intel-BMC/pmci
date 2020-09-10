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

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <memory>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <vector>

#include "base.h"
#include "mctpw.h"

std::shared_ptr<boost::asio::io_context> getIoContext();
std::shared_ptr<sdbusplus::asio::connection> getSdBus();
std::shared_ptr<sdbusplus::asio::object_server> getObjServer();

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

/** @brief Returns PLDM message Instance ID
 *
 * Extracts Instance ID out of a PLDM message
 *
 * @param message - PLDM message
 *
 * @return Instance ID
 */
std::optional<uint8_t> getInstanceId(std::vector<uint8_t>& message);

/** @brief Send and Receive PLDM message
 *
 * Atomic API to send and receive PLDM message.
 * The consumer of the API can use coroutine to invoke the method.
 * The asynchronous message send operation with in the method will suspends
 * coroutine till it gets a response.
 * PLDM request messages such as getTID, setTID can pass EID as input param
 * since they don't have the knowledge of TID
 *
 * @param yield - Context object the represents the currently executing
 * coroutine
 * @param tid - TID of the PLDM device
 * @param timeout - Maximum time period within the response is expected
 * @param pldmReq - PLDM request message
 * @param pldmResp - PLDM response message(Pass empty vector to capture
 * response)
 * @param eid - EID of the MCTP device
 *
 * @return Status of the operation
 */
bool sendReceivePldmMessage(boost::asio::yield_context yield,
                            const pldm_tid_t tid, const uint16_t timeout,
                            std::vector<uint8_t> pldmReq,
                            std::vector<uint8_t>& pldmResp,
                            std::optional<mctpw_eid_t> eid = std::nullopt);

// Helper functions to manage EID-TID mapping
std::optional<pldm_tid_t> allocateTid();
void addToMapper(const pldm_tid_t tid, const mctpw_eid_t eid);
std::optional<pldm_tid_t> getTidFromMapper(const mctpw_eid_t eid);
std::optional<mctpw_eid_t> getEidFromMapper(const pldm_tid_t tid);

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
