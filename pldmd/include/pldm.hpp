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

#include "base.hpp"

#include <boost/asio.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/spawn.hpp>
#include <memory>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <unordered_map>
#include <vector>

#include "base.h"
#include "mctpw.h"

std::shared_ptr<boost::asio::io_context> getIoContext();
std::shared_ptr<sdbusplus::asio::connection> getSdBus();
std::shared_ptr<sdbusplus::asio::object_server> getObjServer();
std::unique_ptr<sdbusplus::asio::dbus_interface>
    addUniqueInterface(const std::string& path, const std::string& name);

/** @brief flag to enable debugging*/
extern bool debug;

namespace pldm
{
using DBusInterfacePtr = std::shared_ptr<sdbusplus::asio::dbus_interface>;
using DBusObjectPath = std::string;

constexpr pldm_tid_t pldmInvalidTid = 0;
constexpr uint8_t pldmInvalidType = 0xFF;
constexpr size_t pldmMsgHdrSize = sizeof(pldm_msg_hdr);

/** @brief Limit the maximum length of PLDM message*/
constexpr size_t maxPLDMMessageLen = 64 /*Maximum MCTP packet payload len*/ -
                                     1 /*MCTP messageType size*/ -
                                     pldmMsgHdrSize;

/** @brief pldm_empty_request
 *
 * structure representing PLDM empty request.
 */
struct PLDMEmptyRequest
{
    struct pldm_msg_hdr header;
} __attribute__((packed));

/** @brief Creates new Instance ID for PLDM messages
 *
 * Generated instance ID will be unique for each TID
 *
 * @param tid - TID of the PLDM device
 *
 * @return PLDM Instance ID
 */
uint8_t createInstanceId(pldm_tid_t tid);

/** @brief Reserves Bandwidth for firmware device to send command to update
agent
 *
 * During firmware update firmware device need to send commands to update agent.
With this API PLDM daemon tells MCTP daemon to hold the MUX. So that FD can send
the commands to UA(BMC)
 * @param yield - Context object that represents the currently executing
 * coroutine.
 * @param tid - TID of the PLDM device
 * @param pldmType - pldm type.
 * @param timeout - Maximum time period in seconds to hold the mux
 *
 * @return Status of the operation
 */
bool reserveBandwidth(const boost::asio::yield_context yield,
                      const pldm_tid_t tid, const uint8_t pldmType,
                      const uint16_t timeout);

/** @brief Release Bandwidth for tid
 *
 * @param yield - Context object that represents the currently executing
 * coroutine.
 * @param tid - TID of the PLDM device
 * @param pldmType - pldm type.
 *
 * @return Status of the operation
 */
bool releaseBandwidth(const boost::asio::yield_context yield,
                      const pldm_tid_t tid, const uint8_t pldmType);
// TODO: Add an API to free the Instance ID after usage.

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
                            size_t retryCount, std::vector<uint8_t> pldmReq,
                            std::vector<uint8_t>& pldmResp,
                            std::optional<mctpw_eid_t> eid = std::nullopt);

// Helper functions to manage EID-TID mapping
void addToMapper(const pldm_tid_t tid, const mctpw_eid_t eid);
void removeFromMapper(const pldm_tid_t tid);
std::optional<pldm_tid_t> getTidFromMapper(const mctpw_eid_t eid);
std::optional<mctpw_eid_t> getEidFromMapper(const pldm_tid_t tid);

/** @brief Validate PLDM message encode
 *
 * @param tid[in] - TID of the PLDM device
 * @param rc[in] - Return code of the decode operation
 * @param commandString[in] - Command name
 *
 * @return Validation status
 */
bool validatePLDMReqEncode(const pldm_tid_t tid, const int rc,
                           const std::string& commandString);

/** @brief Validate PLDM message decode
 *
 * @param tid[in] - TID of the PLDM device
 * @param rc[in] - Return code of the decode operation
 * @param completionCode[in] - Completion code in the response
 * @param commandString[in] - Command name
 *
 * @return Validation status
 */
bool validatePLDMRespDecode(const pldm_tid_t tid, const int rc,
                            const uint8_t completionCode,
                            const std::string& commandString);

/** @brief Send PLDM message
 *
 * Sends PLDM messages to a PLDM device.
 * Can be used for
 * 1) Broadcast packets
 * 2) PLDM Responses
 * Even if the sender is expecting a response for the message,
 * it can be received through pldmMsgRecvCallback()
 *
 * @param tid - TID of the PLDM device
 * @param msgTag - MCTP message tag
 * @param tagOwner - MCTP tag owner bit
 * @param payload - PLDM message payload
 *
 * @return Status of the operation
 */
bool sendPldmMessage(const pldm_tid_t tid, const uint8_t msgTag,
                     const bool tagOwner, std::vector<uint8_t> payload);

namespace platform
{

/** @brief Initilize Platform Monitoring and Control
 *
 * Initilizes supported functionalities defined in spec DSP0248.
 *
 * @param yield - Context object the represents the currently executing
 * coroutine
 * @param tid - TID of the PLDM terminus
 * @param commandTable - PLDM command table which defines supported Platform M&C
 * versions and commands
 *
 * @return Status of the operation
 */
bool platformInit(boost::asio::yield_context yield, const pldm_tid_t tid,
                  const pldm::base::CommandSupportTable& commandTable);

/** @brief Delete Platform Monitoring and Control
 *
 * Destroy Platform Monitoring and Control resources allocated for specific TID.
 *
 * @param tid - TID of the PLDM terminus
 *
 * @return Status of the operation
 */

bool deleteMnCTerminus(const pldm_tid_t tid);

} // namespace platform

namespace fru
{

bool fruInit(boost::asio::yield_context yield, const pldm_tid_t tid);
bool deleteFRUDevice(const pldm_tid_t tid);

} // namespace fru

namespace fwu
{

bool fwuInit(boost::asio::yield_context yield, const pldm_tid_t tid);
bool deleteFWDevice(const pldm_tid_t tid);
void pldmMsgRecvFwUpdCallback(const pldm_tid_t tid, const uint8_t msgTag,
                              const bool tagOwner,
                              std::vector<uint8_t>& message);

} // namespace fwu

} // namespace pldm
