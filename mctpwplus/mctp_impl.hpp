/*
// Copyright (c) 2021 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#pragma once

#include "mctp_wrapper.hpp"

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace mctpw
{
/// MCTP Endpoint Id
using eid_t = uint8_t;
using ByteArray = std::vector<uint8_t>;

namespace internal
{
struct NewServiceCallback;
struct DeleteServiceCallback;
} // namespace internal

/**
 * @brief Wrapper class to access MCTP functionalities
 *
 */
class MCTPImpl
{
  public:
    /**
     * @brief Construct a new MCTPImpl object
     *
     * @param ioContext boost io_context object
     * @param configIn MCTP configuration to describe message type and vendor
     * specific data if required.
     * @param networkChangeCb Callback to be executed when a network change
     * occurs in the system. For example a new device is inserted or removed etc
     * @param rxCb Callback to be executed when new MCTP message is
     */
    MCTPImpl(boost::asio::io_context& ioContext,
             const MCTPConfiguration& configIn,
             const ReconfigurationCallback& networkChangeCb,
             const ReceiveMessageCallback& rxCb);
    /**
     * @brief Construct a new MCTPImpl object
     *
     * @param conn shared_ptr to already existing boost asio::connection object
     * @param configIn MCTP configuration to describe message type and vendor
     * specific data if required.
     * @param networkChangeCb Callback to be executed when a network change
     * occurs in the system. For example a new device is inserted or removed etc
     * @param rxCb Callback to be executed when new MCTP message is
     */
    MCTPImpl(std::shared_ptr<sdbusplus::asio::connection> conn,
             const MCTPConfiguration& configIn,
             const ReconfigurationCallback& networkChangeCb,
             const ReceiveMessageCallback& rxCb);

    using StatusCallback =
        std::function<void(boost::system::error_code, void*)>;
    /* Endpoint map entry: eid_t,pair(bus,service) */
    using EndpointMap =
        std::unordered_map<uint8_t, std::pair<unsigned, std::string>>;
    using ReceiveCallback =
        std::function<void(boost::system::error_code, ByteArray&)>;
    using SendCallback = std::function<void(boost::system::error_code, int)>;
    using ReconfigurationCallback = std::function<void(
        void*, const Event&, boost::asio::yield_context& yield)>;
    using ReceiveMessageCallback =
        std::function<void(void*, eid_t, bool, uint8_t, const ByteArray&, int)>;
    std::shared_ptr<sdbusplus::asio::connection> connection;
    mctpw::MCTPConfiguration config{};
    /// Callback to be executed when a network change occurs
    ReconfigurationCallback networkChangeCallback = nullptr;
    /// Callback to be executed when a MCTP message received
    ReceiveMessageCallback receiveCallback = nullptr;

    static const inline std::unordered_map<MessageType, const std::string>
        msgTypeToPropertyName = {{MessageType::pldm, "PLDM"},
                                 {MessageType::ncsi, "NCSI"},
                                 {MessageType::ethernet, "Ethernet"},
                                 {MessageType::nvmeMgmtMsg, "NVMeMgmtMsg"},
                                 {MessageType::spdm, "SPDM "},
                                 {MessageType::securedMsg, "SECUREDMSG"},
                                 {MessageType::vdpci, "VDPCI"},
                                 {MessageType::vdiana, "VDIANA"}};
    /**
     * @brief This method or its yield variant must be called before accessing
     * any send receive functions. It scan and detect all mctp endpoints exposed
     * on dbus.
     *
     * @param callback Callback to be invoked after mctp endpoint detection with
     * status of the operation
     */
    void detectMctpEndpointsAsync(StatusCallback&& callbackc);
    /**
     * @brief This method or its async variant must be called before accessing
     * any send receive functions. It scan and detect all mctp endpoints exposed
     * on dbus.
     *
     * @param yield boost yield_context object to yield on dbus calls
     * @return boost::system::error_code
     */
    boost::system::error_code
        detectMctpEndpoints(boost::asio::yield_context yield);
    /**
     * @brief Get a reference to internaly maintained EndpointMap
     *
     * @return const EndpointMap&
     */
    inline const EndpointMap& getEndpointMap() const
    {
        return this->endpointMap;
    }

    /**
     * @brief Send request to dstEId and receive response asynchronously in
     * receiveCb
     *
     * @param receiveCb Callback to be executed when response is ready
     * @param dstEId Destination MCTP Endpoint ID
     * @param request MCTP request byte array
     * @param timeout MCTP receive timeout
     */
    void sendReceiveAsync(ReceiveCallback receiveCb, eid_t dstEId,
                          const ByteArray& request,
                          std::chrono::milliseconds timeout);

    /**
     * @brief Send request to dstEId and receive response using yield_context
     *
     * @param yield Boost yield_context to use on dbus call
     * @param dstEId Destination MCTP Endpoint ID
     * @param request MCTP request byte array
     * @param timeout MCTP receive timeout
     * @return std::pair<boost::system::error_code, ByteArray> Pair of boost
     * error code and response byte array
     */
    std::pair<boost::system::error_code, ByteArray>
        sendReceiveYield(boost::asio::yield_context yield, eid_t dstEId,
                         const ByteArray& request,
                         std::chrono::milliseconds timeout);
    /**
     * @brief Send MCTP request to dstEId and receive status of send operation
     * in callback
     *
     * @param callback Callback that will be invoked with status of send
     * operation
     * @param dstEId Destination MCTP Endpoint ID
     * @param msgTag MCTP message tag value
     * @param tagOwner MCTP tag owner bit. Identifies whether the message tag
     * was originated by the endpoint that is the source of the message
     * @param request MCTP request byte array
     */
    void sendAsync(const SendCallback& callback, const eid_t dstEId,
                   const uint8_t msgTag, const bool tagOwner,
                   const ByteArray& request);

    /**
     * @brief Send MCTP request to dstEId and receive status of send operation
     *
     * @param yield boost yiled_context object to yield on dbus calls
     * @param dstEId Destination MCTP Endpoint ID
     * @param msgTag MCTP message tag value
     * @param tagOwner MCTP tag owner bit. Identifies whether the message tag
     * was originated by the endpoint that is the source of the message
     * @param request MCTP request byte array
     * @return std::pair<boost::system::error_code, int> Pair of boost
     * error_code and dbus send method call return value
     */
    std::pair<boost::system::error_code, int>
        sendYield(boost::asio::yield_context& yield, const eid_t dstEId,
                  const uint8_t msgTag, const bool tagOwner,
                  const ByteArray& request);
    void addToEidMap(boost::asio::yield_context yield,
                     const std::string& serviceName/*, uint16_t vid,
                     uint16_t vmsgType*/);
    size_t eraseDevice(eid_t eid);

  private:
    std::unordered_map<
        std::string, std::vector<std::unique_ptr<sdbusplus::bus::match::match>>>
        matchers;
    std::unordered_map<std::string,
                       std::unique_ptr<sdbusplus::bus::match::match>>
        monitorServiceMatchers;
    EndpointMap endpointMap;
    // Get list of pair<bus, service_name_string> which expose mctp object
    std::optional<std::vector<std::pair<unsigned, std::string>>>
        findBusByBindingType(boost::asio::yield_context yield);
    /* Return format: map<Eid, pair<bus, service_name_string>> */
    EndpointMap buildMatchingEndpointMap(
        boost::asio::yield_context yield,
        std::vector<std::pair<unsigned, std::string>>& buses);
    // Get bus id from servicename. Example: Returns 2 if device path is
    // /dev/i2c-2
    int getBusId(const std::string& serviceName);
    void listenForNewMctpServices();
    void listenForRemovedMctpServices();
    void registerListeners(const std::string& serviceName);
    void unRegisterListeners(const std::string& serviceName);
    friend struct internal::NewServiceCallback;
    friend struct internal::DeleteServiceCallback;
};
} // namespace mctpw
