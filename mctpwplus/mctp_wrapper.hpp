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

/**
 * @brief MCTP Binding Type
 *
 */
enum class BindingType : uint8_t
{
    mctpOverSmBus = 0x01,
    mctpOverPcieVdm = 0x02,
    mctpOverUsb = 0x03,
    mctpOverKcs = 0x04,
    mctpOverSerial = 0x05,
    vendorDefined = 0xFF,
};

/**
 * @brief MCTP Message Type
 *
 */
enum class MessageType : uint8_t
{
    /** @brief Platform Level Data Model over MCTP */
    pldm = 0x01,
    /** @brief NC-SI over MCTP */
    ncsi = 0x02,
    /** @brief Ethernet over MCTP */
    ethernet = 0x03,
    /** @brief NVM Express Management Messages over MCTP */
    nvmeMgmtMsg = 0x04,
    /** @brief Security Protocol and Data Model over MCTP */
    spdm = 0x05,
    /** @brief Vendor Defined PCI */
    vdpci = 0x7E,
    /** @brief Vendor Defined IANA */
    vdiana = 0x7F,
};

/**
 * @brief Configuration values to create MCTPWrapper
 *
 */
struct MCTPConfiguration
{
    /**
     * @brief Construct a new MCTPConfiguration object with default values
     *
     */
    MCTPConfiguration() = default;
    /**
     * @brief Construct a new MCTPConfiguration object
     *
     * @param msgType MCTP message type
     * @param binding MCTP binding type
     */
    MCTPConfiguration(MessageType msgType, BindingType binding);
    /**
     * @brief Construct a new MCTPConfiguration object
     *
     * @param msgType MCTP message type. Only VDPCI supported now with vendor
     * defined parameters
     * @param binding MCTP binding type
     * @param vid Vendor Id
     * @param vendorMsgType Vendor defined message type
     * @param vendorMsgTypeMask Vendor defines message type mask
     */
    MCTPConfiguration(MessageType msgType, BindingType binding, uint16_t vid,
                      uint16_t vendorMsgType, uint16_t vendorMsgTypeMask);

    /// MCTP message type
    MessageType type;
    /// MCTP binding type
    BindingType bindingType;

    struct VendorDefinedValues
    {
        VendorDefinedValues(uint16_t vid, uint16_t type, uint16_t mask) :
            vendorId(vid), vendorMessageType(type), vendorMessageTypeMask(mask)
        {
        }
        /// Vendor Id
        uint16_t vendorId;
        /// Vendor defined message type
        uint16_t vendorMessageType;
        /// Vendor defined message mask
        uint16_t vendorMessageTypeMask;
    };
    std::optional<VendorDefinedValues> vendorDefinedValues = std::nullopt;

    /**
     * @brief Set vendor defined parameters. Input values are expected to be in
     * CPU byte order
     *
     * @param vid Vendor Id
     * @param msgType Vendor Message Type
     * @param mask Vednor Message Type Mask
     */
    inline void setVendorDefinedValues(uint16_t vid, uint16_t msgType,
                                       uint16_t mask)
    {
        this->vendorDefinedValues = std::make_optional<VendorDefinedValues>(
            htobe16(vid), htobe16(msgType), htobe16(mask));
    }
};

struct Event
{
    enum class EventType : uint8_t
    {
        deviceAdded,
        deviceRemoved,
    };
    EventType type;
    eid_t eid;
};

using ReconfigurationCallback =
    std::function<void(void*, const Event&, boost::asio::yield_context& yield)>;
using ReceiveMessageCallback =
    std::function<void(void*, eid_t, bool, uint8_t, const ByteArray&, int)>;

/**
 * @brief Wrapper class to access MCTP functionalities
 *
 */
class MCTPWrapper
{
  public:
    using StatusCallback =
        std::function<void(boost::system::error_code, void*)>;
    /* Endpoint map entry: eid_t,pair(bus,service) */
    using EndpointMap =
        std::unordered_map<uint8_t, std::pair<unsigned, std::string>>;
    using ReceiveCallback =
        std::function<void(boost::system::error_code, ByteArray&)>;
    using SendCallback = std::function<void(boost::system::error_code, int)>;

    /**
     * @brief Construct a new MCTPWrapper object
     *
     * @param ioContext boost io_context object. Usable if invoker is an sdbus
     * unaware app.
     * @param configIn MCTP configuration to describe message type and vendor
     * specific data if required.
     * @param networkChangeCb Callback to be executed when a network change
     * occurs in the system. For example a new device is inserted or removed etc
     * @param rxCb Callback to be executed when new MCTP message is
     * received.
     */
    MCTPWrapper(boost::asio::io_context& ioContext,
                const MCTPConfiguration& configIn,
                const ReconfigurationCallback& networkChangeCb = nullptr,
                const ReceiveMessageCallback& rxCb = nullptr);
    /**
     * @brief Construct a new MCTPWrapper object
     *
     * @param conn shared_ptr to already existing boost asio::connection
     * object. Usable if invoker is sdbus aware and uses asio::connection for
     * some other purposes.
     * @param configIn MCTP configuration to describe message type and vendor
     * specific data if required.
     * @param networkChangeCb Callback to be executed when a network change
     * occurs in the system. For example a new device is inserted or removed etc
     * @param rxCb Callback to be executed when new MCTP message is
     * received.
     */
    MCTPWrapper(std::shared_ptr<sdbusplus::asio::connection> conn,
                const MCTPConfiguration& configIn,
                const ReconfigurationCallback& networkChangeCb = nullptr,
                const ReceiveMessageCallback& rxCb = nullptr);
    /**
     * @brief Destroy the MCTPWrapper object
     *
     */
    ~MCTPWrapper() noexcept;
    /**
     * @brief This method or its yield variant must be called before accessing
     * any send receive functions. It scan and detect all mctp endpoints exposed
     * on dbus.
     *
     * @param callback Callback to be invoked after mctp endpoint detection with
     * status of the operation
     */
    void detectMctpEndpointsAsync(StatusCallback&& callback);
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
     * @brief Send MCTP request to dstEID and receive status of send operation
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
     * @brief Send MCTP request to dstEID and receive status of send operation
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

    /// Callback to be executed when a network change occurs
    ReconfigurationCallback networkChangeCallback = nullptr;
    /// Callback to be executed when a MCTP message received
    ReceiveMessageCallback receiveCallback = nullptr;
    /// MCTP Configuration to store message type and vendor defined properties
    MCTPConfiguration config{};

  private:
    std::vector<std::unique_ptr<sdbusplus::bus::match::match>> matchers;
    EndpointMap endpointMap;
    std::shared_ptr<sdbusplus::asio::connection> connection;

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
};

} // namespace mctpw
