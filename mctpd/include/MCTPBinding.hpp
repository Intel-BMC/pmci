#pragma once

#include <libmctp-cmds.h>
#include <libmctp.h>

#include <boost/asio/steady_timer.hpp>
#include <iostream>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/MCTP/Base/server.hpp>
#include <xyz/openbmc_project/MCTP/Endpoint/server.hpp>
#include <xyz/openbmc_project/MCTP/SupportedMessageTypes/server.hpp>

#ifdef USE_MOCK
#include "../tests/mocks/objectServerMock.hpp"
using object_server = mctpd_mock::object_server_mock;
using dbus_interface = mctpd_mock::dbus_interface_mock;
#else
using object_server = sdbusplus::asio::object_server;
using dbus_interface = sdbusplus::asio::dbus_interface;
#endif

using mctp_server = sdbusplus::xyz::openbmc_project::MCTP::server::Base;
using mctp_endpoint = sdbusplus::xyz::openbmc_project::MCTP::server::Endpoint;
using mctp_msg_types =
    sdbusplus::xyz::openbmc_project::MCTP::server::SupportedMessageTypes;

class SMBusBinding;
class PCIeBinding;

struct SMBusConfiguration
{
    mctp_server::MctpPhysicalMediumIdentifiers mediumId;
    mctp_server::BindingModeTypes mode;
    uint8_t defaultEid;
    std::set<uint8_t> eidPool;
    std::string bus;
    bool arpMasterSupport;
    uint8_t bmcSlaveAddr;
    unsigned int reqToRespTime;
    uint8_t reqRetryCount;
};

struct PcieConfiguration
{
    mctp_server::MctpPhysicalMediumIdentifiers mediumId;
    mctp_server::BindingModeTypes mode;
    uint8_t defaultEid;
    uint16_t bdf;
    unsigned int reqToRespTime;
    uint8_t reqRetryCount;
    uint8_t getRoutingInterval;
};

struct MsgTypes
{
    bool mctpControl = true;
    bool pldm = false;
    bool ncsi = false;
    bool ethernet = false;
    bool nvmeMgmtMsg = false;
    bool spdm = false;
    bool vdpci = false;
    bool vdiana = false;
};

struct EndpointProperties
{
    uint8_t endpointEid;
    std::string uuid;
    mctp_server::BindingModeTypes mode;
    uint16_t networkId;
    MsgTypes endpointMsgTypes;
};

struct MsgTypeSupportCtrlResp
{
    mctp_ctrl_msg_hdr ctrlMsgHeader;
    uint8_t completionCode;
    uint8_t msgTypeCount;
    std::vector<uint8_t> msgType;
};

struct MctpVersionSupportCtrlResp
{
    mctp_ctrl_msg_hdr ctrlMsgHeader;
    uint8_t completionCode;
    uint8_t verNoEntryCount;
    std::vector<std::vector<uint8_t>> verNoEntry;
};

enum class PacketState : uint8_t
{
    invalidPacket,
    pushedForTransmission,
    transmitted,
    receivedResponse,
    noResponse
};

using ConfigurationVariant =
    std::variant<SMBusConfiguration, PcieConfiguration>;

extern std::shared_ptr<sdbusplus::asio::connection> conn;

class MctpTransmissionQueue
{
  public:
    struct Message
    {
        Message(size_t index_, std::vector<uint8_t>&& payload_,
                std::vector<uint8_t>&& privateData_,
                boost::asio::io_context& ioc);

        size_t index{0};
        std::optional<uint8_t> tag;
        std::vector<uint8_t> payload{};
        std::vector<uint8_t> privateData{};
        boost::asio::steady_timer timer;
        std::optional<std::vector<uint8_t>> response{};
    };

    std::shared_ptr<Message> transmit(struct mctp* mctp, mctp_eid_t destEid,
                                      std::vector<uint8_t>&& payload,
                                      std::vector<uint8_t>&& privateData,
                                      boost::asio::io_context& ioc);

    bool receive(struct mctp* mctp, mctp_eid_t srcEid, uint8_t msgTag,
                 std::vector<uint8_t>&& response, boost::asio::io_context& ioc);

    void dispose(mctp_eid_t destEid, const std::shared_ptr<Message>& message);

  private:
    struct Tags
    {
        std::optional<uint8_t> next() const;
        void emplace(uint8_t flag);
        void erase(uint8_t flag);

        uint8_t bits{0xff};
    };

    struct Endpoint
    {
        Tags availableTags;
        std::map<uint8_t, std::shared_ptr<Message>> transmittedMessages{};
        std::map<size_t, std::shared_ptr<Message>> queuedMessages{};

        size_t msgCounter{0u};
        void transmitQueuedMessages(struct mctp* mctp, mctp_eid_t destEid);
    };

    std::map<mctp_eid_t, Endpoint> endpoints{};
};

class MctpBinding
{
  public:
    MctpBinding(std::shared_ptr<object_server>& objServer,
                const std::string& objPath, ConfigurationVariant& conf,
                boost::asio::io_context& ioc);
    MctpBinding() = delete;
    virtual ~MctpBinding();
    virtual void initializeBinding() = 0;
    void initializeEidPool(const std::set<mctp_eid_t>& eidPool);

    void handleCtrlReq(uint8_t destEid, void* bindingPrivate, const void* req,
                       size_t len, uint8_t msgTag);

  protected:
    unsigned int ctrlTxRetryDelay;
    uint8_t ctrlTxRetryCount;
    boost::asio::io_context& io;
    mctp_server::BindingModeTypes bindingModeType{};
    struct mctp* mctp = nullptr;
    uint8_t ownEid;
    uint8_t busOwnerEid;
    MctpTransmissionQueue transmissionQueue;

    void initializeMctp();
    void initializeLogging(void);
    virtual std::optional<std::vector<uint8_t>>
        getBindingPrivateData(uint8_t dstEid);
    virtual bool isReceivedPrivateDataCorrect(const void* bindingPrivate);
    virtual bool handlePrepareForEndpointDiscovery(
        mctp_eid_t destEid, void* bindingPrivate, std::vector<uint8_t>& request,
        std::vector<uint8_t>& response);
    virtual bool handleEndpointDiscovery(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual bool handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual bool handleGetVersionSupport(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleGetMsgTypeSupport(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    bool getEidCtrlCmd(boost::asio::yield_context& yield,
                       const std::vector<uint8_t>& bindingPrivate,
                       const mctp_eid_t destEid, std::vector<uint8_t>& resp);
    bool setEidCtrlCmd(boost::asio::yield_context& yield,
                       const std::vector<uint8_t>& bindingPrivate,
                       const mctp_eid_t destEid,
                       const mctp_ctrl_cmd_set_eid_op operation, mctp_eid_t eid,
                       std::vector<uint8_t>& resp);
    bool getUuidCtrlCmd(boost::asio::yield_context& yield,
                        const std::vector<uint8_t>& bindingPrivate,
                        const mctp_eid_t destEid, std::vector<uint8_t>& resp);
    bool getMsgTypeSupportCtrlCmd(boost::asio::yield_context& yield,
                                  const std::vector<uint8_t>& bindingPrivate,
                                  const mctp_eid_t destEid,
                                  MsgTypeSupportCtrlResp* msgTypeSupportResp);
    bool getMctpVersionSupportCtrlCmd(
        boost::asio::yield_context& yield,
        const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
        uint8_t msgTypeNo,
        MctpVersionSupportCtrlResp* mctpVersionSupportCtrlResp);
    bool discoveryNotifyCtrlCmd(boost::asio::yield_context& yield,
                                const std::vector<uint8_t>& bindingPrivate,
                                const mctp_eid_t destEid);
    bool getRoutingTableCtrlCmd(boost::asio::yield_context& yield,
                                const std::vector<uint8_t>& bindingPrivate,
                                const mctp_eid_t destEid, uint8_t entryHandle,
                                std::vector<uint8_t>& resp);
    std::optional<mctp_eid_t>
        registerEndpoint(boost::asio::yield_context& yield,
                         const std::vector<uint8_t>& bindingPrivate,
                         mctp_eid_t eid = 0xFF,
                         mctp_server::BindingModeTypes bindingMode =
                             mctp_server::BindingModeTypes::Endpoint);
    void unregisterEndpoint(mctp_eid_t eid);

    // MCTP Callbacks
    void handleCtrlResp(void* msg, const size_t len);
    static void rxMessage(uint8_t srcEid, void* data, void* msg, size_t len,
                          bool tagOwner, uint8_t msgTag, void* bindingPrivate);
    static void handleMCTPControlRequests(uint8_t srcEid, void* data, void* msg,
                                          size_t len, bool tagOwner,
                                          uint8_t msgTag, void* bindingPrivate);

    template <typename Interface, typename PropertyType>
    void registerProperty(Interface ifc, const std::string& name,
                          const PropertyType& property,
                          sdbusplus::asio::PropertyPermission access =
                              sdbusplus::asio::PropertyPermission::readOnly)
    {
        if (ifc->register_property(name, property, access) != true)
        {
            throw std::invalid_argument(name);
        }
    }

  private:
    bool staticEid;
    std::vector<uint8_t> uuid;
    mctp_server::BindingTypes bindingID{};
    mctp_server::MctpPhysicalMediumIdentifiers bindingMediumID{};
    std::shared_ptr<object_server>& objectServer;
    std::shared_ptr<dbus_interface> mctpInterface;
    std::vector<std::shared_ptr<dbus_interface>> endpointInterface;
    std::vector<std::shared_ptr<dbus_interface>> msgTypeInterface;
    std::vector<std::shared_ptr<dbus_interface>> uuidInterface;
    boost::asio::steady_timer ctrlTxTimer;

    // map<EID, assigned>
    std::unordered_map<mctp_eid_t, bool> eidPoolMap;
    bool ctrlTxTimerExpired = true;
    // <state, retryCount, maxRespDelay, destEid, BindingPrivate, ReqPacket,
    //  Callback>
    std::vector<
        std::tuple<PacketState, uint8_t, unsigned int, mctp_eid_t,
                   std::vector<uint8_t>, std::vector<uint8_t>,
                   std::function<void(PacketState, std::vector<uint8_t>&)>>>
        ctrlTxQueue;

    void createUuid();
    void updateEidStatus(const mctp_eid_t endpointId, const bool assigned);
    mctp_eid_t getAvailableEidFromPool();
    bool sendMctpMessage(mctp_eid_t destEid, std::vector<uint8_t> req,
                         bool tagOwner, uint8_t msgTag,
                         std::vector<uint8_t> bindingPrivate);
    void processCtrlTxQueue();
    void pushToCtrlTxQueue(
        PacketState pktState, const mctp_eid_t destEid,
        const std::vector<uint8_t>& bindingPrivate,
        const std::vector<uint8_t>& req,
        std::function<void(PacketState, std::vector<uint8_t>&)>& callback);
    PacketState sendAndRcvMctpCtrl(boost::asio::yield_context& yield,
                                   const std::vector<uint8_t>& req,
                                   const mctp_eid_t destEid,
                                   const std::vector<uint8_t>& bindingPrivate,
                                   std::vector<uint8_t>& resp);
    template <int cmd, typename... Args>
    bool getFormattedReq(std::vector<uint8_t>& req, Args&&... reqParam);
    std::optional<mctp_eid_t>
        busOwnerRegisterEndpoint(boost::asio::yield_context& yield,
                                 const std::vector<uint8_t>& bindingPrivate);
    void registerMsgTypes(std::shared_ptr<dbus_interface>& msgTypeIntf,
                          const MsgTypes& messageType);
    void populateEndpointProperties(const EndpointProperties& epProperties);
    mctp_server::BindingModeTypes getEndpointType(const uint8_t types);
    MsgTypes getMsgTypes(const std::vector<uint8_t>& msgType);
    std::vector<uint8_t> getBindingMsgTypes();
    void removeInterface(
        std::string& interfacePath,
        std::vector<std::shared_ptr<dbus_interface>>& interfaces);
};
