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

using BindingVariant =
    std::variant<std::unique_ptr<SMBusBinding>, std::unique_ptr<PCIeBinding>>;

extern BindingVariant bindingPtr;

void rxMessage(uint8_t /*srcEid*/, void* /*data*/, void* /*msg*/,
               size_t /*len*/, bool /*tagOwner*/, uint8_t /*msgTag*/,
               void* /*msg_binding_private*/);

void handleMCTPControlRequests(uint8_t /*srcEid*/, void* /*data*/,
                               void* /*msg*/, size_t /*len*/, bool /*tagOwner*/,
                               uint8_t /*msgTag*/, void* /*bindingPrivate*/);

class MctpBinding
{
  public:
    MctpBinding(std::shared_ptr<object_server>& objServer,
                const std::string& objPath, ConfigurationVariant& conf,
                boost::asio::io_context& ioc);
    MctpBinding() = delete;
    virtual ~MctpBinding();
    virtual void initializeBinding(ConfigurationVariant& conf) = 0;
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
    void initializeMctp(void);
    virtual bool getBindingPrivateData(uint8_t dstEid,
                                       std::vector<uint8_t>& pvtData);
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
    std::pair<bool, mctp_eid_t>
        registerEndpoint(boost::asio::yield_context& yield,
                         const std::vector<uint8_t>& bindingPrivate,
                         bool isBusOwner);

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

    void createUuid(void);
    void updateEidStatus(const mctp_eid_t endpointId, const bool assigned);
    mctp_eid_t getAvailableEidFromPool(void);
    bool sendMctpMessage(mctp_eid_t destEid, std::vector<uint8_t> req,
                         bool tagOwner, uint8_t msgTag,
                         std::vector<uint8_t> bindingPrivate);
    void processCtrlTxQueue(void);
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
    std::pair<bool, mctp_eid_t>
        busOwnerRegisterEndpoint(boost::asio::yield_context& yield,
                                 const std::vector<uint8_t>& bindingPrivate);
    void registerMsgTypes(std::shared_ptr<dbus_interface>& msgTypeIntf,
                          const MsgTypes& messageType);
    void populateEndpointProperties(const EndpointProperties& epProperties);
    mctp_server::BindingModeTypes getEndpointType(const uint8_t types);
    MsgTypes getMsgTypes(const std::vector<uint8_t>& msgType);
};
