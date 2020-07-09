#pragma once

#include <libmctp.h>

#include <iostream>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/MCTP/Base/server.hpp>

#ifdef USE_MOCK
#include "../tests/mocks/objectServerMock.hpp"
using object_server = mctpd_mock::object_server_mock;
using dbus_interface = mctpd_mock::dbus_interface_mock;
#else
using object_server = sdbusplus::asio::object_server;
using dbus_interface = sdbusplus::asio::dbus_interface;
#endif

using mctp_server = sdbusplus::xyz::openbmc_project::MCTP::server::Base;

struct SMBusConfiguration
{
    const mctp_server::BindingTypes bindingType =
        mctp_server::BindingTypes::MctpOverSmbus;
    mctp_server::MctpPhysicalMediumIdentifiers mediumId;
    mctp_server::BindingModeTypes mode;
    uint8_t defaultEid;
    // TODO: Use std::set for EID pool to avoid duplicates
    std::vector<uint8_t> eidPool;
    std::string bus;
    bool arpMasterSupport;
    uint8_t bmcSlaveAddr;
};

struct PcieConfiguration
{
    const mctp_server::BindingTypes bindingType =
        mctp_server::BindingTypes::MctpOverPcieVdm;
    mctp_server::MctpPhysicalMediumIdentifiers mediumId;
    mctp_server::BindingModeTypes mode;
    uint8_t defaultEid;
    uint16_t bdf;
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

void rxMessage(uint8_t /*srcEid*/, void* /*data*/, void* /*msg*/,
               size_t /*len*/, void* /*msg_binding_private*/);

class MctpBinding
{
  public:
    MctpBinding(std::shared_ptr<object_server>& objServer, std::string& objPath,
                ConfigurationVariant& conf, boost::asio::io_context& ioc);
    MctpBinding() = delete;
    virtual ~MctpBinding();
    virtual void initializeBinding(ConfigurationVariant& conf) = 0;
    void initializeEidPool(const std::vector<mctp_eid_t>& eidPool);

  protected:
    mctp_server::BindingModeTypes bindingModeType{};
    struct mctp* mctp = nullptr;
    uint8_t ownEid;
    void initializeMctp(void);
    virtual bool getBindingPrivateData(uint8_t dstEid,
                                       std::vector<uint8_t>& pvtData);

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
    boost::asio::io_context& io;
    std::shared_ptr<object_server>& objectServer;
    std::shared_ptr<dbus_interface> mctpInterface;
    boost::asio::steady_timer ctrlTxTimer;

    void createUuid(void);
    void updateEidStatus(const mctp_eid_t endpointId, const bool assigned);
    mctp_eid_t getAvailableEidFromPool(void);
    bool sendMctpMessage(mctp_eid_t destEid, std::vector<uint8_t> req,
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
};
