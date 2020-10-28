#pragma once

#include "MCTPBinding.hpp"

#include <libmctp-astpcie.h>
#include <libmctp-cmds.h>
#include <libudev.h>

#include <boost/asio/deadline_timer.hpp>
#include <xyz/openbmc_project/MCTP/Binding/PCIe/server.hpp>

constexpr uint8_t vendorIdNoMoreSets = 0xff;

struct InternalVdmSetDatabase
{
    uint8_t idFormat;
    uint16_t idData;
    uint16_t commandSetType;
};

using pcie_binding =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::PCIe;

class PCIeBinding : public MctpBinding
{
  public:
    PCIeBinding() = delete;
    PCIeBinding(std::shared_ptr<object_server>& objServer, std::string& objPath,
                ConfigurationVariant& conf, boost::asio::io_context& ioc);
    virtual ~PCIeBinding();
    virtual void initializeBinding() override;

  protected:
    virtual bool handlePrepareForEndpointDiscovery(
        mctp_eid_t destEid, void* bindingPrivate, std::vector<uint8_t>& request,
        std::vector<uint8_t>& response) override;
    virtual bool
        handleEndpointDiscovery(mctp_eid_t destEid, void* bindingPrivate,
                                std::vector<uint8_t>& request,
                                std::vector<uint8_t>& response) override;
    virtual bool handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response) override;
    virtual bool handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response) override;
    virtual bool
        handleGetVersionSupport(mctp_eid_t destEid, void* bindingPrivate,
                                std::vector<uint8_t>& request,
                                std::vector<uint8_t>& response) override;
    virtual bool
        handleGetMsgTypeSupport(mctp_eid_t destEid, void* bindingPrivate,
                                std::vector<uint8_t>& request,
                                std::vector<uint8_t>& response) override;
    virtual bool handleGetVdmSupport(mctp_eid_t endpointEid,
                                     void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response) override;

  private:
    using routingTableEntry_t =
        std::tuple<uint8_t /*eid*/, uint16_t /*bdf*/, uint8_t /*entryType*/>;
    uint16_t bdf;
    uint16_t busOwnerBdf;
    std::shared_ptr<dbus_interface> pcieInterface;
    udev* udevContext;
    udev_device* udevice;
    udev_monitor* umonitor;
    static constexpr const char* astUdevPath =
        "/sys/devices/platform/ahb/ahb:apb/1e6e8000.mctp/misc/aspeed-mctp";
    pcie_binding::DiscoveryFlags discoveredFlag{};
    struct mctp_binding_astpcie* pcie = nullptr;
    boost::asio::posix::stream_descriptor streamMonitor;
    boost::asio::posix::stream_descriptor ueventMonitor;
    boost::posix_time::seconds getRoutingInterval;
    boost::asio::deadline_timer getRoutingTableTimer;
    std::vector<routingTableEntry_t> routingTable;
    bool endpointDiscoveryFlow();
    void updateRoutingTable();
    void processRoutingTableChanges(
        const std::vector<routingTableEntry_t>& newTable,
        boost::asio::yield_context& yield, const std::vector<uint8_t>& prvData);
    void readResponse();
    std::optional<std::vector<uint8_t>>
        getBindingPrivateData(uint8_t dstEid) override;
    bool isReceivedPrivateDataCorrect(const void* bindingPrivate) override;
    std::vector<InternalVdmSetDatabase> vdmSetDatabase;
    mctp_server::BindingModeTypes
        getBindingMode(const routingTableEntry_t& routingEntry);
    void changeDiscoveredFlag(pcie_binding::DiscoveryFlags flag);
    bool initializeUdev();
    void monitorUdevEvents();
    void ueventHandlePcieReady(udev_device* dev);
};
