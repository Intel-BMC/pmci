#pragma once

#include "MCTPBinding.hpp"
#include "hw/DeviceMonitor.hpp"
#include "hw/PCIeDriver.hpp"

#include <libmctp-astpcie.h>
#include <libmctp-cmds.h>

#include <boost/asio/deadline_timer.hpp>
#include <xyz/openbmc_project/MCTP/Binding/PCIe/server.hpp>

using pcie_binding =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::PCIe;

class PCIeBinding : public MctpBinding,
                    public hw::DeviceObserver,
                    public std::enable_shared_from_this<hw::DeviceObserver>
{
  public:
    PCIeBinding() = delete;
    PCIeBinding(std::shared_ptr<object_server>& objServer,
                const std::string& objPath, const PcieConfiguration& conf,
                boost::asio::io_context& ioc,
                std::shared_ptr<hw::PCIeDriver>&& hw,
                std::shared_ptr<hw::DeviceMonitor>&& hwMonitor);
    ~PCIeBinding() override = default;
    void initializeBinding() override;

  protected:
    bool handlePrepareForEndpointDiscovery(
        mctp_eid_t destEid, void* bindingPrivate, std::vector<uint8_t>& request,
        std::vector<uint8_t>& response) override;
    bool handleEndpointDiscovery(mctp_eid_t destEid, void* bindingPrivate,
                                 std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response) override;
    bool handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                             std::vector<uint8_t>& request,
                             std::vector<uint8_t>& response) override;
    bool handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                             std::vector<uint8_t>& request,
                             std::vector<uint8_t>& response) override;
    bool handleGetVersionSupport(mctp_eid_t destEid, void* bindingPrivate,
                                 std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response) override;
    bool handleGetMsgTypeSupport(mctp_eid_t destEid, void* bindingPrivate,
                                 std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response) override;
    bool handleGetVdmSupport(mctp_eid_t endpointEid, void* bindingPrivate,
                             std::vector<uint8_t>& request,
                             std::vector<uint8_t>& response) override;

    void deviceReadyNotify(bool ready) override;

    std::shared_ptr<hw::PCIeDriver> hw;
    std::shared_ptr<hw::DeviceMonitor> hwMonitor;

  private:
    using routingTableEntry_t =
        std::tuple<uint8_t /*eid*/, uint16_t /*bdf*/, uint8_t /*entryType*/>;
    uint16_t bdf;
    uint16_t busOwnerBdf;
    std::shared_ptr<dbus_interface> pcieInterface;
    pcie_binding::DiscoveryFlags discoveredFlag{};
    boost::posix_time::seconds getRoutingInterval;
    boost::asio::deadline_timer getRoutingTableTimer;
    std::vector<routingTableEntry_t> routingTable;
    void endpointDiscoveryFlow();
    void updateRoutingTable();
    void processRoutingTableChanges(
        const std::vector<routingTableEntry_t>& newTable,
        boost::asio::yield_context& yield, const std::vector<uint8_t>& prvData);
    bool setDriverEndpointMap();
    std::optional<std::vector<uint8_t>>
        getBindingPrivateData(uint8_t dstEid) override;
    bool isReceivedPrivateDataCorrect(const void* bindingPrivate) override;
    mctp_server::BindingModeTypes
        getBindingMode(const routingTableEntry_t& routingEntry);
    void changeDiscoveredFlag(pcie_binding::DiscoveryFlags flag);
};
