#pragma once

#include "MCTPBinding.hpp"

#include <libmctp-astpcie.h>

#include <boost/asio/deadline_timer.hpp>
#include <xyz/openbmc_project/MCTP/Binding/PCIe/server.hpp>

using pcie_binding =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::PCIe;

class PCIeBinding : public MctpBinding
{
  public:
    PCIeBinding() = delete;
    PCIeBinding(std::shared_ptr<object_server>& objServer, std::string& objPath,
                ConfigurationVariant& conf, boost::asio::io_context& ioc);
    virtual ~PCIeBinding();
    virtual void initializeBinding(ConfigurationVariant& conf) override;

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

  private:
    using routingTableEntry_t =
        std::tuple<uint8_t /*eid*/, uint16_t /*bdf*/, uint8_t /*entryType*/>;
    uint16_t bdf;
    uint16_t busOwnerBdf;
    pcie_binding::DiscoveryFlags discoveredFlag{};
    struct mctp_binding_astpcie* pcie = nullptr;
    boost::asio::posix::stream_descriptor streamMonitor;
    boost::posix_time::seconds getRoutingInterval;
    boost::asio::deadline_timer getRoutingTableTimer;
    std::vector<routingTableEntry_t> routingTable;
    bool endpointDiscoveryFlow();
    void updateRoutingTable();
    void processRoutingTableChanges(
        const std::vector<routingTableEntry_t>& newTable,
        boost::asio::yield_context& yield, const std::vector<uint8_t>& prvData);
    void readResponse();
    bool getBindingPrivateData(uint8_t dstEid,
                               std::vector<uint8_t>& pvtData) override;
    bool isReceivedPrivateDataCorrect(const void* bindingPrivate) override;
    mctp_server::BindingModeTypes
        getBindingMode(const routingTableEntry_t& routingEntry);
};
