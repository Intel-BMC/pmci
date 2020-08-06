#pragma once

#include "MCTPBinding.hpp"

#include <libmctp-astpcie.h>

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

  private:
    uint16_t bdf;
    pcie_binding::DiscoveryFlags discoveredFlag{};
    struct mctp_binding_astpcie* pcie = nullptr;
    boost::asio::posix::stream_descriptor streamMonitor;
    bool endpointDiscoveryFlow();
    void readResponse();
};
