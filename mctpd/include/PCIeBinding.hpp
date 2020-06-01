#pragma once

#include "MCTPBinding.hpp"

#include <xyz/openbmc_project/MCTP/Binding/PCIe/server.hpp>

using pcie_binding =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::PCIe;

class PCIeBinding : public MctpBinding
{
  public:
    PCIeBinding() = delete;
    PCIeBinding(std::shared_ptr<sdbusplus::asio::object_server>& objServer,
                std::string& objPath, ConfigurationVariant& conf,
                boost::asio::io_context& ioc);
    virtual ~PCIeBinding() = default;
    virtual void initializeBinding(ConfigurationVariant& conf) override;

  private:
    uint16_t bdf;
    pcie_binding::DiscoveryFlags discoveredFlag{};
};
