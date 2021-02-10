#pragma once

#include "bindings/pcie/TestPCIeBinding.hpp"
#include "utils/AsyncTestBase.hpp"

class PCIeTestBase : public AsyncTestBase
{
  protected:
    constexpr static uint16_t myBdf = 0x1234;

  public:
    PCIeTestBase()
    {
        bus = std::make_shared<mctpd_mock::object_server_mock>();

        // Create ifaces beforehand, to configure mock
        mctpInterface = bus->backdoor.add_interface(
            "/xyz/openbmc_project/test_mctp", mctp_server::interface);
        mctpInterface->returnByDefault(true);

        pcieInterface = bus->backdoor.add_interface(
            "/xyz/openbmc_project/test_mctp", pcie_binding::interface);
        pcieInterface->returnByDefault(true);

        config.bdf = myBdf;
        config.reqRetryCount = 0;
        config.reqToRespTime =
            std::chrono::milliseconds{executionTimeout / 2}.count();
        config.mode = mctp_server::BindingModeTypes::Endpoint;
        config.getRoutingInterval = std::chrono::seconds{1}.count();

        binding = std::make_shared<TestPCIeBinding>(
            bus, "/xyz/openbmc_project/test_mctp", config, ioc);
        binding->initializeBinding();
    }

    auto observeInterface(const std::string& path, const std::string& name)
    {
        auto async = std::make_shared<AsyncTestBase::AsyncPair<void>>();
        auto iface = bus->backdoor.get_interface(path, name);
        ON_CALL(*iface, initialize()).WillByDefault([async]() {
            async->promise.set_value();
            return true;
        });
        return std::make_pair(iface, async);
    }

    PcieConfiguration config{};
    std::shared_ptr<TestPCIeBinding> binding;

    std::shared_ptr<mctpd_mock::object_server_mock> bus;
    std::shared_ptr<mctpd_mock::dbus_interface_mock> mctpInterface;
    std::shared_ptr<mctpd_mock::dbus_interface_mock> pcieInterface;
};
