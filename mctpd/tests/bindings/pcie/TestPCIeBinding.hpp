#pragma once

#include "PCIeBinding.hpp"
#include "mocks/hw/FakePCIeDriver.hpp"
#include "mocks/objectServerMock.hpp"
#include "utils/BindingBackdoor.hpp"

class TestDeviceMonitor : public hw::DeviceMonitor
{
  public:
    MOCK_METHOD(bool, initialize, (), (override));
    MOCK_METHOD(void, observe, (std::weak_ptr<hw::DeviceObserver>), (override));

    virtual ~TestDeviceMonitor() = default;
};

class TestPCIeBinding : public PCIeBinding
{
    static constexpr size_t packetSize = 4096;

  public:
    using PrvDataType = mctp_astpcie_pkt_private;
    using Backdoor = BindingBackdoor<PrvDataType>;

    template <typename Payload>
    using BindingIO = Backdoor::BindingIO<Payload>;

    TestPCIeBinding(std::shared_ptr<sdbusplus::asio::connection> conn,
                    std::shared_ptr<object_server>& objServer,
                    const std::string& objPath, PcieConfiguration& conf,
                    boost::asio::io_context& ioc) :
        PCIeBinding(
            conn, objServer, objPath, conf, ioc,
            std::make_shared<FakePCIeDriver>(packetSize, sizeof(PrvDataType)),
            std::make_shared<::testing::NiceMock<TestDeviceMonitor>>()),
        backdoor{std::static_pointer_cast<FakePCIeDriver>(hw)->hw}
    {
        auto monitor = std::static_pointer_cast<TestDeviceMonitor>(hwMonitor);
        ON_CALL(*monitor, initialize).WillByDefault(::testing::Return(true));
    }

    ~TestPCIeBinding() override = default;

    Backdoor backdoor;

    // Extract protected members exernally
    using PCIeBinding::hw;
    using PCIeBinding::hwMonitor;
};