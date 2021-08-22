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
            conn, bus, "/xyz/openbmc_project/test_mctp", config, ioc);
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

    auto observeAnyInterfaceRemoved()
    {
        using ::testing::_;

        auto async = makePromise<void>();
        EXPECT_CALL(*bus, remove_interface(_))
            .WillOnce([&](auto& interface) {
                async.promise.set_value();
                return bus->backdoor.remove_interface(interface->path,
                                                      interface->name);
            })
            .WillRepeatedly([&](auto& interface) {
                return bus->backdoor.remove_interface(interface->path,
                                                      interface->name);
            });

        return async;
    }

    template <typename Payload>
    void sendCtrlRequestAsync(const uint8_t command,
                              TestPCIeBinding::Backdoor::Route route,
                              const TestPCIeBinding::PrvDataType& prvData = {},
                              std::function<void(Payload&)>&& setup = nullptr,
                              const size_t padding = 0)
    {
        auto request = binding->backdoor.prepareCtrlRequest<Payload>(
            command, route, prvData, padding);

        if (setup)
        {
            setup(*request.payload);
        }

        binding->backdoor.rx(request);
    }

    template <typename Payload>
    void sendCtrlRequest(const uint8_t command,
                         TestPCIeBinding::Backdoor::Route route,
                         const TestPCIeBinding::PrvDataType& prvData = {},
                         std::function<void(Payload&)>&& setup = nullptr,
                         const size_t padding = 0)
    {
        auto async = makePromise<void>();
        binding->backdoor.onOutgoingCtrlCommand(
            command, [&]() { async.promise.set_value(); });
        sendCtrlRequestAsync(command, route, prvData, std::move(setup),
                             padding);
        try
        {
            waitFor(async.future);
        }
        catch (timeout_occurred& e)
        {
            throw timeout_occurred(
                "Timeout while waiting for response to command: " +
                std::to_string(command));
        }
    }

    template <typename Payload, typename ResponsePayload>
    ResponsePayload
        sendCtrlRequest(const uint8_t command,
                        TestPCIeBinding::Backdoor::Route route,
                        const TestPCIeBinding::PrvDataType& prvData = {},
                        std::function<void(Payload&)>&& setup = nullptr,
                        const size_t padding = 0)
    {
        auto async = makePromise<ResponsePayload>();
        binding->backdoor.onOutgoingCtrlCommand(command, [&]() {
            async.promise.set_value(lastOutgoingPayload<ResponsePayload>());
        });
        sendCtrlRequestAsync(command, route, prvData, std::move(setup),
                             padding);
        try
        {
            return waitFor(async.future);
        }
        catch (timeout_occurred& e)
        {
            throw timeout_occurred(
                "Timeout while waiting for response to command: " +
                std::to_string(command));
        }
    }

    template <typename Payload>
    void sendCtrlResponseAsync(const TestPCIeBinding::PrvDataType& prvData = {},
                               std::function<void(Payload&)>&& setup = nullptr,
                               const size_t padding = 0)
    {
        auto response =
            binding->backdoor.prepareCtrlResponse<Payload>(prvData, padding);

        if (setup)
        {
            setup(*response.payload);
        }

        binding->backdoor.rx(response);
    }

    template <typename Payload>
    void sendCtrlResponseAsync(std::function<void(Payload&)>&& setup = nullptr,
                               const size_t padding = 0)
    {
        sendCtrlResponseAsync<Payload>({}, std::move(setup), padding);
    }

    template <typename T>
    T lastOutgoingPayload()
    {
        auto frame = binding->backdoor.lastOutgoingMessage<T>();
        return *frame.payload;
    }

    template <typename T>
    TestPCIeBinding::BindingIO<T> lastOutgoingFrame()
    {
        auto frame = binding->backdoor.lastOutgoingMessage<T>();
        return frame;
    }

    PcieConfiguration config{};
    std::shared_ptr<TestPCIeBinding> binding;

    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::shared_ptr<mctpd_mock::object_server_mock> bus;
    std::shared_ptr<mctpd_mock::dbus_interface_mock> mctpInterface;
    std::shared_ptr<mctpd_mock::dbus_interface_mock> pcieInterface;
};
