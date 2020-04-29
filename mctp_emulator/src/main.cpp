#include "MCTPBinding.hpp"
#include "SMBusBinding.hpp"

#include <CLI/CLI.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>

std::map<std::string, binding> mctpBindingsMap = {{"smbus", binding::smbus},
                                                  {"pcie", binding::pcie}};

std::shared_ptr<sdbusplus::asio::connection> bus;
int main()
{
    // TODO: Read the binding configuration from a json file
    std::string binding("smbus");

    std::string mctpBaseObj = "/xyz/openbmc_project/mctp";
    boost::asio::io_context ioc;
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc](const boost::system::error_code&, const int&) { ioc.stop(); });

    bus = std::make_shared<sdbusplus::asio::connection>(ioc);

    std::string mctpServiceName = "xyz.openbmc_project.mctp-emulator";
    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(bus);
    bus->request_name(mctpServiceName.c_str());

    auto objManager = std::make_shared<sdbusplus::server::manager::manager>(
        *bus, mctpBaseObj.c_str());

    // TODO: Initialise binding based on configurations exposed by Entity
    // Manager
    switch (mctpBindingsMap[binding])
    {
        case binding::smbus:
        {
            SMBusBinding SMBus(objectServer, mctpBaseObj);
            break;
        }
        case binding::pcie:
        {
            break;
        }
        default:
        {
            break;
        }
    }

    ioc.run();

    return 0;
}
