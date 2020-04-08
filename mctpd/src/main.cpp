#include "MCTPBinding.hpp"
#include "SMBusBinding.hpp"

#include <CLI/CLI.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>

std::map<std::string, binding> mctpBindingsMap = {{"smbus", binding::SMBus},
                                                  {"pcie", binding::PCIe}};

int main(int argc, char* argv[])
{
    CLI::App app("MCTP Daemon");
    std::string binding;
    app.add_option("-b,--binding", binding,
                   "MCTP Physical Binding. Supported: -b smbus, -b pcie");
    CLI11_PARSE(app, argc, argv);

    auto it = mctpBindingsMap.find(binding);
    if (it == mctpBindingsMap.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid binding; exiting");
        return -1;
    }

    std::string mctpBaseObj = "/xyz/openbmc_project/mctp";
    boost::asio::io_context ioc;
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc](const boost::system::error_code&, const int&) { ioc.stop(); });

    std::shared_ptr<sdbusplus::asio::connection> bus;

    bus = std::make_shared<sdbusplus::asio::connection>(ioc);

    std::string mctpServiceName = "xyz.openbmc_project.MCTP-";
    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(bus);
    bus->request_name((mctpServiceName + binding).c_str());

    auto objManager = std::make_shared<sdbusplus::server::manager::manager>(
        *bus, mctpBaseObj.c_str());

    // TODO: Initialise binding based on configurations exposed by Entity
    // Manager
    switch (mctpBindingsMap[binding])
    {
        case binding::SMBus:
        {
            SMBusBinding SMBus(objectServer, mctpBaseObj);
            break;
        }
        case binding::PCIe:
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
