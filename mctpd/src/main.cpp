#include "MCTPBinding.hpp"
#include "PCIeBinding.hpp"
#include "SMBusBinding.hpp"
#include "hw/aspeed/PCIeDriver.hpp"
#include "hw/aspeed/PCIeMonitor.hpp"

#include <CLI/CLI.hpp>
#include <boost/asio/signal_set.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>

std::shared_ptr<sdbusplus::asio::connection> conn;

std::shared_ptr<MctpBinding>
    getBindingPtr(const Configuration& configuration,
                  std::shared_ptr<object_server>& objectServer,
                  boost::asio::io_context& ioc)
{
    std::string mctpBaseObj = "/xyz/openbmc_project/mctp";

    if (auto smbusConfig =
            dynamic_cast<const SMBusConfiguration*>(&configuration))
    {
        return std::make_shared<SMBusBinding>(objectServer, mctpBaseObj,
                                              *smbusConfig, ioc);
    }
    else if (auto pcieConfig =
                 dynamic_cast<const PcieConfiguration*>(&configuration))
    {
        return std::make_shared<PCIeBinding>(
            objectServer, mctpBaseObj, *pcieConfig, ioc,
            std::make_unique<hw::aspeed::PCIeDriver>(ioc),
            std::make_unique<hw::aspeed::PCIeMonitor>(ioc));
    }

    return nullptr;
}

int main(int argc, char* argv[])
{
    CLI::App app("MCTP Daemon");
    std::string binding;
    std::string configPath = "/usr/share/mctp/mctp_config.json";
    std::optional<std::pair<std::string, std::unique_ptr<Configuration>>>
        mctpdConfigurationPair;

    app.add_option("-b,--binding", binding,
                   "MCTP Physical Binding. Supported: -b smbus, -b pcie")
        ->required();
    app.add_option("-c,--config", configPath, "Path to configuration file.",
                   true);
    CLI11_PARSE(app, argc, argv);

    boost::asio::io_context ioc;
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc](const boost::system::error_code&, const int&) { ioc.stop(); });

    conn = std::make_shared<sdbusplus::asio::connection>(ioc);

    /* Process configuration */
    try
    {
        mctpdConfigurationPair = getConfiguration(binding, configPath);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Exception: ") + e.what()).c_str());
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid configuration; exiting");
        return -1;
    }

    if (!mctpdConfigurationPair)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Could not load any configuration; exiting");
        return -1;
    }

    auto& [mctpdName, mctpdConfiguration] = *mctpdConfigurationPair;
    auto objectServer = std::make_shared<object_server>(conn, true);
    const std::string mctpServiceName = "xyz.openbmc_project." + mctpdName;
    conn->request_name(mctpServiceName.c_str());

    auto bindingPtr = getBindingPtr(*mctpdConfiguration, objectServer, ioc);
    try
    {
        bindingPtr->initializeBinding();
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Exception: ") + e.what()).c_str());
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to intialize MCTP binding; exiting");
        return -1;
    }
    ioc.run();

    return 0;
}
