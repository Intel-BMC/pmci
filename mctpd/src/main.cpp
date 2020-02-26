#include "MCTPBinding.hpp"
#include "SMBusBinding.hpp"

#include <iostream>
#include <sdbusplus/asio/object_server.hpp>

int main()
{
    boost::asio::io_context ioc;
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc](const boost::system::error_code&, const int&) { ioc.stop(); });

    std::shared_ptr<sdbusplus::asio::connection> bus;

    bus = std::make_shared<sdbusplus::asio::connection>(ioc);

    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(bus);
    bus->request_name("xyz.openbmc_project.mctp");
    auto objManager = std::make_shared<sdbusplus::server::manager::manager>(
        *bus, "/xyz/openbmc_project/mctp_binding");

    // TODO: Initialise binding based on configurations exposed by Entity
    // Manager

    ioc.run();

    return 0;
}
