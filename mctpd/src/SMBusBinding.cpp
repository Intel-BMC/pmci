#include "SMBusBinding.hpp"

#include <xyz/openbmc_project/MCTP/Binding/SMBus/server.hpp>

using smbus_server =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::SMBus;

SMBusBinding::SMBusBinding(
    std::shared_ptr<sdbusplus::asio::object_server>& objServer,
    std::string& objPath, ConfigurationVariant& conf) :
    MctpBinding(objServer, objPath, conf)
{
    // TODO: Add SMBusInterfaces here
    std::shared_ptr<sdbusplus::asio::dbus_interface> smbusInterface =
        objServer->add_interface(objPath, smbus_server::interface);

    smbusInterface->initialize();
}
