#include "SMBusBinding.hpp"

#include "MCTPBinding.hpp"

#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/MCTP/Binding/SMBus/server.hpp>

using smbus_server =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::SMBus;

SMBusBinding::SMBusBinding(
    std::shared_ptr<sdbusplus::asio::object_server>& objServer,
    std::string& objPath, ConfigurationVariant& conf,
    boost::asio::io_context& ioc) :
    MctpBinding(objServer, objPath, conf, ioc)
{
    std::shared_ptr<sdbusplus::asio::dbus_interface> smbusInterface =
        objServer->add_interface(objPath, smbus_server::interface);

    try
    {
        this->arpMasterSupport =
            std::get<SMBusConfiguration>(conf).arpMasterSupport;
        this->bus = std::get<SMBusConfiguration>(conf).bus;
        this->bmcSlaveAddr = std::get<SMBusConfiguration>(conf).bmcSlaveAddr;
        smbusInterface->register_property("ArpMasterSupport", arpMasterSupport);
        smbusInterface->register_property("BusNumber", bus);
        smbusInterface->register_property("BmcSlaveAddress", bmcSlaveAddr);
        smbusInterface->initialize();
    }

    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SMBus Interface init failed",
            phosphor::logging::entry("Exception:", e.what()));

        throw;
    }
}
