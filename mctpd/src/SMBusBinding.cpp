#include "SMBusBinding.hpp"

#include "MCTPBinding.hpp"

#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/MCTP/Binding/SMBus/server.hpp>

using smbus_server =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::SMBus;

SMBusBinding::SMBusBinding(std::shared_ptr<object_server>& objServer,
                           std::string& objPath, ConfigurationVariant& conf,
                           boost::asio::io_context& ioc) :
    MctpBinding(objServer, objPath, conf, ioc)
{
    std::shared_ptr<dbus_interface> smbusInterface =
        objServer->add_interface(objPath, smbus_server::interface);

    try
    {
        this->arpMasterSupport =
            std::get<SMBusConfiguration>(conf).arpMasterSupport;
        this->bus = std::get<SMBusConfiguration>(conf).bus;
        this->bmcSlaveAddr = std::get<SMBusConfiguration>(conf).bmcSlaveAddr;
        registerProperty(smbusInterface, "ArpMasterSupport", arpMasterSupport);
        registerProperty(smbusInterface, "BusNumber", bus);
        registerProperty(smbusInterface, "BmcSlaveAddress", bmcSlaveAddr);
        if (smbusInterface->initialize() == false)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }
    }

    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SMBus Interface init failed",
            phosphor::logging::entry("Exception:", e.what()));

        throw;
    }
}
