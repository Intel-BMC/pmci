#include "SMBusBinding.hpp"

std::string smbusIntf = "xyz.openbmc_project.MCTP.Binding.SMBus";

SMBusBinding::SMBusBinding(
    std::shared_ptr<sdbusplus::asio::object_server>& objServer,
    std::string& objPath) :
    MctpBinding(objServer, objPath)
{
    // TODO: Add SMBusInterfaces here
    std::shared_ptr<sdbusplus::asio::dbus_interface> smbusInterface =
        objServer->add_interface(objPath, smbusIntf.c_str());

    bool arpSupport = false;
    std::string busNumber = "/dev/i2c-2";
    uint8_t slaveAddress = 0x21;
    smbusInterface->register_property("ArpMasterSupport", arpSupport);
    smbusInterface->register_property("BusPath", busNumber);
    smbusInterface->register_property("SlaveAddress", slaveAddress);
    smbusInterface->initialize();
}
