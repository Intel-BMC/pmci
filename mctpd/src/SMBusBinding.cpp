#include "SMBusBinding.hpp"

std::string smbusIntf = "xyz.openbmc_project.mctp.smbus";

SMBusBinding::SMBusBinding(
    std::shared_ptr<sdbusplus::asio::object_server> &objServer,
    std::string &objPath)
    : MctpBinding(objServer, objPath) {
  // TODO: Add SMBusInterfaces here
  std::shared_ptr<sdbusplus::asio::dbus_interface> smbusInterface =
      objServer->add_interface(objPath, smbusIntf.c_str());

  smbusInterface->initialize();
}
