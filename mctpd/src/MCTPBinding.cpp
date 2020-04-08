#include "MCTPBinding.hpp"

#include "libmctp.h"

MctpBinding::MctpBinding(
    std::shared_ptr<sdbusplus::asio::object_server>& objServer,
    std::string& objPath)
{
    eid = 0;
    // TODO:Add MCTP Binding interfaces here

    std::string mctpIntf = "xyz.openbmc_project.mctp.base";

    std::shared_ptr<sdbusplus::asio::dbus_interface> mctpInterface =
        objServer->add_interface(objPath, mctpIntf.c_str());

    mctpInterface->initialize();
}
