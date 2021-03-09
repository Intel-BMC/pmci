#include "OemBinding.hpp"

OemBinding::OemBinding(
    std::shared_ptr<sdbusplus::asio::object_server>& objServer,
    std::string& objPath) :
    MctpBinding(objServer, objPath)
{
}
