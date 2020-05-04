#include <systemd/sd-bus.h>

#include <iostream>
#include <sdbusplus/asio/object_server.hpp>

#include "gtest/gtest.h"
#include <gmock/gmock.h>

namespace mctpd_mock
{

class dbus_interface_mock
{
  public:
    dbus_interface_mock(__attribute__((unused)) const std::string& path,
                        __attribute__((unused)) const std::string& name){};
    virtual ~dbus_interface_mock(){};

    MOCK_METHOD2(register_property, bool(const char*, uint8_t));
    MOCK_METHOD2(register_property, bool(const char*, const std::string&));
    MOCK_METHOD2(register_property, bool(const char*, bool));
    MOCK_METHOD2(register_property, bool(const char*, std::vector<uint8_t>));
    MOCK_METHOD(bool, initialize, ());
};

class object_server_mock
{
  public:
    const std::string mctpIntf = "xyz.openbmc_project.mctp.mock.base";
    std::shared_ptr<dbus_interface_mock> dbusIfMock;

    object_server_mock(const std::string& path)
    {
        dbusIfMock = std::make_shared<dbus_interface_mock>(path, mctpIntf);
    };
    virtual ~object_server_mock(){};

    std::shared_ptr<dbus_interface_mock> add_interface(__attribute__((unused))
                                                       const std::string& path,
                                                       __attribute__((unused))
                                                       const std::string& name)
    {
        return dbusIfMock;
    };
};

} // namespace mctpd_mock
