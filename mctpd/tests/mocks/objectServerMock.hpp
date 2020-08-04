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

    MOCK_METHOD3(register_property, bool(const std::string&, uint8_t,
                                         sdbusplus::asio::PropertyPermission&));
    MOCK_METHOD3(register_property, bool(const std::string&, uint16_t,
                                         sdbusplus::asio::PropertyPermission&));
    MOCK_METHOD3(register_property, bool(const std::string&, const std::string&,
                                         sdbusplus::asio::PropertyPermission&));
    MOCK_METHOD3(register_property, bool(const std::string&, bool,
                                         sdbusplus::asio::PropertyPermission&));
    MOCK_METHOD3(register_property,
                 bool(const std::string&, std::vector<uint8_t>,
                      sdbusplus::asio::PropertyPermission&));
    MOCK_METHOD2(register_property, bool(const std::string&, uint8_t));
    MOCK_METHOD2(register_property, bool(const std::string&, uint16_t));
    MOCK_METHOD2(register_property,
                 bool(const std::string&, const std::string&));
    MOCK_METHOD2(register_property, bool(const std::string&, bool));
    MOCK_METHOD2(register_property,
                 bool(const std::string&, std::vector<uint8_t>));
    MOCK_METHOD1(register_method, bool(const std::string&));
    MOCK_METHOD1(register_signal, bool(const std::string&));

    template <typename... SignalSignature>
    bool register_signal(const std::string& name)
    {
        return register_signal(name);
    }

    template <typename CallbackType>
    bool register_method(const std::string& name,
                         __attribute__((unused)) CallbackType&& value)
    {
        return register_method(name);
    }

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

    bool remove_interface(__attribute__((unused))
                          std::shared_ptr<dbus_interface_mock>& iface)
    {
        return true;
    };
};

} // namespace mctpd_mock
