#pragma once

#include <systemd/sd-bus.h>

#include <iostream>
#include <sdbusplus/asio/object_server.hpp>

#include "gtest/gtest.h"
#include <gmock/gmock.h>

namespace mctpd_mock
{

// Setting NiceMock as default as D-Bus calls tends to grow in the code and we
// don't want our tests to be warning/failing everytime something changes
//
// Change to 'NaggyMock' if you want previous behavior (warning messages) in
// your tests. It can be useful during developing tests.
#define MockType ::testing::NiceMock

namespace impl
{

// Mixin class used to generate proper function for type T
template <typename T>
struct register_property_mock
{
    MOCK_METHOD(bool, register_property,
                (const std::string&, T, sdbusplus::asio::PropertyPermission&));
    MOCK_METHOD(bool, register_property, (const std::string&, T));
};

template <typename... PropertyTypes>
class dbus_interface_mock
    : public MockType<register_property_mock<PropertyTypes>>...
{
  public:
    // Need those to properly extract mocked functions
    using MockType<register_property_mock<PropertyTypes>>::register_property...;
    using MockType<
        register_property_mock<PropertyTypes>>::gmock_register_property...;

    dbus_interface_mock(__attribute__((unused)) const std::string& path,
                        __attribute__((unused)) const std::string& name)
    {
    }
    virtual ~dbus_interface_mock()
    {
    }

    MOCK_METHOD(bool, initialize, ());
    MOCK_METHOD(bool, register_method, (const std::string&));
    MOCK_METHOD(bool, register_signal, (const std::string&));

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

    void returnByDefault(const bool expectedReturn)
    {
        using ::testing::_;
        using ::testing::An;
        using ::testing::Return;

        ON_CALL(*this, initialize).WillByDefault(Return(expectedReturn));
        ON_CALL(*this, register_signal).WillByDefault(Return(expectedReturn));
        ON_CALL(*this, register_method).WillByDefault(Return(expectedReturn));

        // Applies return for each type in PropertyTypes list
        (..., ON_CALL(*this, register_property(_, An<PropertyTypes>()))
                  .WillByDefault(Return(expectedReturn)));
        (..., ON_CALL(*this, register_property(
                                 _, An<PropertyTypes>(),
                                 An<sdbusplus::asio::PropertyPermission&>()))
                  .WillByDefault(Return(expectedReturn)));
    }
};

template <typename dbus_interface_mock>
class object_server_mock
{
  public:
    const std::string mctpIntf = "xyz.openbmc_project.mctp.mock.base";
    std::shared_ptr<dbus_interface_mock> dbusIfMock;

    object_server_mock(const std::string& path) :
        dbusIfMock(std::make_shared<dbus_interface_mock>(path, mctpIntf))
    {
    }

    virtual ~object_server_mock()
    {
    }

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
    }
};

} // namespace impl

// DBus interface with list of property types supported
using dbus_interface_mock = MockType<impl::dbus_interface_mock<
    bool, uint8_t, uint16_t, const std::string&, std::vector<uint8_t>>>;

using object_server_mock =
    MockType<impl::object_server_mock<dbus_interface_mock>>;

} // namespace mctpd_mock
