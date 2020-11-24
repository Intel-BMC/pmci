#pragma once

#include <systemd/sd-bus.h>

#include <iostream>
#include <map>
#include <sdbusplus/asio/object_server.hpp>
#include <tuple>
#include <type_traits>

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

// Mixin class used to generate proper function for type T
template <typename T>
struct set_property_mock
{
    MOCK_METHOD(bool, set_property, (const std::string&, T));
};

template <typename... PropertyTypes>
class Properties
{
  public:
    template <typename T>
    T get(const std::string& name)
    {
        return std::get<T>(properties.at(name));
    }

    template <typename T>
    void put(const std::string& name, const T& value)
    {
        properties[name] = value;
    }

  private:
    std::map<std::string, std::variant<std::decay_t<PropertyTypes>...>>
        properties;
};

template <typename... PropertyTypes>
class dbus_interface_mock
    : public MockType<register_property_mock<PropertyTypes>>...,
      public MockType<set_property_mock<PropertyTypes>>...
{
  public:
    // Need those to properly extract mocked functions
    using MockType<register_property_mock<PropertyTypes>>::register_property...;
    using MockType<
        register_property_mock<PropertyTypes>>::gmock_register_property...;
    using MockType<set_property_mock<PropertyTypes>>::set_property...;
    using MockType<set_property_mock<PropertyTypes>>::gmock_set_property...;

    std::string path;
    std::string name;
    Properties<PropertyTypes...> properties;

    dbus_interface_mock(const std::string& pathArg,
                        const std::string& nameArg) :
        path{pathArg},
        name{nameArg}
    {
        returnByDefault(true);
    }

    virtual ~dbus_interface_mock() = default;

    MOCK_METHOD(bool, initialize, ());
    MOCK_METHOD(bool, register_method, (const std::string&));
    MOCK_METHOD(bool, register_signal, (const std::string&));

    template <typename... SignalSignature>
    bool register_signal(const std::string& signalName)
    {
        return register_signal(signalName);
    }

    template <typename CallbackType>
    bool register_method(const std::string& methodName,
                         __attribute__((unused)) CallbackType&& value)
    {
        return register_method(methodName);
    }

    std::string get_object_path(void)
    {
        return path;
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
                  .WillByDefault([this, expectedReturn](const std::string& n,
                                                        PropertyTypes p) {
                      properties.put(n, p);
                      return expectedReturn;
                  }));

        (...,
         ON_CALL(*this,
                 register_property(_, An<PropertyTypes>(),
                                   An<sdbusplus::asio::PropertyPermission&>()))
             .WillByDefault(
                 [this, expectedReturn](const std::string& n, PropertyTypes p,
                                        sdbusplus::asio::PropertyPermission&) {
                     properties.put(n, p);
                     return expectedReturn;
                 }));

        (..., ON_CALL(*this, set_property(_, An<PropertyTypes>()))
                  .WillByDefault([this, expectedReturn](const std::string& n,
                                                        PropertyTypes p) {
                      properties.put(n, p);
                      return expectedReturn;
                  }));
    }
};

template <typename dbus_interface_mock>
class object_server_mock
{
  public:
    class Backdoor
    {
      public:
        std::shared_ptr<dbus_interface_mock>
            add_interface(const std::string& path, const std::string& name)
        {
            auto it = std::find_if(
                interfaces.begin(), interfaces.end(),
                [&](const std::shared_ptr<dbus_interface_mock>& interface) {
                    return (interface->path == path) &&
                           (interface->name == name);
                });
            if (it != interfaces.end())
            {
                return *it;
            }

            return interfaces.emplace_back(
                std::make_shared<dbus_interface_mock>(path, name));
        }

        bool remove_interface(const std::string& path, const std::string& name)
        {
            auto it = std::find_if(
                interfaces.begin(), interfaces.end(),
                [&](const std::shared_ptr<dbus_interface_mock>& interface) {
                    return (interface->path == path) &&
                           (interface->name == name);
                });
            if (it != interfaces.end())
            {
                interfaces.erase(it);
                return true;
            }
            return false;
        }

        std::shared_ptr<dbus_interface_mock>
            get_interface(const std::string& path, const std::string& name)
        {
            return add_interface(path, name);
        }

        std::vector<std::shared_ptr<dbus_interface_mock>> interfaces;
    };

    object_server_mock()
    {
        using ::testing::Return;

        ON_CALL(*this, add_interface)
            .WillByDefault([this](const std::string& pathArg,
                                  const std::string& ifaceArg) {
                return backdoor.add_interface(pathArg, ifaceArg);
            });

        ON_CALL(*this, remove_interface)
            .WillByDefault([this](std::shared_ptr<dbus_interface_mock>& iface) {
                return backdoor.remove_interface(iface->path, iface->name);
            });

        ON_CALL(*this, add_manager).WillByDefault(Return(true));
    }

    virtual ~object_server_mock() = default;

    MOCK_METHOD(bool, add_manager, (const std::string&));
    MOCK_METHOD(std::shared_ptr<dbus_interface_mock>, add_interface,
                (const std::string&, const std::string&));
    MOCK_METHOD(bool, remove_interface,
                (std::shared_ptr<dbus_interface_mock>&));

    Backdoor backdoor;
};

} // namespace impl

// DBus interface with list of property types supported
using dbus_interface_mock = MockType<
    impl::dbus_interface_mock<bool, uint8_t, uint16_t, const std::string&,
                              std::vector<uint8_t>, std::vector<uint16_t>>>;

using object_server_mock =
    MockType<impl::object_server_mock<dbus_interface_mock>>;

} // namespace mctpd_mock
