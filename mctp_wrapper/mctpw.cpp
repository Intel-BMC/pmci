/*
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "mctpw.h"

#include <stdio.h>
#include <stdlib.h>

#include <atomic>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/container/flat_map.hpp>
#include <iostream>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/slot.hpp>

#define UNUSED(x) (void)(x)

template <typename T1, typename T2>
using DictType = boost::container::flat_map<T1, T2>;
using ServiceHandleType = std::pair<mctpw_binding_type_t, std::string>;
using MctpPropertiesVariantType =
    std::variant<uint16_t, int16_t, int32_t, uint32_t, bool, std::string,
                 uint8_t, std::vector<uint8_t>>;

static std::shared_ptr<sdbusplus::bus::bus> mctpwBus;

class mctpw_exception : public std::exception
{
  private:
    int errCode;
    std::string descr;

  public:
    mctpw_exception() = delete;
    mctpw_exception(int e) : errCode(e), descr(std::to_string(e)){};
    mctpw_exception(int e, std::string s) :
        errCode(e), descr(s + std::to_string(e)){};
    virtual ~mctpw_exception(){};
    virtual const char* what() const noexcept override
    {
        return descr.c_str();
    }
    int get()
    {
        return errCode;
    }
};

static const std::unordered_map<mctpw_binding_type_t, const std::string>
    bindingToInterface = {
        {mctp_over_smbus, "xyz.openbmc_project.MCTP.Binding.SMBus"},
        {mctp_over_pcie_vdm, "xyz.openbmc_project.MCTP.Binding.PCIe"},
        {mctp_over_usb, ""},
        {mctp_over_kcs, ""},
        {mctp_over_serial, ""},
        {vendor_defined, ""}};

struct clientContext
{
    ServiceHandleType* service_h;
    mctpw_message_type_t type;
    uint32_t vendor_id;
    uint16_t vendor_message_type;
    uint16_t vendor_message_type_mask;
    mctpw_reconfiguration_callback_t nc_cb;
    mctpw_receive_message_callback_t rx_cb;
    std::atomic_flag thread_run_flag;
    std::mutex thread_mutex;
    std::vector<std::unique_ptr<sdbusplus::bus::match::match>> matchers;
};

template <typename Property>
static auto
    readPropertyValue(sdbusplus::bus::bus& bus, const std::string& service,
                      const std::string& path, const std::string& interface,
                      const std::string& property)
{
    auto msg = bus.new_method_call(service.c_str(), path.c_str(),
                                   "org.freedesktop.DBus.Properties", "Get");

    msg.append(interface.c_str(), property.c_str());
    auto reply = bus.call(msg);

    sdbusplus::message::variant<Property> v;
    reply.read(v);
    return sdbusplus::message::variant_ns::get<Property>(v);
}

static auto register_signal_handler(sdbusplus::bus::bus& bus,
                                    sd_bus_message_handler_t handler, void* ctx,
                                    std::string interface, std::string name,
                                    std::string sender, std::string arg0)
{
    std::string matcherString = "type='signal',interface='";

    matcherString += interface + "'";
    matcherString += ", member='" + name + "'";
    if (sender.size())
    {
        matcherString += ", sender='" + sender + "'";
    }
    if (arg0.size())
    {
        matcherString += ", arg0=" + arg0;
    }

    return std::make_unique<sdbusplus::bus::match::match>(bus, matcherString,
                                                          handler, ctx);
}

int mctpw_find_bus_by_binding_type(mctpw_binding_type_t binding_type,
                                   unsigned bus_index, void** mctpw_bus_handle)
{
    try
    {
        std::unique_ptr<ServiceHandleType> serviceHandle =
            std::make_unique<ServiceHandleType>();
        if (!mctpwBus)
        {
            mctpwBus = std::make_shared<sdbusplus::bus::bus>(
                sdbusplus::bus::new_default_system());
        }

        auto msg = mctpwBus->new_method_call(
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetObject");

        std::vector<std::string> interfaces;
        interfaces.push_back(bindingToInterface.at(binding_type));

        msg.append("/xyz/openbmc_project/mctp", interfaces);
        auto reply = mctpwBus->call(msg);
        if (reply.is_method_error())
        {
            mctpw_exception err(reply.get_errno(), "Method GetObject failed:");
            throw err;
        }
        DictType<std::string, std::vector<std::string>> services;
        reply.read(services);

        for (auto& i : services)
        {
            int bus = -1;
            if (binding_type == mctp_over_smbus)
            {
                std::string pv = readPropertyValue<std::string>(
                    *mctpwBus, i.first, "/xyz/openbmc_project/mctp",
                    bindingToInterface.at(binding_type), "BusNumber");
                /* format of BusNumber:path-bus */
                std::vector<std::string> splitted;
                boost::split(splitted, pv, boost::is_any_of("-"));
                if (splitted.size() == 2)
                {
                    try
                    {
                        bus = std::stoi(splitted[1]);
                    }
                    catch (std::exception& e)
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            e.what());
                        continue;
                    }
                }
            }
            else if (binding_type == mctp_over_pcie_vdm)
            {
                uint16_t pv = readPropertyValue<uint16_t>(
                    *mctpwBus, i.first, "/xyz/openbmc_project/mctp",
                    bindingToInterface.at(binding_type), "BDF");
                /* format of BDF:
                 *  Byte 1 [7:0] Bus number
                 *  Byte 2 [7:3] Device number [2:0] Function Number
                 */
                bus = pv & 0xff;
            }
            else
            {
                mctpw_exception err(EINVAL, "Unsupported binding type:");
                throw err;
            }

            if (static_cast<unsigned>(bus) == bus_index)
            {
                serviceHandle->first = binding_type;
                serviceHandle->second = i.first;
                *mctpw_bus_handle = static_cast<void*>(serviceHandle.release());
                return 0;
            }
        }
    }
    catch (std::exception& e)
    {
        *mctpw_bus_handle = nullptr;
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return -EREMOTEIO;
    }
    catch (...)
    {
        *mctpw_bus_handle = nullptr;
        return -EREMOTEIO;
    }
    return -ENOENT;
}

static int network_reconfiguration_cb(sd_bus_message* m, void* userdata,
                                      sd_bus_error* ret_error)
{
    std::vector<std::string> tracedProperties = {
        "Eid",          "EidPool",  "Mode", "NetworkId", "discoveredFlag",
        "SlaveAddress", "BusNumber"};
    std::vector<std::string> tracedInterfaces = {
        "xyz.openbmc_project.MCTP.Binding.PCIe",
        "xyz.openbmc_project.MCTP.Binding.SMBus",
        "xyz.openbmc_project.MCTP.Endpoint",
        "xyz.openbmc_project.MCTP.BusOwner"};

    if (!userdata || (ret_error && sd_bus_error_is_set(ret_error)))
    {
        return 0;
    }

    try
    {
        clientContext* context = static_cast<clientContext*>(userdata);
        sdbusplus::message::message message{m};

        if (!context->nc_cb)
        {
            return 0;
        }

        std::string cb_type = message.get_member();

        if (cb_type == "PropertiesChanged")
        {
            /* Signal format:
             * STRING interface_name,
             * DICT<STRING,VARIANT> changed_properties,
             * ARRAY<STRING> invalidated_properties
             */
            DictType<std::string, MctpPropertiesVariantType> properties;
            std::string interface;

            message.read(interface, properties);

            for (auto& i : properties)
            {
                if (std::find(tracedProperties.begin(), tracedProperties.end(),
                              i.first) != tracedProperties.end())
                {
                    context->nc_cb(userdata);
                }
            }
        }
        else if (cb_type == "InterfacesAdded")
        {
            /* Signal format:
             * OBJPATH object_path,
             * DICT<STRING,DICT<STRING,VARIANT>> interfaces_and_properties
             */
            DictType<std::string,
                     DictType<std::string, MctpPropertiesVariantType>>
                values;
            sdbusplus::message::object_path object_path;

            message.read(object_path, values);

            for (auto& i : values)
            {
                if (std::find(tracedInterfaces.begin(), tracedInterfaces.end(),
                              i.first) != tracedInterfaces.end())
                {
                    context->nc_cb(userdata);
                }
            }
        }
        else if (cb_type == "InterfacesRemoved")
        {
            /* Signal message format:
             * OBJPATH object_path, ARRAY<STRING> interfaces);
             */
            std::vector<std::string> values;
            sdbusplus::message::object_path object_path;

            message.read(object_path, values);
            for (auto& i : values)
            {
                if (std::find(tracedInterfaces.begin(), tracedInterfaces.end(),
                              i) != tracedInterfaces.end())
                {
                    context->nc_cb(userdata);
                }
            }
        }
        else
        {
            return 0;
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
    }
    catch (...)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown exception from  network_reconfiguration_cb");
    }

    return 0;
}

int mctpw_register_client(void* mctpw_bus_handle, mctpw_message_type_t type,
                          uint32_t vendor_id, bool receive_requests,
                          uint16_t vendor_message_type,
                          uint16_t vendor_message_type_mask,
                          mctpw_reconfiguration_callback_t nc_cb,
                          mctpw_receive_message_callback_t rx_cb,
                          void** client_context)
{
    clientContext* ctx = new clientContext;
    UNUSED(receive_requests);

    if (!mctpw_bus_handle)
    {
        return -EINVAL;
    }
    if (!ctx)
    {
        return -ENOMEM;
    }

    try
    {
        ctx->service_h = static_cast<ServiceHandleType*>(mctpw_bus_handle);
        ctx->type = type;
        ctx->vendor_id = vendor_id;
        ctx->vendor_message_type = vendor_message_type;
        ctx->vendor_message_type_mask = vendor_message_type_mask;
        ctx->rx_cb = rx_cb ? rx_cb : nullptr;
        ctx->nc_cb = nc_cb ? nc_cb : nullptr;

        /* check if any async opertations will be used */
        if (ctx->nc_cb || ctx->rx_cb)
        {
            std::thread t([=] {
                try
                {
                    sdbusplus::bus::bus bus =
                        sdbusplus::bus::new_default_system();
                    if (ctx->nc_cb)
                    {
                        ctx->matchers.push_back(register_signal_handler(
                            bus, network_reconfiguration_cb,
                            static_cast<void*>(ctx),
                            "org.freedesktop.DBus.Properties",
                            "PropertiesChanged", ctx->service_h->second, ""));
                        ctx->matchers.push_back(register_signal_handler(
                            bus, network_reconfiguration_cb,
                            static_cast<void*>(ctx),
                            "org.freedesktop.DBus.ObjectManager",
                            "InterfacesAdded", ctx->service_h->second, ""));
                        ctx->matchers.push_back(register_signal_handler(
                            bus, network_reconfiguration_cb,
                            static_cast<void*>(ctx),
                            "org.freedesktop.DBus.ObjectManager",
                            "InterfacesRemoved", ctx->service_h->second, ""));
                    }
                    // todo: Register for receive signal
                    ctx->thread_run_flag.test_and_set();
                    ctx->thread_mutex.lock();
                    while (ctx->thread_run_flag.test_and_set())
                    {
                        bus.process_discard();
                        bus.wait(10 * 1000);
                    }
                }
                catch (...)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Unhandled exception in io thread");
                }
                ctx->thread_mutex.unlock();
            });
            t.detach();
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        delete ctx;
        *client_context = nullptr;
        return -EINVAL;
    }
    catch (...)
    {
        delete ctx;
        *client_context = nullptr;
        return -EINVAL;
    }
    *client_context = static_cast<void*>(ctx);
    return 0;
}

void mctpw_unregister_client(void* client_context)
{
    if (!client_context)
    {
        return;
    }

    clientContext* ctx = static_cast<clientContext*>(client_context);

    /* stop bus processing loop*/
    ctx->thread_run_flag.clear();
    /* wait for thread to be sure that ctx ptr will not be used */
    ctx->thread_mutex.lock();
    /* unlock mutex before destruction */
    ctx->thread_mutex.unlock();
    delete ctx;
    return;
}
