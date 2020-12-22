/*
// Copyright (c) 2021 Intel Corporation
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

#include "mctp_wrapper.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sstream>
#include <unordered_set>

using namespace mctpw;

static const std::unordered_map<MessageType, const std::string>
    msgTypeToPropertyName = {{MessageType::pldm, "PLDM"},
                             {MessageType::ncsi, "NCSI"},
                             {MessageType::ethernet, "Ethernet"},
                             {MessageType::nvmeMgmtMsg, "NVMeMgmtMsg"},
                             {MessageType::spdm, "SPDM "},
                             {MessageType::vdpci, "VDPCI"},
                             {MessageType::vdiana, "VDIANA"}};

static const std::unordered_map<BindingType, const std::string>
    bindingToInterface = {
        {BindingType::mctpOverSmBus, "xyz.openbmc_project.MCTP.Binding.SMBus"},
        {BindingType::mctpOverPcieVdm, "xyz.openbmc_project.MCTP.Binding.PCIe"},
        {BindingType::mctpOverUsb, ""},
        {BindingType::mctpOverKcs, ""},
        {BindingType::mctpOverSerial, ""},
        {BindingType::vendorDefined, ""}};

template <typename T1, typename T2>
using DictType = boost::container::flat_map<T1, T2>;
using ServiceHandleType = std::pair<BindingType, std::string>;
using MctpPropertiesVariantType =
    std::variant<uint16_t, int16_t, int32_t, uint32_t, bool, std::string,
                 uint8_t, std::vector<uint8_t>>;

template <typename Property>
static auto
    read_property_value(sdbusplus::bus::bus& bus, const std::string& service,
                        const std::string& path, const std::string& interface,
                        const std::string& property)
{
    auto msg = bus.new_method_call(service.c_str(), path.c_str(),
                                   "org.freedesktop.DBus.Properties", "Get");

    msg.append(interface.c_str(), property.c_str());
    auto reply = bus.call(msg);

    std::variant<Property> v;
    reply.read(v);
    return std::get<Property>(v);
}

MCTPConfiguration::MCTPConfiguration(MessageType msgType, BindingType binding) :
    type(msgType), bindingType(binding)
{
}

MCTPConfiguration::MCTPConfiguration(MessageType msgType, BindingType binding,
                                     uint16_t vid, uint16_t vendorMsgType,
                                     uint16_t vendorMsgTypeMask) :
    type(msgType),
    bindingType(binding)
{
    if (MessageType::vdpci != msgType)
    {
        throw std::invalid_argument("MsgType expected VDPCI");
    }
    setVendorDefinedValues(vid, vendorMsgType, vendorMsgTypeMask);
}

MCTPWrapper::MCTPWrapper(boost::asio::io_context& ioContext,
                         const MCTPConfiguration& configIn,
                         const ReconfigurationCallback& networkChangeCb,
                         const ReceiveMessageCallback& rxCb) :
    networkChangeCallback(networkChangeCb),
    receiveCallback(rxCb), config(configIn),
    connection(std::make_shared<sdbusplus::asio::connection>(ioContext))
{
}

MCTPWrapper::MCTPWrapper(std::shared_ptr<sdbusplus::asio::connection> conn,
                         const MCTPConfiguration& configIn,
                         const ReconfigurationCallback& networkChangeCb,
                         const ReceiveMessageCallback& rxCb) :
    networkChangeCallback(networkChangeCb),
    receiveCallback(rxCb), config(configIn), connection(conn)
{
}

MCTPWrapper::~MCTPWrapper() noexcept
{
}

template <typename Arr, typename Key>
inline static bool containsKey(const Arr& c, const Key& x)
{
    return c.find(x) != std::end(c);
}

void MCTPWrapper::detectMctpEndpointsAsync(StatusCallback&& registerCB)
{
    boost::asio::spawn(connection->get_io_context(),
                       [&, this](boost::asio::yield_context yield) {
                           auto ec = detectMctpEndpoints(yield);
                           registerCB(ec, this);
                       });
}

boost::system::error_code
    MCTPWrapper::detectMctpEndpoints(boost::asio::yield_context yield)
{
    boost::system::error_code ec =
        boost::system::errc::make_error_code(boost::system::errc::success);

    if (auto bus_vector = findBusByBindingType(yield))
    {
        endpointMap = buildMatchingEndpointMap(yield, bus_vector.value());
    }
    else
    {
        ec = boost::system::errc::make_error_code(
            boost::system::errc::not_supported);
    }
    return ec;
}

int MCTPWrapper::getBusID(const std::string& serviceName)
{
    int bus = -1;
    if (config.bindingType == BindingType::mctpOverSmBus)
    {
        std::string pv = read_property_value<std::string>(
            static_cast<sdbusplus::bus::bus&>(*connection), serviceName,
            "/xyz/openbmc_project/mctp",
            bindingToInterface.at(config.bindingType), "BusPath");
        // sample buspath like /dev/i2c-2
        /* format of BusPath:path-bus */
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
                throw std::runtime_error(std::string("Invalid buspath on ") +
                                         pv);
            }
        }
    }
    else if (config.bindingType == BindingType::mctpOverPcieVdm)
    {
        bus = read_property_value<uint16_t>(
            static_cast<sdbusplus::bus::bus&>(*connection), serviceName,
            "/xyz/openbmc_project/mctp",
            bindingToInterface.at(config.bindingType), "BDF");
    }
    else
    {
        throw std::invalid_argument("Unsupported binding type");
    }
    return bus;
}

std::optional<std::vector<std::pair<unsigned, std::string>>>
    MCTPWrapper::findBusByBindingType(boost::asio::yield_context yield)
{
    boost::system::error_code ec;
    std::vector<std::pair<unsigned, std::string>> buses;
    DictType<std::string, std::vector<std::string>> services;
    std::vector<std::string> interfaces;

    try
    {
        interfaces.push_back(bindingToInterface.at(config.bindingType));
        // find the services, with their interfaces, that implement a certain
        // object path
        services = connection->yield_method_call<decltype(services)>(
            yield, ec, "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetObject",
            "/xyz/openbmc_project/mctp", interfaces);

        if (ec)
        {
            throw std::runtime_error(
                (std::string("Error getting mctp services. ") + ec.message())
                    .c_str());
        }

        for (const auto& [service, intfs] : services)
        {
            int bus = this->getBusID(service);
            buses.emplace_back(bus, service);
        }
        // buses will contain list of {busid servicename}. Sample busid may be
        // from i2cdev-2
        return buses;
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (std::string("findBusByBindingType: ") + ec.message()).c_str());
        return std::nullopt;
    }
}

/* Return format:
 * map<EId, pair<bus, service_name_string>>
 */
MCTPWrapper::EndpointMap MCTPWrapper::buildMatchingEndpointMap(
    boost::asio::yield_context yield,
    std::vector<std::pair<unsigned, std::string>>& buses)
{
    std::unordered_map<uint8_t, std::pair<unsigned, std::string>> eids;

    for (auto& bus : buses)
    {
        boost::system::error_code ec;
        DictType<sdbusplus::message::object_path,
                 DictType<std::string,
                          DictType<std::string, MctpPropertiesVariantType>>>
            values;
        // get all objects, interfaces and properties in a single method call
        // DICT<OBJPATH,DICT<STRING,DICT<STRING,VARIANT>>>
        // objpath_interfaces_and_properties
        values = connection->yield_method_call<decltype(values)>(
            yield, ec, bus.second.c_str(), "/xyz/openbmc_project/mctp",
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                (std::string("Error getting managed objects on ") + bus.second +
                 ". Bus " + std::to_string(bus.first))
                    .c_str());
            continue;
        }

        for (const auto& [objectPath, interfaces] : values)
        {
            DictType<std::string,
                     DictType<std::string, MctpPropertiesVariantType>>
                interface;

            if (containsKey(interfaces, "xyz.openbmc_project.MCTP.Endpoint"))
            {
                try
                {
                    /* SupportedMessageTypes interface should be present for
                     * each endpoint
                     */
                    auto& msgIf = interfaces.at(
                        "xyz.openbmc_project.MCTP.SupportedMessageTypes");
                    MctpPropertiesVariantType pv;
                    // TODO: Add support for vendor defined message types.
                    pv = msgIf.at(msgTypeToPropertyName.at(config.type));

                    if (std::get<bool>(pv) == true)
                    {
                        /* format of of endpoint path: path/Eid */
                        std::vector<std::string> splitted;
                        boost::split(splitted, objectPath.str,
                                     boost::is_any_of("/"));
                        if (splitted.size())
                        {
                            /* take the last element and convert it to eid */
                            uint8_t eid = static_cast<eid_t>(
                                std::stoi(splitted[splitted.size() - 1]));
                            eids[eid] = bus;
                        }
                    }
                }
                catch (std::exception& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        e.what());
                }
            }
        }
    }
    return eids;
}
