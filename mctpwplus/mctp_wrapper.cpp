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

#include "dbus_cb.hpp"
#include "service_monitor.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>
#include <unordered_set>

using namespace mctpw;

template <typename T1, typename T2>
using DictType = boost::container::flat_map<T1, T2>;
using ServiceHandleType = std::pair<BindingType, std::string>;
using MctpPropertiesVariantType =
    std::variant<uint16_t, int16_t, int32_t, uint32_t, bool, std::string,
                 uint8_t, std::vector<uint8_t>>;

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

    std::variant<Property> v;
    reply.read(v);
    return std::get<Property>(v);
}

static auto registerSignalHandler(sdbusplus::bus::bus& bus,
                                  sd_bus_message_handler_t handler, void* ctx,
                                  const std::string& interface,
                                  const std::string& name,
                                  const std::string& sender,
                                  const std::string& arg0)
{
    std::string matcherString = sdbusplus::bus::match::rules::type::signal();

    matcherString += sdbusplus::bus::match::rules::interface(interface);
    matcherString += sdbusplus::bus::match::rules::member(name);
    if (!sender.empty())
    {
        matcherString += sdbusplus::bus::match::rules::sender(sender);
    }
    if (!arg0.empty())
    {
        matcherString += sdbusplus::bus::match::rules::argN(0, arg0);
    }
    return std::make_unique<sdbusplus::bus::match::match>(bus, matcherString,
                                                          handler, ctx);
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
    listenForNewMctpServices();
}

MCTPWrapper::MCTPWrapper(std::shared_ptr<sdbusplus::asio::connection> conn,
                         const MCTPConfiguration& configIn,
                         const ReconfigurationCallback& networkChangeCb,
                         const ReceiveMessageCallback& rxCb) :
    networkChangeCallback(networkChangeCb),
    receiveCallback(rxCb), config(configIn), connection(conn)
{
    listenForNewMctpServices();
}

MCTPWrapper::~MCTPWrapper() noexcept
{
}

void MCTPWrapper::detectMctpEndpointsAsync(StatusCallback&& registerCB)
{
    boost::asio::spawn(connection->get_io_context(),
                       [&, this](boost::asio::yield_context yield) {
                           auto ec = detectMctpEndpoints(yield);
                           if (registerCB)
                           {
                               registerCB(ec, this);
                           }
                       });
}

void MCTPWrapper::registerListeners(const std::string& serviceName)
{
    if (networkChangeCallback)
    {
        matchers.push_back(registerSignalHandler(
            static_cast<sdbusplus::bus::bus&>(*connection), onPropertiesChanged,
            static_cast<void*>(this), "org.freedesktop.DBus.Properties",
            "PropertiesChanged", serviceName, ""));
        matchers.push_back(registerSignalHandler(
            static_cast<sdbusplus::bus::bus&>(*connection), onInterfacesAdded,
            static_cast<void*>(this), "org.freedesktop.DBus.ObjectManager",
            "InterfacesAdded", serviceName, ""));
        matchers.push_back(registerSignalHandler(
            static_cast<sdbusplus::bus::bus&>(*connection), onInterfacesRemoved,
            static_cast<void*>(this), "org.freedesktop.DBus.ObjectManager",
            "InterfacesRemoved", serviceName, ""));
    }
    if (receiveCallback)
    {
        matchers.push_back(registerSignalHandler(
            static_cast<sdbusplus::bus::bus&>(*connection),
            mctpw::onMessageReceivedSignal, static_cast<void*>(this),
            "xyz.openbmc_project.MCTP.Base", "MessageReceivedSignal",
            serviceName, ""));
    }
}

boost::system::error_code
    MCTPWrapper::detectMctpEndpoints(boost::asio::yield_context yield)
{
    boost::system::error_code ec =
        boost::system::errc::make_error_code(boost::system::errc::success);

    auto bus_vector = findBusByBindingType(yield);
    if (!bus_vector)
    {
        return boost::system::errc::make_error_code(
            boost::system::errc::not_supported);
    }

    endpointMap = buildMatchingEndpointMap(yield, bus_vector.value());

    // No need to register for dbus signal multiple times. This method may
    // be called again from reconfiguration callbacks
    if (!matchers.empty())
    {
        return ec;
    }
    for (auto& [busId, serviceName] : bus_vector.value())
    {
        registerListeners(serviceName);
    }
    return ec;
}

int MCTPWrapper::getBusId(const std::string& serviceName)
{
    try
    {
        int bus = -1;
        if (config.bindingType == BindingType::mctpOverSmBus)
        {
            std::string pv = readPropertyValue<std::string>(
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
                    throw std::runtime_error(
                        std::string("Invalid buspath on ") + pv);
                }
            }
        }
        else if (config.bindingType == BindingType::mctpOverPcieVdm)
        {
            bus = readPropertyValue<uint16_t>(
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
    catch (const std::exception& e)
    {
        throw boost::system::system_error(
            boost::system::errc::make_error_code(boost::system::errc::io_error),
            (std::string("Error in getting Bus property from ") + serviceName +
             ". " + e.what()));
    }
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
        // find the services, with their interfaces, that implement a
        // certain object path
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
            try
            {
                int bus = this->getBusId(service);
                buses.emplace_back(bus, service);
            }
            catch (const std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    e.what());
            }
        }
        // buses will contain list of {busid servicename}. Sample busid may
        // be from i2cdev-2
        return buses;
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (std::string("findBusByBindingType: ") + e.what()).c_str());
        return std::nullopt;
    }
}

/* Return format:
 * map<Eid, pair<bus, service_name_string>>
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
        // get all objects, interfaces and properties in a single method
        // call DICT<OBJPATH,DICT<STRING,DICT<STRING,VARIANT>>>
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

            if (interfaces.find("xyz.openbmc_project.MCTP.Endpoint") ==
                interfaces.end())
            {
                continue;
            }
            try
            {
                /*SupportedMessageTypes interface is mandatory*/
                auto& msgIf = interfaces.at(
                    "xyz.openbmc_project.MCTP.SupportedMessageTypes");
                MctpPropertiesVariantType pv;
                pv = msgIf.at(msgTypeToPropertyName.at(config.type));

                if (std::get<bool>(pv) == false)
                {
                    continue;
                }
                if (MessageType::vdpci == config.type)
                {
                    static const char* vdMsgTypeInterface =
                        "xyz.openbmc_project.MCTP.PCIVendorDefined";
                    auto vendorIdStr = readPropertyValue<std::string>(
                        *connection, bus.second.c_str(), objectPath.str,
                        vdMsgTypeInterface, "VendorID");
                    uint16_t vendorId;
                    {
                        std::stringstream ss;
                        ss << std::hex << vendorIdStr;
                        ss >> vendorId;
                        if (ss.fail())
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::WARNING>(
                                ("Unable to parse vendor id from " +
                                 vendorIdStr)
                                    .c_str());
                            continue;
                        }
                    }
                    if (vendorId !=
                        be16toh(config.vendorDefinedValues->vendorId))
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            ("VendorID not matching for " + objectPath.str)
                                .c_str());
                        continue;
                    }
                    auto msgTypes = readPropertyValue<std::vector<uint16_t>>(
                        *connection, bus.second.c_str(), objectPath.str,
                        vdMsgTypeInterface, "MessageTypeProperty");
                    auto itMsgType = std::find(
                        msgTypes.begin(), msgTypes.end(),
                        be16toh(config.vendorDefinedValues->vendorMessageType));
                    if (msgTypes.end() == itMsgType)
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            ("Vendor Message Type not matching for " +
                             objectPath.str)
                                .c_str());
                        continue;
                    }
                }
                /* format of of endpoint path: path/Eid */
                std::vector<std::string> splitted;
                boost::split(splitted, objectPath.str, boost::is_any_of("/"));
                if (splitted.size())
                {
                    /* take the last element and convert it to eid */
                    uint8_t eid = static_cast<eid_t>(
                        std::stoi(splitted[splitted.size() - 1]));
                    eids[eid] = bus;
                }
            }
            catch (std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            }
        }
    }
    return eids;
}

void MCTPWrapper::sendReceiveAsync(ReceiveCallback callback, eid_t dstEId,
                                   const ByteArray& request,
                                   std::chrono::milliseconds timeout)
{
    ByteArray response;

    auto it = this->endpointMap.find(dstEId);
    if (this->endpointMap.end() == it)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SendReceiveAsync: Eid not found in end point map",
            phosphor::logging::entry("EID=%d", dstEId));
        boost::system::error_code ec =
            boost::system::errc::make_error_code(boost::system::errc::io_error);
        if (callback)
        {
            callback(ec, response);
        }
        return;
    }

    connection->async_method_call(
        callback, it->second.second, "/xyz/openbmc_project/mctp",
        "xyz.openbmc_project.MCTP.Base", "SendReceiveMctpMessagePayload",
        dstEId, request, static_cast<uint16_t>(timeout.count()));
}

std::pair<boost::system::error_code, ByteArray>
    MCTPWrapper::sendReceiveYield(boost::asio::yield_context yield,
                                  eid_t dstEId, const ByteArray& request,
                                  std::chrono::milliseconds timeout)
{
    auto receiveResult = std::make_pair(
        boost::system::errc::make_error_code(boost::system::errc::success),
        ByteArray());

    auto it = this->endpointMap.find(dstEId);
    if (this->endpointMap.end() == it)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SendReceiveYield: Eid not found in end point map",
            phosphor::logging::entry("EID=%d", dstEId));
        receiveResult.first =
            boost::system::errc::make_error_code(boost::system::errc::io_error);
        return receiveResult;
    }

    receiveResult.second = connection->yield_method_call<ByteArray>(
        yield, receiveResult.first, it->second.second,
        "/xyz/openbmc_project/mctp", "xyz.openbmc_project.MCTP.Base",
        "SendReceiveMctpMessagePayload", dstEId, request,
        static_cast<uint16_t>(timeout.count()));

    return receiveResult;
}

void MCTPWrapper::sendAsync(const SendCallback& callback, const eid_t dstEId,
                            const uint8_t msgTag, const bool tagOwner,
                            const ByteArray& request)
{
    auto it = this->endpointMap.find(dstEId);
    if (this->endpointMap.end() == it)
    {
        boost::system::error_code ec =
            boost::system::errc::make_error_code(boost::system::errc::io_error);
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "sendAsync: Eid not found in end point map",
            phosphor::logging::entry("EID=%d", dstEId));
        if (callback)
        {
            callback(ec, -1);
        }
        return;
    }

    connection->async_method_call(
        callback, it->second.second, "/xyz/openbmc_project/mctp",
        "xyz.openbmc_project.MCTP.Base", "SendMctpMessagePayload", dstEId,
        msgTag, tagOwner, request);
}

std::pair<boost::system::error_code, int>
    MCTPWrapper::sendYield(boost::asio::yield_context& yield,
                           const eid_t dstEId, const uint8_t msgTag,
                           const bool tagOwner, const ByteArray& request)
{
    auto it = this->endpointMap.find(dstEId);
    if (this->endpointMap.end() == it)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "sendYield: Eid not found in end point map",
            phosphor::logging::entry("EID=%d", dstEId));
        return std::make_pair(
            boost::system::errc::make_error_code(boost::system::errc::io_error),
            -1);
    }

    boost::system::error_code ec =
        boost::system::errc::make_error_code(boost::system::errc::success);
    int status = connection->yield_method_call<int>(
        yield, ec, it->second.second, "/xyz/openbmc_project/mctp",
        "xyz.openbmc_project.MCTP.Base", "SendMctpMessagePayload", dstEId,
        msgTag, tagOwner, request);

    return std::make_pair(ec, status);
}

void MCTPWrapper::addToEidMap(boost::asio::yield_context yield,
                              const std::string& serviceName)
{
    int busID = getBusId(serviceName);
    std::vector<std::pair<unsigned, std::string>> buses;
    buses.emplace_back(busID, serviceName);
    auto eidMap = buildMatchingEndpointMap(yield, buses);
    this->endpointMap.insert(eidMap.begin(), eidMap.end());
}

size_t MCTPWrapper::eraseDevice(eid_t eid)
{
    return endpointMap.erase(eid);
}

void MCTPWrapper::listenForNewMctpServices()
{
    static const std::string matchRule =
        "type='signal',member='InterfacesAdded',interface='org.freedesktop."
        "DBus.ObjectManager',path='/xyz/openbmc_project/"
        "mctp'";
    this->matchers.push_back(std::make_unique<sdbusplus::bus::match::match>(
        *connection, matchRule, internal::NewServiceCallback(*this)));
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Wrapper: Listening for new MCTP services");

    // TODO. Listen for mctp services going down and cleanup match rules
}