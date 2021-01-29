#include "OemBinding.hpp"

#include <CLI/CLI.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/bus.hpp>
#include <sstream>
#include <xyz/openbmc_project/MCTP/Base/server.hpp>
#include <xyz/openbmc_project/MCTP/Endpoint/server.hpp>
#include <xyz/openbmc_project/MCTP/SupportedMessageTypes/server.hpp>

std::shared_ptr<sdbusplus::asio::connection> bus;
std::string uuidIntf = "xyz.openbmc_project.Common.UUID";
std::string endpointDataFile = "/usr/share/mctp-emulator/endpoints.json";
std::string pciVdMsgIntf = "xyz.openbmc_project.MCTP.PCIVendorDefined";
std::string mctpDevObj = "/xyz/openbmc_project/mctp/device/";
std::vector<std::shared_ptr<sdbusplus::asio::dbus_interface>> msgTypeInterface;
std::vector<std::shared_ptr<sdbusplus::asio::dbus_interface>>
    vendorDefMsgInterface;
std::vector<std::shared_ptr<sdbusplus::asio::dbus_interface>> uuidInterface;

using json = nlohmann::json;
using mctp_base = sdbusplus::xyz::openbmc_project::MCTP::server::Base;
using mctp_endpoint = sdbusplus::xyz::openbmc_project::MCTP::server::Endpoint;
using mctp_msg_types =
    sdbusplus::xyz::openbmc_project::MCTP::server::SupportedMessageTypes;

std::unordered_map<std::string, mctp_base::BindingModeTypes>
    stringToBindingModeMap = {
        {"busowner", mctp_base::BindingModeTypes::BusOwner},
        {"endpoint", mctp_base::BindingModeTypes::Endpoint}};

void initEndPointDevices(
    std::shared_ptr<sdbusplus::asio::object_server>& objectServer)
{
    std::ifstream jsonFile(endpointDataFile);
    if (!jsonFile.good())
    {
        std::cerr << "unable to open " << endpointDataFile << "\n";
    }

    json endpoints = nullptr;
    uint8_t eid;
    std::string uuid;
    mctp_base::BindingModeTypes mode;
    uint16_t networkId;
    json msgType;
    bool mctpControl;
    bool pldm;
    bool ncsi;
    bool ethernet;
    bool nvmeMgmtMsg;
    bool spdm;
    bool securedMsg;
    bool vdpci;
    bool vdiana;
    std::string vendorID = "0x8086";
    std::vector<uint16_t> msgTypeProperty;
    try
    {
        endpoints = json::parse(jsonFile, nullptr, false);
    }
    catch (json::exception& e)
    {
        std::cerr << "Error parsing " << endpointDataFile << "\n"
                  << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << std::endl;
        return;
    }

    for (auto iter : endpoints["Endpoints"])
    {
        try
        {
            eid = iter["Eid"];
            uuid = iter["Uuid"];
            mode = stringToBindingModeMap.at(iter["Mode"]);
            networkId = iter["NetworkId"];
            msgType = iter["SupportedMessageTypes"];
            mctpControl = msgType["MctpControl"];
            pldm = msgType["PLDM"];
            ncsi = msgType["NCSI"];
            ethernet = msgType["Ethernet"];
            nvmeMgmtMsg = msgType["NVMeMgmtMsg"];
            spdm = msgType["SPDM"];
            securedMsg = msgType["SECUREDMSG"];
            vdpci = msgType["VDPCI"];
            vdiana = msgType["VDIANA"];
            if (vdpci == true)
            {
                json vdpcimt = iter["VDPCIMT"];
                msgTypeProperty =
                    vdpcimt.at("CapabilitySets").get<std::vector<uint16_t>>();
            }
        }
        catch (json::exception& e)
        {
            std::cerr << "message: " << e.what() << '\n'
                      << "exception id: " << e.id << std::endl;
            continue;
        }
        catch (std::out_of_range& e)
        {
            std::cerr << "message: " << e.what() << std::endl;
            continue;
        }

        std::shared_ptr<sdbusplus::asio::dbus_interface> endpointIntf;
        std::shared_ptr<sdbusplus::asio::dbus_interface> msgTypeIntf;
        std::shared_ptr<sdbusplus::asio::dbus_interface> vendorDefMsgIntf;
        std::string mctpEpObj = mctpDevObj + std::to_string(eid);
        std::shared_ptr<sdbusplus::asio::dbus_interface> uuidEndPointIntf;

        auto enpointObjManager =
            std::make_shared<sdbusplus::server::manager::manager>(
                *bus, mctpEpObj.c_str());

        endpointIntf =
            objectServer->add_interface(mctpEpObj, mctp_endpoint::interface);
        endpointIntf->register_property(
            "Mode", mctp_base::convertBindingModeTypesToString(mode));
        endpointIntf->register_property("NetworkId", networkId);
        endpointIntf->initialize();
        endpointInterface.push_back(endpointIntf);

        msgTypeIntf =
            objectServer->add_interface(mctpEpObj, mctp_msg_types::interface);
        msgTypeIntf->register_property("MctpControl", mctpControl);
        msgTypeIntf->register_property("PLDM", pldm);
        msgTypeIntf->register_property("NCSI", ncsi);
        msgTypeIntf->register_property("Ethernet", ethernet);
        msgTypeIntf->register_property("NVMeMgmtMsg", nvmeMgmtMsg);
        msgTypeIntf->register_property("SPDM", spdm);
        msgTypeIntf->register_property("SECUREDMSG", securedMsg);
        msgTypeIntf->register_property("VDPCI", vdpci);
        msgTypeIntf->register_property("VDIANA", vdiana);
        msgTypeIntf->initialize();
        msgTypeInterface.push_back(msgTypeIntf);
        if (vdpci == true)
        {
            vendorDefMsgIntf =
                objectServer->add_interface(mctpEpObj, pciVdMsgIntf);
            vendorDefMsgIntf->register_property("VendorID", vendorID);
            vendorDefMsgIntf->register_property("MessageTypeProperty",
                                                msgTypeProperty);
            vendorDefMsgIntf->initialize();
            vendorDefMsgInterface.push_back(vendorDefMsgIntf);
        }

        uuidEndPointIntf = objectServer->add_interface(mctpEpObj, uuidIntf);
        uuidEndPointIntf->register_property("UUID", uuid);
        uuidEndPointIntf->initialize();
        uuidInterface.push_back(uuidEndPointIntf);
    }
}

int main()
{
    std::string mctpBaseObj = "/xyz/openbmc_project/mctp";
    boost::asio::io_context ioc;
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc](const boost::system::error_code&, const int&) { ioc.stop(); });

    bus = std::make_shared<sdbusplus::asio::connection>(ioc);

    std::string mctpServiceName = "xyz.openbmc_project.mctp-emulator";
    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(bus);
    bus->request_name(mctpServiceName.c_str());

    auto objManager = std::make_shared<sdbusplus::server::manager::manager>(
        *bus, mctpBaseObj.c_str());

    // Create a virtual binding
    OemBinding oemInstance(objectServer, mctpBaseObj);
    initEndPointDevices(objectServer);

    ioc.run();

    return 0;
}
