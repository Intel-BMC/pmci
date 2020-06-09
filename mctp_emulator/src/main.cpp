#include "MCTPBinding.hpp"
#include "SMBusBinding.hpp"

#include <CLI/CLI.hpp>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/MCTP/Base/server.hpp>
#include <xyz/openbmc_project/MCTP/Endpoint/server.hpp>
#include <xyz/openbmc_project/MCTP/SupportedMessageTypes/server.hpp>

std::map<std::string, binding> mctpBindingsMap = {{"smbus", binding::smbus},
                                                  {"pcie", binding::pcie}};

std::shared_ptr<sdbusplus::asio::connection> bus;

std::string endpointDataFile = "/usr/share/mctp-emulator/endpoints.json";
std::string mctpDevObj = "/xyz/openbmc_project/mctp/device/";
std::vector<std::shared_ptr<sdbusplus::asio::dbus_interface>> endpointInterface;
std::vector<std::shared_ptr<sdbusplus::asio::dbus_interface>> msgTypeInterface;

using json = nlohmann::json;
using mctp_base = sdbusplus::xyz::openbmc_project::MCTP::server::Base;
using mctp_endpoint = sdbusplus::xyz::openbmc_project::MCTP::server::Endpoint;
using mctp_msg_types =
    sdbusplus::xyz::openbmc_project::MCTP::server::SupportedMessageTypes;

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
    std::string mode;
    uint16_t networkId;
    json msgType;
    bool mctpControl;
    bool pldm;
    bool ncsi;
    bool ethernet;
    bool nvmeMgmtMsg;
    bool spdm;
    bool vdpci;
    bool vdiana;

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
            mode = iter["Mode"];
            networkId = iter["NetworkId"];
            msgType = iter["SupportedMessageTypes"];
            mctpControl = msgType["MctpControl"];
            pldm = msgType["PLDM"];
            ncsi = msgType["NCSI"];
            ethernet = msgType["Ethernet"];
            nvmeMgmtMsg = msgType["NVMeMgmtMsg"];
            spdm = msgType["SPDM"];
            vdpci = msgType["VDPCI"];
            vdiana = msgType["VDIANA"];
        }
        catch (json::exception& e)
        {
            std::cerr << "message: " << e.what() << '\n'
                      << "exception id: " << e.id << std::endl;
            continue;
        }

        std::shared_ptr<sdbusplus::asio::dbus_interface> endpointIntf;
        std::shared_ptr<sdbusplus::asio::dbus_interface> msgTypeIntf;
        std::string mctpEpObj = mctpDevObj + std::to_string(eid);

        auto enpointObjManager =
            std::make_shared<sdbusplus::server::manager::manager>(
                *bus, mctpEpObj.c_str());

        endpointIntf =
            objectServer->add_interface(mctpEpObj, mctp_endpoint::interface);
        endpointIntf->register_property(
            "Uuid", std::vector<uint8_t>(uuid.begin(), uuid.end()));
        endpointIntf->register_property(
            "Mode", mctp_base::convertBindingModeTypesToString(
                        static_cast<mctp_base::BindingModeTypes>(1)));
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
        msgTypeIntf->register_property("VDPCI", vdpci);
        msgTypeIntf->register_property("VDIANA", vdiana);
        msgTypeIntf->initialize();
        msgTypeInterface.push_back(msgTypeIntf);
    }
}

int main()
{
    // TODO: Read the binding configuration from a json file
    std::string binding("smbus");

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

    // TODO: Initialise binding based on configurations exposed by Entity
    // Manager
    switch (mctpBindingsMap[binding])
    {
        case binding::smbus:
        {
            SMBusBinding SMBus(objectServer, mctpBaseObj);
            break;
        }
        case binding::pcie:
        {
            break;
        }
        default:
        {
            break;
        }
    }
    initEndPointDevices(objectServer);
    ioc.run();

    return 0;
}
