#include "MCTPBinding.hpp"

#include <fstream>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>

#include "libmctp.h"

using json = nlohmann::json;

std::string reqRespDataFile = "/usr/share/mctp-emulator/req_resp.json";

std::shared_ptr<sdbusplus::asio::dbus_interface> mctpInterface;
std::string mctpIntf = "xyz.openbmc_project.MCTP.Base";

void processMctpCommand(uint8_t dstEid, std::vector<uint8_t>& payload)
{
    uint8_t msgType;
    uint8_t srcEid = dstEid;
    uint8_t msgTag = 0;    // Hardcode Message Tag until a usecase arrives
    bool tagOwner = false; // This is false for responders

    msgType = payload.at(0);

    // TODO : enum for Message Types

    std::ifstream jsonFile(reqRespDataFile);
    // TODO:Validate the file

    json reqResp = nullptr;
    reqResp = json::parse(jsonFile, nullptr, false);
    // TODO:Validate Json data

    switch (msgType)
    {
        case 1: // PLDM
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "mctp-emulator: PLDM Request");
            for (auto iter : reqResp["PLDM"])
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "mctp-emulator: Parsing PLDM commands..");

                std::vector<uint8_t> req = iter["request"];
                req.insert(req.begin(), msgType);
                if (req == payload)
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "mctp-emulator: PLDM Request Matched!");
                    std::vector<uint8_t> response = iter["response"];
                    // TODO:Add a virtual processing delay and send signal
                    auto m = bus->new_signal("/xyz/openbmc_project/mctp",
                                             mctpIntf.c_str(),
                                             "MessageReceivedSignal");
                    m.append(msgType, srcEid, msgTag, tagOwner, response);
                    m.signal_send();
                }
            }
            break;
    }
}

MctpBinding::MctpBinding(
    std::shared_ptr<sdbusplus::asio::object_server>& objServer,
    std::string& objPath)
{
    eid = 8;

    // TODO:Probably read these from mctp_config.json ?
    uint8_t bindingType = 2;
    uint8_t bindingMedium = 3;
    bool staticEidSupport = false;
    std::string uuid("MCTPDBG_EMULATOR");
    std::string bindingMode("xyz.openbmc_project.MCTP.BusOwner");
    // TODO:Add MCTP Binding interfaces here

    mctpInterface = objServer->add_interface(objPath, mctpIntf.c_str());

    mctpInterface->register_method(
        "SendMctpMessagePayload",
        [](uint8_t DstEid, uint8_t MsgTag, bool TagOwner,
           std::vector<uint8_t> payload) {
            uint8_t rc = 0;

            // Dummy entries to get around unused-variable compiler errors
            DstEid = DstEid;
            MsgTag = MsgTag;
            TagOwner = TagOwner;

            phosphor::logging::log<phosphor::logging::level::INFO>(
                "mctp-emulator: Received Payload");

            processMctpCommand(DstEid, payload);

            return rc;
        });

    mctpInterface->register_signal<uint8_t, uint8_t, uint8_t, bool,
                                   std::vector<uint8_t>>(
        "MessageReceivedSignal");

    mctpInterface->register_property("Eid", eid);

    // TODO:Use the enum from D-Bus interface
    mctpInterface->register_property("BindingID", bindingType);

    mctpInterface->register_property("BindingMediumID", bindingMedium);

    mctpInterface->register_property("StaticEidSupport", staticEidSupport);

    mctpInterface->register_property(
        "UUID", std::vector<uint8_t>(uuid.begin(), uuid.end()));

    mctpInterface->register_property("BindingMode", bindingMode);

    mctpInterface->initialize();
}
