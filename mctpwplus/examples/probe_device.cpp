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

#include <CLI/CLI.hpp>
#include <boost/asio.hpp>
#include <iostream>

using namespace mctpw;

static void onDeviceUpdate(void*, const Event& evt, boost::asio::yield_context&)
{
    switch (evt.type)
    {
        case Event::EventType::deviceAdded: {
            std::cout << "Device added " << static_cast<int>(evt.eid) << '\n';
        }
        break;
        case Event::EventType::deviceRemoved: {
            std::cout << "Device removed " << static_cast<int>(evt.eid) << '\n';
        }
        break;
    }
    return;
}

int main(int argc, char* argv[])
{
    CLI::App app("MCTP Device Manager");
    uint16_t vendorId = 0;
    uint16_t vdmType = 0;
    uint16_t vdmMask = 0;
    BindingType bindingType{};
    MessageType msgType{};

    std::map<std::string, BindingType> bindingArgs{
        {"smbus", BindingType::mctpOverSmBus},
        {"pcie", BindingType::mctpOverPcieVdm},
        {"usb", BindingType::mctpOverUsb},
        {"kcs", BindingType::mctpOverKcs},
        {"serial", BindingType::mctpOverSerial},
        {"vendor", BindingType::vendorDefined}};

    std::map<std::string, MessageType> msgTypeArgs{
        {"pldm", MessageType::pldm},    {"ncsi", MessageType::ncsi},
        {"eth", MessageType::ethernet}, {"nvme", MessageType::nvmeMgmtMsg},
        {"spdm", MessageType::spdm},    {"sec", MessageType::securedMsg},
        {"vdpci", MessageType::vdpci},  {"vdiana", MessageType::vdiana}};

    app.add_option("-m,--msgtype", msgType, "MCTP Message type")
        ->transform(CLI::CheckedTransformer(msgTypeArgs, CLI::ignore_case))
        ->required();
    app.add_option("-b,--binding", bindingType, "MCTP binding type")
        ->transform(CLI::CheckedTransformer(bindingArgs, CLI::ignore_case))
        ->required();
    app.add_option("--vid", vendorId, "Vendor Id");
    app.add_option("--vdmtype", vdmType, "Vendor defined message type");
    app.add_option("--vdmmask", vdmMask, "Vendor defined message type mask");

    CLI11_PARSE(app, argc, argv);

    boost::asio::io_context io;
    boost::asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait(
        [&io](const boost::system::error_code&, const int&) { io.stop(); });

    MCTPConfiguration config;

    if (msgType == MessageType::vdpci && vendorId)
    {
        if (vdmType)
        {
            config = MCTPConfiguration(msgType, bindingType, vendorId, vdmType,
                                       vdmMask);
        }
        else
        {
            config = MCTPConfiguration(msgType, bindingType, vendorId);
        }
    }
    else
    {
        config = MCTPConfiguration(msgType, bindingType);
    }

    MCTPWrapper mctpWrapper(io, config, onDeviceUpdate, nullptr);

    auto registerCB = [&mctpWrapper](boost::system::error_code ec, void*) {
        if (ec)
        {
            std::cerr << "Error" << ec.message() << '\n';
            return;
        }

        auto& ep = mctpWrapper.getEndpointMap();
        for (auto& i : ep)
        {

            std::cout << "EID:" << static_cast<unsigned>(i.first)
                      << " Bus:" << i.second.first
                      << " Service:" << i.second.second << '\n';
        }
    };

    mctpWrapper.detectMctpEndpointsAsync(registerCB);

    io.run();
    return 0;
}
