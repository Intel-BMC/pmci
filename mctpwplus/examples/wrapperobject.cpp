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

#include "mctpwrapper.hpp"

#include <CLI/CLI.hpp>
#include <boost/asio.hpp>
#include <iostream>

using namespace mctpw;

int main(int argc, char* argv[])
{
    CLI::App app("MCTPWrapper Constructor Demo");
    uint16_t vendorId = 0;
    uint16_t vdmType = 0;
    uint16_t vdmMask = 0;
    bool dbusAwareApp = false;
    BindingType bindingType = BindingType::mcptOverSmBus;
    MessageType msgType = MessageType::pldm;

    app.add_option("--mctpmsgtype", msgType,
                   "MCTP Message type. 0x7E for VDPCI");
    app.add_option("--binding", bindingType, "MCTP binding type");
    app.add_option("--vid", vendorId, "Vendor Id");
    app.add_option("--vdmsgtype", vdmType, "Vendor defined message type");
    app.add_option("--vdmsgmask", vdmMask, "Vendor defined message type mask");
    app.add_flag("--dbus", dbusAwareApp, "DBus aware application");

    CLI11_PARSE(app, argc, argv);

    boost::asio::io_context io;
    boost::asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait(
        [&io](const boost::system::error_code&, const int&) { io.stop(); });

    std::unique_ptr<MCTPConfiguration> config;

    if (msgType == MessageType::vdpci && (vendorId != 0 && vendorId != 0xFFFF))
    {
        std::cout << "Using vendor defined values. VendorId " << vendorId
                  << ". MessageType " << vdmType << ". Mask " << vdmMask
                  << '\n';
        config = std::make_unique<MCTPConfiguration>(
            msgType, bindingType, vendorId, vdmType, vdmMask);
    }
    else
    {
        std::cout << "Using message type : 0x" << std::hex
                  << static_cast<int>(msgType) << '\n';
        config = std::make_unique<MCTPConfiguration>(msgType, bindingType);
    }

    std::shared_ptr<MCTPWrapper> mctpWrapper;
    if (!dbusAwareApp)
    {
        // DBus unaware apps wont have access to sdbusplus:: apis. MCTPWrapper
        // will create its own sdbusplus::asio::connection
        mctpWrapper =
            std::make_shared<MCTPWrapper>(io, *config, nullptr, nullptr);
        std::cout << "Created MCTPWrapper object from io context\n";
    }
    else
    {
        // DBus aware apps may have existing sdbusplus::asio::connection. And
        // that can be shared with MCTPWrapper
        auto connection = std::make_shared<sdbusplus::asio::connection>(io);
        mctpWrapper = std::make_shared<MCTPWrapper>(connection, *config,
                                                    nullptr, nullptr);
        std::cout << "Created MCTPWrapper using shared asio::connection\n";
    }

    io.run();
    return 0;
}
