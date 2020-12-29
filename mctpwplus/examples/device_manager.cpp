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

#include "mctp_wrapper.hpp"

#include <boost/asio.hpp>
#include <iostream>

using namespace mctpw;

static void onDeviceUpdate(void*, const Event& evt, boost::asio::yield_context&)
{
    std::cout << "Network reconfiguration_callback." << std::endl;
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

int main()
{
    boost::asio::io_context io;
    boost::asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait(
        [&io](const boost::system::error_code&, const int&) { io.stop(); });

    auto registerCB = [](boost::system::error_code ec, void* ctx) {
        if (ec)
        {
            std::cout << "Error" << ec.message() << std::endl;
            return;
        }
        if (ctx)
        {
            auto mctpwCtx = reinterpret_cast<MCTPWrapper*>(ctx);
            auto& ep = mctpwCtx->getEndpointMap();
            for (auto& i : ep)
            {
                std::cout << "EID:" << static_cast<unsigned>(i.first)
                          << " Bus:" << i.second.first
                          << " Service:" << i.second.second << std::endl;
            }
        }
    };

    MCTPConfiguration config(MessageType::pldm, BindingType::mctpOverSmBus);
    MCTPWrapper mctpWrapper(io, config, onDeviceUpdate, nullptr);
    mctpWrapper.detectMctpEndpointsAsync(registerCB);

    io.run();
    return 0;
}
