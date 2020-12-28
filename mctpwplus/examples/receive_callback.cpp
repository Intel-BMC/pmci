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

#include <boost/asio.hpp>
#include <iostream>

using namespace mctpw;

int main(int argc, char* argv[])
{
    constexpr uint8_t defaultEId = 8;
    uint8_t eid =
        argc < 2 ? defaultEId : static_cast<uint8_t>(std::stoi(argv[1]));

    boost::asio::io_context io;
    boost::asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait(
        [&io](const boost::system::error_code&, const int&) { io.stop(); });

    auto onMCTPReceive = [](void*, eid_t eidReceived, bool, uint8_t,
                            const std::vector<uint8_t>& data, int status) {
        std::cout << "onMCTPReceive EID " << static_cast<int>(eidReceived)
                  << '\n';
        std::cout << "onMCTPReceive Status " << status << '\n';
        std::cout << "onMCTPReceive Response ";
        for (int n : data)
        {
            std::cout << n << ' ';
        }
        std::cout << '\n';
    };

    auto sendCB = [](boost::system::error_code ec, int status) {
        if (ec)
        {
            std::cout << "Send callback error " << ec.message() << '\n';
        }
        std::cout << "Send status async " << status << '\n';
    };
    auto registerCB = [eid, sendCB](boost::system::error_code ec, void* ctx) {
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

            // GetVersion request for PLDM Base
            std::vector<uint8_t> request = {1, 143, 0, 3, 0, 0, 0, 0, 1, 0};
            mctpwCtx->sendAsync(sendCB, eid, 0, false, request);

            boost::asio::spawn([mctpwCtx,
                                eid](boost::asio::yield_context yield) {
                // GetUID request
                std::vector<uint8_t> request2 = {1, 143, 2, 3};
                std::vector<uint8_t> response;
                auto status =
                    mctpwCtx->sendYield(yield, eid, 0, false, request2);
                std::cout << "Yield Status "
                          << (status.first ? status.first.message() : "true")
                          << ". Send status " << status.second << '\n';
                return;
            });
        }
    };

    MCTPConfiguration config(MessageType::pldm, BindingType::mctpOverSmBus);
    MCTPWrapper mctpWrapper(io, config, nullptr, onMCTPReceive);
    mctpWrapper.detectMctpEndpointsAsync(registerCB);

    io.run();
    return 0;
}
