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
#include <sdbusplus/asio/connection.hpp>

using namespace mctpw;

int main(int argc, char*[])
{
    bool useYield = argc > 1 ? true : false;
    boost::asio::io_context io;
    boost::asio::signal_set signals(io, SIGINT, SIGTERM);

    signals.async_wait(
        [&io](const boost::system::error_code&, const int&) { io.stop(); });

    MCTPConfiguration config(mctpw::MessageType::pldm,
                             mctpw::BindingType::mctpOverSmBus);
    MCTPWrapper mctpWrapper(io, config, nullptr, nullptr);

    auto printEPMap = [&mctpWrapper]() {
        auto epMap = mctpWrapper.getEndpointMap();
        for (const auto& [eid, serviceName] : epMap)
        {
            std::cout << "EId " << static_cast<int>(eid) << " on "
                      << serviceName.second << '\n';
        }
    };

    if (useYield)
    {
        boost::asio::spawn(
            [&mctpWrapper, &printEPMap](boost::asio::yield_context yield) {
                mctpWrapper.detectMctpEndpoints(yield);
                printEPMap();
            });
    }
    else
    {
        auto registerCB = [&printEPMap](boost::system::error_code ec,
                                        void* ctx) {
            if (ec)
            {
                std::cout << "Error: " << ec << std::endl;
                return;
            }
            if (ctx)
            {
                printEPMap();
            }
        };
        mctpWrapper.detectMctpEndpointsAsync(registerCB);
    }

    io.run();
    return 0;
}
