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

using namespace mctpw;

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
