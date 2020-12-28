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

#include "dbus_cb.hpp"

#include "mctp_wrapper.hpp"

#include <phosphor-logging/log.hpp>

namespace mctpw
{

int onMessageReceivedSignal(sd_bus_message* rawMsg, void* userData,
                            sd_bus_error* retError)
{
    if (!userData || (retError && sd_bus_error_is_set(retError)))
    {
        return -1;
    }

    try
    {
        MCTPWrapper* context = static_cast<MCTPWrapper*>(userData);
        sdbusplus::message::message message{rawMsg};

        if (!context->receiveCallback)
        {
            return -1;
        }
        uint8_t messageType;
        uint8_t srcEid;
        uint8_t msgTag;
        bool tagOwner;
        std::vector<uint8_t> payload;

        message.read(messageType, srcEid, msgTag, tagOwner, payload);

        if (static_cast<MessageType>(messageType) != context->config.type)
        {
            return -1;
        }

        if (static_cast<MessageType>(messageType) == MessageType::vdpci)
        {
            struct VendorHeader
            {
                uint16_t vendorId;
                uint16_t vendorMessageId;
            } __attribute__((packed));
            VendorHeader* vendorHdr =
                reinterpret_cast<VendorHeader*>(payload.data());

            if (!context->config.vendorDefinedValues ||
                (vendorHdr->vendorId !=
                 context->config.vendorDefinedValues->vendorId) ||
                ((vendorHdr->vendorMessageId &
                  context->config.vendorDefinedValues->vendorMessageTypeMask) !=
                 context->config.vendorDefinedValues->vendorMessageTypeMask))
            {
                return -1;
            }
        }
        context->receiveCallback(context, srcEid, tagOwner, msgTag, payload, 0);
        return 1;
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (std::string("onMessageReceivedSignal failed. ") + e.what())
                .c_str());
    }

    return -1;
}

} // namespace mctpw
