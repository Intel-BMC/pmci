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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>

#include "mctpw.h"

#define UNUSED(x) (void)(x)
#define EID_LIST_SIZE 32

void* context;
constexpr unsigned tout_5000ms = 5000;
constexpr uint16_t vendor_id = 0x8086;
constexpr uint16_t vd_message_type = 0x8002;
constexpr uint16_t vd_msg_type_mask = 0x80FF;
uint8_t vd_payload[] = {0x01, 0x02, 0x01, 0x89};
static unsigned response_counter = 3;

void async_send_status_cb1(int ec, const void* user_ctx)
{
    const char* str = static_cast<const char*>(user_ctx);
    if (ec == 0)
    {
        std::cout << "[Send callback1]" << str << "Send operation success"
                  << std::endl;
    }
    else
    {
        std::cout << "[Send callback1]" << str << "Send operation error:" << ec
                  << std::endl;
    }
}

void async_send_status_cb2(int ec, const void* user_ctx)
{
    const char* str = static_cast<const char*>(user_ctx);
    if (ec == 0)
    {
        std::cout << "[Send callback2]" << str << "Send operation success"
                  << std::endl;
    }
    else
    {
        std::cout << "[Send callback2]" << str << "Send operation error:" << ec
                  << std::endl;
    }
}

void async_send_receive_atomic_cb(int ec, const void* user_ctx,
                                  uint8_t* response, size_t response_length)
{
    const char* str = static_cast<const char*>(user_ctx);
    if (ec == 0)
    {
        std::cout << "[Send receive callback]" << str
                  << "Payload:" << std::endl;
        for (unsigned n = 0; n < response_length; n++)
        {
            std::cout << " " << std::hex << static_cast<unsigned>(response[n]);
        }
        std::cout << std::endl;
    }
    else
    {
        std::cout << "[Send receive callback]" << str
                  << "Operation error:" << ec << std::endl;
    }
    response_counter--;
}

void rx_callback(void* client_context, mctpw_eid_t src_eid, bool tag_owner,
                 uint8_t tag, uint8_t* payload, size_t payload_length, int err)
{
    UNUSED(client_context);
    std::cout << "[Rx callback]Response:" << std::endl;
    std::cout << "Src Eid: " << static_cast<unsigned>(src_eid);
    std::cout << " Tag owner: " << (tag_owner ? "true" : "false");
    std::cout << " Tag: " << static_cast<unsigned>(tag);
    std::cout << " Error: " << err << std::endl;
    std::cout << "Payload:";
    for (unsigned n = 0; n < payload_length; n++)
    {
        std::cout << " " << std::hex << static_cast<unsigned>(payload[n]);
    }
    std::cout << std::endl;
    response_counter--;
}

void signal_handler(int signo)
{
    if (signo == SIGINT && context)
    {
        mctpw_unregister_client(context);
        context = nullptr;
    }
}

int main(void)
{
    void* bus_handler;
    int ret;
    bool found = false;
    unsigned eid_list_size;
    mctpw_eid_t eid_list[EID_LIST_SIZE];

    signal(SIGINT, signal_handler);

    for (int bus = 0; bus < 10; bus++)
    {
        if (mctpw_find_bus_by_binding_type(MCTP_OVER_SMBUS, bus,
                                           &bus_handler) == 0)
        {
            found = true;
            break;
        }
    }
    if (!found)
    {
        return -ENOENT;
    }

    if ((ret = mctpw_register_client(bus_handler, VDPCI, vendor_id, true,
                                     vd_message_type, vd_msg_type_mask, nullptr,
                                     rx_callback, &context)) < 0)
    {
        return ret;
    }

    /* Get first endpoint */
    eid_list_size = 1;
    if ((ret = mctpw_get_matching_endpoint_list(context, eid_list,
                                                &eid_list_size)) < 0)
    {
        mctpw_unregister_client(context);
        return ret;
    }

    /* Non blocking send, use callback to receive operation status */
    std::cout << "Two not blocking async send" << std::endl;
    if ((ret = mctpw_async_send_message(
             context, eid_list[0], true, 0x1, vd_payload, sizeof(vd_payload),
             "[Send request 1]", async_send_status_cb1)) < 0)
    {
        std::cout << "Send message failed" << std::endl;
        mctpw_unregister_client(context);
        return ret;
    }

    if ((ret = mctpw_async_send_message(
             context, eid_list[0], true, 0x2, vd_payload, sizeof(vd_payload),
             "[Send request 2]", async_send_status_cb2)) < 0)
    {
        std::cout << "Send message failed" << std::endl;
        mctpw_unregister_client(context);
        return ret;
    }

    /* Atomic send-receive, without blocking*/
    std::cout << "Atomic send-receive request " << std::endl;
    if ((ret = mctpw_async_send_receive_atomic_message(
             context, eid_list[0], vd_payload, sizeof(vd_payload), tout_5000ms,
             "[Atomic send-receive async request]",
             async_send_receive_atomic_cb)) < 0)
    {
        std::cout << "Atomic send-receive failed" << std::endl;
        mctpw_unregister_client(context);
        return ret;
    }

    /* Blocking send, wait for send status */
    std::cout << "Blocking send request" << std::endl;
    if ((ret = mctpw_send_message(context, eid_list[0], true, 0x3, vd_payload,
                                  sizeof(vd_payload))) < 0)
    {
        std::cout << "Send message failed" << std::endl;
        mctpw_unregister_client(context);
        return ret;
    }

    /* Atomic send-receive, wait for response */
    uint8_t response_buffer[256];
    size_t response_buffer_length = sizeof(response_buffer);

    std::cout << "Blocking atomic send-receive request " << std::endl;
    if ((ret = mctpw_send_receive_atomic_message(
             context, eid_list[0], vd_payload, sizeof(vd_payload),
             response_buffer, &response_buffer_length, tout_5000ms)) == 0)
    {
        std::cout << "Response from atomic send receive:" << std::endl
                  << "Payload:";
        for (unsigned n = 0; n < response_buffer_length; n++)
        {
            std::cout << " " << std::hex
                      << static_cast<unsigned>(response_buffer[n]);
        }
        std::cout << std::endl;
    }
    else
    {
        std::cout << "Atomic send-receive failed" << std::endl;
        mctpw_unregister_client(context);
        return ret;
    }

    /* mctpw process loop */
    do
    {
        mctpw_process_one(context);
    } while (response_counter);

    mctpw_unregister_client(context);
    std::cout << "Client unregistered." << std::endl;

    return 0;
}
