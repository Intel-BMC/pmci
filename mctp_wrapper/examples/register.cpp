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

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>

#include "mctpw.h"
#define UNUSED(x) (void)(x)
#define EID_LIST_SIZE 32

void* context;
volatile bool run_flag = true;

void network_reconfiguration_callback(void* client_context)
{
    UNUSED(client_context);
    std::cout << "Network reconfiguration_callback." << std::endl;
    return;
}

void signal_handler(int signo)
{
    if (signo == SIGINT && context)
    {
        mctpw_unregister_client(context);
        context = nullptr;
        run_flag = false;
        std::cout << "Client unregistered." << std::endl;
    }
}

int main(void)
{
    void* bus_handler;
    int bus, ret;
    bool found = false;
    unsigned eid_list_size;
    mctpw_eid_t eid_list[EID_LIST_SIZE];

    signal(SIGINT, signal_handler);

    /* find first MCTP_OVER_SMBUS binding */
    for (bus = 0; bus < 10; bus++)
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

    std::cout << "Register client on bus " << bus << std::endl;
    if ((ret = mctpw_register_client(bus_handler, VDPCI, 0x8086, true, 1,
                                     0xFFFF, network_reconfiguration_callback,
                                     nullptr, &context)) < 0)
    {
        std::cout << "Client registration failed\n" << std::endl;
        return ret;
    }

    eid_list_size = EID_LIST_SIZE;
    if ((ret = mctpw_get_endpoint_list(context, eid_list, &eid_list_size)) < 0)
    {
        mctpw_unregister_client(context);
        return ret;
    }
    std::cout << std::endl
              << "On bus " << bus << " found " << eid_list_size << " endpoints."
              << std::endl;
    for (unsigned i = 0; i < eid_list_size; i++)
    {
        std::cout << "Eid" << i << " = " << static_cast<unsigned>(eid_list[i])
                  << std::endl;
    }

    eid_list_size = EID_LIST_SIZE;
    if ((ret = mctpw_get_matching_endpoint_list(context, eid_list,
                                                &eid_list_size)) < 0)
    {
        mctpw_unregister_client(context);
        return ret;
    }

    std::cout << std::endl
              << eid_list_size << " endpoints supports registered message type."
              << std::endl;

    for (unsigned i = 0; i < eid_list_size; i++)
    {
        std::cout << "Eid" << i << " = " << static_cast<unsigned>(eid_list[i])
                  << std::endl;
    }

    mctpw_endpoint_properties_t endpoint_prop;
    for (unsigned i = 0; i < eid_list_size; i++)
    {
        if (mctpw_get_endpoint_properties(context, eid_list[i],
                                          &endpoint_prop) == 0)
        {
            std::cout << std::endl
                      << "EP Eid " << static_cast<unsigned>(eid_list[i])
                      << " properties:" << std::endl;
            std::cout << "network_id:"
                      << static_cast<unsigned>(endpoint_prop.network_id)
                      << std::endl;
            std::cout << "mctp_control: "
                      << (endpoint_prop.mctp_control ? "true" : "false")
                      << std::endl;
            std::cout << "pldm: " << (endpoint_prop.pldm ? "true" : "false")
                      << std::endl;
            std::cout << "ncsi: " << (endpoint_prop.ncsi ? "true" : "false")
                      << std::endl;
            std::cout << "ethernet: "
                      << (endpoint_prop.ethernet ? "true" : "false")
                      << std::endl;
            std::cout << "nvme_mgmt_msg: "
                      << (endpoint_prop.nvme_mgmt_msg ? "true" : "false")
                      << std::endl;
            std::cout << "spdm: " << (endpoint_prop.spdm ? "true" : "false")
                      << std::endl;
            std::cout << "vdpci: " << (endpoint_prop.vdpci ? "true" : "false")
                      << std::endl;
            std::cout << "vdiana: " << (endpoint_prop.vdiana ? "true" : "false")
                      << std::endl;
        }
    }

    while (run_flag == true)
    {
        usleep(1000);
    }

    return 0;
}
