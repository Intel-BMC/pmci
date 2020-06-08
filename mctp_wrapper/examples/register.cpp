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

    signal(SIGINT, signal_handler);

    /* find first mctp_over_smbus binding */
    for (bus = 0; bus < 10; bus++)
    {
        if (mctpw_find_bus_by_binding_type(mctp_over_smbus, bus,
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
    if ((ret = mctpw_register_client(bus_handler, vdpci, 0x8086, true, 1,
                                     0xFFFF, network_reconfiguration_callback,
                                     nullptr, &context)) < 0)
    {
        std::cout << "Client registration failed\n" << std::endl;
        return ret;
    }

    while (run_flag == true)
    {
        usleep(1000);
    }

    return 0;
}
