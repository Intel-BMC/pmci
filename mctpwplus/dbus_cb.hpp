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

#pragma once

#include <systemd/sd-bus.h>

#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>

namespace mctpw
{
int onMessageReceivedSignal(sd_bus_message* rawMsg, void* userData,
                            sd_bus_error* retError);
int onPropertiesChanged(sd_bus_message* rawMsg, void* userData,
                        sd_bus_error* retError);
int onInterfacesAdded(sd_bus_message* rawMsg, void* userData,
                      sd_bus_error* retError);
int onInterfacesRemoved(sd_bus_message* rawMsg, void* userData,
                        sd_bus_error* retError);

} // namespace mctpw
