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

#include "service_monitor.hpp"

#include "mctp_wrapper.hpp"

#include <boost/asio.hpp>
#include <boost/container/flat_map.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>

using mctpw::internal::NewServiceCallback;

template <typename T1, typename T2>
using DictType = boost::container::flat_map<T1, T2>;
using MctpPropertiesVariantType =
    std::variant<uint16_t, int16_t, int32_t, uint32_t, bool, std::string,
                 uint8_t, std::vector<uint8_t>>;

NewServiceCallback::NewServiceCallback(MCTPWrapper& mctpWrapper) :
    parent(mctpWrapper)
{
}

void NewServiceCallback::operator()(sdbusplus::message::message& msg)
{
    DictType<std::string, DictType<std::string, MctpPropertiesVariantType>>
        values;
    sdbusplus::message::object_path object_path;

    msg.read(object_path, values);
    if (values.end() == values.find(mctpw::MCTPWrapper::bindingToInterface.at(
                            parent.config.bindingType)))
    {
        return;
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        (std::string("New service ") + msg.get_sender()).c_str());
    parent.registerListeners(msg.get_sender());
}
