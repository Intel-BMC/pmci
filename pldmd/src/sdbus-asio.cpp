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

#include <boost/asio.hpp>
#include <memory>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>

namespace
{

std::shared_ptr<boost::asio::io_context> ioCtx;
std::shared_ptr<sdbusplus::asio::connection> sdbusp;
std::shared_ptr<sdbusplus::asio::object_server> objServer;

} // namespace

void setIoContext(const std::shared_ptr<boost::asio::io_context>& newIo)
{
    ioCtx = newIo;
}

std::shared_ptr<boost::asio::io_context> getIoContext()
{
    return ioCtx;
}

void setSdBus(const std::shared_ptr<sdbusplus::asio::connection>& newBus)
{
    sdbusp = newBus;
}

std::shared_ptr<sdbusplus::asio::connection> getSdBus()
{
    return sdbusp;
}

void setObjServer(
    const std::shared_ptr<sdbusplus::asio::object_server>& newServer)
{
    objServer = newServer;
}

std::shared_ptr<sdbusplus::asio::object_server> getObjServer()
{
    return objServer;
}

std::unique_ptr<sdbusplus::asio::dbus_interface>
    addUniqueInterface(const std::string& path, const std::string& name)
{
    return std::make_unique<sdbusplus::asio::dbus_interface>(sdbusp, path,
                                                             name);
}
