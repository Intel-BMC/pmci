#pragma once

#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/MCTP/Base/server.hpp>
#include <xyz/openbmc_project/MCTP/Endpoint/server.hpp>
#include <xyz/openbmc_project/MCTP/SupportedMessageTypes/server.hpp>

#ifdef USE_MOCK
#include "../tests/mocks/objectServerMock.hpp"
using object_server = mctpd_mock::object_server_mock;
using dbus_interface = mctpd_mock::dbus_interface_mock;
#else
using object_server = sdbusplus::asio::object_server;
using dbus_interface = sdbusplus::asio::dbus_interface;
#endif

using mctp_server = sdbusplus::xyz::openbmc_project::MCTP::server::Base;
using mctp_endpoint = sdbusplus::xyz::openbmc_project::MCTP::server::Endpoint;
using mctp_msg_types =
    sdbusplus::xyz::openbmc_project::MCTP::server::SupportedMessageTypes;