#pragma once

#include <iostream>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/MCTP/Base/server.hpp>

#ifdef USE_MOCK
#include "../tests/mocks/objectServerMock.hpp"
using object_server = mctpd_mock::object_server_mock;
using dbus_interface = mctpd_mock::dbus_interface_mock;
#else
using object_server = sdbusplus::asio::object_server;
using dbus_interface = sdbusplus::asio::dbus_interface;
#endif

using mctp_server = sdbusplus::xyz::openbmc_project::MCTP::server::Base;

struct SMBusConfiguration
{
    const mctp_server::BindingTypes bindingType =
        mctp_server::BindingTypes::MctpOverSmbus;
    mctp_server::MctpPhysicalMediumIdentifiers mediumId;
    mctp_server::BindingModeTypes mode;
    uint8_t defaultEid;
    std::vector<uint8_t> eidPool;
    std::string bus;
    bool arpMasterSupport;
    uint8_t bmcSlaveAddr;
};

struct PcieConfiguration
{
    const mctp_server::BindingTypes bindingType =
        mctp_server::BindingTypes::MctpOverPcieVdm;
    mctp_server::MctpPhysicalMediumIdentifiers mediumId;
    mctp_server::BindingModeTypes mode;
    uint8_t defaultEid;
    uint16_t bdf;
};

using ConfigurationVariant =
    std::variant<SMBusConfiguration, PcieConfiguration>;

class MctpBinding
{
  public:
    MctpBinding(std::shared_ptr<object_server>& objServer, std::string& objPath,
                ConfigurationVariant& conf, boost::asio::io_context& ioc);
    MctpBinding() = delete;
    ~MctpBinding() = default;

  protected:
    mctp_server::BindingModeTypes bindingModeType{};

  private:
    uint8_t eid;
    bool staticEid;
    std::vector<uint8_t> uuid;
    mctp_server::BindingTypes bindingID{};
    mctp_server::MctpPhysicalMediumIdentifiers bindingMediumID{};
    boost::asio::io_context& io;

    void createUuid(void);
};
