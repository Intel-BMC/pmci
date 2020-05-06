#pragma once

#include <iostream>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/MCTP/Base/server.hpp>

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
    MctpBinding(std::shared_ptr<sdbusplus::asio::object_server>& objServer,
                std::string& objPath, ConfigurationVariant& conf);
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

    void createUuid(void);
};
