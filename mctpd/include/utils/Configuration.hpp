#pragma once

#include "utils/types.hpp"

#include <filesystem>
#include <set>
#include <string>

struct Configuration
{
    mctp_server::MctpPhysicalMediumIdentifiers mediumId;
    mctp_server::BindingModeTypes mode;
    uint8_t defaultEid;
    unsigned int reqToRespTime;
    uint8_t reqRetryCount;

    virtual ~Configuration();
};

struct SMBusConfiguration : Configuration
{
    std::set<uint8_t> eidPool;
    std::string bus;
    bool arpMasterSupport;
    uint8_t bmcSlaveAddr;
    std::set<uint8_t> supportedEndpointSlaveAddress;
    uint8_t routingIntervalSec;
    uint64_t scanInterval;

    ~SMBusConfiguration() override;
};

struct PcieConfiguration : Configuration
{
    uint16_t bdf;
    uint8_t getRoutingInterval = 0;

    ~PcieConfiguration() override;
};

std::optional<std::pair<std::string, std::unique_ptr<Configuration>>>
    getConfiguration(std::shared_ptr<sdbusplus::asio::connection> conn,
                     const std::string& configurationName,
                     const std::filesystem::path& configPath);
