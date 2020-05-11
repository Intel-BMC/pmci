#pragma once

#include "MCTPBinding.hpp"

#include <iostream>

class SMBusBinding : public MctpBinding
{
  public:
    SMBusBinding() = delete;
    SMBusBinding(std::shared_ptr<sdbusplus::asio::object_server>& objServer,
                 std::string& objPath, ConfigurationVariant& conf);
    ~SMBusBinding() = default;

  private:
    std::string bus;
    bool arpMasterSupport;
    uint8_t bmcSlaveAddr;
};
