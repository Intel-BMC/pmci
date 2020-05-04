#pragma once

#include "MCTPBinding.hpp"

#include <iostream>

class SMBusBinding : public MctpBinding
{
  public:
    SMBusBinding() = delete;
    SMBusBinding(std::shared_ptr<object_server>& objServer,
                 std::string& objPath, ConfigurationVariant& conf,
                 boost::asio::io_context& ioc);
    ~SMBusBinding() = default;

  private:
    std::string bus;
    bool arpMasterSupport;
    uint8_t bmcSlaveAddr;
};
