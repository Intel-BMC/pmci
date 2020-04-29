#pragma once

#include "MCTPBinding.hpp"

class SMBusBinding : public MctpBinding
{
  public:
    SMBusBinding() = delete;
    SMBusBinding(std::shared_ptr<sdbusplus::asio::object_server>& objServer,
                 std::string& objPath);
    ~SMBusBinding() = default;
};
