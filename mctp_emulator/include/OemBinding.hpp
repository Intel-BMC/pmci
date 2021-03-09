#pragma once

#include "MCTPBinding.hpp"

class OemBinding : public MctpBinding
{
  public:
    OemBinding() = delete;
    OemBinding(std::shared_ptr<sdbusplus::asio::object_server>& objServer,
               std::string& objPath);
    ~OemBinding() = default;
};
