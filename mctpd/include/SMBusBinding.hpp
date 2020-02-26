#pragma once

#include "MCTPBinding.hpp"

#include <iostream>

class SMbusBinding : public MctpBinding
{
  public:
    SMbusBinding();
    ~SMbusBinding()=default;
};
