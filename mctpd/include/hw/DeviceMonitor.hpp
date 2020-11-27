#pragma once
#include <memory>

namespace hw
{

class DeviceObserver
{
  public:
    virtual void deviceReadyNotify(bool ready) = 0;

    virtual ~DeviceObserver();
};

class DeviceMonitor
{
  public:
    virtual bool initialize() = 0;
    virtual void observe(std::weak_ptr<DeviceObserver> target) = 0;

    virtual ~DeviceMonitor();
};

} // namespace hw
