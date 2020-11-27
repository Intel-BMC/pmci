#pragma once
#include "hw/DeviceMonitor.hpp"

#include <libudev.h>

#include <boost/asio/posix/stream_descriptor.hpp>
#include <phosphor-logging/log.hpp>

namespace hw
{

namespace aspeed
{

class PCIeMonitor : public hw::DeviceMonitor
{
    static constexpr const char* astUdevPath =
        "/sys/devices/platform/ahb/ahb:apb/1e6e8000.mctp/misc/aspeed-mctp";

  public:
    PCIeMonitor(boost::asio::io_context& ioc);
    ~PCIeMonitor() override;

    bool initialize() override;
    void observe(std::weak_ptr<DeviceObserver> target) override;

  private:
    udev* udevContext;
    udev_device* udevice;
    udev_monitor* umonitor;
    boost::asio::posix::stream_descriptor ueventMonitor;
};

} // namespace aspeed
} // namespace hw
