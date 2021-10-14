#include "hw/aspeed/PCIeMonitor.hpp"

namespace hw
{
namespace aspeed
{

static void ueventHandlePcieReady(std::weak_ptr<DeviceObserver> target,
                                  udev_device* dev)
{
    bool ready = false;
    const char* value = udev_device_get_property_value(dev, "PCIE_READY");
    if (!value)
    {
        return;
    }

    if (strcmp(value, "1") == 0)
    {
        ready = true;
    }

    if (auto observer = target.lock())
    {
        observer->deviceReadyNotify(ready);
    }
}

PCIeMonitor::PCIeMonitor(boost::asio::io_context& ioc) : ueventMonitor(ioc)
{
}

bool PCIeMonitor::initialize()
{
    try
    {
        udevContext = udev_new();
        if (!udevContext)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }
        udevice = udev_device_new_from_syspath(udevContext, astUdevPath);
        if (!udevice)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }
        umonitor = udev_monitor_new_from_netlink(udevContext, "udev");
        if (!umonitor)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }
        /* TODO: Uncomment when event subsytem fix in KMD will be ready */
        // udev_monitor_filter_add_match_subsystem_devtype(umonitor, "misc",
        // NULL);
        udev_monitor_enable_receiving(umonitor);
        ueventMonitor.assign(udev_monitor_get_fd(umonitor));
        return true;
    }
    catch (std::exception& e)
    {
        if (udevice)
        {
            udev_device_unref(udevice);
            udevice = nullptr;
        }
        if (udevContext)
        {
            udev_unref(udevContext);
            udevContext = nullptr;
        }
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Udev initialization failed",
            phosphor::logging::entry("Exception:", e.what()));
    }
    return false;
}

void PCIeMonitor::observe(std::weak_ptr<DeviceObserver> target)
{
    if (target.expired())
    {
        throw std::runtime_error("Observer weak_ptr is expired on arrival. Is "
                                 "the Observer contained within shared_ptr?");
    }

    ueventMonitor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this, observer{target}](const boost::system::error_code& ec) {
            if (ec)
            {
                if (ec == boost::asio::error::operation_aborted)
                {
                    return;
                }

                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error reading uevents",
                    phosphor::logging::entry("error:", ec.message().c_str()));
                observe(observer);
                return;
            }

            udev_device* dev = udev_monitor_receive_device(umonitor);
            if (dev)
            {
                ueventHandlePcieReady(observer, dev);
                udev_device_unref(dev);
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Udev monitor get device failed");
            }

            observe(observer);
        });
}

PCIeMonitor::~PCIeMonitor()
{
    if (umonitor)
    {
        ueventMonitor.release();
        udev_monitor_unref(umonitor);
        udev_device_unref(udevice);
        udev_unref(udevContext);
    }
}

} // namespace aspeed
} // namespace hw