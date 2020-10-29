#pragma once

#include <sdbusplus/asio/object_server.hpp>

extern std::shared_ptr<sdbusplus::asio::connection> bus;
extern std::vector<std::shared_ptr<sdbusplus::asio::dbus_interface>>
    endpointInterface;
// TODO:Use the hpp from D-Bus interface
enum class binding
{
    smbus = 0x01,
    pcie = 0x02,
    usb = 0x03,
    kcs = 0x04,
    serial = 0x05,
    vendorDefined = 0xFF
};

class MctpBinding
{
  public:
    MctpBinding(std::shared_ptr<sdbusplus::asio::object_server>& objServer,
                std::string& objPath);
    MctpBinding() = delete;
    ~MctpBinding() = default;

  private:
    uint8_t eid;
    void getSystemAppUuid(void);
};
