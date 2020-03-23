#pragma once

#include <iostream>
#include <sdbusplus/asio/object_server.hpp>

enum class binding {
  SMBus = 0x01,
  PCIe = 0x02,
  Usb = 0x03,
  Kcs = 0x04,
  Serial = 0x05,
  VendorDefined = 0xFF
};

class MctpBinding {
public:
  MctpBinding(std::shared_ptr<sdbusplus::asio::object_server> &objServer,
              std::string &objPath);
  MctpBinding() = delete;
  ~MctpBinding() = default;

private:
  uint8_t eid;
};
