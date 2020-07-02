#pragma once

#include "MCTPBinding.hpp"

#include <libmctp-smbus.h>

#include <iostream>

class SMBusBinding : public MctpBinding
{
  public:
    SMBusBinding() = delete;
    SMBusBinding(std::shared_ptr<object_server>& objServer,
                 std::string& objPath, ConfigurationVariant& conf,
                 boost::asio::io_context& ioc);
    virtual ~SMBusBinding();
    virtual void initializeBinding(ConfigurationVariant& conf) override;
    virtual bool getBindingPrivateData(uint8_t dstEid,
                                       std::vector<uint8_t>& pvtData);

  private:
    void SMBusInit(ConfigurationVariant& conf);
    void readResponse();
    std::string bus;
    bool arpMasterSupport;
    uint8_t bmcSlaveAddr;
    struct mctp_binding_smbus* smbus = nullptr;
    int inFd{-1};  // in_fd for the smbus binding
    int outFd{-1}; // out_fd for the root bus
    std::vector<std::pair<int, int>> muxFds;
    boost::asio::ip::tcp::socket smbusSlaveSocket;
};
