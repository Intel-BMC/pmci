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
    virtual void initializeBinding() override;
    virtual std::optional<std::vector<uint8_t>>
        getBindingPrivateData(uint8_t dstEid) override;
    virtual bool handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response) override;

  private:
    void SMBusInit();
    void readResponse();
    void initEndpointDiscovery();
    std::string bus;
    bool arpMasterSupport;
    uint8_t bmcSlaveAddr;
    struct mctp_binding_smbus* smbus = nullptr;
    int inFd{-1};  // in_fd for the smbus binding
    int outFd{-1}; // out_fd for the root bus
    std::vector<std::pair<int, int>> muxFds;
    boost::asio::posix::stream_descriptor smbusReceiverFd;
    bool isMuxFd(const int fd);
    std::vector<std::pair<mctp_eid_t, struct mctp_smbus_extra_params>>
        smbusDeviceTable;
    void scanAllPorts(void);
    void scanPort(const int scanFd);
};
