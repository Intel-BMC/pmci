#pragma once

#include "MCTPBinding.hpp"

#include <libmctp-smbus.h>

enum class DiscoveryFlags : uint8_t
{
    kNotApplicable = 0,
    kUnDiscovered,
    kDiscovered,
};

enum class MuxIdleModes : uint8_t
{
    muxIdleModeConnect = 0,
    muxIdleModeDisconnect,
};

class SMBusBinding : public MctpBinding
{
  public:
    SMBusBinding() = delete;
    SMBusBinding(std::shared_ptr<sdbusplus::asio::connection> conn,
                 std::shared_ptr<object_server>& objServer,
                 const std::string& objPath, const SMBusConfiguration& conf,
                 boost::asio::io_context& ioc);
    ~SMBusBinding() override;
    void initializeBinding() override;
    std::optional<std::vector<uint8_t>>
        getBindingPrivateData(uint8_t dstEid) override;
    bool handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                             std::vector<uint8_t>& request,
                             std::vector<uint8_t>& response) override;
    bool handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                             std::vector<uint8_t>& request,
                             std::vector<uint8_t>& response) override;
    bool handleGetVersionSupport(mctp_eid_t destEid, void* bindingPrivate,
                                 std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response) override;
    bool handleGetMsgTypeSupport(mctp_eid_t destEid, void* bindingPrivate,
                                 std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response) override;
    bool handleGetVdmSupport(mctp_eid_t endpointEid, void* bindingPrivate,
                             std::vector<uint8_t>& request,
                             std::vector<uint8_t>& response) override;
    void addUnknownEIDToDeviceTable(const mctp_eid_t eid,
                                    void* bindingPrivate) override;

  private:
    using DeviceTableEntry_t =
        std::pair<mctp_eid_t /*eid*/,
                  struct mctp_smbus_pkt_private /*binding prv data*/>;
    std::string SMBusInit();
    void readResponse();
    void initEndpointDiscovery(boost::asio::yield_context& yield);
    bool reserveBandwidth(const mctp_eid_t eid,
                          const uint16_t timeout) override;
    void startTimerAndReleaseBW(const uint16_t interval,
                                const mctp_smbus_pkt_private prvt);
    bool releaseBandwidth(const mctp_eid_t eid) override;
    void triggerDeviceDiscovery() override;
    std::string bus;
    bool arpMasterSupport;
    uint8_t bmcSlaveAddr;
    std::set<uint8_t> supportedEndpointSlaveAddress;
    struct mctp_binding_smbus* smbus = nullptr;
    int inFd{-1};  // in_fd for the smbus binding
    int outFd{-1}; // out_fd for the root bus
    DiscoveryFlags discoveredFlag;
    boost::asio::posix::stream_descriptor smbusReceiverFd;
    boost::asio::steady_timer reserveBWTimer;
    std::shared_ptr<dbus_interface> smbusInterface;
    bool isMuxFd(const int fd);
    std::vector<DeviceTableEntry_t> smbusDeviceTable;
    boost::asio::steady_timer scanTimer;
    std::map<int, int> muxPortMap;
    std::set<std::pair<int, uint8_t>> rootDeviceMap;
    bool addRootDevices;
    std::unordered_map<std::string, std::string> muxIdleModeMap{};
    uint8_t smbusRoutingInterval;
    std::unique_ptr<boost::asio::steady_timer> smbusRoutingTableTimer;
    uint8_t busOwnerSlaveAddr;
    int busOwnerFd;
    void scanDevices();
    std::map<int, int> getMuxFds(const std::string& rootPort);
    void scanPort(const int scanFd,
                  std::set<std::pair<int, uint8_t>>& deviceMap);
    void scanMuxBus(std::set<std::pair<int, uint8_t>>& deviceMap);
    mctp_eid_t
        getEIDFromDeviceTable(const std::vector<uint8_t>& bindingPrivate);
    void removeDeviceTableEntry(const mctp_eid_t eid);
    void updateDiscoveredFlag(DiscoveryFlags flag);
    std::string convertToString(DiscoveryFlags flag);
    void restoreMuxIdleMode();
    mctp_server::BindingModeTypes
        getBindingMode(const DeviceTableEntry_t& deviceTableEntry);
    bool isDeviceEntryPresent(
        const DeviceTableEntry_t& deviceEntry,
        const std::vector<DeviceTableEntry_t>& deviceTable);
    bool isDeviceTableChanged(const std::vector<DeviceTableEntry_t>& tableMain,
                              const std::vector<DeviceTableEntry_t>& tableTmp);
    bool isBindingDataSame(const mctp_smbus_pkt_private& dataMain,
                           const mctp_smbus_pkt_private& dataTmp);
    void updateRoutingTable();
    void processRoutingTableChanges(
        const std::vector<DeviceTableEntry_t>& newTable,
        boost::asio::yield_context& yield, const std::vector<uint8_t>& prvData);
    void setMuxIdleMode(const MuxIdleModes mode);
    size_t ret = 0;
};
