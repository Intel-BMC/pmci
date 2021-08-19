#pragma once

#include "utils/Configuration.hpp"
#include "utils/device_watcher.hpp"
#include "utils/eid_pool.hpp"
#include "utils/transmission_queue.hpp"
#include "utils/types.hpp"

#include <libmctp-cmds.h>
#include <libmctp.h>

#include <boost/asio/steady_timer.hpp>
#include <numeric>
#include <unordered_set>

class SMBusBinding;
class PCIeBinding;

constexpr uint8_t vendorIdNoMoreSets = 0xff;

using endpointInterfaceMap =
    std::unordered_map<mctp_eid_t, std::shared_ptr<dbus_interface>>;

enum MctpStatus
{
    mctpErrorOperationNotAllowed = -5,
    mctpErrorReleaseBWFailed = -4,
    mctpErrorRsvBWIsNotActive = -3,
    mctpErrorRsvBWFailed = -2,
    mctpInternalError = -1,
    mctpSuccess = 0
};

struct MsgTypes
{
    bool mctpControl = true;
    bool pldm = false;
    bool ncsi = false;
    bool ethernet = false;
    bool nvmeMgmtMsg = false;
    bool spdm = false;
    bool vdpci = false;
    bool vdiana = false;
};

struct EndpointProperties
{
    uint8_t endpointEid;
    std::string uuid;
    mctp_server::BindingModeTypes mode;
    uint16_t networkId;
    MsgTypes endpointMsgTypes;
    // Vendor PCI ID Support
    std::vector<uint16_t> vendorIdCapabilitySets;
    std::string vendorIdFormat;
};

struct MsgTypeSupportCtrlResp
{
    mctp_ctrl_msg_hdr ctrlMsgHeader;
    uint8_t completionCode;
    uint8_t msgTypeCount;
    std::vector<uint8_t> msgType;
};

struct MCTPVersionFields
{
    uint8_t major;
    uint8_t minor;
    uint8_t update;
    uint8_t alpha;
};

struct MctpVersionSupportCtrlResp
{
    mctp_ctrl_msg_hdr ctrlMsgHeader;
    uint8_t completionCode;
    uint8_t verNoEntryCount;
    std::vector<struct MCTPVersionFields> verNoEntry;
};

// VendorPCI ID Support Structure
struct MctpVendIdMsgSupportResp
{
    mctp_ctrl_msg_hdr ctrlMsgHeader;
    uint8_t completionCode;
    uint8_t vendorIdSet;
    uint8_t vendorIdFormat;
    uint16_t vendorIdFormatData;
    uint16_t vendorIdSetCmdType;
};

enum class PacketState : uint8_t
{
    invalidPacket,
    pushedForTransmission,
    transmitted,
    receivedResponse,
    noResponse
};

struct InternalVdmSetDatabase
{
    uint8_t vendorIdFormat;
    uint16_t vendorId;
    uint16_t commandSetType;
};

extern std::shared_ptr<sdbusplus::asio::connection> conn;

class MctpBinding
{
  public:
    MctpBinding(std::shared_ptr<object_server>& objServer,
                const std::string& objPath, const Configuration& conf,
                boost::asio::io_context& ioc,
                const mctp_server::BindingTypes bindingType);
    MctpBinding() = delete;
    virtual ~MctpBinding();
    virtual void initializeBinding() = 0;

    void handleCtrlReq(uint8_t destEid, void* bindingPrivate, const void* req,
                       size_t len, uint8_t msgTag);

  protected:
    unsigned int ctrlTxRetryDelay;
    uint8_t ctrlTxRetryCount;
    boost::asio::io_context& io;
    std::shared_ptr<object_server> objectServer;
    mctp_server::BindingModeTypes bindingModeType{};
    mctp_server::MctpPhysicalMediumIdentifiers bindingMediumID{};
    std::shared_ptr<dbus_interface> mctpInterface;
    struct mctp* mctp = nullptr;
    uint8_t ownEid;
    uint8_t busOwnerEid;
    bool rsvBWActive = false;
    mctp_eid_t reservedEID = 0;
    mctpd::MctpTransmissionQueue transmissionQueue;
    mctpd::DeviceWatcher deviceWatcher{};
    mctpd::EidPool eidPool;

    std::unordered_map<uint8_t, version_entry>
        versionNumbersForUpperLayerResponder;

    // vendor PCI Msg Interface
    endpointInterfaceMap vendorIdInterface;

    void initializeMctp();
    void initializeLogging(void);
    virtual std::optional<std::vector<uint8_t>>
        getBindingPrivateData(uint8_t dstEid);
    virtual bool isReceivedPrivateDataCorrect(const void* bindingPrivate);
    virtual bool handlePrepareForEndpointDiscovery(
        mctp_eid_t destEid, void* bindingPrivate, std::vector<uint8_t>& request,
        std::vector<uint8_t>& response);
    virtual bool reserveBandwidth(const mctp_eid_t eid, const uint16_t timeout);
    virtual bool releaseBandwidth(const mctp_eid_t eid);
    virtual void triggerDeviceDiscovery();
    virtual bool handleEndpointDiscovery(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual bool handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual bool handleGetVersionSupport(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleGetMsgTypeSupport(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleGetVdmSupport(mctp_eid_t endpointEid,
                                     void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual void addUnknownEIDToDeviceTable(const mctp_eid_t eid,
                                            void* bindingPrivate);
    bool getEidCtrlCmd(boost::asio::yield_context& yield,
                       const std::vector<uint8_t>& bindingPrivate,
                       const mctp_eid_t destEid, std::vector<uint8_t>& resp);
    bool setEidCtrlCmd(boost::asio::yield_context& yield,
                       const std::vector<uint8_t>& bindingPrivate,
                       const mctp_eid_t destEid,
                       const mctp_ctrl_cmd_set_eid_op operation, mctp_eid_t eid,
                       std::vector<uint8_t>& resp);
    bool getUuidCtrlCmd(boost::asio::yield_context& yield,
                        const std::vector<uint8_t>& bindingPrivate,
                        const mctp_eid_t destEid, std::vector<uint8_t>& resp);
    bool getMsgTypeSupportCtrlCmd(boost::asio::yield_context& yield,
                                  const std::vector<uint8_t>& bindingPrivate,
                                  const mctp_eid_t destEid,
                                  MsgTypeSupportCtrlResp* msgTypeSupportResp);
    bool getMctpVersionSupportCtrlCmd(
        boost::asio::yield_context& yield,
        const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
        uint8_t msgTypeNo,
        MctpVersionSupportCtrlResp* mctpVersionSupportCtrlResp);

    bool registerUpperLayerResponder(uint8_t typeNo,
                                     std::vector<uint8_t>& list);
    bool manageVersionInfo(uint8_t typeNo, std::vector<uint8_t>& list);

    // vendor PCI ID Function
    bool getPCIVDMessageSupportCtrlCmd(
        boost::asio::yield_context& yield,
        const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
        std::vector<uint16_t>& vendorSetIdList, std::string& venformat);

    bool manageVdpciVersionInfo(uint16_t vendorId, uint16_t cmdSetType);

    bool discoveryNotifyCtrlCmd(boost::asio::yield_context& yield,
                                const std::vector<uint8_t>& bindingPrivate,
                                const mctp_eid_t destEid);
    bool getRoutingTableCtrlCmd(boost::asio::yield_context& yield,
                                const std::vector<uint8_t>& bindingPrivate,
                                const mctp_eid_t destEid, uint8_t entryHandle,
                                std::vector<uint8_t>& resp);
    std::optional<mctp_eid_t>
        registerEndpoint(boost::asio::yield_context& yield,
                         const std::vector<uint8_t>& bindingPrivate,
                         mctp_eid_t eid,
                         mctp_server::BindingModeTypes bindingMode =
                             mctp_server::BindingModeTypes::Endpoint);
    void unregisterEndpoint(mctp_eid_t eid);

    // MCTP Callbacks
    void handleCtrlResp(void* msg, const size_t len);
    static void rxMessage(uint8_t srcEid, void* data, void* msg, size_t len,
                          bool tagOwner, uint8_t msgTag, void* bindingPrivate);
    static void handleMCTPControlRequests(uint8_t srcEid, void* data, void* msg,
                                          size_t len, bool tagOwner,
                                          uint8_t msgTag, void* bindingPrivate);

    template <typename Interface, typename PropertyType>
    void registerProperty(Interface ifc, const std::string& name,
                          const PropertyType& property,
                          sdbusplus::asio::PropertyPermission access =
                              sdbusplus::asio::PropertyPermission::readOnly)
    {
        if (ifc->register_property(name, property, access) != true)
        {
            throw std::invalid_argument(name);
        }
    }
    bool setMediumId(uint8_t value,
                     mctp_server::MctpPhysicalMediumIdentifiers& mediumId);

    bool isMCTPVersionSupported(const MCTPVersionFields& version);
    void logUnsupportedMCTPVersion(
        const std::vector<struct MCTPVersionFields> versionsData,
        const mctp_eid_t eid);

    // Register MCTP responder for upper layer
    std::vector<InternalVdmSetDatabase> vdmSetDatabase;

  private:
    bool staticEid;
    std::vector<uint8_t> uuid;
    mctp_server::BindingTypes bindingID{};
    endpointInterfaceMap endpointInterface;
    endpointInterfaceMap msgTypeInterface;
    endpointInterfaceMap uuidInterface;

    boost::asio::steady_timer ctrlTxTimer;

    bool ctrlTxTimerExpired = true;
    // <state, retryCount, maxRespDelay, destEid, BindingPrivate, ReqPacket,
    //  Callback>
    std::vector<
        std::tuple<PacketState, uint8_t, unsigned int, mctp_eid_t,
                   std::vector<uint8_t>, std::vector<uint8_t>,
                   std::function<void(PacketState, std::vector<uint8_t>&)>>>
        ctrlTxQueue;
    // <eid, uuid>
    std::vector<std::pair<mctp_eid_t, std::string>> uuidTable;

    void createUuid();
    bool sendMctpCtrlMessage(mctp_eid_t destEid, std::vector<uint8_t> req,
                             bool tagOwner, uint8_t msgTag,
                             std::vector<uint8_t> bindingPrivate);
    void processCtrlTxQueue();
    void pushToCtrlTxQueue(
        PacketState pktState, const mctp_eid_t destEid,
        const std::vector<uint8_t>& bindingPrivate,
        const std::vector<uint8_t>& req,
        std::function<void(PacketState, std::vector<uint8_t>&)>& callback);
    PacketState sendAndRcvMctpCtrl(boost::asio::yield_context& yield,
                                   const std::vector<uint8_t>& req,
                                   const mctp_eid_t destEid,
                                   const std::vector<uint8_t>& bindingPrivate,
                                   std::vector<uint8_t>& resp);
    template <int cmd, typename... Args>
    bool getFormattedReq(std::vector<uint8_t>& req, Args&&... reqParam);
    std::optional<mctp_eid_t>
        busOwnerRegisterEndpoint(boost::asio::yield_context& yield,
                                 const std::vector<uint8_t>& bindingPrivate,
                                 mctp_eid_t eid);
    void registerMsgTypes(std::shared_ptr<dbus_interface>& msgTypeIntf,
                          const MsgTypes& messageType);
    bool populateEndpointProperties(const EndpointProperties& epProperties);
    void
        getVendorDefinedMessageTypes(boost::asio::yield_context yield,
                                     const std::vector<uint8_t>& bindingPrivate,
                                     mctp_eid_t destEid,
                                     EndpointProperties& epProperties);
    mctp_server::BindingModeTypes getEndpointType(const uint8_t types);
    MsgTypes getMsgTypes(const std::vector<uint8_t>& msgType);
    std::vector<uint8_t> getBindingMsgTypes();
    bool removeInterface(mctp_eid_t eid, endpointInterfaceMap& interfaces);
    std::optional<mctp_eid_t> getEIDFromUUID(std::string& uuidStr);
    void clearRegisteredDevice(const mctp_eid_t eid);
    bool isEIDMappedToUUID(mctp_eid_t& eid, std::string& destUUID);
    bool isEIDRegistered(mctp_eid_t eid);
};
