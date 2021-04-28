#include "MCTPBinding.hpp"

#include "PCIeBinding.hpp"
#include "SMBusBinding.hpp"

#include <systemd/sd-id128.h>

#include <phosphor-logging/log.hpp>

#include "libmctp-cmds.h"
#include "libmctp-msgtypes.h"
#include "libmctp.h"

constexpr int noMoreSet = 0xFF;
static std::string vendIdFormat = "0x8086";

constexpr sd_id128_t mctpdAppId = SD_ID128_MAKE(c4, e4, d9, 4a, 88, 43, 4d, f0,
                                                94, 9d, bb, 0a, af, 53, 4e, 6d);
constexpr unsigned int ctrlTxPollInterval = 5;
constexpr size_t minCmdRespSize = 4;
constexpr int completionCodeIndex = 3;

/* According DSP0239(Version: 1.7.0) */
static const std::unordered_map<uint8_t,
                                mctp_server::MctpPhysicalMediumIdentifiers>
    valueToMediumId = {
        /*0x00 Unspecified*/
        {0x01,
         mctp_server::MctpPhysicalMediumIdentifiers::Smbus}, /*SMBus 2.0 100 kHz
                                                                compatible*/
        {0x02, mctp_server::MctpPhysicalMediumIdentifiers::
                   SmbusI2c}, /*SMBus 2.0 + I2C 100 kHz compatible*/
        {0x03, mctp_server::MctpPhysicalMediumIdentifiers::
                   I2cCompatible}, /*I2C 100 kHz compatible (Standard-mode)*/
        {0x04, mctp_server::MctpPhysicalMediumIdentifiers::
                   Smbus3OrI2c400khzCompatible}, /*SMBus 3.0 or I2C 400 kHz
                                                    compatible (Fast-mode)*/
        {0x05, mctp_server::MctpPhysicalMediumIdentifiers::
                   Smbus3OrI2c1MhzCompatible}, /*SMBus 3.0 or I2C 1 MHz
                                                  compatible (Fast-mode Plus)*/
        {0x06,
         mctp_server::MctpPhysicalMediumIdentifiers::
             I2c3Mhz4Compatible}, /*I2C 3.4 MHz compatible (High-speed mode)*/
        /*0x07 Reserved*/
        {0x08, mctp_server::MctpPhysicalMediumIdentifiers::
                   Pcie11}, /*PCIe revision 1.1 compatible*/
        {0x09,
         mctp_server::MctpPhysicalMediumIdentifiers::Pcie2}, /*PCIe revision 2.0
                                                                compatible*/
        {0x0A, mctp_server::MctpPhysicalMediumIdentifiers::
                   Pcie21}, /*PCIe revision 2.1 compatible*/
        {0x0B,
         mctp_server::MctpPhysicalMediumIdentifiers::Pcie3}, /*PCIe revision 3.x
                                                                compatible*/
        {0x0C,
         mctp_server::MctpPhysicalMediumIdentifiers::Pcie4}, /*PCIe revision 4.x
                                                                compatible*/
        {0x0D,
         mctp_server::MctpPhysicalMediumIdentifiers::Pcie5}, /*PCIe revision 5.x
                                                                compatible*/
        /*0x0E Reserved*/
        {0x0F, mctp_server::MctpPhysicalMediumIdentifiers::
                   PciCompatible}, /*PCI compatible
                                      (PCI 1.0,2.0,2.1,2.2,2.3,3.0,PCI-X 1.0,
                                      PCI-X 2.0)*/
        {0x10, mctp_server::MctpPhysicalMediumIdentifiers::
                   Usb11Compatible}, /*USB 1.1 compatible*/
        {0x11, mctp_server::MctpPhysicalMediumIdentifiers::
                   Usb20Compatible}, /*USB 2.0 compatible*/
        {0x12, mctp_server::MctpPhysicalMediumIdentifiers::
                   Usb30Compatible}, /*USB 3.0 compatible*/
        /*0x13:0x17 Reserved*/
        {0x18, mctp_server::MctpPhysicalMediumIdentifiers::
                   NcSiOverRbt}, /*NC-SI over RBT (A physical interface based on
                                    RMII as defined inDSP0222)*/
        /*0x19:0x1F Reserved*/
        {0x20, mctp_server::MctpPhysicalMediumIdentifiers::
                   KcsLegacy}, /*KCS / Legacy (Fixed Address Decoding)*/
        {0x21, mctp_server::MctpPhysicalMediumIdentifiers::
                   KcsPci}, /*KCS / PCI (Base Class 0xC0 Subclass 0x01)*/
        {0x22, mctp_server::MctpPhysicalMediumIdentifiers::
                   SerialHostLegacy}, /*Serial Host / Legacy (Fixed Address
                                         Decoding)*/
        {0x23, mctp_server::MctpPhysicalMediumIdentifiers::
                   SerialHostPci}, /*Serial Host / PCI (Base Class 0x07 Subclass
                                      0x00)*/
        {0x24,
         mctp_server::MctpPhysicalMediumIdentifiers::
             AsynchronousSerial}, /*Asynchronous Serial3(Between MCs and IMDs)*/
        {0x30, mctp_server::MctpPhysicalMediumIdentifiers::
                   I3cSDR}, /*I3C 12.5 MHz compatible (SDR)*/
        {0x31, mctp_server::MctpPhysicalMediumIdentifiers::
                   I3cHDRDDR} /*I3C 25 MHz compatible (HDR-DDR)*/
                              /*0x32:0x3F Reserved */
                              /*0x40, CXL 1.x*/
                              /*0x41:0xFF Reserved*/
};

static uint8_t getInstanceId(const uint8_t msg)
{
    return msg & MCTP_CTRL_HDR_INSTANCE_ID_MASK;
}

MctpTransmissionQueue::Message::Message(size_t index_,
                                        std::vector<uint8_t>&& payload_,
                                        std::vector<uint8_t>&& privateData_,
                                        boost::asio::io_context& ioc) :
    index(index_),
    payload(std::move(payload_)), privateData(std::move(privateData_)),
    timer(ioc)
{
}

std::optional<uint8_t> MctpTransmissionQueue::Tags::next() const
{
    if (!bits)
    {
        return std::nullopt;
    }
    return static_cast<uint8_t>(__builtin_ctz(bits));
}

void MctpTransmissionQueue::Tags::emplace(uint8_t flag)
{
    bits |= static_cast<uint8_t>(1 << flag);
}

void MctpTransmissionQueue::Tags::erase(uint8_t flag)
{
    bits &= static_cast<uint8_t>(~(1 << flag));
}

std::shared_ptr<MctpTransmissionQueue::Message> MctpTransmissionQueue::transmit(
    struct mctp* mctp, mctp_eid_t destEid, std::vector<uint8_t>&& payload,
    std::vector<uint8_t>&& privateData, boost::asio::io_context& ioc)
{
    auto& endpoint = endpoints[destEid];
    auto msgIndex = endpoint.msgCounter++;
    auto message = std::make_shared<Message>(msgIndex, std::move(payload),
                                             std::move(privateData), ioc);
    endpoint.queuedMessages.emplace(msgIndex, message);
    endpoint.transmitQueuedMessages(mctp, destEid);
    return message;
}

void MctpTransmissionQueue::Endpoint::transmitQueuedMessages(struct mctp* mctp,
                                                             mctp_eid_t destEid)
{
    while (!queuedMessages.empty())
    {
        const std::optional<uint8_t> nextTag = availableTags.next();
        if (!nextTag)
        {
            break;
        }
        auto msgTag = nextTag.value();
        auto queuedMessageIter = queuedMessages.begin();
        auto message = std::move(queuedMessageIter->second);
        queuedMessages.erase(queuedMessageIter);

        int rc = mctp_message_tx(mctp, destEid, message->payload.data(),
                                 message->payload.size(), true, msgTag,
                                 message->privateData.data());
        if (rc < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error in mctp_message_tx");
            continue;
        }

        availableTags.erase(msgTag);
        message->tag = msgTag;
        transmittedMessages.emplace(msgTag, std::move(message));
    }
}

bool MctpTransmissionQueue::receive(struct mctp* mctp, mctp_eid_t srcEid,
                                    uint8_t msgTag,
                                    std::vector<uint8_t>&& response,
                                    boost::asio::io_context& ioc)
{
    auto endpointIter = endpoints.find(srcEid);
    if (endpointIter == endpoints.end())
    {
        return false;
    }

    auto& endpoint = endpointIter->second;
    auto messageIter = endpoint.transmittedMessages.find(msgTag);
    if (messageIter == endpoint.transmittedMessages.end())
    {
        return false;
    }

    const auto message = messageIter->second;
    message->response = std::move(response);
    endpoint.transmittedMessages.erase(messageIter);
    message->tag.reset();
    endpoint.availableTags.emplace(msgTag);

    // Now that another tag is available, try to transmit any queued messages
    message->timer.cancel();
    ioc.post([this, mctp, srcEid] {
        endpoints[srcEid].transmitQueuedMessages(mctp, srcEid);
    });
    return true;
}

void MctpTransmissionQueue::dispose(mctp_eid_t destEid,
                                    const std::shared_ptr<Message>& message)
{
    auto& endpoint = endpoints[destEid];
    auto queuedMessageIter = endpoint.queuedMessages.find(message->index);
    if (queuedMessageIter != endpoint.queuedMessages.end())
    {
        endpoint.queuedMessages.erase(queuedMessageIter);
    }
    if (message->tag)
    {
        auto msgTag = message->tag.value();
        endpoint.availableTags.emplace(msgTag);

        auto transmittedMessageIter = endpoint.transmittedMessages.find(msgTag);
        if (transmittedMessageIter != endpoint.transmittedMessages.end())
        {
            endpoint.transmittedMessages.erase(transmittedMessageIter);
        }
    }
}

void MctpBinding::handleCtrlResp(void* msg, const size_t len)
{
    mctp_ctrl_msg_hdr* respHeader = reinterpret_cast<mctp_ctrl_msg_hdr*>(msg);

    auto reqItr =
        std::find_if(ctrlTxQueue.begin(), ctrlTxQueue.end(), [&](auto& ctrlTx) {
            auto& [state, retryCount, maxRespDelay, destEid, bindingPrivate,
                   req, callback] = ctrlTx;

            mctp_ctrl_msg_hdr* reqHeader =
                reinterpret_cast<mctp_ctrl_msg_hdr*>(req.data());

            if (!reqHeader)
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "MCTP Control Request Header is null");
                return false;
            }

            // TODO: Check Message terminus with Instance ID
            // (EID, TO, Msg Tag) + Instance ID
            if (getInstanceId(reqHeader->rq_dgram_inst) ==
                getInstanceId(respHeader->rq_dgram_inst))
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "Matching Control command request found");

                uint8_t* tmp = reinterpret_cast<uint8_t*>(msg);
                std::vector<uint8_t> resp =
                    std::vector<uint8_t>(tmp, tmp + len);
                state = PacketState::receivedResponse;

                // Call Callback function
                callback(state, resp);
                return true;
            }
            return false;
        });

    if (reqItr != ctrlTxQueue.end())
    {
        // Delete the entry from queue after receiving response
        ctrlTxQueue.erase(reqItr);
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No matching Control command request found");
    }
}

/*
 * Comment out unused parameters since rxMessage is a callback
 * passed to libmctp and we have to match its expected prototype.
 */
void MctpBinding::rxMessage(uint8_t srcEid, void* data, void* msg, size_t len,
                            bool tagOwner, uint8_t msgTag,
                            void* /*bindingPrivate*/)
{
    uint8_t* payload = reinterpret_cast<uint8_t*>(msg);
    uint8_t msgType = payload[0]; // Always the first byte
    std::vector<uint8_t> response;

    response.assign(payload, payload + len);

    auto& binding = *static_cast<MctpBinding*>(data);

    if (msgType != MCTP_MESSAGE_TYPE_MCTP_CTRL)
    {
        if (!tagOwner &&
            binding.transmissionQueue.receive(binding.mctp, srcEid, msgTag,
                                              std::move(response), binding.io))
        {
            return;
        }

        auto msgSignal =
            conn->new_signal("/xyz/openbmc_project/mctp",
                             mctp_server::interface, "MessageReceivedSignal");
        msgSignal.append(msgType, srcEid, msgTag, tagOwner, response);
        msgSignal.signal_send();
        return;
    }

    // TODO: Take into account the msgTags too when we verify control messages.
    if (!tagOwner && mctp_is_mctp_ctrl_msg(msg, len) &&
        !mctp_ctrl_msg_is_req(msg, len))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "MCTP Control packet response received!!");
        binding.handleCtrlResp(msg, len);
    }
}

void MctpBinding::handleMCTPControlRequests(uint8_t srcEid, void* data,
                                            void* msg, size_t len,
                                            bool tagOwner, uint8_t msgTag,
                                            void* bindingPrivate)
{
    /*
     * We only check the msg pointer, private data may be unused by some
     * bindings.
     */
    if (msg == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "MCTP Control Message is not initialized.");
        return;
    }
    if (!tagOwner)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "MCTP Control Message expects that tagOwner is set");
        return;
    }
    auto& binding = *static_cast<MctpBinding*>(data);
    binding.handleCtrlReq(srcEid, bindingPrivate, msg, len, msgTag);
}

std::optional<std::vector<uint8_t>>
    MctpBinding::getBindingPrivateData(uint8_t /*dstEid*/)
{
    // No Binding data by default
    return std::vector<uint8_t>();
}

bool MctpBinding::reserveBandwidth(const mctp_eid_t /*eid*/,
                                   const uint16_t /*timeout*/)
{
    return true;
}

bool MctpBinding::releaseBandwidth(const mctp_eid_t /*eid*/)
{
    return true;
}

bool MctpBinding::isReceivedPrivateDataCorrect(const void* /*bindingPrivate*/)
{
    return true;
}

MctpBinding::MctpBinding(std::shared_ptr<object_server>& objServer,
                         const std::string& objPath, const Configuration& conf,
                         boost::asio::io_context& ioc,
                         const mctp_server::BindingTypes bindingType) :
    io(ioc),
    bindingID(bindingType), objectServer(objServer), ctrlTxTimer(io)
{
    objServer->add_manager(objPath);
    mctpInterface = objServer->add_interface(objPath, mctp_server::interface);

    /*initialize the map*/
    versionNumbersForUpperLayerResponder.insert(
        std::pair<uint8_t, version_entry>{MCTP_MESSAGE_TYPE_MCTP_CTRL,
                                          {0xF1, 0xF3, 0xF1, 0}});
    versionNumbersForUpperLayerResponder.insert(
        std::pair<uint8_t, version_entry>{MCTP_GET_VERSION_SUPPORT_BASE_INFO,
                                          {0xF1, 0xF3, 0xF1, 0}});

    try
    {
        ownEid = conf.defaultEid;
        bindingMediumID = conf.mediumId;
        bindingModeType = conf.mode;

        ctrlTxRetryDelay = conf.reqToRespTime;
        ctrlTxRetryCount = conf.reqRetryCount;

        createUuid();
        registerProperty(mctpInterface, "Eid", ownEid);

        registerProperty(mctpInterface, "StaticEid", staticEid);

        registerProperty(mctpInterface, "Uuid", uuid);

        registerProperty(mctpInterface, "BindingID",
                         mctp_server::convertBindingTypesToString(bindingID));

        registerProperty(
            mctpInterface, "BindingMediumID",
            mctp_server::convertMctpPhysicalMediumIdentifiersToString(
                bindingMediumID));

        registerProperty(
            mctpInterface, "BindingMode",
            mctp_server::convertBindingModeTypesToString(bindingModeType));

        /*
         * msgTag and tagOwner are not currently used, but can't be removed
         * since they are defined for SendMctpMessagePayload() in the current
         * version of MCTP D-Bus interface.
         */
        mctpInterface->register_method(
            "SendMctpMessagePayload",
            [this](uint8_t dstEid, uint8_t msgTag, bool tagOwner,
                   std::vector<uint8_t> payload) {
                if (payload.size() > 0)
                {
                    uint8_t msgType = payload[0]; // Always the first byte
                    if (msgType == MCTP_MESSAGE_TYPE_MCTP_CTRL)
                    {
                        phosphor::logging::log<
                            phosphor::logging::level::WARNING>(
                            "Cannot transmit control messages");
                        return static_cast<int>(mctpErrorOperationNotAllowed);
                    }
                }

                if (rsvBWActive && dstEid != reservedEID)
                {
                    phosphor::logging::log<phosphor::logging::level::WARNING>(
                        (("SendMctpMessagePayload is not allowed. "
                          "ReserveBandwidth is active "
                          "for EID: ") +
                         std::to_string(reservedEID))
                            .c_str());
                    return static_cast<int>(mctpErrorRsvBWIsNotActive);
                }
                std::optional<std::vector<uint8_t>> pvtData =
                    getBindingPrivateData(dstEid);
                if (!pvtData)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "SendMctpMessagePayload: Invalid destination EID");
                    return static_cast<int>(mctpInternalError);
                }
                if (mctp_message_tx(mctp, dstEid, payload.data(),
                                    payload.size(), tagOwner, msgTag,
                                    pvtData->data()) < 0)
                {
                    return static_cast<int>(mctpInternalError);
                }
                return static_cast<int>(mctpSuccess);
            });

        mctpInterface->register_method(
            "ReserveBandwidth",
            [this](const mctp_eid_t eid, const uint16_t timeout) {
                if (!reserveBandwidth(eid, timeout))
                {
                    phosphor::logging::log<phosphor::logging::level::WARNING>(
                        ("Reserve bandwidth failed for EID: " +
                         std::to_string(eid))
                            .c_str());
                    return static_cast<int>(mctpErrorRsvBWFailed);
                }
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("Reserve bandwidth is active for EID: " +
                     std::to_string(eid))
                        .c_str());
                return static_cast<int>(mctpSuccess);
            });
        mctpInterface->register_method("ReleaseBandwidth", [this](
                                                               const mctp_eid_t
                                                                   eid) {
            if (!releaseBandwidth(eid))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("Release bandwidth failed for EID: " + std::to_string(eid))
                        .c_str());
                return static_cast<int>(mctpErrorReleaseBWFailed);
            }
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Bandwidth released for EID: " + std::to_string(eid)).c_str());
            return static_cast<int>(mctpSuccess);
        });
        mctpInterface->register_method(
            "SendReceiveMctpMessagePayload",
            [this](boost::asio::yield_context yield, uint8_t dstEid,
                   std::vector<uint8_t> payload,
                   uint16_t timeout) -> std::vector<uint8_t> {
                if (rsvBWActive && dstEid != reservedEID)
                {
                    phosphor::logging::log<phosphor::logging::level::WARNING>(
                        (("SendReceiveMctpMessagePayload is not allowed. "
                          "ReserveBandwidth is "
                          "active for EID: ") +
                         std::to_string(reservedEID))
                            .c_str());
                    throw std::system_error(
                        std::make_error_code(std::errc::invalid_argument));
                }

                if (payload.size() > 0)
                {
                    uint8_t msgType = payload[0]; // Always the first byte
                    if (msgType == MCTP_MESSAGE_TYPE_MCTP_CTRL)
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "Cannot transmit control messages");
                        throw std::system_error(
                            std::make_error_code(std::errc::invalid_argument));
                    }
                }

                std::optional<std::vector<uint8_t>> pvtData =
                    getBindingPrivateData(dstEid);
                if (!pvtData)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "SendReceiveMctpMessagePayload: Invalid destination "
                        "EID");
                    throw std::system_error(
                        std::make_error_code(std::errc::invalid_argument));
                }

                boost::system::error_code ec;
                auto message =
                    transmissionQueue.transmit(mctp, dstEid, std::move(payload),
                                               std::move(pvtData).value(), io);

                message->timer.expires_after(
                    std::chrono::milliseconds(timeout));
                message->timer.async_wait(yield[ec]);

                if (ec && ec != boost::asio::error::operation_aborted)
                {
                    transmissionQueue.dispose(dstEid, message);
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Timer failed");
                    throw std::system_error(
                        std::make_error_code(std::errc::connection_aborted));
                }
                if (!message->response)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "No response");
                    throw std::system_error(
                        std::make_error_code(std::errc::timed_out));
                }
                if (message->response->empty())
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Empty response");
                    throw std::system_error(
                        std::make_error_code(std::errc::no_message_available));
                }
                return std::move(message->response).value();
            });

        mctpInterface->register_signal<uint8_t, uint8_t, uint8_t, bool,
                                       std::vector<uint8_t>>(
            "MessageReceivedSignal");

        mctpInterface->register_method(
            "RegisterResponder",
            [this](uint8_t msgTypeName,
                   std::vector<uint8_t> inputVersion) -> bool {
                return registerUpperLayerResponder(msgTypeName, inputVersion);
            });

        if (mctpInterface->initialize() == false)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "MCTP Interface initialization failed.",
            phosphor::logging::entry("Exception:", e.what()));
        throw;
    }
}

bool MctpBinding::registerUpperLayerResponder(uint8_t typeNo,
                                              std::vector<uint8_t>& versionData)
{
    bool ret = false;
    switch (typeNo)
    {
        case MCTP_MESSAGE_TYPE_PLDM:
        case MCTP_MESSAGE_TYPE_NCSI:
        case MCTP_MESSAGE_TYPE_ETHERNET:
        case MCTP_MESSAGE_TYPE_NVME:
        case MCTP_MESSAGE_TYPE_SPDM:
            ret = manageVersionInfo(typeNo, versionData);
            break;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid Type for Registration To MCTP");
            break;
    }
    return ret;
}

bool MctpBinding::manageVersionInfo(uint8_t typeNo,
                                    std::vector<uint8_t>& versionInfo)
{
    struct version_entry verString;

    if (versionInfo.size() != 4)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "The Version info is of invalid length...");
        return false;
    }

    if (versionNumbersForUpperLayerResponder.find(typeNo) ==
        versionNumbersForUpperLayerResponder.end())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "No existing Data for typeNo, So pushing into map");
        std::copy_n(versionInfo.begin(), sizeof(version_entry),
                    reinterpret_cast<uint8_t*>(&verString));

        versionNumbersForUpperLayerResponder.emplace(typeNo, verString);
        return true;
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Existing Data In Map for the typeNo");
    return false;
}

MctpBinding::~MctpBinding()
{
    for (auto [eid, assigned] : eidPoolMap)
    {
        if (assigned)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Unregistering EID", phosphor::logging::entry("EID=%d", eid));
            unregisterEndpoint(eid);
        }
    }
    objectServer->remove_interface(mctpInterface);
    if (mctp)
    {
        mctp_destroy(mctp);
    }
}

void MctpBinding::createUuid()
{
    sd_id128_t id;

    if (sd_id128_get_machine_app_specific(mctpdAppId, &id))
    {
        throw std::system_error(
            std::make_error_code(std::errc::address_not_available));
    }

    uuid.insert(uuid.begin(), std::begin(id.bytes), std::end(id.bytes));
    if (uuid.size() != 16)
    {
        throw std::system_error(std::make_error_code(std::errc::bad_address));
    }
}

void MctpBinding::initializeMctp()
{
    initializeLogging();
    mctp = mctp_init();
    if (!mctp)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to init mctp");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
}

void MctpBinding::initializeLogging(void)
{
    // Default log level
    mctp_set_log_stdio(MCTP_LOG_INFO);

    if (auto envPtr = std::getenv("MCTP_TRACES"))
    {
        std::string value(envPtr);
        if (value == "1")
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "MCTP traces enabled, expect lower performance");
            mctp_set_log_stdio(MCTP_LOG_DEBUG);
            mctp_set_tracing_enabled(true);
        }
    }
}

void MctpBinding::initializeEidPool(const std::set<mctp_eid_t>& pool)
{
    for (auto const& epId : pool)
    {
        eidPoolMap.emplace(epId, false);
    }
}

void MctpBinding::updateEidStatus(const mctp_eid_t endpointId,
                                  const bool assigned)
{
    auto eidItr = eidPoolMap.find(endpointId);
    if (eidItr != eidPoolMap.end())
    {
        eidItr->second = assigned;
        if (assigned)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("EID " + std::to_string(endpointId) + " is assigned").c_str());
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("EID " + std::to_string(endpointId) + " added to pool")
                    .c_str());
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Unable to find EID " + std::to_string(endpointId) +
             " in the pool")
                .c_str());
    }
}

mctp_eid_t MctpBinding::getAvailableEidFromPool()
{
    // Note:- No need to check for busowner role explicitly when accessing EID
    // pool since getAvailableEidFromPool will be called only in busowner mode.

    for (auto& eidPair : eidPoolMap)
    {
        if (!eidPair.second)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Allocated EID: " + std::to_string(eidPair.first)).c_str());
            eidPair.second = true;
            return eidPair.first;
        }
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "No free EID in the pool");
    throw std::system_error(
        std::make_error_code(std::errc::address_not_available));
}

bool MctpBinding::sendMctpMessage(mctp_eid_t destEid, std::vector<uint8_t> req,
                                  bool tagOwner, uint8_t msgTag,
                                  std::vector<uint8_t> bindingPrivate)
{
    if (mctp_message_tx(mctp, destEid, req.data(), req.size(), tagOwner, msgTag,
                        bindingPrivate.data()) < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in mctp_message_tx");
        return false;
    }
    return true;
}

void MctpBinding::processCtrlTxQueue()
{
    ctrlTxTimerExpired = false;
    ctrlTxTimer.expires_after(std::chrono::milliseconds(ctrlTxPollInterval));
    ctrlTxTimer.async_wait([this](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted)
        {
            // timer aborted do nothing
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "ctrlTxTimer operation_aborted");
            return;
        }
        else if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ctrlTxTimer failed");
            return;
        }

        // Discard the packet if retry count exceeded

        ctrlTxQueue.erase(
            std::remove_if(
                ctrlTxQueue.begin(), ctrlTxQueue.end(),
                [this](auto& ctrlTx) {
                    auto& [state, retryCount, maxRespDelay, destEid,
                           bindingPrivate, req, callback] = ctrlTx;

                    maxRespDelay -= ctrlTxPollInterval;

                    // If no reponse:
                    // Retry the packet on every ctrlTxRetryDelay
                    // Total no of tries = 1 + ctrlTxRetryCount
                    if (maxRespDelay > 0 &&
                        state != PacketState::receivedResponse)
                    {
                        if (retryCount > 0 &&
                            maxRespDelay <= retryCount * ctrlTxRetryDelay)
                        {
                            if (sendMctpMessage(destEid, req, true, 0,
                                                bindingPrivate))
                            {
                                phosphor::logging::log<
                                    phosphor::logging::level::DEBUG>(
                                    "Packet transmited");
                                state = PacketState::transmitted;
                            }

                            // Decrement retry count
                            retryCount--;
                        }

                        return false;
                    }

                    state = PacketState::noResponse;
                    std::vector<uint8_t> resp1 = {};
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Retry timed out, No response");

                    // Call Callback function
                    callback(state, resp1);
                    return true;
                }),
            ctrlTxQueue.end());

        if (ctrlTxQueue.empty())
        {
            ctrlTxTimer.cancel();
            ctrlTxTimerExpired = true;
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "ctrlTxQueue empty, canceling timer");
        }
        else
        {
            processCtrlTxQueue();
        }
    });
}

void MctpBinding::handleCtrlReq(uint8_t destEid, void* bindingPrivate,
                                const void* req, size_t len, uint8_t msgTag)
{
    if (req == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "MCTP Control Request is not initialized.");
        return;
    }
    if (!isReceivedPrivateDataCorrect(bindingPrivate))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Binding Private Data is not correct.");
        return;
    }

    std::vector<uint8_t> response = {};
    bool sendResponse = false;
    auto reqPtr = reinterpret_cast<const uint8_t*>(req);
    std::vector<uint8_t> request(reqPtr, reqPtr + len);
    mctp_ctrl_msg_hdr* reqHeader =
        reinterpret_cast<mctp_ctrl_msg_hdr*>(request.data());

    if (!reqHeader)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "MCTP Control Request Header is null");
        return;
    }

    switch (reqHeader->command_code)
    {
        case MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY: {
            sendResponse = handlePrepareForEndpointDiscovery(
                destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_ENDPOINT_DISCOVERY: {
            sendResponse = handleEndpointDiscovery(destEid, bindingPrivate,
                                                   request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_ENDPOINT_ID: {
            sendResponse =
                handleGetEndpointId(destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_SET_ENDPOINT_ID: {
            sendResponse =
                handleSetEndpointId(destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_VERSION_SUPPORT: {
            sendResponse = handleGetVersionSupport(destEid, bindingPrivate,
                                                   request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT: {
            sendResponse = handleGetMsgTypeSupport(destEid, bindingPrivate,
                                                   request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT: {
            sendResponse =
                handleGetVdmSupport(destEid, bindingPrivate, request, response);
            break;
        }
        default: {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Message not supported");
        }
    }

    if (sendResponse)
    {
        auto respHeader = reinterpret_cast<mctp_ctrl_msg_hdr*>(response.data());
        *respHeader = *reqHeader;
        respHeader->rq_dgram_inst &=
            static_cast<uint8_t>(~MCTP_CTRL_HDR_FLAG_REQUEST);
        mctp_message_tx(mctp, destEid, response.data(), response.size(), false,
                        msgTag, bindingPrivate);
    }
    return;
}

bool MctpBinding::handlePrepareForEndpointDiscovery(mctp_eid_t, void*,
                                                    std::vector<uint8_t>&,
                                                    std::vector<uint8_t>&)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Message not supported");
    return false;
}

bool MctpBinding::handleEndpointDiscovery(mctp_eid_t, void*,
                                          std::vector<uint8_t>&,
                                          std::vector<uint8_t>&)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Message not supported");
    return false;
}

bool MctpBinding::handleGetEndpointId(mctp_eid_t destEid, void*,
                                      std::vector<uint8_t>&,
                                      std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_ctrl_resp_get_eid));
    auto resp = reinterpret_cast<mctp_ctrl_resp_get_eid*>(response.data());

    bool busownerMode =
        bindingModeType == mctp_server::BindingModeTypes::BusOwner ? true
                                                                   : false;
    mctp_ctrl_cmd_get_endpoint_id(mctp, destEid, busownerMode, resp);
    return true;
}

bool MctpBinding::handleSetEndpointId(mctp_eid_t destEid, void*,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{
    if (bindingModeType != mctp_server::BindingModeTypes::Endpoint)
    {
        return false;
    }
    response.resize(sizeof(mctp_ctrl_resp_set_eid));
    auto resp = reinterpret_cast<mctp_ctrl_resp_set_eid*>(response.data());
    auto req = reinterpret_cast<mctp_ctrl_cmd_set_eid*>(request.data());

    mctp_ctrl_cmd_set_endpoint_id(mctp, destEid, req, resp);
    if (resp->completion_code == MCTP_CTRL_CC_SUCCESS)
    {
        busOwnerEid = destEid;
        ownEid = resp->eid_set;
    }
    return true;
}

bool MctpBinding::handleGetVersionSupport(mctp_eid_t, void*,
                                          std::vector<uint8_t>& request,
                                          std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_ctrl_resp_get_mctp_ver_support));
    auto req =
        reinterpret_cast<mctp_ctrl_cmd_get_mctp_ver_support*>(request.data());
    auto resp =
        reinterpret_cast<mctp_ctrl_resp_get_mctp_ver_support*>(response.data());

    std::vector<version_entry> versions = {};

    if (versionNumbersForUpperLayerResponder.find(req->msg_type_number) ==
        versionNumbersForUpperLayerResponder.end())
    {
        resp->completion_code =
            MCTP_CTRL_CC_GET_MCTP_VER_SUPPORT_UNSUPPORTED_TYPE;
    }
    else
    {
        versions.push_back(
            versionNumbersForUpperLayerResponder.at(req->msg_type_number));
        resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    }
    resp->number_of_entries = static_cast<uint8_t>(versions.size());
    std::copy(reinterpret_cast<uint8_t*>(versions.data()),
              reinterpret_cast<uint8_t*>(versions.data() + versions.size()),
              std::back_inserter(response));
    return true;
}

bool MctpBinding::handleGetMsgTypeSupport(mctp_eid_t, void*,
                                          std::vector<uint8_t>&,
                                          std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_ctrl_resp_get_msg_type_support));
    std::vector<uint8_t> supportedMsgTypes = getBindingMsgTypes();
    auto resp =
        reinterpret_cast<mctp_ctrl_resp_get_msg_type_support*>(response.data());
    resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    resp->msg_type_count = static_cast<uint8_t>(supportedMsgTypes.size());
    std::copy(supportedMsgTypes.begin(), supportedMsgTypes.end(),
              std::back_inserter(response));
    return true;
}

std::vector<uint8_t> MctpBinding::getBindingMsgTypes()
{
    // TODO: endpoints should expose info about message types
    // supported by upper layer applications
    std::vector<uint8_t> bindingMsgTypes = {MCTP_MESSAGE_TYPE_MCTP_CTRL};
    return bindingMsgTypes;
}

bool MctpBinding::handleGetVdmSupport(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    [[maybe_unused]] std::vector<uint8_t>& response)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Message not supported");
    return false;
}

void MctpBinding::pushToCtrlTxQueue(
    PacketState state, const mctp_eid_t destEid,
    const std::vector<uint8_t>& bindingPrivate, const std::vector<uint8_t>& req,
    std::function<void(PacketState, std::vector<uint8_t>&)>& callback)
{
    ctrlTxQueue.push_back(std::make_tuple(
        state, ctrlTxRetryCount, ((ctrlTxRetryCount + 1) * ctrlTxRetryDelay),
        destEid, bindingPrivate, req, callback));

    if (sendMctpMessage(destEid, req, true, 0, bindingPrivate))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Packet transmited");
        state = PacketState::transmitted;
    }

    if (ctrlTxTimerExpired)
    {
        processCtrlTxQueue();
    }
}

PacketState MctpBinding::sendAndRcvMctpCtrl(
    boost::asio::yield_context& yield, const std::vector<uint8_t>& req,
    const mctp_eid_t destEid, const std::vector<uint8_t>& bindingPrivate,
    std::vector<uint8_t>& resp)
{
    if (req.empty())
    {
        return PacketState::invalidPacket;
    }

    PacketState pktState = PacketState::pushedForTransmission;
    boost::system::error_code ec;
    boost::asio::steady_timer timer(io);

    std::function<void(PacketState, std::vector<uint8_t>&)> callback =
        [&resp, &pktState, &timer](PacketState state,
                                   std::vector<uint8_t>& response) {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Callback triggered");

            resp = response;
            pktState = state;
            timer.cancel();

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Packet state: " + std::to_string(static_cast<int>(pktState)))
                    .c_str());
        };

    pushToCtrlTxQueue(pktState, destEid, bindingPrivate, req, callback);

    // Wait for the state to change
    while (pktState == PacketState::pushedForTransmission)
    {
        timer.expires_after(std::chrono::milliseconds(ctrlTxRetryDelay));
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "sendAndRcvMctpCtrl: Timer created, ctrl cmd waiting");
        timer.async_wait(yield[ec]);
        if (ec && ec != boost::asio::error::operation_aborted)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "sendAndRcvMctpCtrl: async_wait error");
        }
    }

    return pktState;
}

static uint8_t createInstanceId()
{
    static uint8_t instanceId = 0x00;

    instanceId = (instanceId + 1) & MCTP_CTRL_HDR_INSTANCE_ID_MASK;
    return instanceId;
}

static uint8_t getRqDgramInst()
{
    uint8_t instanceID = createInstanceId();
    uint8_t rqDgramInst = instanceID | MCTP_CTRL_HDR_FLAG_REQUEST;
    return rqDgramInst;
}

template <int cmd, typename... Args>
bool MctpBinding::getFormattedReq(std::vector<uint8_t>& req, Args&&... reqParam)
{
    if constexpr (cmd == MCTP_CTRL_CMD_GET_ENDPOINT_ID)
    {
        req.resize(sizeof(mctp_ctrl_cmd_get_eid));
        mctp_ctrl_cmd_get_eid* getEidCmd =
            reinterpret_cast<mctp_ctrl_cmd_get_eid*>(req.data());

        mctp_encode_ctrl_cmd_get_eid(getEidCmd, getRqDgramInst());
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_SET_ENDPOINT_ID)
    {
        req.resize(sizeof(mctp_ctrl_cmd_set_eid));
        mctp_ctrl_cmd_set_eid* setEidCmd =
            reinterpret_cast<mctp_ctrl_cmd_set_eid*>(req.data());

        mctp_encode_ctrl_cmd_set_eid(setEidCmd, getRqDgramInst(),
                                     std::forward<Args>(reqParam)...);
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_GET_ENDPOINT_UUID)
    {
        req.resize(sizeof(mctp_ctrl_cmd_get_uuid));
        mctp_ctrl_cmd_get_uuid* getUuid =
            reinterpret_cast<mctp_ctrl_cmd_get_uuid*>(req.data());

        mctp_encode_ctrl_cmd_get_uuid(getUuid, getRqDgramInst());
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_GET_VERSION_SUPPORT)
    {
        req.resize(sizeof(mctp_ctrl_cmd_get_mctp_ver_support));
        mctp_ctrl_cmd_get_mctp_ver_support* getVerSupport =
            reinterpret_cast<mctp_ctrl_cmd_get_mctp_ver_support*>(req.data());

        mctp_encode_ctrl_cmd_get_ver_support(getVerSupport, getRqDgramInst(),
                                             std::forward<Args>(reqParam)...);
        return true;
    }

    else if constexpr (cmd == MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT)
    {
        req.resize(sizeof(mctp_ctrl_cmd_get_msg_type_support));
        mctp_ctrl_cmd_get_msg_type_support* getMsgType =
            reinterpret_cast<mctp_ctrl_cmd_get_msg_type_support*>(req.data());

        mctp_encode_ctrl_cmd_get_msg_type_support(getMsgType, getRqDgramInst());
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT)
    {
        req.resize(sizeof(struct mctp_ctrl_cmd_get_vdm_support));
        struct mctp_ctrl_cmd_get_vdm_support* getVdmSupport =
            reinterpret_cast<struct mctp_ctrl_cmd_get_vdm_support*>(req.data());

        mctp_encode_ctrl_cmd_get_vdm_support(getVdmSupport, getRqDgramInst(),
                                             std::forward<Args>(reqParam)...);
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_DISCOVERY_NOTIFY)
    {
        req.resize(sizeof(mctp_ctrl_cmd_discovery_notify));
        mctp_ctrl_cmd_discovery_notify* discoveryNotify =
            reinterpret_cast<mctp_ctrl_cmd_discovery_notify*>(req.data());

        mctp_encode_ctrl_cmd_discovery_notify(discoveryNotify,
                                              getRqDgramInst());
        return true;
    }
    else if constexpr (cmd == MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES)
    {
        req.resize(sizeof(mctp_ctrl_cmd_get_routing_table));
        mctp_ctrl_cmd_get_routing_table* getRoutingTable =
            reinterpret_cast<mctp_ctrl_cmd_get_routing_table*>(req.data());

        mctp_encode_ctrl_cmd_get_routing_table(
            getRoutingTable, getRqDgramInst(), std::forward<Args>(reqParam)...);
        return true;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Control command not defined");
        return false;
    }
}

static bool checkMinRespSize(const std::vector<uint8_t>& resp)
{
    return (resp.size() >= minCmdRespSize);
}

template <typename structure>
static bool checkRespSizeAndCompletionCode(std::vector<uint8_t>& resp)
{
    if (!checkMinRespSize(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid response length");
        return false;
    }

    structure* respPtr = reinterpret_cast<structure*>(resp.data());

    if (respPtr->completion_code != MCTP_CTRL_CC_SUCCESS ||
        resp.size() != sizeof(structure))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid response", phosphor::logging::entry("LEN=%d", resp.size()),
            phosphor::logging::entry("CC=0x%02X", respPtr->completion_code));
        return false;
    }
    return true;
}

bool MctpBinding::getEidCtrlCmd(boost::asio::yield_context& yield,
                                const std::vector<uint8_t>& bindingPrivate,
                                const mctp_eid_t destEid,
                                std::vector<uint8_t>& resp)
{
    std::vector<uint8_t> req = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_GET_ENDPOINT_ID>(req))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get EID: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get EID: Unable to get response");
        return false;
    }

    if (!checkRespSizeAndCompletionCode<mctp_ctrl_resp_get_eid>(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Get EID failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>("Get EID success");
    return true;
}

bool MctpBinding::setEidCtrlCmd(boost::asio::yield_context& yield,
                                const std::vector<uint8_t>& bindingPrivate,
                                const mctp_eid_t destEid,
                                const mctp_ctrl_cmd_set_eid_op operation,
                                mctp_eid_t eid, std::vector<uint8_t>& resp)
{
    std::vector<uint8_t> req = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_SET_ENDPOINT_ID>(req, operation, eid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Set EID: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Set EID: Unable to get response");
        return false;
    }

    if (!checkRespSizeAndCompletionCode<mctp_ctrl_resp_set_eid>(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Set EID failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>("Set EID success");
    return true;
}

bool MctpBinding::getUuidCtrlCmd(boost::asio::yield_context& yield,
                                 const std::vector<uint8_t>& bindingPrivate,
                                 const mctp_eid_t destEid,
                                 std::vector<uint8_t>& resp)
{
    std::vector<uint8_t> req = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_GET_ENDPOINT_UUID>(req))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get UUID: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get UUID: Unable to get response");
        return false;
    }

    if (!checkRespSizeAndCompletionCode<mctp_ctrl_resp_get_uuid>(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get UUID failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>("Get UUID success");
    return true;
}

bool MctpBinding::getMsgTypeSupportCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
    MsgTypeSupportCtrlResp* msgTypeSupportResp)
{
    std::vector<uint8_t> req = {};
    std::vector<uint8_t> resp = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT>(req))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support: Unable to get response");
        return false;
    }

    if (!checkMinRespSize(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support: Invalid response");
        return false;
    }

    const size_t minMsgTypeRespLen = 5;
    uint8_t completionCode = resp[completionCodeIndex];
    if (completionCode != MCTP_CTRL_CC_SUCCESS ||
        resp.size() <= minMsgTypeRespLen)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support: Invalid response",
            phosphor::logging::entry("CC=0x%02X", completionCode),
            phosphor::logging::entry("LEN=0x%02X", resp.size()));

        std::vector<uint8_t> respHeader =
            std::vector<uint8_t>(resp.begin(), resp.begin() + minCmdRespSize);
        std::copy(
            respHeader.begin(), respHeader.end(),
            reinterpret_cast<uint8_t*>(&msgTypeSupportResp->ctrlMsgHeader));
        msgTypeSupportResp->completionCode = completionCode;
        return false;
    }

    std::copy_n(resp.begin(), minMsgTypeRespLen,
                reinterpret_cast<uint8_t*>(msgTypeSupportResp));
    if ((resp.size() - minMsgTypeRespLen) != msgTypeSupportResp->msgTypeCount)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support: Invalid response length");
        return false;
    }

    msgTypeSupportResp->msgType.assign(resp.begin() + minMsgTypeRespLen,
                                       resp.end());

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Get Message Type Support success");
    return true;
}

bool MctpBinding::getMctpVersionSupportCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
    const uint8_t msgTypeNo,
    MctpVersionSupportCtrlResp* mctpVersionSupportCtrlResp)
{
    std::vector<uint8_t> req = {};
    std::vector<uint8_t> resp = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_GET_VERSION_SUPPORT>(req, msgTypeNo))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get MCTP Version Support: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get MCTP Version Support: Unable to get response");
        return false;
    }

    if (!checkMinRespSize(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get MCTP Version Support: Invalid response");
        return false;
    }

    const ssize_t minMsgTypeRespLen = 5;
    const ssize_t mctpVersionLen = 4;
    uint8_t completionCode = resp[completionCodeIndex];
    if (completionCode != MCTP_CTRL_CC_SUCCESS ||
        resp.size() <= minMsgTypeRespLen)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get MCTP Version Support: Invalid response",
            phosphor::logging::entry("CC=0x%02X", completionCode),
            phosphor::logging::entry("LEN=0x%02X", resp.size()));

        std::vector<uint8_t> respHeader =
            std::vector<uint8_t>(resp.begin(), resp.begin() + minCmdRespSize);
        std::copy(respHeader.begin(), respHeader.end(),
                  reinterpret_cast<uint8_t*>(
                      &mctpVersionSupportCtrlResp->ctrlMsgHeader));
        mctpVersionSupportCtrlResp->completionCode = completionCode;
        return false;
    }

    std::copy_n(resp.begin(), minMsgTypeRespLen,
                reinterpret_cast<uint8_t*>(mctpVersionSupportCtrlResp));
    if ((resp.size() - minMsgTypeRespLen) !=
        mctpVersionSupportCtrlResp->verNoEntryCount * mctpVersionLen)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get MCTP Version Support: Invalid response length");
        return false;
    }

    for (int iter = 1; iter <= mctpVersionSupportCtrlResp->verNoEntryCount;
         iter++)
    {
        ssize_t verNoEntryStartOffset =
            minMsgTypeRespLen + (mctpVersionLen * (iter - 1));
        ssize_t verNoEntryEndOffset =
            minMsgTypeRespLen + (mctpVersionLen * iter);
        std::vector<uint8_t> version(resp.begin() + verNoEntryStartOffset,
                                     resp.begin() + verNoEntryEndOffset);

        mctpVersionSupportCtrlResp->verNoEntry.push_back(version);
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Get MCTP Version Support success");
    return true;
}

bool MctpBinding::getPCIVDMessageSupportCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
    std::vector<uint16_t>& vendorSetIdList, std::string& venFormatData)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "getPCIVendorIdMessageSupportCtrlCmd called...");
    std::vector<uint8_t> req = {};
    std::vector<uint8_t> resp = {};
    uint8_t vendorIdSet = 0;
    venFormatData.clear();
    // local structure to receive the vendor ID response
    MctpVendIdMsgSupportResp pciVendIdMsgSupportResp;
    // cannot be sure of the count, so processing from 0 ~ 255
    while (vendorIdSet < 255)
    {
        // format the data as per the request msg format
        if (!getFormattedReq<MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT>(
                req, vendorIdSet))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get MCTP Vendor Id Support: Request formatting failed");
            return false;
        }

        if (PacketState::receivedResponse !=
            sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get MCTP Vendor Id Support: sending & receiving failed");
            return false;
        }

        // total resp size(including ctrl header) '10'
        // ctrlheader  Compl.Code  VendIdSet  VendIdFmt  VendorFrmtData
        // vendIdSetType
        //     3           1          1          1             2             2
        //     (bytes)
        const ssize_t pciVDMessageSupportCmdRespSize =
            sizeof(MctpVendIdMsgSupportResp);

        if (!checkMinRespSize(resp))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get MCTP Vendor Id Support: Invalid Response Length");
            return false;
        }

        // assuming 1st byte after ctrl header is completion code index
        uint8_t completionCode = resp[completionCodeIndex];
        if ((completionCode != MCTP_CTRL_CC_SUCCESS) ||
            (resp.size() < pciVDMessageSupportCmdRespSize))
        {

            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get MCTP Vendor Id Support: Invalid response",
                phosphor::logging::entry("CC=0x%02X", completionCode),
                phosphor::logging::entry("LEN=0x%02X", resp.size()));
            return false;
        }

        pciVendIdMsgSupportResp = {};

        // copy the response onto local structure
        std::copy_n(resp.begin(), pciVDMessageSupportCmdRespSize,
                    reinterpret_cast<uint8_t*>(&pciVendIdMsgSupportResp));

        uint16_t venid = htobe16(pciVendIdMsgSupportResp.vendorIdFormatData);
        std::stringstream op_str;
        op_str << std::hex << venid;
        venFormatData = op_str.str();

        vendorSetIdList.push_back(
            htobe16(pciVendIdMsgSupportResp.vendorIdSetCmdType));

        if (pciVendIdMsgSupportResp.vendorIdSet == noMoreSet)
        {
            // break the loop once 0xFF is found in set.
            vendorIdSet = 0;
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Vendor Id Set-Selector loop Break");
            break;
        }
        vendorIdSet++;
        if (vendorIdSet == 255 &&
            pciVendIdMsgSupportResp.vendorIdSet != noMoreSet)
        { // invalid scenario iteration
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid vendor ID set iteration");
            return false;
        }
    }
    return true;
}

bool MctpBinding::discoveryNotifyCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid)
{
    std::vector<uint8_t> req = {};
    std::vector<uint8_t> resp = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_DISCOVERY_NOTIFY>(req))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Discovery Notify: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Discovery Notify: Unable to get response");
        return false;
    }

    if (!checkRespSizeAndCompletionCode<mctp_ctrl_resp_discovery_notify>(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Discovery Notify failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Discovery Notify success");
    return true;
}

bool MctpBinding::getRoutingTableCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid,
    uint8_t entryHandle, std::vector<uint8_t>& resp)
{
    std::vector<uint8_t> req = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES>(req,
                                                                  entryHandle))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Routing Table Entry: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Routing Table Entry: Unable to get response");
        return false;
    }

    if (!checkMinRespSize(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid response length");
        return false;
    }

    uint8_t* respPtr = resp.data();
    if (*(respPtr + sizeof(mctp_ctrl_msg_hdr)) != MCTP_CTRL_CC_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Routing Table Entry failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Get Routing Table Entry success");
    return true;
}

void MctpBinding::registerMsgTypes(std::shared_ptr<dbus_interface>& msgTypeIntf,
                                   const MsgTypes& messageType)
{
    msgTypeIntf->register_property("MctpControl", messageType.mctpControl);
    msgTypeIntf->register_property("PLDM", messageType.pldm);
    msgTypeIntf->register_property("NCSI", messageType.ncsi);
    msgTypeIntf->register_property("Ethernet", messageType.ethernet);
    msgTypeIntf->register_property("NVMeMgmtMsg", messageType.nvmeMgmtMsg);
    msgTypeIntf->register_property("SPDM", messageType.spdm);
    msgTypeIntf->register_property("VDPCI", messageType.vdpci);
    msgTypeIntf->register_property("VDIANA", messageType.vdiana);
    msgTypeIntf->initialize();
}

void MctpBinding::populateEndpointProperties(
    const EndpointProperties& epProperties)
{

    std::string mctpDevObj = "/xyz/openbmc_project/mctp/device/";
    std::shared_ptr<dbus_interface> endpointIntf;
    std::string mctpEpObj =
        mctpDevObj + std::to_string(epProperties.endpointEid);

    // Endpoint interface
    endpointIntf =
        objectServer->add_interface(mctpEpObj, mctp_endpoint::interface);
    endpointIntf->register_property(
        "Mode",
        mctp_server::convertBindingModeTypesToString(epProperties.mode));
    endpointIntf->register_property("NetworkId", epProperties.networkId);
    endpointIntf->initialize();
    endpointInterface.push_back(endpointIntf);

    // Message type interface
    std::shared_ptr<dbus_interface> msgTypeIntf;
    msgTypeIntf =
        objectServer->add_interface(mctpEpObj, mctp_msg_types::interface);
    registerMsgTypes(msgTypeIntf, epProperties.endpointMsgTypes);
    msgTypeInterface.push_back(msgTypeIntf);

    // UUID interface
    std::shared_ptr<dbus_interface> uuidIntf;
    uuidIntf = objectServer->add_interface(mctpEpObj,
                                           "xyz.openbmc_project.Common.UUID");
    uuidIntf->register_property("UUID", epProperties.uuid);
    uuidIntf->initialize();
    uuidInterface.push_back(uuidIntf);
    if (epProperties.endpointMsgTypes.vdpci)
    {
        std::shared_ptr<dbus_interface> vendorIdIntf;
        vendorIdIntf = objectServer->add_interface(
            mctpEpObj, "xyz.openbmc_project.MCTP.PCIVendorDefined");
        vendorIdIntf->register_property("MessageTypeProperty",
                                        epProperties.vendorIdCapabilitySets);
        vendorIdIntf->register_property("VendorID",
                                        epProperties.vendorIdFormat);
        vendorIdIntf->initialize();
        vendorIdInterface.push_back(vendorIdIntf);
    }
}

mctp_server::BindingModeTypes MctpBinding::getEndpointType(const uint8_t types)
{
    constexpr uint8_t endpointTypeMask = 0x30;
    constexpr int endpointTypeShift = 0x04;
    constexpr uint8_t simpleEndpoint = 0x00;
    constexpr uint8_t busOwnerBridge = 0x01;

    uint8_t endpointType = (types & endpointTypeMask) >> endpointTypeShift;

    if (endpointType == simpleEndpoint)
    {
        return mctp_server::BindingModeTypes::Endpoint;
    }
    else if (endpointType == busOwnerBridge)
    {
        // TODO: need to differentiate between BusOwner and Bridge
        return mctp_server::BindingModeTypes::Bridge;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid endpoint type value");
        throw;
    }
}

MsgTypes MctpBinding::getMsgTypes(const std::vector<uint8_t>& msgType)
{
    MsgTypes messageTypes;

    for (auto type : msgType)
    {
        switch (type)
        {
            case MCTP_MESSAGE_TYPE_MCTP_CTRL: {
                messageTypes.mctpControl = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_PLDM: {
                messageTypes.pldm = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_NCSI: {
                messageTypes.ncsi = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_ETHERNET: {
                messageTypes.ethernet = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_NVME: {
                messageTypes.nvmeMgmtMsg = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_SPDM: {
                messageTypes.spdm = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_VDPCI: {
                messageTypes.vdpci = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_VDIANA: {
                messageTypes.vdiana = true;
                break;
            }
            default: {
                // TODO: Add OEM Message Type support
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Invalid message type");
                break;
            }
        }
    }
    return messageTypes;
}

bool MctpBinding::setMediumId(
    uint8_t value, mctp_server::MctpPhysicalMediumIdentifiers& mediumId)
{
    auto id = valueToMediumId.find(value);
    if (id != valueToMediumId.end())
    {
        mediumId = id->second;
        return true;
    }
    return false;
}

static std::string formatUUID(guid_t& uuid)
{
    const size_t safeBufferLength = 50;
    char buf[safeBufferLength] = {0};
    auto ptr = reinterpret_cast<uint8_t*>(&uuid);

    snprintf(
        buf, safeBufferLength,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7], ptr[8],
        ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15]);
    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    return std::string(buf);
}

std::optional<mctp_eid_t> MctpBinding::busOwnerRegisterEndpoint(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate)
{
    // Send getMctpVersionSupport for MCTP Control commands to a NULL EID

    MctpVersionSupportCtrlResp getMctpControlVersion;
    if (!(getMctpVersionSupportCtrlCmd(yield, bindingPrivate, MCTP_EID_NULL,
                                       MCTP_MESSAGE_TYPE_MCTP_CTRL,
                                       &getMctpControlVersion)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get MCTP Control Version failed");
        return std::nullopt;
    }

    // TODO: Validate MCTP Control message version supported

    // Get EID
    std::vector<uint8_t> getEidResp = {};
    if (!(getEidCtrlCmd(yield, bindingPrivate, MCTP_EID_NULL, getEidResp)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Get EID failed");
        return std::nullopt;
    }

    mctp_ctrl_resp_get_eid* getEidRespPtr =
        reinterpret_cast<mctp_ctrl_resp_get_eid*>(getEidResp.data());
    mctp_eid_t destEid = getEidRespPtr->eid;

    if (getEidRespPtr->eid != MCTP_EID_NULL)
    {
        updateEidStatus(destEid, true);
    }

    // Get UUID (Not mandatory to support)
    std::vector<uint8_t> getUuidResp = {};
    if (!(getUuidCtrlCmd(yield, bindingPrivate, destEid, getUuidResp)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get UUID failed");
    }

    // TODO: Check the obtained UUID from the route table and verify whether
    // it had an entry in the route table
    // TODO: Routing table construction
    // TODO: Assigne pool of EID if the endpoint is a bridge
    // TODO: Wait for T-reclame to free an EID
    // TODO: Take care of EIDs(Static EID) which are not owned by us
    // TODO: Set EID should use previously known EID if there was a UUID match

    // Set EID
    if (getEidRespPtr->eid == MCTP_EID_NULL)
    {
        mctp_eid_t eid;
        try
        {
            eid = getAvailableEidFromPool();
        }
        catch (const std::exception&)
        {
            return std::nullopt;
        }
        std::vector<uint8_t> setEidResp = {};
        if (!(setEidCtrlCmd(yield, bindingPrivate, 0x00, set_eid, eid,
                            setEidResp)))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Set EID failed");
            updateEidStatus(eid, false);
            return std::nullopt;
        }

        mctp_ctrl_resp_set_eid* setEidRespPtr =
            reinterpret_cast<mctp_ctrl_resp_set_eid*>(setEidResp.data());
        destEid = setEidRespPtr->eid_set;

        // If EID in the resp is different from the one sent in request,
        // we need to check if that EID exists in the pool and update its
        // status as assigned.
        updateEidStatus(destEid, true);
    }

    // Get Message Type Support
    MsgTypeSupportCtrlResp msgTypeSupportResp;
    if (!(getMsgTypeSupportCtrlCmd(yield, bindingPrivate, destEid,
                                   &msgTypeSupportResp)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support failed");
        return std::nullopt;
    }

    // Expose interface as per the result
    EndpointProperties epProperties;
    epProperties.endpointEid = destEid;
    mctp_ctrl_resp_get_uuid* getUuidRespPtr =
        reinterpret_cast<mctp_ctrl_resp_get_uuid*>(getUuidResp.data());
    epProperties.uuid = formatUUID(getUuidRespPtr->uuid);
    try
    {
        epProperties.mode = getEndpointType(getEidRespPtr->eid_type);
    }
    catch (const std::exception&)
    {
        return std::nullopt;
    }
    // Network ID need to be assigned only if EP is requesting for the same.
    // Keep Network ID as zero and update it later if a change happend.
    epProperties.networkId = 0x00;
    epProperties.endpointMsgTypes = getMsgTypes(msgTypeSupportResp.msgType);

    // vendor ID message support...
    // if its true get VDPCIMT capabilities
    std::vector<uint16_t> vendorSetIdList = {};
    std::string vendorFormat;
    if (epProperties.endpointMsgTypes.vdpci)
    {
        if (!getPCIVDMessageSupportCtrlCmd(yield, bindingPrivate, destEid,
                                           vendorSetIdList, vendorFormat))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get Vendor Id Support failed");
            /*
              If this command fails, still go ahead with endpoint
              registration since this is an optional command
            */
        }
        epProperties.vendorIdCapabilitySets.assign(vendorSetIdList.begin(),
                                                   vendorSetIdList.end());

        epProperties.vendorIdFormat = "0x";
        epProperties.vendorIdFormat.append(vendorFormat);
    }

    populateEndpointProperties(epProperties);

    return destEid;
}

/* This api provides option to register an endpoint using the binding
 * private data. The callers of this api can parallelize multiple
 * endpoint registrations by spawning coroutines and passing yield contexts.*/

std::optional<mctp_eid_t>
    MctpBinding::registerEndpoint(boost::asio::yield_context& yield,
                                  const std::vector<uint8_t>& bindingPrivate,
                                  mctp_eid_t eid,
                                  mctp_server::BindingModeTypes bindingMode)
{
    if (bindingModeType == mctp_server::BindingModeTypes::BusOwner)
    {
        return busOwnerRegisterEndpoint(yield, bindingPrivate);
    }

    MsgTypeSupportCtrlResp msgTypeSupportResp;
    if (!(getMsgTypeSupportCtrlCmd(yield, bindingPrivate, eid,
                                   &msgTypeSupportResp)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support failed");
        return std::nullopt;
    }

    EndpointProperties epProperties;
    std::vector<uint8_t> getUuidResp;

    if (!(getUuidCtrlCmd(yield, bindingPrivate, eid, getUuidResp)))
    {
        /* In case EP doesn't support Get UUID set to all 0 */
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get UUID failed");
        epProperties.uuid = "00000000-0000-0000-0000-000000000000";
    }
    else
    {
        mctp_ctrl_resp_get_uuid* getUuidRespPtr =
            reinterpret_cast<mctp_ctrl_resp_get_uuid*>(getUuidResp.data());
        epProperties.uuid = formatUUID(getUuidRespPtr->uuid);
    }

    epProperties.endpointEid = eid;
    epProperties.mode = bindingMode;
    // TODO:get Network ID, now set it to 0
    epProperties.networkId = 0x00;
    epProperties.endpointMsgTypes = getMsgTypes(msgTypeSupportResp.msgType);
    populateEndpointProperties(epProperties);
    return eid;
}

void MctpBinding::removeInterface(
    std::string& interfacePath,
    std::vector<std::shared_ptr<dbus_interface>>& interfaces)
{
    for (auto dbusInterface = interfaces.begin();
         dbusInterface != interfaces.end(); dbusInterface++)
    {
        if ((*dbusInterface)->get_object_path() == interfacePath)
        {
            std::shared_ptr<dbus_interface> tmpIf = *dbusInterface;
            interfaces.erase(dbusInterface);
            objectServer->remove_interface(tmpIf);
            break;
        }
    }
}

void MctpBinding::unregisterEndpoint(mctp_eid_t eid)
{
    std::string mctpDevObj = "/xyz/openbmc_project/mctp/device/";
    std::string mctpEpObj = mctpDevObj + std::to_string(eid);

    removeInterface(mctpEpObj, endpointInterface);
    removeInterface(mctpEpObj, msgTypeInterface);
    removeInterface(mctpEpObj, uuidInterface);
    // Vendor ID set Support
    removeInterface(mctpEpObj, vendorIdInterface);
}
