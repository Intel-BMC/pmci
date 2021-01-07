#include "PCIeBinding.hpp"

#include <phosphor-logging/log.hpp>

PCIeBinding::PCIeBinding(std::shared_ptr<object_server>& objServer,
                         const std::string& objPath,
                         const PcieConfiguration& conf,
                         boost::asio::io_context& ioc) :
    MctpBinding(objServer, objPath, conf, ioc,
                mctp_server::BindingTypes::MctpOverPcieVdm),
    streamMonitor(ioc), ueventMonitor(ioc),
    getRoutingInterval(conf.getRoutingInterval),
    getRoutingTableTimer(ioc, getRoutingInterval)
{
    pcieInterface = objServer->add_interface(objPath, pcie_binding::interface);

    try
    {
        bdf = conf.bdf;

        if (bindingModeType == mctp_server::BindingModeTypes::BusOwner)
            discoveredFlag = pcie_binding::DiscoveryFlags::NotApplicable;
        else
            discoveredFlag = pcie_binding::DiscoveryFlags::Undiscovered;

        registerProperty(pcieInterface, "BDF", bdf);

        registerProperty(
            pcieInterface, "DiscoveredFlag",
            pcie_binding::convertDiscoveryFlagsToString(discoveredFlag));
        if (pcieInterface->initialize() == false)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }

        if (bindingModeType != mctp_server::BindingModeTypes::BusOwner)
        {
            getRoutingTableTimer.async_wait(
                std::bind(&PCIeBinding::updateRoutingTable, this));
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "MCTP PCIe Interface initialization failed.",
            phosphor::logging::entry("Exception:", e.what()));
        throw;
    }
}

bool PCIeBinding::endpointDiscoveryFlow()
{
    struct mctp_astpcie_pkt_private pktPrv;
    pktPrv.routing = PCIE_ROUTE_TO_RC;
    pktPrv.remote_id = bdf;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData =
        std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof pktPrv);
    changeDiscoveredFlag(pcie_binding::DiscoveryFlags::Undiscovered);

    boost::asio::spawn(io, [prvData, this](boost::asio::yield_context yield) {
        if (!discoveryNotifyCtrlCmd(yield, prvData, MCTP_EID_NULL))
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Discovery Notify failed");
            return false;
        }
        return true;
    });
    return false;
}

mctp_server::BindingModeTypes
    PCIeBinding::getBindingMode(const routingTableEntry_t& routingEntry)
{
    if (std::get<1>(routingEntry) == busOwnerBdf)
    {
        return mctp_server::BindingModeTypes::BusOwner;
    }
    switch (std::get<2>(routingEntry))
    {
        case MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS:
        case MCTP_ROUTING_ENTRY_BRIDGE:
            return mctp_server::BindingModeTypes::Bridge;
        case MCTP_ROUTING_ENTRY_ENDPOINT:
        case MCTP_ROUTING_ENTRY_ENDPOINTS:
        default:
            return mctp_server::BindingModeTypes::Endpoint;
    }
}

void PCIeBinding::updateRoutingTable()
{
    struct mctp_astpcie_pkt_private pktPrv;
    getRoutingTableTimer.expires_from_now(getRoutingInterval);
    getRoutingTableTimer.async_wait(
        std::bind(&PCIeBinding::updateRoutingTable, this));

    if (discoveredFlag != pcie_binding::DiscoveryFlags::Discovered)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Routing Table failed, undiscovered");
        return;
    }
    pktPrv.routing = PCIE_ROUTE_BY_ID;
    pktPrv.remote_id = busOwnerBdf;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData = std::vector<uint8_t>(
        pktPrvPtr, pktPrvPtr + sizeof(mctp_astpcie_pkt_private));

    boost::asio::spawn(io, [prvData, this](boost::asio::yield_context yield) {
        std::vector<uint8_t> getRoutingTableEntryResp = {};
        std::vector<routingTableEntry_t> routingTableTmp;
        uint8_t entryHandle = 0x00;

        while (entryHandle != 0xff)
        {
            if (!getRoutingTableCtrlCmd(yield, prvData, MCTP_EID_NULL,
                                        entryHandle, getRoutingTableEntryResp))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Get Routing Table failed");
                return;
            }
            auto routingTableHdr =
                reinterpret_cast<mctp_ctrl_resp_get_routing_table*>(
                    getRoutingTableEntryResp.data());
            size_t entryOffset = sizeof(mctp_ctrl_resp_get_routing_table);

            for (uint8_t i = 0; i < routingTableHdr->number_of_entries; i++)
            {
                auto routingTableEntry =
                    reinterpret_cast<get_routing_table_entry*>(
                        getRoutingTableEntryResp.data() + entryOffset);

                entryOffset += sizeof(get_routing_table_entry);
                if (routingTableEntry->phys_transport_binding_id !=
                    MCTP_BINDING_PCIE)
                {
                    entryOffset += routingTableEntry->phys_address_size;
                    continue;
                }
                uint16_t endpointBdf = be16toh(static_cast<uint16_t>(
                    static_cast<uint16_t>(
                        getRoutingTableEntryResp[entryOffset]) |
                    (static_cast<uint16_t>(
                         getRoutingTableEntryResp[entryOffset + 1])
                     << 8)));

                for (uint8_t j = 0; j < routingTableEntry->eid_range_size; j++)
                {
                    routingTableTmp.push_back(std::make_tuple(
                        routingTableEntry->starting_eid + j, endpointBdf,
                        routingTableEntry->entry_type));
                }
                entryOffset += routingTableEntry->phys_address_size;
            }
            entryHandle = routingTableHdr->next_entry_handle;
        }

        if (routingTableTmp != routingTable)
        {
            processRoutingTableChanges(routingTableTmp, yield, prvData);
            routingTable = routingTableTmp;

            if (!setDriverEndpointMap())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to store routing table in KMD");
            }
        }
    });
}

/* Function takes new routing table, detect changes and creates or removes
 * device interfaces on dbus.
 */
void PCIeBinding::processRoutingTableChanges(
    const std::vector<routingTableEntry_t>& newTable,
    boost::asio::yield_context& yield, const std::vector<uint8_t>& prvData)
{
    /* find removed endpoints, in case entry is not present
     * in the newly read routing table remove dbus interface
     * for this device
     */
    for (auto& routingEntry : routingTable)
    {
        if (find(newTable.begin(), newTable.end(), routingEntry) ==
            newTable.end())
        {
            unregisterEndpoint(std::get<0>(routingEntry));
        }
    }

    /* find new endpoints, in case entry is in the newly read
     * routing table but not present in the routing table stored as
     * the class member, register new dbus device interface
     */
    for (auto& routingEntry : newTable)
    {
        if (find(routingTable.begin(), routingTable.end(), routingEntry) ==
            routingTable.end())
        {
            registerEndpoint(yield, prvData, std::get<0>(routingEntry),
                             getBindingMode(routingEntry));
        }
    }
}

bool PCIeBinding::setDriverEndpointMap()
{
    std::vector<std::tuple<uint8_t, uint16_t>> endpoints;

    for (const auto& [eid, busDevFunc, type] : routingTable)
    {
        endpoints.push_back({eid, busDevFunc});
    }

    return !mctp_astpcie_set_eid_info_ioctl(
        pcie, endpoints.data(), static_cast<uint16_t>(endpoints.size()));
}

bool PCIeBinding::isReceivedPrivateDataCorrect(const void* bindingPrivate)
{
    auto pciePrivate =
        reinterpret_cast<const mctp_astpcie_pkt_private*>(bindingPrivate);
    if (pciePrivate == nullptr || pciePrivate->remote_id == 0x00)
    {
        return false;
    }
    return true;
}

bool PCIeBinding::handlePrepareForEndpointDiscovery(
    mctp_eid_t, void* bindingPrivate, std::vector<uint8_t>&,
    std::vector<uint8_t>& response)
{
    if (bindingModeType != mctp_server::BindingModeTypes::Endpoint)
    {
        return false;
    }
    auto pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (pciePrivate->routing != PCIE_BROADCAST_FROM_RC)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Prepare for Endpoint Discovery command can only be accepted as "
            "broadcast.");
        return false;
    }
    response.resize(sizeof(mctp_ctrl_resp_prepare_discovery));
    auto resp =
        reinterpret_cast<mctp_ctrl_resp_prepare_discovery*>(response.data());

    changeDiscoveredFlag(pcie_binding::DiscoveryFlags::Undiscovered);
    resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    pciePrivate->routing = PCIE_ROUTE_TO_RC;
    return true;
}

bool PCIeBinding::handleEndpointDiscovery(mctp_eid_t, void* bindingPrivate,
                                          std::vector<uint8_t>&,
                                          std::vector<uint8_t>& response)
{
    if (discoveredFlag == pcie_binding::DiscoveryFlags::Discovered)
    {
        return false;
    }
    mctp_astpcie_pkt_private* pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (pciePrivate->routing != PCIE_BROADCAST_FROM_RC)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Endpoint Discovery command can only be accepted as broadcast.");
        return false;
    }
    busOwnerBdf = pciePrivate->remote_id;
    response.resize(sizeof(mctp_ctrl_resp_endpoint_discovery));
    auto resp =
        reinterpret_cast<mctp_ctrl_resp_endpoint_discovery*>(response.data());

    resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    pciePrivate->routing = PCIE_ROUTE_TO_RC;
    return true;
}

bool PCIeBinding::handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{
    auto pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (!MctpBinding::handleGetEndpointId(destEid, bindingPrivate, request,
                                          response))
    {
        return false;
    }

    pciePrivate->routing = PCIE_ROUTE_BY_ID;
    return true;
}

bool PCIeBinding::handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{
    auto pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (pciePrivate->remote_id != busOwnerBdf)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Set EID requested from non-bus owner.");
        return false;
    }
    if (!MctpBinding::handleSetEndpointId(destEid, bindingPrivate, request,
                                          response))
    {
        return false;
    }
    response.resize(sizeof(mctp_ctrl_resp_set_eid));
    auto resp = reinterpret_cast<mctp_ctrl_resp_set_eid*>(response.data());

    if (resp->completion_code == MCTP_CTRL_CC_SUCCESS)
    {
        changeDiscoveredFlag(pcie_binding::DiscoveryFlags::Discovered);
        mctpInterface->set_property("Eid", ownEid);
    }
    pciePrivate->routing = PCIE_ROUTE_BY_ID;
    return true;
}

bool PCIeBinding::handleGetVersionSupport(mctp_eid_t destEid,
                                          void* bindingPrivate,
                                          std::vector<uint8_t>& request,
                                          std::vector<uint8_t>& response)
{
    auto pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (!MctpBinding::handleGetVersionSupport(destEid, bindingPrivate, request,
                                              response))
    {
        return false;
    }

    pciePrivate->routing = PCIE_ROUTE_BY_ID;
    return true;
}

bool PCIeBinding::handleGetMsgTypeSupport(mctp_eid_t destEid,
                                          void* bindingPrivate,
                                          std::vector<uint8_t>& request,
                                          std::vector<uint8_t>& response)
{
    auto pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (!MctpBinding::handleGetMsgTypeSupport(destEid, bindingPrivate, request,
                                              response))
    {
        return false;
    }

    pciePrivate->routing = PCIE_ROUTE_BY_ID;
    return true;
}

bool PCIeBinding::handleGetVdmSupport(mctp_eid_t destEid, void* bindingPrivate,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_pci_ctrl_resp_get_vdm_support));

    struct mctp_ctrl_cmd_get_vdm_support* req =
        reinterpret_cast<struct mctp_ctrl_cmd_get_vdm_support*>(request.data());

    /* Generic library API. Specialized later on. */
    struct mctp_ctrl_resp_get_vdm_support* libResp =
        reinterpret_cast<struct mctp_ctrl_resp_get_vdm_support*>(
            response.data());

    if (mctp_ctrl_cmd_get_vdm_support(mctp, destEid, libResp) < 0)
    {
        return false;
    }

    mctp_astpcie_pkt_private* pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    pciePrivate->routing = PCIE_ROUTE_TO_RC;

    /* Cast to full binding specific response. */
    mctp_pci_ctrl_resp_get_vdm_support* resp =
        reinterpret_cast<mctp_pci_ctrl_resp_get_vdm_support*>(response.data());
    uint8_t setIndex = req->vendor_id_set_selector;

    if (setIndex + 1U > vdmSetDatabase.size())
    {
        resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
        response.resize(sizeof(mctp_ctrl_msg_hdr) +
                        sizeof(resp->completion_code));
        return true;
    }

    if (setIndex + 1U == vdmSetDatabase.size())
    {
        resp->vendor_id_set_selector = vendorIdNoMoreSets;
    }
    else
    {
        resp->vendor_id_set_selector = static_cast<uint8_t>(setIndex + 1U);
    }
    resp->vendor_id_format = vdmSetDatabase[setIndex].idFormat;
    resp->vendor_id_data = vdmSetDatabase[setIndex].idData;
    resp->command_set_type = vdmSetDatabase[setIndex].commandSetType;

    return true;
}

void PCIeBinding::readResponse()
{
    streamMonitor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code& ec) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error reading PCIe response");
                readResponse();
            }
            mctp_astpcie_rx(pcie);
            readResponse();
        });
}

void PCIeBinding::initializeBinding()
{
    int status = 0;
    initializeMctp();
    pcie = mctp_astpcie_init();
    if (pcie == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in MCTP PCIe init");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
    struct mctp_binding* binding = mctp_astpcie_core(pcie);
    if (binding == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in MCTP binding init");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
    status = mctp_register_bus_dynamic_eid(mctp, binding);
    if (status < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Bus registration of binding failed");
        throw std::system_error(
            std::make_error_code(static_cast<std::errc>(-status)));
    }
    if (mctp_astpcie_register_default_handler(pcie) != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Registration as default control service failed");
        throw std::system_error(
            std::make_error_code(std::errc::operation_not_permitted));
    }

    mctp_set_rx_all(mctp, &MctpBinding::rxMessage,
                    static_cast<MctpBinding*>(this));
    mctp_set_rx_ctrl(mctp, &MctpBinding::handleMCTPControlRequests,
                     static_cast<MctpBinding*>(this));
    mctp_binding_set_tx_enabled(binding, true);

    int driverFd = mctp_astpcie_get_fd(pcie);
    if (driverFd < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error opening driver file");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
    streamMonitor.assign(driverFd);

    if (initializeUdev() == false)
    {
        throw std::system_error(
            std::make_error_code(std::errc::function_not_supported));
    }

    readResponse();
    if (bindingModeType == mctp_server::BindingModeTypes::Endpoint)
    {
        boost::asio::post(io, [this]() {
            if (!endpointDiscoveryFlow())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Send Discovery Notify Error");
            }
        });
    }

    if (mctp_astpcie_get_bdf(pcie, &bdf) == 0)
    {
        pcieInterface->set_property("BDF", bdf);
    }

    if (setMediumId(mctp_astpcie_get_medium_id(pcie), bindingMediumID))
    {
        mctpInterface->set_property(
            "BindingMediumID",
            mctp_server::convertMctpPhysicalMediumIdentifiersToString(
                bindingMediumID));
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Incorrect medium id, BindingMediumID property not updated");
    }

    monitorUdevEvents();
}

bool PCIeBinding::initializeUdev()
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

void PCIeBinding::monitorUdevEvents()
{
    ueventMonitor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code& ec) {
            if (ec)
            {
                if (ec == boost::asio::error::operation_aborted)
                {
                    return;
                }

                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error reading uevents",
                    phosphor::logging::entry("error:", ec.message().c_str()));
                monitorUdevEvents();
                return;
            }

            udev_device* dev = udev_monitor_receive_device(umonitor);
            if (dev)
            {
                ueventHandlePcieReady(dev);
                udev_device_unref(dev);
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Udev monitor get device failed");
            }

            monitorUdevEvents();
        });
}

void PCIeBinding::ueventHandlePcieReady(udev_device* dev)
{
    const char* value = udev_device_get_property_value(dev, "PCIE_READY");

    if (!value)
    {
        return;
    }

    if (strcmp(value, "1") == 0)
    {
        if (mctp_astpcie_get_bdf(pcie, &bdf) != 0)
        {
            bdf = 0;
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Astpcie get bdf failed");
        }
    }
    else
    {
        bdf = 0;
        if (bindingModeType != mctp_server::BindingModeTypes::BusOwner)
        {
            changeDiscoveredFlag(pcie_binding::DiscoveryFlags::Undiscovered);
        }
    }
    pcieInterface->set_property("BDF", bdf);
}

std::optional<std::vector<uint8_t>>
    PCIeBinding::getBindingPrivateData(uint8_t dstEid)
{
    mctp_astpcie_pkt_private pktPrv = {};

    pktPrv.routing = PCIE_ROUTE_BY_ID;
    auto it = find_if(routingTable.begin(), routingTable.end(),
                      [&dstEid](const auto& entry) {
                          const auto& [eid, endpointBdf, entryType] = entry;
                          return eid == dstEid;
                      });
    if (it == routingTable.end())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Eid not found in routing table");
        return std::nullopt;
    }
    const auto& [eid, endpointBdf, entryType] = *it;
    pktPrv.remote_id = endpointBdf;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    return std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof(pktPrv));
}

void PCIeBinding::changeDiscoveredFlag(pcie_binding::DiscoveryFlags flag)
{
    discoveredFlag = flag;
    pcieInterface->set_property(
        "DiscoveredFlag", pcie_binding::convertDiscoveryFlagsToString(flag));
}

PCIeBinding::~PCIeBinding()
{

    streamMonitor.release();

    if (umonitor)
    {
        ueventMonitor.release();
        udev_monitor_unref(umonitor);
        udev_device_unref(udevice);
        udev_unref(udevContext);
    }
    if (pcie)
    {
        mctp_astpcie_free(pcie);
    }
}
