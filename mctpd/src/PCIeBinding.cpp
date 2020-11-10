#include "PCIeBinding.hpp"

#include <phosphor-logging/log.hpp>

PCIeBinding::PCIeBinding(std::shared_ptr<object_server>& objServer,
                         std::string& objPath, ConfigurationVariant& conf,
                         boost::asio::io_context& ioc) :
    MctpBinding(objServer, objPath, conf, ioc),
    streamMonitor(ioc),
    getRoutingInterval(std::get<PcieConfiguration>(conf).getRoutingInterval),
    getRoutingTableTimer(ioc, getRoutingInterval)
{
    pcieInterface = objServer->add_interface(objPath, pcie_binding::interface);

    try
    {
        bdf = std::get<PcieConfiguration>(conf).bdf;

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
            struct mctp_ctrl_resp_get_routing_table* routingTableHdr =
                reinterpret_cast<struct mctp_ctrl_resp_get_routing_table*>(
                    getRoutingTableEntryResp.data());
            size_t entryOffset = sizeof(mctp_ctrl_resp_get_routing_table);

            for (uint8_t i = 0; i < routingTableHdr->number_of_entries; i++)
            {
                struct get_routing_table_entry* routingTableEntry =
                    reinterpret_cast<struct get_routing_table_entry*>(
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
            registerEndpoint(yield, prvData, false, std::get<0>(routingEntry),
                             getBindingMode(routingEntry));
        }
    }
}

bool PCIeBinding::isReceivedPrivateDataCorrect(const void* bindingPrivate)
{
    const mctp_astpcie_pkt_private* pciePrivate;

    pciePrivate =
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
    mctp_astpcie_pkt_private* pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (pciePrivate->routing != PCIE_BROADCAST_FROM_RC)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Prepare for Endpoint Discovery command can only be accepted as "
            "broadcast.");
        return false;
    }
    response.resize(sizeof(mctp_ctrl_resp_prepare_discovery));
    struct mctp_ctrl_resp_prepare_discovery* resp =
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
    struct mctp_ctrl_resp_endpoint_discovery* resp =
        reinterpret_cast<mctp_ctrl_resp_endpoint_discovery*>(response.data());

    resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    pciePrivate->routing = PCIE_ROUTE_TO_RC;
    return true;
}

bool PCIeBinding::handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{
    mctp_astpcie_pkt_private* pciePrivate =
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
    mctp_astpcie_pkt_private* pciePrivate =
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
    struct mctp_ctrl_resp_set_eid* resp =
        reinterpret_cast<mctp_ctrl_resp_set_eid*>(response.data());

    if (resp->completion_code == MCTP_CTRL_CC_SUCCESS)
    {
        changeDiscoveredFlag(pcie_binding::DiscoveryFlags::Discovered);
    }
    pciePrivate->routing = PCIE_ROUTE_BY_ID;
    return true;
}

bool PCIeBinding::handleGetVersionSupport(mctp_eid_t destEid,
                                          void* bindingPrivate,
                                          std::vector<uint8_t>& request,
                                          std::vector<uint8_t>& response)
{
    mctp_astpcie_pkt_private* pciePrivate =
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
    mctp_astpcie_pkt_private* pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (!MctpBinding::handleGetMsgTypeSupport(destEid, bindingPrivate, request,
                                              response))
    {
        return false;
    }

    pciePrivate->routing = PCIE_ROUTE_BY_ID;
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

/*
 * conf can't be removed since we override virtual function that has the
 * ConfigurationVariant& as argument
 */
void PCIeBinding::initializeBinding(ConfigurationVariant& /*conf*/)
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
}

bool PCIeBinding::getBindingPrivateData(uint8_t dstEid,
                                        std::vector<uint8_t>& pvtData)
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
        return false;
    }
    const auto& [eid, endpointBdf, entryType] = *it;
    pktPrv.remote_id = endpointBdf;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    pvtData = std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof(pktPrv));

    return true;
}

void PCIeBinding::changeDiscoveredFlag(pcie_binding::DiscoveryFlags flag)
{
    discoveredFlag = flag;
    pcieInterface->set_property(
        "DiscoveredFlag", pcie_binding::convertDiscoveryFlagsToString(flag));
}

PCIeBinding::~PCIeBinding()
{
    if (streamMonitor.native_handle() >= 0)
    {
        streamMonitor.release();
    }
    if (pcie)
    {
        mctp_astpcie_free(pcie);
    }
}
