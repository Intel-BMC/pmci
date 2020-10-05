#include "PCIeBinding.hpp"

#include <phosphor-logging/log.hpp>

PCIeBinding::PCIeBinding(std::shared_ptr<object_server>& objServer,
                         std::string& objPath, ConfigurationVariant& conf,
                         boost::asio::io_context& ioc) :
    MctpBinding(objServer, objPath, conf, ioc),
    streamMonitor(ioc)
{
    std::shared_ptr<dbus_interface> pcieInterface =
        objServer->add_interface(objPath, pcie_binding::interface);

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
    /*
     * The workaround is temporarily needed for the current libmctp-intel
     * to determine whether the message is a request or a response.
     * Any other flag except for TO is set in libmctp.
     */
#ifdef MCTP_ASTPCIE_RESPONSE_WA
    pktPrv.flags_seq_tag = 0;
    pktPrv.flags_seq_tag |= MCTP_HDR_FLAG_TO;
#endif
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData =
        std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof pktPrv);

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
void PCIeBinding::initializeBinding([[maybe_unused]] ConfigurationVariant& conf)
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
    mctp_set_rx_all(mctp, rxMessage, this);
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
