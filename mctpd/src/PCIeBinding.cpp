#include "PCIeBinding.hpp"

#include <phosphor-logging/log.hpp>

PCIeBinding::PCIeBinding(
    std::shared_ptr<sdbusplus::asio::object_server>& objServer,
    std::string& objPath, ConfigurationVariant& conf,
    boost::asio::io_context& ioc) :
    MctpBinding(objServer, objPath, conf, ioc)
{
    std::shared_ptr<sdbusplus::asio::dbus_interface> pcieInterface =
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
