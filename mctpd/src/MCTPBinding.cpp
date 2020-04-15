#include "MCTPBinding.hpp"

#include <systemd/sd-id128.h>

#include <phosphor-logging/log.hpp>

#include "libmctp.h"

constexpr sd_id128_t mctpdAppId = SD_ID128_MAKE(c4, e4, d9, 4a, 88, 43, 4d, f0,
                                                94, 9d, bb, 0a, af, 53, 4e, 6d);

MctpBinding::MctpBinding(
    std::shared_ptr<sdbusplus::asio::object_server>& objServer,
    std::string& objPath, ConfigurationVariant& conf)
{
    std::shared_ptr<sdbusplus::asio::dbus_interface> mctpInterface =
        objServer->add_interface(objPath, mctp_server::interface);

    try
    {
        if (SMBusConfiguration* smbusConf =
                std::get_if<SMBusConfiguration>(&conf))
        {
            eid = smbusConf->defaultEid;
            bindingID = smbusConf->bindingType;
            bindingMediumID = smbusConf->mediumId;
            bindingModeType = smbusConf->mode;
        }
        // TODO: else { pcieConf = std::get<PcieConfiguration>...

        createUuid();
        mctpInterface->register_property("Eid", eid);

        mctpInterface->register_property("StaticEid", staticEid);

        mctpInterface->register_property("Uuid", uuid);

        mctpInterface->register_property(
            "BindingID", mctp_server::convertBindingTypesToString(bindingID));

        mctpInterface->register_property(
            "BindingMediumID",
            mctp_server::convertMctpPhysicalMediumIdentifiersToString(
                bindingMediumID));

        mctpInterface->register_property(
            "BindingMode",
            mctp_server::convertBindingModeTypesToString(bindingModeType));

        mctpInterface->initialize();
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "MCTP Interface initialization failed.",
            phosphor::logging::entry("Exception:", e.what()));
        throw;
    }
}

void MctpBinding::createUuid(void)
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
