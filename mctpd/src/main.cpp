#include "MCTPBinding.hpp"
#include "SMBusBinding.hpp"

#include <CLI/CLI.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>

using json = nlohmann::json;

std::string configPath = "/usr/share/mctp/mctp_config.json";

std::unordered_map<std::string, mctp_server::BindingTypes> mctpBindingsMap = {
    {"smbus", mctp_server::BindingTypes::MctpOverSmbus},
    {"pcie", mctp_server::BindingTypes::MctpOverPcieVdm}};

void parseConfig(mctp_server::BindingTypes bindingType,
                 ConfigurationVariant& conf)
{
    std::ifstream jsonFile(configPath);
    static std::unordered_map<std::string, mctp_server::BindingModeTypes>
        stringToBindingModeMap = {
            {"busowner", mctp_server::BindingModeTypes::BusOwner},
            {"endpoint", mctp_server::BindingModeTypes::Endpoint},
            {"bridge", mctp_server::BindingModeTypes::Bridge}};

    static std::unordered_map<std::string,
                              mctp_server::MctpPhysicalMediumIdentifiers>
        stringToMediumID = {
            {"Smbus", mctp_server::MctpPhysicalMediumIdentifiers::Smbus},
            {"SmbusI2c", mctp_server::MctpPhysicalMediumIdentifiers::SmbusI2c},
            {"I2cCompatible",
             mctp_server::MctpPhysicalMediumIdentifiers::I2cCompatible},
            {"Smbus3OrI2c400khzCompatible",
             mctp_server::MctpPhysicalMediumIdentifiers::
                 Smbus3OrI2c400khzCompatible},
            {"Smbus3OrI2c1MhzCompatible",
             mctp_server::MctpPhysicalMediumIdentifiers::
                 Smbus3OrI2c1MhzCompatible},
            {"I2c3Mhz4Compatible",
             mctp_server::MctpPhysicalMediumIdentifiers::I2c3Mhz4Compatible},
            {"Pcie11", mctp_server::MctpPhysicalMediumIdentifiers::Pcie11},
            {"Pcie2", mctp_server::MctpPhysicalMediumIdentifiers::Pcie2},
            {"Pcie21", mctp_server::MctpPhysicalMediumIdentifiers::Pcie21},
            {"Pcie3", mctp_server::MctpPhysicalMediumIdentifiers::Pcie3},
            {"Pcie4", mctp_server::MctpPhysicalMediumIdentifiers::Pcie4},
            {"Pcie5", mctp_server::MctpPhysicalMediumIdentifiers::Pcie5},
            {"PciCompatible",
             mctp_server::MctpPhysicalMediumIdentifiers::PciCompatible},
            {"Usb11Compatible",
             mctp_server::MctpPhysicalMediumIdentifiers::Usb11Compatible},
            {"Usb20Compatible",
             mctp_server::MctpPhysicalMediumIdentifiers::Usb20Compatible},
            {"Usb30Compatible",
             mctp_server::MctpPhysicalMediumIdentifiers::Usb30Compatible},
            {"NcSiOverRbt",
             mctp_server::MctpPhysicalMediumIdentifiers::NcSiOverRbt},
            {"KcsLegacy",
             mctp_server::MctpPhysicalMediumIdentifiers::KcsLegacy},
            {"KcsPci", mctp_server::MctpPhysicalMediumIdentifiers::KcsPci},
            {"SerialHostLegacy",
             mctp_server::MctpPhysicalMediumIdentifiers::SerialHostLegacy},
            {"SerialHostPci",
             mctp_server::MctpPhysicalMediumIdentifiers::SerialHostPci},
            {"AsynchronousSerial",
             mctp_server::MctpPhysicalMediumIdentifiers::AsynchronousSerial},
            {"I3cSDR", mctp_server::MctpPhysicalMediumIdentifiers::I3cSDR},
            {"I3cHDRDDR",
             mctp_server::MctpPhysicalMediumIdentifiers::I3cHDRDDR}};

    if (!jsonFile.is_open())
    {
        throw std::system_error(
            std::make_error_code(std::errc::no_such_file_or_directory));
    }
    json jsonConfig = json::parse(jsonFile, nullptr, false);
    if (jsonConfig.size() == 0)
    {
        throw std::system_error(
            std::make_error_code(std::errc::no_such_file_or_directory));
    }

    switch (bindingType)
    {
        case mctp_server::BindingTypes::MctpOverSmbus:
        {
            SMBusConfiguration smbusConfig;
            auto smbus = jsonConfig.at("smbus");

            smbusConfig.defaultEid = smbus.at("default-eid").get<uint8_t>();

            smbusConfig.mode =
                stringToBindingModeMap.at(smbus.at("role").get<std::string>());
            smbusConfig.bus = smbus.at("bus").get<std::string>();
            smbusConfig.eidPool =
                smbus.at("eid-pool").get<std::vector<uint8_t>>();
            smbusConfig.mediumId = stringToMediumID.at(
                smbus.at("PhysicalMediumID").get<std::string>());
            conf.emplace<SMBusConfiguration>(smbusConfig);
            break;
        }
        case mctp_server::BindingTypes::MctpOverPcieVdm:
        {
            PcieConfiguration pcieConfig;
            auto pcie = jsonConfig.at("pcie");

            pcieConfig.defaultEid = pcie.at("default-eid").get<uint8_t>();
            pcieConfig.mode =
                stringToBindingModeMap.at(pcie.at("role").get<std::string>());

            conf.emplace<PcieConfiguration>(pcieConfig);
            break;
        }
        case mctp_server::BindingTypes::MctpOverUsb:
        case mctp_server::BindingTypes::MctpOverKcs:
        case mctp_server::BindingTypes::MctpOverSerial:
        case mctp_server::BindingTypes::VendorDefined:
        default:
            throw std::system_error(
                std::make_error_code(std::errc::invalid_argument));
            break;
    }
}

int main(int argc, char* argv[])
{
    CLI::App app("MCTP Daemon");
    std::string binding;
    mctp_server::BindingTypes bindingType;
    ConfigurationVariant mctpdConfiuration;

    app.add_option("-b,--binding", binding,
                   "MCTP Physical Binding. Supported: -b smbus, -b pcie");
    app.add_option("-c,--config", configPath, "Path to configuration file.",
                   true);
    CLI11_PARSE(app, argc, argv);

    /* Process configuration */
    try
    {
        bindingType = mctpBindingsMap.at(binding);
        parseConfig(bindingType, mctpdConfiuration);
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid configuration; exiting",
            phosphor::logging::entry("Exception:", e.what()));
        return -1;
    }

    std::string mctpBaseObj = "/xyz/openbmc_project/mctp";
    boost::asio::io_context ioc;
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc](const boost::system::error_code&, const int&) { ioc.stop(); });

    std::shared_ptr<sdbusplus::asio::connection> bus;

    bus = std::make_shared<sdbusplus::asio::connection>(ioc);

    std::string mctpServiceName = "xyz.openbmc_project.MCTP-";
    auto objectServer = std::make_shared<sdbusplus::asio::object_server>(bus);
    bus->request_name((mctpServiceName + binding).c_str());

    auto objManager = std::make_shared<sdbusplus::server::manager::manager>(
        *bus, mctpBaseObj.c_str());

    // TODO: Initialise binding based on configurations exposed by Entity
    // Manager
    switch (bindingType)
    {
        case mctp_server::BindingTypes::MctpOverSmbus:
        {
            SMBusBinding SMBus(objectServer, mctpBaseObj, mctpdConfiuration);
            break;
        }
        case mctp_server::BindingTypes::MctpOverPcieVdm:
        {
            break;
        }
        default:
        {
            break;
        }
    }

    ioc.run();

    return 0;
}
