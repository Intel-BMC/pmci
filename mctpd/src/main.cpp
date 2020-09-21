#include "MCTPBinding.hpp"
#include "PCIeBinding.hpp"
#include "SMBusBinding.hpp"

#include <CLI/CLI.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <regex>
#include <sdbusplus/asio/object_server.hpp>

using json = nlohmann::json;

using ConfigurationField =
    std::variant<bool, uint64_t, std::string, std::vector<uint64_t>>;

using ConfigurationMap = std::unordered_map<std::string, ConfigurationField>;

static const std::string mctpTypeName =
    "xyz.openbmc_project.Configuration.MctpConfiguration";

static const std::string boardPathNamespace =
    "/xyz/openbmc_project/inventory/system/board";

static std::string configPath = "/usr/share/mctp/mctp_config.json";

std::shared_ptr<sdbusplus::asio::connection> conn;

static const std::unordered_map<std::string, mctp_server::BindingModeTypes>
    stringToBindingModeMap = {
        {"busowner", mctp_server::BindingModeTypes::BusOwner},
        {"BusOwner", mctp_server::BindingModeTypes::BusOwner},
        {"endpoint", mctp_server::BindingModeTypes::Endpoint},
        {"Endpoint", mctp_server::BindingModeTypes::Endpoint},
        {"bridge", mctp_server::BindingModeTypes::Bridge},
        {"Bridge", mctp_server::BindingModeTypes::Bridge}};

static const std::unordered_map<std::string,
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
         mctp_server::MctpPhysicalMediumIdentifiers::Smbus3OrI2c1MhzCompatible},
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
        {"KcsLegacy", mctp_server::MctpPhysicalMediumIdentifiers::KcsLegacy},
        {"KcsPci", mctp_server::MctpPhysicalMediumIdentifiers::KcsPci},
        {"SerialHostLegacy",
         mctp_server::MctpPhysicalMediumIdentifiers::SerialHostLegacy},
        {"SerialHostPci",
         mctp_server::MctpPhysicalMediumIdentifiers::SerialHostPci},
        {"AsynchronousSerial",
         mctp_server::MctpPhysicalMediumIdentifiers::AsynchronousSerial},
        {"I3cSDR", mctp_server::MctpPhysicalMediumIdentifiers::I3cSDR},
        {"I3cHDRDDR", mctp_server::MctpPhysicalMediumIdentifiers::I3cHDRDDR}};

template <typename T>
static bool getField(const ConfigurationMap& configuration,
                     const std::string& fieldName, T& value)
{
    auto it = configuration.find(fieldName);
    if (it != configuration.end())
    {
        const T* ptrValue = std::get_if<T>(&it->second);
        if (ptrValue != nullptr)
        {
            value = *ptrValue;
            return true;
        }
    }
    phosphor::logging::log<phosphor::logging::level::WARNING>(
        ("Missing configuration field " + fieldName).c_str());
    return false;
}

template <typename T>
static bool getField(const json& configuration, const std::string& fieldName,
                     T& value)
{
    if (!configuration.contains(fieldName))
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("Missing configuration field " + fieldName).c_str());
        return false;
    }

    try
    {
        value = configuration.at(fieldName).get<T>();
        return true;
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("Error reading configuration field " + fieldName + ": " + e.what())
                .c_str());
        return false;
    }
}

template <typename Configuration>
static std::optional<SMBusConfiguration>
    getSMBusConfiguration(const Configuration& map)
{
    std::string physicalMediumID;
    std::string role;
    uint64_t defaultEID = 0;
    std::vector<uint64_t> eidPool;
    std::string bus;
    bool arpOwnerSupport = false;
    uint64_t bmcReceiverAddress = 0;
    uint64_t reqToRespTimeMs = 0;
    uint64_t reqRetryCount = 0;

    if (!getField(map, "PhysicalMediumID", physicalMediumID))
    {
        return std::nullopt;
    }

    if (!getField(map, "Role", role) && !getField(map, "role", role))
    {
        return std::nullopt;
    }

    if (!getField(map, "DefaultEID", defaultEID) &&
        !getField(map, "default-eid", defaultEID))
    {
        return std::nullopt;
    }

    if (!getField(map, "Bus", bus) && !getField(map, "bus", bus))
    {
        return std::nullopt;
    }

    if (!getField(map, "ARPOwnerSupport", arpOwnerSupport) &&
        !getField(map, "ARPMasterSupport", arpOwnerSupport))
    {
        return std::nullopt;
    }

    if (!getField(map, "BMCReceiverAddress", bmcReceiverAddress) &&
        !getField(map, "BMCSlaveAddress", bmcReceiverAddress))
    {
        return std::nullopt;
    }

    if (!getField(map, "ReqToRespTimeMs", reqToRespTimeMs) ||
        !getField(map, "ReqRetryCount", reqRetryCount))
    {
        return std::nullopt;
    }

    const auto mode = stringToBindingModeMap.at(role);
    if (mode == mctp_server::BindingModeTypes::BusOwner &&
        !getField(map, "EIDPool", eidPool) &&
        !getField(map, "eid-pool", eidPool))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Role is set to BusOwner but EIDPool is missing");
        return std::nullopt;
    }

    SMBusConfiguration config;
    config.mediumId = stringToMediumID.at(physicalMediumID);
    config.mode = mode;
    config.defaultEid = static_cast<uint8_t>(defaultEID);
    if (mode == mctp_server::BindingModeTypes::BusOwner)
    {
        config.eidPool = std::set<uint8_t>(eidPool.begin(), eidPool.end());
    }
    config.bus = bus;
    config.arpMasterSupport = arpOwnerSupport;
    config.bmcSlaveAddr = static_cast<uint8_t>(bmcReceiverAddress);
    config.reqToRespTime = static_cast<unsigned int>(reqToRespTimeMs);
    config.reqRetryCount = static_cast<uint8_t>(reqRetryCount);

    return config;
}

template <typename Configuration>
static std::optional<PcieConfiguration>
    getPcieConfiguration(const Configuration& map)
{
    std::string physicalMediumID;
    std::string role;
    uint64_t defaultEID;
    uint64_t bdf;
    uint64_t reqToRespTimeMs;
    uint64_t reqRetryCount;

    if (!getField(map, "PhysicalMediumID", physicalMediumID))
    {
        return std::nullopt;
    }

    if (!getField(map, "Role", role) && !getField(map, "role", role))
    {
        return std::nullopt;
    }

    if (!getField(map, "DefaultEID", defaultEID) &&
        !getField(map, "default-eid", defaultEID))
    {
        return std::nullopt;
    }

    if (!getField(map, "BDF", bdf) && !getField(map, "bdf", bdf))
    {
        return std::nullopt;
    }

    if (!getField(map, "ReqToRespTimeMs", reqToRespTimeMs) ||
        !getField(map, "ReqRetryCount", reqRetryCount))
    {
        return std::nullopt;
    }

    PcieConfiguration config;
    config.mediumId = stringToMediumID.at(physicalMediumID);
    config.mode = stringToBindingModeMap.at(role);
    config.defaultEid = static_cast<uint8_t>(defaultEID);
    config.bdf = static_cast<uint16_t>(bdf);
    config.reqToRespTime = static_cast<unsigned int>(reqToRespTimeMs);
    config.reqRetryCount = static_cast<uint8_t>(reqRetryCount);

    return config;
}

static ConfigurationMap
    getConfigurationMap(const std::string& configurationPath)
{
    auto method_call = conn->new_method_call(
        "xyz.openbmc_project.EntityManager", configurationPath.c_str(),
        "org.freedesktop.DBus.Properties", "GetAll");
    method_call.append(mctpTypeName);

    // Note: This is a blocking call.
    // However, there is nothing to do until the configuration is retrieved.
    auto reply = conn->call(method_call);
    ConfigurationMap map;
    reply.read(map);
    return map;
}

static std::string getBindingName(std::string binding)
{
    const std::regex illegal_name_regex("[^A-Za-z0-9_.]");
    std::regex_replace(binding.begin(), binding.begin(), binding.end(),
                       illegal_name_regex, "_");
    return binding;
}

static std::optional<ConfigurationVariant>
    getConfigurationFromEntityManager(const std::string& configurationName)
{
    const std::string relativePath =
        boost::algorithm::replace_all_copy(configurationName, "_2f", "/");
    if (relativePath == configurationName)
    {
        return std::nullopt;
    }

    const std::string objectPath = boardPathNamespace + "/" + relativePath;
    const ConfigurationMap map = getConfigurationMap(objectPath);

    std::string name;
    if (!getField(map, "Name", name))
    {
        return std::nullopt;
    }

    std::string bindingType;
    if (!getField(map, "BindingType", bindingType))
    {
        return std::nullopt;
    }

    std::optional<ConfigurationVariant> configuration;
    if (bindingType == "MctpSMBus")
    {
        configuration = getSMBusConfiguration(map);
    }
    else if (bindingType == "MctpPCIe")
    {
        configuration = getPcieConfiguration(map);
    }
    return configuration;
}

static std::optional<ConfigurationVariant>
    getConfigurationFromFile(const std::string& configurationName)
{
    std::ifstream jsonFile(configPath);
    if (!jsonFile.is_open())
    {
        return std::nullopt;
    }

    json jsonConfig = json::parse(jsonFile, nullptr, false);
    if (jsonConfig.size() == 0 || !jsonConfig.contains(configurationName))
    {
        return std::nullopt;
    }

    std::optional<ConfigurationVariant> configuration;
    if (configurationName == "smbus")
    {
        configuration = getSMBusConfiguration(jsonConfig.at("smbus"));
    }
    else if (configurationName == "pcie")
    {
        configuration = getPcieConfiguration(jsonConfig.at("pcie"));
    }
    return configuration;
}

static std::optional<ConfigurationVariant>
    getConfiguration(const std::string& configurationName)
{
    std::optional<ConfigurationVariant> configuration =
        getConfigurationFromEntityManager(configurationName);
    if (!configuration)
    {
        configuration = getConfigurationFromFile(configurationName);
    }
    return configuration;
}

template <class... Types>
struct overload : Types...
{
    using Types::operator()...;
};

template <class... Types>
overload(Types...) -> overload<Types...>;

int main(int argc, char* argv[])
{
    CLI::App app("MCTP Daemon");
    std::string binding;
    std::optional<ConfigurationVariant> mctpdConfiguration;

    app.add_option("-b,--binding", binding,
                   "MCTP Physical Binding. Supported: -b smbus, -b pcie")
        ->required();
    app.add_option("-c,--config", configPath, "Path to configuration file.",
                   true);
    CLI11_PARSE(app, argc, argv);

    boost::asio::io_context ioc;
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [&ioc](const boost::system::error_code&, const int&) { ioc.stop(); });

    conn = std::make_shared<sdbusplus::asio::connection>(ioc);

    auto objectServer = std::make_shared<object_server>(conn);
    const std::string mctpServiceName =
        "xyz.openbmc_project.MCTP-" + getBindingName(binding);
    conn->request_name(mctpServiceName.c_str());

    /* Process configuration */
    try
    {
        mctpdConfiguration = getConfiguration(binding);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Exception: ") + e.what()).c_str());
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid configuration; exiting");
        return -1;
    }

    if (!mctpdConfiguration)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Could not load any configuration; exiting");
        return -1;
    }

    std::string mctpBaseObj = "/xyz/openbmc_project/mctp";
    using BindingVariant = std::variant<std::unique_ptr<SMBusBinding>,
                                        std::unique_ptr<PCIeBinding>>;
    auto ptr = std::visit(
        overload{[&mctpdConfiguration, &objectServer, &mctpBaseObj,
                  &ioc](SMBusConfiguration&) -> BindingVariant {
                     return std::make_unique<SMBusBinding>(
                         objectServer, mctpBaseObj, *mctpdConfiguration, ioc);
                 },
                 [&mctpdConfiguration, &objectServer, &mctpBaseObj,
                  &ioc](PcieConfiguration&) -> BindingVariant {
                     return std::make_unique<PCIeBinding>(
                         objectServer, mctpBaseObj, *mctpdConfiguration, ioc);
                 }},
        *mctpdConfiguration);

    try
    {
        std::visit([&mctpdConfiguration](
                       auto& b) { b->initializeBinding(*mctpdConfiguration); },
                   ptr);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Exception: ") + e.what()).c_str());
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to intialize MCTP binding; exiting");
        return -1;
    }
    ioc.run();

    return 0;
}
