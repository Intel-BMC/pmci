#include "SMBusBinding.hpp"

#include "MCTPBinding.hpp"

#include <errno.h>
#include <i2c/smbus.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>

#include <boost/algorithm/string.hpp>
#include <filesystem>
#include <fstream>
#include <phosphor-logging/log.hpp>
#include <regex>
#include <string>
#include <xyz/openbmc_project/MCTP/Binding/SMBus/server.hpp>

using smbus_server =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::SMBus;

namespace fs = std::filesystem;

static bool isNum(const std::string& s)
{
    if (s.empty())
        return false;

    for (size_t i = 0; i < s.length(); i++)
        if (isdigit(s[i]) == false)
            return false;

    return true;
}

static bool findFiles(const fs::path& dirPath, const std::string& matchString,
                      std::vector<std::string>& foundPaths)
{
    if (!fs::exists(dirPath))
        return false;

    std::regex search(matchString);
    for (const auto& p : fs::directory_iterator(dirPath))
    {
        std::string path = p.path().string();
        if (std::regex_search(path, search))
        {
            foundPaths.emplace_back(p.path().string());
        }
    }
    return true;
}

static bool getBusNumFromPath(const std::string& path, std::string& busStr)
{
    std::vector<std::string> parts;
    boost::split(parts, path, boost::is_any_of("-"));
    if (parts.size() == 2)
    {
        busStr = parts[1];
        if (isNum(busStr))
        {
            return true;
        }
    }
    return false;
}

static bool getRootBus(const std::string& muxBus, std::string& rootBus)
{
    auto ec = std::error_code();
    auto path = fs::read_symlink(
        fs::path("/sys/bus/i2c/devices/i2c-" + muxBus + "/mux_device"), ec);
    if (ec)
    {
        return false;
    }

    std::string filename = path.filename();
    std::vector<std::string> parts;
    boost::split(parts, filename, boost::is_any_of("-"));
    if (parts.size() == 2)
    {
        rootBus = parts[0];
        if (isNum(rootBus))
        {
            return true;
        }
    }
    return false;
}

static bool isMuxBus(const std::string& bus)
{
    return is_symlink(
        fs::path("/sys/bus/i2c/devices/i2c-" + bus + "/mux_device"));
}

int getSMBusOutputAddress(uint8_t dstEid, uint8_t* outAddr)
{
    // Dummy stuff to get rid of -used-variable compiler error
    dstEid = dstEid;

    // Mapping should rely on routing table and message binding private
    // Handling this here until libmctp implements routing infrastructure
    *outAddr = 0xB0; // Add in card addresses
    return 0;
}

SMBusBinding::SMBusBinding(std::shared_ptr<object_server>& objServer,
                           std::string& objPath, ConfigurationVariant& conf,
                           boost::asio::io_context& ioc) :
    MctpBinding(objServer, objPath, conf, ioc)
{
    std::shared_ptr<dbus_interface> smbusInterface =
        objServer->add_interface(objPath, smbus_server::interface);

    try
    {
        this->arpMasterSupport =
            std::get<SMBusConfiguration>(conf).arpMasterSupport;
        this->bus = std::get<SMBusConfiguration>(conf).bus;
        this->bmcSlaveAddr = std::get<SMBusConfiguration>(conf).bmcSlaveAddr;
        registerProperty(smbusInterface, "ArpMasterSupport", arpMasterSupport);
        registerProperty(smbusInterface, "BusNumber", bus);
        registerProperty(smbusInterface, "BmcSlaveAddress", bmcSlaveAddr);
        if (smbusInterface->initialize() == false)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }
    }

    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SMBus Interface init failed",
            phosphor::logging::entry("Exception:", e.what()));

        throw;
    }
}

void SMBusBinding::initializeBinding(ConfigurationVariant& conf)
{
    try
    {
        initializeMctp();
        SMBusInit(conf);
    }

    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to initialise SMBus binding");
    }
}

SMBusBinding::~SMBusBinding()
{
    if (inFd >= 0)
    {
        close(inFd);
    }
    if (outFd >= 0)
    {
        close(outFd);
    }
    mctp_smbus_free(smbus);
}

void SMBusBinding::SMBusInit(ConfigurationVariant& /*conf*/)
{
    smbus = mctp_smbus_init();
    if (smbus == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in mctp sbus init");
        return;
    }

    mctp_smbus_register_bus(smbus, mctp, ownEid);
    mctp_set_rx_all(mctp, rxMessage, nullptr);

    std::string rootPort;
    if (!getBusNumFromPath(bus, rootPort))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in opening smbus rootport");
        return;
    }
    std::string inputDevice =
        "/sys/bus/i2c/devices/" + rootPort + "-1008/slave-mqueue";

    inFd = open(inputDevice.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);

    // Doesn't exist, try to create one
    if (inFd < 0)
    {
        std::string newInputDevice =
            "/sys/bus/i2c/devices/i2c-" + rootPort + "/new_device";
        std::string para("slave-mqueue 0x1008");
        std::fstream deviceFile;
        deviceFile.open(newInputDevice, std::ios::out);
        deviceFile << para;
        deviceFile.close();

        inFd = open(inputDevice.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (inFd < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error in opening smbus binding in_bus");
            return;
        }
    }

    // Open root bus
    outFd = open(bus.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);

    if (outFd < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in opening smbus binding out bus");
        return;
    }

    auto devDir = fs::path("/dev/");
    auto matchString = std::string(R"(i2c-\d+$)");
    std::vector<std::string> i2cBuses;

    // Search for mux ports
    if (!findFiles(devDir, matchString, i2cBuses))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "unable to find i2c devices");
        return;
    }

    for (auto i2cPath : i2cBuses)
    {
        std::string i2cPort, rootBus;
        if (!getBusNumFromPath(i2cPath, i2cPort))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "i2c bus path is malformed",
                phosphor::logging::entry("PATH=%s", i2cPath.c_str()));
            continue;
        }

        if (!isMuxBus(i2cPort))
        {
            continue; // we found regular i2c port
        }

        if (!getRootBus(i2cPort, rootBus))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error getting root port for the bus",
                phosphor::logging::entry("BUS:", i2cPort.c_str()));
            continue;
        }

        // Add to list of muxes if rootport matches to the one defined in mctp
        // configuration
        if (rootPort == rootBus)
        {
            int muxfd = open(i2cPath.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
            if (muxfd < 0)
            {

                continue;
            }
            std::pair<int, int> entry(std::stoi(rootPort), muxfd);
            muxFds.push_back(entry);
        }
    }

    mctp_smbus_set_in_fd(smbus, inFd);
    mctp_smbus_set_out_fd(smbus, outFd);
    mctp_binding_set_slave_addr_callback(getSMBusOutputAddress);
}
