#include "SMBusBinding.hpp"

#include "MCTPBinding.hpp"

extern "C" {
#include <errno.h>
#include <i2c/smbus.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
}

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

std::set<std::pair<int, uint8_t>> deviceMap;

static void throwRunTimeError(const std::string& err)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(err.c_str());

    throw std::runtime_error(err);
}

void SMBusBinding::scanPort(const int scanFd)
{
    constexpr uint8_t startAddr = 0x03;
    constexpr uint8_t endAddr = 0x77;

    if (scanFd < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid I2C port fd");
        return;
    }

    for (uint8_t it = startAddr; it < endAddr; it++)
    {
        if (ioctl(scanFd, I2C_SLAVE, it) < 0)
        {
            // busy slave
            continue;
        }

        else if (i2c_smbus_read_byte(scanFd) < 0)
        {
            // no device
            continue;
        }

        /* If we are scanning a mux fd, we will encounter root bus
         * i2c devices, which needs to be part of root bus's devicemap.
         * Skip adding them to the muxfd related devicemap */

        if (scanFd != outFd)
        {
            bool flag = false;
            for (auto& device : deviceMap)
            {
                if ((std::get<0>(device) == outFd) &&
                    (std::get<1>(device) == it))
                {
                    flag = true;
                    break;
                }
            }
            if (flag)
            {
                continue;
            }
        }

        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Adding device " + std::to_string(it)).c_str());

        deviceMap.insert(std::make_pair(scanFd, it));
    }
}

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

/*
 * dstEid can't be removed because this is a callback passed to libmctp and we
 * have to match its expected prototype.
 */
int getSMBusOutputAddress(uint8_t /*dstEid*/, uint8_t* outAddr)
{
    // Mapping should rely on routing table and message binding private
    // Handling this here until libmctp implements routing infrastructure
    *outAddr = 0xB0; // Add in card addresses
    return 0;
}

std::optional<std::vector<uint8_t>>
    SMBusBinding::getBindingPrivateData(uint8_t dstEid)
{
    mctp_smbus_extra_params prvt = {};

    for (auto& device : smbusDeviceTable)
    {
        if (device.first == dstEid)
        {
            mctp_smbus_extra_params temp = device.second;
            prvt.fd = temp.fd;
            if (isMuxFd(prvt.fd))
            {
                prvt.muxHoldTimeOut = 1000;
                prvt.muxFlags = IS_MUX_PORT;
            }
            else
            {
                prvt.muxHoldTimeOut = 0;
                prvt.muxFlags = 0;
            }
            prvt.slave_addr = temp.slave_addr;
            uint8_t* prvtPtr = reinterpret_cast<uint8_t*>(&prvt);
            return std::vector<uint8_t>(prvtPtr, prvtPtr + sizeof(prvt));
        }
    }
    return std::nullopt;
}

bool SMBusBinding::reserveBandwidth(const mctp_eid_t eid,
                                    const uint16_t timeout)
{
    if (rsvBWActive && eid != reservedEID)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (("reserveBandwidth is not allowed for EID: " +
              std::to_string(eid) + ". It is active for EID: ") +
             std::to_string(reservedEID))
                .c_str());
        return false;
    }
    std::optional<std::vector<uint8_t>> pvtData = getBindingPrivateData(eid);
    if (!pvtData)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "reserveBandwidth failed. Invalid destination EID");
        return false;
    }
    const mctp_smbus_extra_params* prvt =
        reinterpret_cast<const mctp_smbus_extra_params*>(pvtData->data());
    if (prvt->muxFlags != IS_MUX_PORT)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "reserveBandwidth not required, fd is not a mux port");
        return false;
    }
    if (mctp_smbus_init_pull_model(prvt) < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "reserveBandwidth: init pull model failed");
        return false;
    }
    rsvBWActive = true;
    reservedEID = eid;
    startTimerAndReleaseBW(timeout, prvt);
    return true;
}

bool SMBusBinding::releaseBandwidth(const mctp_eid_t eid)
{
    if (!rsvBWActive || eid != reservedEID)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (("reserveBandwidth is not active for EID: ") +
             std::to_string(reservedEID))
                .c_str());
        return false;
    }
    std::optional<std::vector<uint8_t>> pvtData = getBindingPrivateData(eid);
    if (!pvtData)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "releaseBandwidth: Invalid destination EID");
        return false;
    }
    mctp_smbus_extra_params* prvt =
        reinterpret_cast<mctp_smbus_extra_params*>(pvtData->data());
    if (mctp_smbus_exit_pull_model(prvt) < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "releaseBandwidth: failed to exit pull model");
        return false;
    }
    rsvBWActive = false;
    reservedEID = 0;
    reserveBWTimer.cancel();
    return true;
}

void SMBusBinding::startTimerAndReleaseBW(const uint16_t interval,
                                          const mctp_smbus_extra_params* prvt)
{
    reserveBWTimer.expires_after(std::chrono::milliseconds(interval * 1000));
    reserveBWTimer.async_wait([this,
                               prvt](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted)
        {
            // timer aborted do nothing
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "startTimerAndReleaseBW: timer operation_aborted");
        }
        else if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "startTimerAndReleaseBW: reserveBWTimer failed");
        }
        if (mctp_smbus_exit_pull_model(prvt) < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "startTimerAndReleaseBW: mctp_smbus_exit_pull_model failed");
            return;
        }
        rsvBWActive = false;
        reservedEID = 0;
    });
}

SMBusBinding::SMBusBinding(std::shared_ptr<object_server>& objServer,
                           const std::string& objPath,
                           const SMBusConfiguration& conf,
                           boost::asio::io_context& ioc) :
    MctpBinding(objServer, objPath, conf, ioc,
                mctp_server::BindingTypes::MctpOverSmbus),
    smbusReceiverFd(ioc), reserveBWTimer(ioc)
{
    std::shared_ptr<dbus_interface> smbusInterface =
        objServer->add_interface(objPath, smbus_server::interface);

    try
    {
        arpMasterSupport = conf.arpMasterSupport;
        bus = conf.bus;
        bmcSlaveAddr = conf.bmcSlaveAddr;

        // TODO: If we are not top most busowner, wait for top mostbus owner to
        // issue EID Pool
        if (conf.mode == mctp_server::BindingModeTypes::BusOwner)
        {
            initializeEidPool(conf.eidPool);
        }

        registerProperty(smbusInterface, "ArpMasterSupport", arpMasterSupport);
        registerProperty(smbusInterface, "BusPath", bus);
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

void SMBusBinding::initializeBinding()
{
    try
    {
        initializeMctp();
        SMBusInit();
        io.post([this]() { initEndpointDiscovery(); });
    }

    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to initialise SMBus binding");
    }
}

SMBusBinding::~SMBusBinding()
{
    if (smbusReceiverFd.native_handle() >= 0)
    {
        smbusReceiverFd.release();
    }
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

void SMBusBinding::SMBusInit()
{
    smbus = mctp_smbus_init();
    if (smbus == nullptr)
    {
        throwRunTimeError("Error in mctp sbus init");
    }

    if (mctp_smbus_register_bus(smbus, mctp, ownEid) != 0)
    {
        throwRunTimeError("Error in SMBus binding registration");
    }

    mctp_set_rx_all(mctp, &MctpBinding::rxMessage,
                    static_cast<MctpBinding*>(this));

    std::string rootPort;
    if (!getBusNumFromPath(bus, rootPort))
    {
        throwRunTimeError("Error in opening smbus rootport");
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
            throwRunTimeError("Error in opening smbus binding in_bus");
        }
    }

    // Open root bus
    outFd = open(bus.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);

    if (outFd < 0)
    {
        throwRunTimeError("Error in opening smbus binding out bus");
    }

    auto devDir = fs::path("/dev/");
    auto matchString = std::string(R"(i2c-\d+$)");
    std::vector<std::string> i2cBuses;

    // Search for mux ports
    if (!findFiles(devDir, matchString, i2cBuses))
    {
        throwRunTimeError("unable to find i2c devices");
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
            std::pair<int, int> entry(std::stoi(i2cPort), muxfd);
            muxFds.push_back(entry);
        }
    }
    mctp_smbus_set_in_fd(smbus, inFd);

    smbusReceiverFd.assign(inFd);
    readResponse();
}

void SMBusBinding::readResponse()
{
    smbusReceiverFd.async_wait(
        boost::asio::posix::descriptor_base::wait_error, [this](auto& ec) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error: mctp_smbus_read()");
                readResponse();
            }
            // through libmctp this will invoke rxMessage and message assembly
            mctp_smbus_read(smbus);

            readResponse();
        });
}

void SMBusBinding::scanAllPorts()
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Scanning root port");
    // Scan rootbus
    scanPort(outFd);

    // scan mux bus
    for (auto& muxFd : muxFds)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Scanning Mux " + std::to_string(std::get<0>(muxFd))).c_str());
        scanPort(std::get<1>(muxFd));
    }
}

bool SMBusBinding::isMuxFd(const int fd)
{
    for (auto& muxFd : muxFds)
    {
        if (fd == std::get<1>(muxFd))
        {
            return true;
        }
    }
    return false;
}

void SMBusBinding::initEndpointDiscovery()
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "InitEndpointDiscovery");

    /* Scan bus once */
    scanAllPorts();

    /* Since i2c muxes restrict that only one command needs to be
     * in flight, we cannot register multiple endpoints in parallel.
     * Thus, in a single yield_context, all the discovered devices
     * are attempted with registration sequentially */

    boost::asio::spawn(io, [this](boost::asio::yield_context yield) {
        for (auto& device : deviceMap)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                ("Checking if device " + std::to_string(std::get<1>(device)) +
                 " is MCTP Capable")
                    .c_str());

            struct mctp_smbus_extra_params smbusBindingPvt;
            smbusBindingPvt.fd = std::get<0>(device);

            if (isMuxFd(smbusBindingPvt.fd))
            {
                smbusBindingPvt.muxHoldTimeOut = ctrlTxRetryDelay;
                smbusBindingPvt.muxFlags = 0x80;
            }
            else
            {
                smbusBindingPvt.muxHoldTimeOut = 0;
                smbusBindingPvt.muxFlags = 0;
            }
            /* Set 8 bit i2c slave address */
            smbusBindingPvt.slave_addr =
                static_cast<uint8_t>((std::get<1>(device) << 1));

            auto const ptr = reinterpret_cast<uint8_t*>(&smbusBindingPvt);
            std::vector<uint8_t> bindingPvtVect(ptr,
                                                ptr + sizeof(smbusBindingPvt));

            auto rc = registerEndpoint(yield, bindingPvtVect);
            if (rc)
            {
                smbusDeviceTable.push_back(
                    std::make_pair(rc.value(), smbusBindingPvt));
            }
        }
    });
}

// TODO: This method is a placeholder and has not been tested
bool SMBusBinding::handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                       std::vector<uint8_t>& request,
                                       std::vector<uint8_t>& response)
{
    if (!MctpBinding::handleGetEndpointId(destEid, bindingPrivate, request,
                                          response))
    {
        return false;
    }

    auto const ptr = reinterpret_cast<uint8_t*>(bindingPrivate);
    if (auto bindingPvtVect = getBindingPrivateData(destEid))
    {
        std::copy(bindingPvtVect->begin(), bindingPvtVect->end(), ptr);
        return true;
    }
    return false;
}
