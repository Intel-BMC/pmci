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

#include "libmctp-msgtypes.h"

using smbus_server =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::SMBus;

namespace fs = std::filesystem;

static void throwRunTimeError(const std::string& err)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(err.c_str());
    throw std::runtime_error(err);
}

void SMBusBinding::scanPort(const int scanFd,
                            std::set<std::pair<int, uint8_t>>& deviceMap)
{
    if (scanFd < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid I2C port fd");
        return;
    }

    for (uint8_t it : supportedEndpointSlaveAddress)
    {
        if (ioctl(scanFd, I2C_SLAVE, it) < 0)
        {
            // busy slave
            continue;
        }

        else
        {
            if ((it >= 0x30 && it <= 0x37) || (it >= 0x50 && it <= 0x5F))
            {
                // EEPROM address range. Use read to detect
                if (i2c_smbus_read_byte(scanFd) < 0)
                {
                    continue;
                }
            }
            else
            {
                if (i2c_smbus_write_quick(scanFd, I2C_SMBUS_WRITE) < 0)
                {
                    continue;
                }
            }
        }

        /* If we are scanning a mux fd, we will encounter root bus
         * i2c devices, which needs to be part of root bus's devicemap.
         * Skip adding them to the muxfd related devicemap */

        if (scanFd != outFd &&
            rootDeviceMap.count(std::make_pair(outFd, it)) != 0)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Skipping device " + std::to_string(it)).c_str());
            continue;
        }

        phosphor::logging::log<phosphor::logging::level::DEBUG>(
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
        const std::string path = p.path().string();
        if (std::regex_search(path, search))
        {
            foundPaths.emplace_back(path);
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

std::map<int, int> SMBusBinding::getMuxFds(const std::string& rootPort)
{
    auto devDir = fs::path("/dev/");
    auto matchString = std::string(R"(i2c-\d+$)");
    std::vector<std::string> i2cBuses{};

    // Search for mux ports
    if (!findFiles(devDir, matchString, i2cBuses))
    {
        throwRunTimeError("unable to find i2c devices");
    }

    std::map<int, int> muxes;
    for (const auto& i2cPath : i2cBuses)
    {
        std::string i2cPort;
        std::string rootBus;
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
            muxes.emplace(muxfd, std::stoi(i2cPort));
        }
    }
    return muxes;
}

std::optional<std::vector<uint8_t>>
    SMBusBinding::getBindingPrivateData(uint8_t dstEid)
{
    mctp_smbus_pkt_private prvt = {};

    for (auto& device : smbusDeviceTable)
    {
        if (std::get<0>(device) == dstEid)
        {
            mctp_smbus_pkt_private temp = std::get<1>(device);
            prvt.fd = temp.fd;
            if (muxPortMap.count(prvt.fd) != 0)
            {
                prvt.mux_hold_timeout = 1000;
                prvt.mux_flags = IS_MUX_PORT;
            }
            else
            {
                prvt.mux_hold_timeout = 0;
                prvt.mux_flags = 0;
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
    const mctp_smbus_pkt_private* prvt =
        reinterpret_cast<const mctp_smbus_pkt_private*>(pvtData->data());
    if (prvt->mux_flags != IS_MUX_PORT)
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
    mctp_smbus_pkt_private* prvt =
        reinterpret_cast<mctp_smbus_pkt_private*>(pvtData->data());
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
                                          const mctp_smbus_pkt_private* prvt)
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
    smbusReceiverFd(ioc), reserveBWTimer(ioc), scanTimer(ioc),
    addRootDevices(true)
{
    smbusInterface = objServer->add_interface(objPath, smbus_server::interface);

    try
    {
        arpMasterSupport = conf.arpMasterSupport;
        bus = conf.bus;
        bmcSlaveAddr = conf.bmcSlaveAddr;
        supportedEndpointSlaveAddress = conf.supportedEndpointSlaveAddress;

        // TODO: If we are not top most busowner, wait for top mostbus owner
        // to issue EID Pool
        if (conf.mode == mctp_server::BindingModeTypes::BusOwner)
        {
            initializeEidPool(conf.eidPool);
        }

        if (bindingModeType == mctp_server::BindingModeTypes::BusOwner)
        {
            discoveredFlag = DiscoveryFlags::kNotApplicable;
        }
        else
        {
            discoveredFlag = DiscoveryFlags::kUnDiscovered;
        }

        registerProperty(smbusInterface, "DiscoveredFlag",
                         convertToString(discoveredFlag));
        registerProperty(smbusInterface, "ArpMasterSupport", arpMasterSupport);
        registerProperty(smbusInterface, "BusPath", bus);
        registerProperty(smbusInterface, "BmcSlaveAddress", bmcSlaveAddr);

        if (smbusInterface->initialize() == false)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SMBus Interface init failed",
            phosphor::logging::entry("Exception:", e.what()));
        throw;
    }
}

void SMBusBinding::scanDevices()
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>("Scanning devices");

    boost::asio::spawn(io, [this](boost::asio::yield_context yield) {
        if (!rsvBWActive)
        {
            deviceWatcher.deviceDiscoveryInit();
            initEndpointDiscovery(yield);
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Reserve bandwidth active. Unable to scan devices");
        }

        // TODO: Get timer tick frequency from EntityManager
        scanTimer.expires_after(std::chrono::seconds(60));
        scanTimer.async_wait([this](const boost::system::error_code& ec) {
            if (ec == boost::asio::error::operation_aborted)
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    "Device scanning aborted");
                return;
            }
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Device scanning timer failed");
                return;
            }
            scanDevices();
        });
    });
}

void SMBusBinding::restoreMuxIdleMode()
{
    auto logMuxErr = [](const std::string& path) {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Unable to restore mux idle mode",
            phosphor::logging::entry("MUX_PATH=%s", path.c_str()));
    };

    for (const auto& [path, idleMode] : muxIdleModeMap)
    {
        fs::path idlePath = fs::path(path);
        if (!fs::exists(idlePath))
        {
            logMuxErr(path);
            continue;
        }

        std::fstream idleFile(idlePath);
        if (idleFile.good())
        {
            idleFile << idleMode;
            if (idleFile.bad())
            {
                logMuxErr(path);
            }
        }
        else
        {
            logMuxErr(path);
        }
    }
}

void SMBusBinding::setMuxIdleModeToDisconnect()
{
    std::string rootPort;
    if (!getBusNumFromPath(bus, rootPort))
    {
        throwRunTimeError("Error in finding root port");
    }

    fs::path rootPath = fs::path("/sys/bus/i2c/devices/i2c-" + rootPort + "/");
    std::string matchString = rootPort + std::string(R"(-\d+$)");
    std::vector<std::string> i2cMuxes{};

    // Search for mux ports
    if (!findFiles(rootPath, matchString, i2cMuxes))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "No mux interfaces found");
        return;
    }

    const std::string muxIdleModeDisconnect = "-2";
    for (const auto& muxPath : i2cMuxes)
    {
        std::string path = muxPath + "/idle_state";
        fs::path idlePath = fs::path(path);
        if (!fs::exists(idlePath))
        {
            continue;
        }

        std::fstream idleFile(idlePath);
        if (idleFile.good())
        {
            std::string currentMuxIdleMode;
            idleFile >> currentMuxIdleMode;
            muxIdleModeMap.insert_or_assign(path, currentMuxIdleMode);

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                (path + " " + currentMuxIdleMode).c_str());

            idleFile << muxIdleModeDisconnect;
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unable to set idle mode for mux",
                phosphor::logging::entry("MUX_PATH=%s", idlePath.c_str()));
        }
    }
}

void SMBusBinding::initializeBinding()
{
    try
    {
        initializeMctp();
        auto rootPort = SMBusInit();
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Scanning root port");
        setMuxIdleModeToDisconnect();
        // Scan root port
        scanPort(outFd, rootDeviceMap);
        muxPortMap = getMuxFds(rootPort);
    }

    catch (const std::exception& e)
    {
        auto error =
            "Failed to initialise SMBus binding: " + std::string(e.what());
        phosphor::logging::log<phosphor::logging::level::ERR>(error.c_str());
        return;
    }

    scanDevices();
}

SMBusBinding::~SMBusBinding()
{
    restoreMuxIdleMode();

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
    objectServer->remove_interface(smbusInterface);
}

std::string SMBusBinding::SMBusInit()
{
    smbus = mctp_smbus_init();
    if (smbus == nullptr)
    {
        throwRunTimeError("Error in mctp smbus init");
    }

    if (mctp_smbus_register_bus(smbus, mctp, ownEid) != 0)
    {
        throwRunTimeError("Error in SMBus binding registration");
    }

    mctp_set_rx_all(mctp, &MctpBinding::rxMessage,
                    static_cast<MctpBinding*>(this));
    mctp_set_rx_ctrl(mctp, &MctpBinding::handleMCTPControlRequests,
                     static_cast<MctpBinding*>(this));
    std::string rootPort;

    if (!getBusNumFromPath(bus, rootPort))
    {
        throwRunTimeError("Error in opening smbus rootport");
    }

    std::stringstream addrStream;
    addrStream.str("");

    int addr7bit = (bmcSlaveAddr >> 1);

    // want the format as 0x0Y
    addrStream << std::setfill('0') << std::setw(2) << std::hex << addr7bit;

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("Slave Address " + addrStream.str()).c_str());

    // MSB fixed to 10 so hex is 0x10XX ~ 0x1005
    std::string hexSlaveAddr("10");
    hexSlaveAddr.append(addrStream.str());

    std::string inputDevice = "/sys/bus/i2c/devices/" + rootPort + "-" +
                              hexSlaveAddr + "/slave-mqueue";

    // Source slave address is in 8 bit format and should always be an odd
    // number
    mctp_smbus_set_src_slave_addr(smbus, bmcSlaveAddr | 0x01);

    inFd = open(inputDevice.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);

    // Doesn't exist, try to create one
    if (inFd < 0)
    {
        std::string newInputDevice =
            "/sys/bus/i2c/devices/i2c-" + rootPort + "/new_device";
        std::string para("slave-mqueue 0x");
        para.append(hexSlaveAddr);

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
    mctp_smbus_set_in_fd(smbus, inFd);
    mctp_smbus_set_out_fd(smbus, outFd);

    smbusReceiverFd.assign(inFd);
    readResponse();
    return rootPort;
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

void SMBusBinding::scanMuxBus(std::set<std::pair<int, uint8_t>>& deviceMap)
{
    for (const auto& [muxFd, muxPort] : muxPortMap)
    {
        // Scan each port only once
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Scanning Mux " + std::to_string(muxPort)).c_str());
        scanPort(muxFd, deviceMap);
    }
}

void SMBusBinding::initEndpointDiscovery(boost::asio::yield_context& yield)
{
    std::set<std::pair<int, uint8_t>> registerDeviceMap;

    if (addRootDevices)
    {
        for (const auto& device : rootDeviceMap)
        {
            registerDeviceMap.insert(device);
        }
    }

    // Scan mux bus to get the list of fd and the corresponding slave address of
    // all the mux ports
    scanMuxBus(registerDeviceMap);

    if (registerDeviceMap.empty())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "No device found");
        return;
    }

    /* Since i2c muxes restrict that only one command needs to be
     * in flight, we cannot register multiple endpoints in parallel.
     * Thus, in a single yield_context, all the discovered devices
     * are attempted with registration sequentially */
    for (const auto& device : registerDeviceMap)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Device discovery: Checking device " +
             std::to_string(std::get<1>(device)))
                .c_str());

        struct mctp_smbus_pkt_private smbusBindingPvt;
        smbusBindingPvt.fd = std::get<0>(device);

        if (muxPortMap.count(smbusBindingPvt.fd) != 0)
        {
            smbusBindingPvt.mux_hold_timeout = ctrlTxRetryDelay;
            smbusBindingPvt.mux_flags = 0x80;
        }
        else
        {
            smbusBindingPvt.mux_hold_timeout = 0;
            smbusBindingPvt.mux_flags = 0;
        }
        /* Set 8 bit i2c slave address */
        smbusBindingPvt.slave_addr =
            static_cast<uint8_t>((std::get<1>(device) << 1));

        auto const ptr = reinterpret_cast<uint8_t*>(&smbusBindingPvt);
        std::vector<uint8_t> bindingPvtVect(ptr, ptr + sizeof(smbusBindingPvt));
        if (!deviceWatcher.isDeviceGoodForInit(bindingPvtVect))
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Device found in ignore list. Skipping discovery");
            continue;
        }

        mctp_eid_t registeredEid = getEIDFromDeviceTable(bindingPvtVect);
        std::optional<mctp_eid_t> eid =
            registerEndpoint(yield, bindingPvtVect, registeredEid);

        if (eid.has_value())
        {
            bool isEidPresent = false;
            for (auto const& [eidEntry, bindingPvt] : smbusDeviceTable)
            {
                if (eidEntry == eid.value())
                {
                    isEidPresent = true;
                }
            }
            if (eid.value() != registeredEid)
            {
                // Remove the entry from DeviceTable
                if (smbusDeviceTable.size())
                {
                    removeDeviceTableEntry(registeredEid);
                }
            }

            if (!isEidPresent && eid.value() != MCTP_EID_NULL)
            {
                smbusDeviceTable.push_back(
                    std::make_pair(eid.value(), smbusBindingPvt));
            }
        }
        else
        {
            // Remove the entry from DeviceTable
            if (smbusDeviceTable.size())
            {
                removeDeviceTableEntry(registeredEid);
            }
        }
    }
    addRootDevices = false;
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

bool SMBusBinding::handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                       std::vector<uint8_t>& request,
                                       std::vector<uint8_t>& response)
{
    if (!MctpBinding::handleSetEndpointId(destEid, bindingPrivate, request,
                                          response))
    {
        return false;
    }

    response.resize(sizeof(mctp_ctrl_resp_set_eid));
    auto resp = reinterpret_cast<mctp_ctrl_resp_set_eid*>(response.data());

    if (resp->completion_code == MCTP_CTRL_CC_SUCCESS)
    {
        updateDiscoveredFlag(DiscoveryFlags::kDiscovered);
        mctpInterface->set_property("Eid", ownEid);
    }

    return true;
}

bool SMBusBinding::handleGetVersionSupport(mctp_eid_t destEid,
                                           void* bindingPrivate,
                                           std::vector<uint8_t>& request,
                                           std::vector<uint8_t>& response)
{
    if (!MctpBinding::handleGetVersionSupport(destEid, bindingPrivate, request,
                                              response))
    {
        return false;
    }

    return true;
}

bool SMBusBinding::handleGetMsgTypeSupport(mctp_eid_t destEid,
                                           void* bindingPrivate,
                                           std::vector<uint8_t>& request,
                                           std::vector<uint8_t>& response)
{
    if (!MctpBinding::handleGetMsgTypeSupport(destEid, bindingPrivate, request,
                                              response))
    {
        return false;
    }

    return true;
}

bool SMBusBinding::handleGetVdmSupport(mctp_eid_t destEid,
                                       [[maybe_unused]] void* bindingPrivate,
                                       std::vector<uint8_t>& request,
                                       std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_pci_ctrl_resp_get_vdm_support));

    if (request.size() < sizeof(struct mctp_ctrl_cmd_get_vdm_support))
    {
        return false;
    }

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
    resp->vendor_id_format = vdmSetDatabase[setIndex].vendorIdFormat;
    resp->vendor_id_data = vdmSetDatabase[setIndex].vendorId;
    resp->command_set_type = vdmSetDatabase[setIndex].commandSetType;

    return true;
}

void SMBusBinding::removeDeviceTableEntry(const mctp_eid_t eid)
{
    smbusDeviceTable.erase(std::remove_if(smbusDeviceTable.begin(),
                                          smbusDeviceTable.end(),
                                          [eid](auto const& tableEntry) {
                                              return (tableEntry.first == eid);
                                          }),
                           smbusDeviceTable.end());
}

mctp_eid_t SMBusBinding::getEIDFromDeviceTable(
    const std::vector<uint8_t>& bindingPrivate)
{
    mctp_eid_t eid = MCTP_EID_NULL;
    for (auto& deviceEntry : smbusDeviceTable)
    {
        const mctp_smbus_pkt_private* ptr =
            reinterpret_cast<const mctp_smbus_pkt_private*>(
                bindingPrivate.data());
        mctp_smbus_pkt_private bindingDataEntry = std::get<1>(deviceEntry);
        if (bindingDataEntry.slave_addr == ptr->slave_addr &&
            bindingDataEntry.fd == ptr->fd)
        {
            eid = std::get<0>(deviceEntry);
            break;
        }
    }
    return eid;
}

std::string SMBusBinding::convertToString(DiscoveryFlags flag)
{
    std::string discoveredStr;
    switch (flag)
    {
        case DiscoveryFlags::kUnDiscovered: {
            discoveredStr = "Undiscovered";
            break;
        }
        case DiscoveryFlags::kDiscovered: {
            discoveredStr = "Discovered";
            break;
        }
        case DiscoveryFlags::kNotApplicable:
        default: {
            discoveredStr = "NotApplicable";
            break;
        }
    }

    return discoveredStr;
}

void SMBusBinding::updateDiscoveredFlag(DiscoveryFlags flag)
{
    discoveredFlag = flag;
    smbusInterface->set_property("DiscoveredFlag", convertToString(flag));
}

void SMBusBinding::addUnknownEIDToDeviceTable(const mctp_eid_t eid,
                                              void* bindingPrivate)
{
    if (bindingPrivate == nullptr)
    {
        return;
    }

    auto deviceIter = std::find_if(
        smbusDeviceTable.begin(), smbusDeviceTable.end(),
        [eid](auto const eidEntry) { return std::get<0>(eidEntry) == eid; });

    if (deviceIter != smbusDeviceTable.end())
    {
        return;
    }

    auto bindingPtr = reinterpret_cast<mctp_smbus_pkt_private*>(bindingPrivate);

    struct mctp_smbus_pkt_private smbusBindingPvt = {};
    smbusBindingPvt.fd = bindingPtr->fd;
    smbusBindingPvt.mux_hold_timeout = bindingPtr->mux_hold_timeout;
    smbusBindingPvt.mux_flags = bindingPtr->mux_flags;
    smbusBindingPvt.slave_addr =
        static_cast<uint8_t>((bindingPtr->slave_addr) & (~1));

    smbusDeviceTable.emplace_back(std::make_pair(eid, smbusBindingPvt));

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("New EID added to device table. EID = " + std::to_string(eid))
            .c_str());
}
