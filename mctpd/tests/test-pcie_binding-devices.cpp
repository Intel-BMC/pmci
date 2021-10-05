#include "utils/pcie/PCIeDiscoveredTestBase.hpp"

#include <array>

#include <gtest/gtest.h>

constexpr unsigned MIN_IFACES_PER_DEVICE = 3;
constexpr unsigned MAX_IFACES_PER_DEVICE = 4;

class PCIeEndpointIfacesTest
    : public PCIeDiscoveredTestBase,
      public ::testing::TestWithParam<
          std::tuple<uint8_t, uint16_t, std::string, std::vector<uint8_t>>>
{
  public:
    void SetUp() override
    {
        DEVICE_EID = std::get<0>(GetParam());
        DEVICE_BDF = std::get<1>(GetParam());
        DEVICE_UUID = std::get<2>(GetParam());
        MESSAGE_TYPES = std::get<3>(GetParam());

        const std::string DEVICE_PATH =
            "/xyz/openbmc_project/mctp/device/" + std::to_string(DEVICE_EID);
        const std::string EXPECTED_MODE =
            (DEVICE_BDF == busOwnerBdf)
                ? "xyz.openbmc_project.MCTP.Base.BindingModeTypes.BusOwner"
                : "xyz.openbmc_project.MCTP.Base.BindingModeTypes.Endpoint";

        provideRoutingTable(
            {{DEVICE_BDF, DEVICE_EID, MCTP_ROUTING_ENTRY_ENDPOINT}});

        provideMessageTypes(DEVICE_EID, MESSAGE_TYPES);

        provideUuid(DEVICE_EID, DEVICE_UUID);

        // Verify that all D-Bus interfaces were created
        auto [endpointIface, endpointIfaceCreated] =
            observeInterface(DEVICE_PATH, mctp_endpoint::interface);
        auto [msgTypesIface, msgTypesIfaceCreated] =
            observeInterface(DEVICE_PATH, mctp_msg_types::interface);
        auto [uuidIface, uuidIfaceCreated] =
            observeInterface(DEVICE_PATH, "xyz.openbmc_project.Common.UUID");

        waitAll(std::chrono::seconds(config.getRoutingInterval * 2),
                endpointIfaceCreated->future, msgTypesIfaceCreated->future,
                uuidIfaceCreated->future);

        endpointInterface = endpointIface;
        msgTypesInterface = msgTypesIface;
        uuidInterface = uuidIface;
    }

    std::shared_ptr<mctpd_mock::dbus_interface_mock> endpointInterface;
    std::shared_ptr<mctpd_mock::dbus_interface_mock> msgTypesInterface;
    std::shared_ptr<mctpd_mock::dbus_interface_mock> uuidInterface;

    uint8_t DEVICE_EID;
    uint16_t DEVICE_BDF;
    std::string DEVICE_UUID;
    std::vector<uint8_t> MESSAGE_TYPES;
};

TEST_P(PCIeEndpointIfacesTest, VerifyEndpointInterface)
{
    const std::string EXPECTED_MODE =
        (DEVICE_BDF == busOwnerBdf)
            ? "xyz.openbmc_project.MCTP.Base.BindingModeTypes.BusOwner"
            : "xyz.openbmc_project.MCTP.Base.BindingModeTypes.Endpoint";

    EXPECT_EQ(EXPECTED_MODE,
              endpointInterface->properties.get<std::string>("Mode"));
    // TODO: Update when will be implemented
    EXPECT_EQ(0x00, endpointInterface->properties.get<uint16_t>("NetworkId"));
}

TEST_P(PCIeEndpointIfacesTest, VerifyUuidInterface)
{
    EXPECT_EQ(DEVICE_UUID, uuidInterface->properties.get<std::string>("UUID"));
}

TEST_P(PCIeEndpointIfacesTest, VerifyMessageTypeInterface)
{
    for (const auto& [msgType, property] : msgTypeToPropertyName)
    {
        bool supported = false;
        if (std::find(MESSAGE_TYPES.begin(), MESSAGE_TYPES.end(), msgType) !=
            MESSAGE_TYPES.end())
        {
            supported = true;
        }

        EXPECT_EQ(supported, msgTypesInterface->properties.get<bool>(property));
    }
}

static const std::vector<uint8_t> ALL_MESSAGE_TYPES{
    MCTP_MESSAGE_TYPE_MCTP_CTRL, MCTP_MESSAGE_TYPE_PLDM,
    MCTP_MESSAGE_TYPE_NCSI,      MCTP_MESSAGE_TYPE_ETHERNET,
    MCTP_MESSAGE_TYPE_NVME,      MCTP_MESSAGE_TYPE_SPDM,
    MCTP_MESSAGE_TYPE_VDPCI,     MCTP_MESSAGE_TYPE_VDIANA};

INSTANTIATE_TEST_SUITE_P(
    InterfacesTest, PCIeEndpointIfacesTest,
    ::testing::Values(std::make_tuple(5, PCIeDiscoveredTestBase::busOwnerBdf,
                                      "12345678-9abc-"
                                      "defe-dcba-"
                                      "987654321012",
                                      ALL_MESSAGE_TYPES),
                      std::make_tuple(10, ~PCIeDiscoveredTestBase::busOwnerBdf,
                                      "87654321-cba0-"
                                      "efed-abcd-"
                                      "210123456789",
                                      ALL_MESSAGE_TYPES),
                      std::make_tuple(15, ~PCIeDiscoveredTestBase::busOwnerBdf,
                                      "87654321-cba0-"
                                      "efed-abcd-"
                                      "210123456789",
                                      std::vector<uint8_t>{
                                          MCTP_MESSAGE_TYPE_MCTP_CTRL,
                                          MCTP_MESSAGE_TYPE_ETHERNET,
                                          MCTP_MESSAGE_TYPE_NVME})));

class PCIeDevicePopulationTest : public PCIeDiscoveredTestBase,
                                 public ::testing::TestWithParam<unsigned>
{
  public:
    struct EndpointParam
    {
        uint8_t eid;
        uint16_t bdf;
        uint8_t messageType;
        std::string uuid;

        std::string path;
        std::string mode;
    };

    void SetUp() override
    {
        const unsigned DEVICE_COUNT = GetParam();

        // Prepare endpoints data
        for (uint8_t i = 0; i < DEVICE_COUNT; i++)
        {
            EndpointParam endpoint;
            endpoint.eid = i;
            endpoint.bdf = busOwnerBdf + i;
            endpoint.messageType =
                ALL_MESSAGE_TYPES[i % ALL_MESSAGE_TYPES.size()];
            endpoint.uuid =
                "12345678-9abc-defe-dcba-" + std::to_string(987654321012 + i);

            endpoint.path = "/xyz/openbmc_project/mctp/device/" +
                            std::to_string(endpoint.eid);
            endpoint.mode =
                (endpoint.bdf == busOwnerBdf)
                    ? "xyz.openbmc_project.MCTP.Base.BindingModeTypes.BusOwner"
                    : "xyz.openbmc_project.MCTP.Base.BindingModeTypes.Endpoint";

            endpoints.push_back(endpoint);
        }

        provideNetworkData();

        waitForInterfacesAdded();
    }

  protected:
    // Simulate the BusOwner
    void provideNetworkData()
    {
        std::vector<RoutingTableParam> routingTableParams;
        std::transform(endpoints.begin(), endpoints.end(),
                       std::back_inserter(routingTableParams),
                       [](const EndpointParam& endpoint) -> RoutingTableParam {
                           return {endpoint.bdf, endpoint.eid,
                                   MCTP_ROUTING_ENTRY_ENDPOINT};
                       });

        provideRoutingTable(routingTableParams);
        for (const auto& endpoint : endpoints)
        {
            provideMessageTypes(endpoint.eid, {endpoint.messageType});
            provideUuid(endpoint.eid, endpoint.uuid);
        }
    }

    void waitForInterfacesAdded()
    {
        // Wait for first and last endpoint with long timeout
        auto [firstIface, firstIfaceCreated] =
            observeInterface(endpoints.front().path, mctp_endpoint::interface);
        auto [lastIface, lastIfaceCreated] =
            observeInterface(endpoints.back().path, mctp_endpoint::interface);
        waitAll(std::chrono::seconds(config.getRoutingInterval * 2),
                firstIfaceCreated->future, lastIfaceCreated->future);
    }

    void waitForInterfacesRemoved()
    {
        auto ifacesRemoved = observeAnyInterfaceRemoved();
        waitFor(std::chrono::seconds(config.getRoutingInterval * 2),
                ifacesRemoved.future);
    }

    void removeDevicesFromNetwork(
        std::function<bool(const EndpointParam&)>&& predicate)
    {
        endpoints.erase(
            std::remove_if(endpoints.begin(), endpoints.end(), predicate),
            endpoints.end());
        provideNetworkData();
        waitForInterfacesRemoved();
    }

    void removeAllDevicesFromNetwork()
    {
        removeDevicesFromNetwork([](const EndpointParam&) { return true; });
    }

    void removeOddDevicesFromNetwork()
    {
        removeDevicesFromNetwork(
            [](const EndpointParam& endpoint) { return endpoint.eid % 2; });
    }

    std::vector<EndpointParam> endpoints;
};

TEST_P(PCIeDevicePopulationTest, VeirfyOwnEidNotRegistered)
{
    for (const auto& iface : bus->backdoor.interfaces)
    {
        ASSERT_NE(iface->path, "/xyz/openbmc_project/mctp/device/" +
                                   std::to_string(assignedEid));
    }
}

TEST_P(PCIeDevicePopulationTest, VerifyEndpointInterface)
{
    for (const auto& endpoint : endpoints)
    {
        if (endpoint.eid == assignedEid)
            continue;

        auto endpointIface = bus->backdoor.get_interface(
            endpoint.path, mctp_endpoint::interface);

        EXPECT_EQ(endpoint.mode,
                  endpointIface->properties.get<std::string>("Mode"));
        // TODO: Update when will be implemented
        EXPECT_EQ(0x00, endpointIface->properties.get<uint16_t>("NetworkId"));
    }
}

TEST_P(PCIeDevicePopulationTest, VerifyMsgTypesInterface)
{
    for (const auto& endpoint : endpoints)
    {
        if (endpoint.eid == assignedEid)
            continue;

        auto msgTypesIface = bus->backdoor.get_interface(
            endpoint.path, mctp_msg_types::interface);

        for (const auto& [msgType, property] : msgTypeToPropertyName)
        {
            // If device is discovered - service alwas states that
            // MCTP_MESSAGE_TYPE_MCTP_CTRL is supported
            bool supported = (msgType == endpoint.messageType ||
                              msgType == MCTP_MESSAGE_TYPE_MCTP_CTRL);
            EXPECT_EQ(supported, msgTypesIface->properties.get<bool>(property));
        }
    }
}
TEST_P(PCIeDevicePopulationTest, VerifyUuidInterface)
{
    for (const auto& endpoint : endpoints)
    {
        if (endpoint.eid == assignedEid)
            continue;

        auto uuidIface = bus->backdoor.get_interface(
            endpoint.path, "xyz.openbmc_project.Common.UUID");

        EXPECT_EQ(endpoint.uuid,
                  uuidIface->properties.get<std::string>("UUID"));
    }
}

TEST_P(PCIeDevicePopulationTest, AllDevicesRemoved)
{
    removeAllDevicesFromNetwork();

    // Check that all interfaces were removed
    auto deviceIfacesCount = std::count_if(
        bus->backdoor.interfaces.begin(), bus->backdoor.interfaces.end(),
        [&](auto& iface) {
            return std::string::npos !=
                   iface->path.find("/xyz/openbmc_project/mctp/device/");
        });
    EXPECT_EQ(0, deviceIfacesCount);
}

TEST_P(PCIeDevicePopulationTest, OddDevicesRemoved)
{
    removeOddDevicesFromNetwork();

    // Verify that proper EIDs are left
    for (auto& endpoint : endpoints)
    {
        if (endpoint.eid == assignedEid)
            continue;

        auto ifacesCount = std::count_if(
            bus->backdoor.interfaces.begin(), bus->backdoor.interfaces.end(),
            [&](auto& iface) { return endpoint.path == iface->path; });

        // Each object spawns 3 interfaces
        EXPECT_TRUE((ifacesCount >= MIN_IFACES_PER_DEVICE) &&
                    (ifacesCount <= MAX_IFACES_PER_DEVICE));
    }

    // Check that amount is expected (no extra interfaces found)
    auto deviceIfacesCount = std::count_if(
        bus->backdoor.interfaces.begin(), bus->backdoor.interfaces.end(),
        [&](auto& iface) {
            return std::string::npos !=
                   iface->path.find("/xyz/openbmc_project/mctp/device/");
        });

    EXPECT_TRUE((deviceIfacesCount >=
                 static_cast<int>(endpoints.size() * MIN_IFACES_PER_DEVICE)) &&
                (deviceIfacesCount <=
                 static_cast<int>(endpoints.size() * MAX_IFACES_PER_DEVICE)));
}

INSTANTIATE_TEST_SUITE_P(AddRemovalTests, PCIeDevicePopulationTest,
                         ::testing::Values(2, 10, 100, 200, 254));
