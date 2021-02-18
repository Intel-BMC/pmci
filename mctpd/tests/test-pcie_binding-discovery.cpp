#include "bindings/pcie/TestPCIeBinding.hpp"
#include "utils/pcie/PCIeTestBase.hpp"

#include <gtest/gtest.h>

class PCIeBindingDiscoveryTest : public PCIeTestBase, public ::testing::Test
{
};

TEST_F(PCIeBindingDiscoveryTest, SendsDiscoveryNotifyAtStart)
{
    auto receiveDiscovery = makePromise<
        TestPCIeBinding::BindingIO<mctp_ctrl_cmd_discovery_notify>>();
    binding->backdoor.onOutgoingCtrlCommand(
        MCTP_CTRL_CMD_DISCOVERY_NOTIFY, [&]() {
            receiveDiscovery.promise.set_value(
                lastOutgoingFrame<mctp_ctrl_cmd_discovery_notify>());
        });
    const auto request = waitFor(receiveDiscovery.future);

    ASSERT_EQ(MCTP_EID_NULL, request.hdr->dest);
    ASSERT_EQ(MCTP_CTRL_CMD_DISCOVERY_NOTIFY,
              request.payload->ctrl_msg_hdr.command_code);
    ASSERT_EQ(PCIE_ROUTE_TO_RC, request.prv->routing);
}

TEST_F(PCIeBindingDiscoveryTest, EndpointDiscovered)
{
    using ::testing::StrEq;
    using ::testing::TypedEq;

    constexpr unsigned BUS_OWNER_BDF = 0x1234;
    constexpr unsigned ASSIGNED_EID = 0x99;

    auto notifyCalled = makePromise<void>();
    binding->backdoor.onOutgoingCtrlCommand(
        MCTP_CTRL_CMD_DISCOVERY_NOTIFY, [&]() {
            sendCtrlResponseAsync<mctp_ctrl_resp_discovery_notify>(
                mctp_astpcie_pkt_private{PCIE_ROUTE_TO_RC, 0},
                [&](auto& payload) {
                    payload.completion_code = MCTP_CTRL_CC_SUCCESS;
                });
            notifyCalled.promise.set_value();
        });
    waitFor(notifyCalled.future);

    {
        auto response = sendCtrlRequest<mctp_ctrl_msg_hdr,
                                        mctp_ctrl_resp_prepare_discovery>(
            MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY, {0, 0},
            {PCIE_BROADCAST_FROM_RC, BUS_OWNER_BDF});
        ASSERT_EQ(MCTP_CTRL_CC_SUCCESS, response.completion_code);
    }

    {
        auto response = sendCtrlRequest<mctp_ctrl_msg_hdr,
                                        mctp_ctrl_resp_endpoint_discovery>(
            MCTP_CTRL_CMD_ENDPOINT_DISCOVERY, {0, 0},
            {PCIE_BROADCAST_FROM_RC, BUS_OWNER_BDF});
        ASSERT_EQ(MCTP_CTRL_CC_SUCCESS, response.completion_code);
    }

    {
        EXPECT_CALL(*pcieInterface,
                    set_property(StrEq("DiscoveredFlag"),
                                 TypedEq<const std::string&>(
                                     "xyz.openbmc_project.MCTP.Binding.PCIe."
                                     "DiscoveryFlags.Discovered")));
        auto response =
            sendCtrlRequest<mctp_ctrl_cmd_set_eid, mctp_ctrl_resp_set_eid>(
                MCTP_CTRL_CMD_SET_ENDPOINT_ID, {0, 0},
                {PCIE_ROUTE_BY_ID, BUS_OWNER_BDF}, [&](auto& payload) {
                    payload.eid = ASSIGNED_EID;
                    payload.operation = set_eid;
                });
        ASSERT_EQ(MCTP_CTRL_CC_SUCCESS, response.completion_code);
        ASSERT_EQ(ASSIGNED_EID, response.eid_set);
    }

    {
        auto response =
            sendCtrlRequest<mctp_ctrl_cmd_get_eid, mctp_ctrl_resp_get_eid>(
                MCTP_CTRL_CMD_GET_ENDPOINT_ID, {0, 0},
                {PCIE_ROUTE_BY_ID, BUS_OWNER_BDF});
        ASSERT_EQ(MCTP_CTRL_CC_SUCCESS, response.completion_code);
        ASSERT_EQ(ASSIGNED_EID, response.eid);
    }
}
