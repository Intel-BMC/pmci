#include "bindings/TestBinding.hpp"
#include "utils/AsyncTestBase.hpp"

#include <gtest/gtest.h>

class BindingBasicTest : public AsyncTestBase, public ::testing::Test
{
  public:
    static constexpr auto messageTimeout = AsyncTestBase::executionTimeout / 2;

    void SetUp() override
    {
        bus = std::make_shared<mctpd_mock::object_server_mock>();

        mctpInterface = bus->backdoor.add_interface(
            "/xyz/openbmc_project/test_mctp", mctp_server::interface);
        mctpInterface->returnByDefault(true);

        Configuration config{};
        config.reqRetryCount = 0;
        config.reqToRespTime =
            std::chrono::milliseconds{messageTimeout}.count();

        binding = std::make_shared<TestBinding>(
            conn, bus, "/xyz/openbmc_project/test_mctp", config, ioc);
        binding->initializeBinding();
    }

    boost::asio::io_context io;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::shared_ptr<TestBinding> binding;

    std::shared_ptr<mctpd_mock::object_server_mock> bus;
    std::shared_ptr<mctpd_mock::dbus_interface_mock> mctpInterface;
};

TEST_F(BindingBasicTest, Send_GetEid_Positive)
{
    constexpr unsigned DEST_EID = 10;

    constexpr unsigned CC_OK = 0;
    constexpr unsigned RESP_EID = 99;
    constexpr unsigned RESP_EID_TYPE = 10;
    constexpr unsigned RESP_MEDIUM_DATA = 12;

    auto getEid = makePromise<std::tuple<bool, std::vector<uint8_t>>>();
    schedule([&](boost::asio::yield_context yield) {
        std::vector<uint8_t> prv, resp;

        bool result = binding->getEidCtrlCmd(yield, prv, DEST_EID, resp);
        getEid.promise.set_value({result, resp});
    });

    schedule([&]() {
        auto response =
            binding->backdoor.prepareCtrlResponse<mctp_ctrl_resp_get_eid>();

        response.payload->completion_code = CC_OK;
        response.payload->eid = RESP_EID;
        response.payload->eid_type = RESP_EID_TYPE;
        response.payload->medium_data = RESP_MEDIUM_DATA;

        binding->backdoor.rx(response);
    });

    // Verify GetEid contents
    {
        const auto [result, resp] = waitFor(getEid.future);
        ASSERT_TRUE(result);
        ASSERT_EQ(resp.size(), sizeof(mctp_ctrl_resp_get_eid));

        auto response =
            reinterpret_cast<const mctp_ctrl_resp_get_eid*>(resp.data());
        ASSERT_EQ(response->completion_code, CC_OK);
        ASSERT_EQ(response->eid, RESP_EID);
        ASSERT_EQ(response->eid_type, RESP_EID_TYPE);
        ASSERT_EQ(response->medium_data, RESP_MEDIUM_DATA);
    }
}

TEST_F(BindingBasicTest, Send_GetEid_Negative)
{
    constexpr unsigned DEST_EID = 10;
    constexpr unsigned CC_FAIL = 255;

    auto getEid = makePromise<std::tuple<bool, std::vector<uint8_t>>>();
    schedule([&](boost::asio::yield_context yield) {
        std::vector<uint8_t> prv, resp;
        bool result = binding->getEidCtrlCmd(yield, prv, DEST_EID, resp);
        getEid.promise.set_value({result, resp});
    });

    schedule([&]() {
        auto response =
            binding->backdoor.prepareCtrlResponse<mctp_ctrl_resp_get_eid>();
        response.payload->completion_code = CC_FAIL;
        binding->backdoor.rx(response);
    });

    // Check that GetEid failed
    {
        const auto [result, resp] = waitFor(getEid.future);
        ASSERT_FALSE(result);
        ASSERT_EQ(resp.size(), sizeof(mctp_ctrl_resp_get_eid));

        auto response =
            reinterpret_cast<const mctp_ctrl_resp_get_eid*>(resp.data());
        ASSERT_EQ(response->completion_code, CC_FAIL);
    }
}

TEST_F(BindingBasicTest, Send_GetEid_Timeout)
{
    constexpr unsigned DEST_EID = 10;

    auto getEid = makePromise<std::tuple<bool, std::vector<uint8_t>>>();
    schedule([&](boost::asio::yield_context yield) {
        std::vector<uint8_t> prv, resp;

        bool result = binding->getEidCtrlCmd(yield, prv, DEST_EID, resp);
        getEid.promise.set_value({result, resp});
    });

    // Check that GetEid has ended with timeout
    {
        const auto [result, resp] = waitFor(getEid.future);
        ASSERT_FALSE(result);
        ASSERT_EQ(0, resp.size());
    }
}
