#include "PCIeBinding.hpp"
#include "SMBusBinding.hpp"

using ::testing::_;
using ::testing::An;
using ::testing::Eq;
using ::testing::Return;
using ::testing::StrEq;

std::shared_ptr<sdbusplus::asio::connection> conn;

class MctpdBaseTest : public ::testing::Test
{
  public:
    void SetUp() override
    {
        objectServerMock =
            std::make_shared<mctpd_mock::object_server_mock>(mctpBaseObj);
    }

    void TearDown() override
    {
    }

    void MakeSmbusConfiguration(
        mctp_server::MctpPhysicalMediumIdentifiers mediumId,
        mctp_server::BindingModeTypes mode, uint8_t defaultEid,
        std::set<uint8_t> eidPool, std::string busName)
    {
        smbusConfig.mediumId = mediumId;
        smbusConfig.mode = mode;
        smbusConfig.defaultEid = defaultEid;
        smbusConfig.eidPool = eidPool;
        smbusConfig.bus = busName;
    }
    std::string mctpBaseObj = "/xyz/openbmc_project/mctp";
    std::shared_ptr<mctpd_mock::object_server_mock> objectServerMock;
    SMBusConfiguration smbusConfig;
};

/*
 * Check if properties for Base interface
 * are registered, property permission is always
 * set to readOnly and interface initialize method
 * is invoked.
 */
TEST_F(MctpdBaseTest, BaseIfPropertyTest)
{
    MakeSmbusConfiguration(mctp_server::MctpPhysicalMediumIdentifiers::SmbusI2c,
                           mctp_server::BindingModeTypes::BusOwner, 1,
                           {2, 3, 4, 5, 6}, "");
    /* Set test pass conditions */
    EXPECT_CALL(
        *objectServerMock->dbusIfMock,
        register_property(StrEq("Eid"), An<uint8_t>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *objectServerMock->dbusIfMock,
        register_property(StrEq("StaticEid"), An<bool>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *objectServerMock->dbusIfMock,
        register_property(StrEq("BindingID"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *objectServerMock->dbusIfMock,
        register_property(StrEq("BindingMediumID"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *objectServerMock->dbusIfMock,
        register_property(StrEq("BindingMode"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *objectServerMock->dbusIfMock,
        register_property(StrEq("Uuid"), An<std::vector<uint8_t>>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*objectServerMock->dbusIfMock,
                register_signal(StrEq("MessageReceivedSignal")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*objectServerMock->dbusIfMock,
                register_method(StrEq("SendMctpMessagePayload")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*objectServerMock->dbusIfMock,
                register_method(StrEq("SendReceiveMctpMessagePayload")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*objectServerMock->dbusIfMock,
                register_method(StrEq("ReserveBandwidth")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *objectServerMock->dbusIfMock,
        register_property(StrEq("ArpMasterSupport"), An<bool>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *objectServerMock->dbusIfMock,
        register_property(StrEq("BusPath"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *objectServerMock->dbusIfMock,
        register_property(StrEq("BmcSlaveAddress"), An<uint8_t>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*objectServerMock->dbusIfMock, initialize())
        .Times(2)
        .WillRepeatedly(Return(true));

    /*Invoke constructor */
    boost::asio::io_context ioc;

    std::unique_ptr<MctpBinding> bindingPtr = std::make_unique<SMBusBinding>(
        objectServerMock, mctpBaseObj, smbusConfig, ioc);
    bindingPtr->initializeBinding();
}
