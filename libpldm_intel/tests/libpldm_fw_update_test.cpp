#include "../base.h"
#include "../firmware_update.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

constexpr auto hdrSize = sizeof(pldm_msg_hdr);

TEST(QueryDeviceIdentifiers, testGoodEncodeRequest)
{
    uint8_t instanceId = 0x01;
    struct pldm_msg msg;

    auto rc = encode_query_device_identifiers_req(instanceId, &msg);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg.hdr.instance_id, instanceId);
    EXPECT_EQ(msg.hdr.type, PLDM_FWU);
    EXPECT_EQ(msg.hdr.command, PLDM_QUERY_DEVICE_IDENTIFIERS);
}

TEST(QueryDeviceIdentifiers, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_SUCCESS;
    uint32_t deviceIdentifiersLen = 0;
    uint8_t descriptorCount = 0;
    // descriptorDataLen is not fixed here taking it as 6
    constexpr uint8_t descriptorDataLen = 6;
    std::array<uint8_t, descriptorDataLen> descriptor_data;

    std::array<uint8_t, hdrSize + sizeof(struct query_device_identifiers_resp) +
                            descriptorDataLen>
        responseMsg{};
    struct query_device_identifiers_resp* inResp =
        reinterpret_cast<struct query_device_identifiers_resp*>(
            responseMsg.data() + hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->device_identifiers_len = descriptorDataLen;
    inResp->descriptor_count = 1;

    // filling descriptor data
    std::fill(responseMsg.data() + hdrSize +
                  sizeof(struct query_device_identifiers_resp),
              responseMsg.end() - 1, 0xFF);

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_query_device_identifiers_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &deviceIdentifiersLen, &descriptorCount, descriptor_data.data());

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);
    EXPECT_EQ(deviceIdentifiersLen, inResp->device_identifiers_len);
    EXPECT_EQ(descriptorCount, inResp->descriptor_count);
    EXPECT_EQ(true,
              std::equal(descriptor_data.begin(), descriptor_data.end(),
                         responseMsg.data() + hdrSize +
                             sizeof(struct query_device_identifiers_resp)));
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
