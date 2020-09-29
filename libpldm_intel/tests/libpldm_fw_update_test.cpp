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

TEST(GetFirmwareParameters, testGoodEncodeRequest)
{
    std::array<uint8_t, sizeof(pldm_msg_hdr)> requestMsg{};
    auto requestPtr = reinterpret_cast<pldm_msg*>(requestMsg.data());
    uint8_t instanceId = 0x01;

    auto rc = encode_get_firmware_parameters_req(
        instanceId, requestPtr, PLDM_GET_FIRMWARE_PARAMENTERS_REQ_BYTES);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(requestPtr->hdr.request, PLDM_REQUEST);
    EXPECT_EQ(requestPtr->hdr.instance_id, instanceId);
    EXPECT_EQ(requestPtr->hdr.type, PLDM_FWU);
    EXPECT_EQ(requestPtr->hdr.command, PLDM_GET_FIRMWARE_PARAMENTERS);
}

TEST(GetFirmwareParameters, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_SUCCESS;
    // ActiveCompImageSetVerStrLen is not fixed here taking it as 8
    constexpr uint8_t activeCompImageSetVerStrLen = 8;
    // PendingCompImageSetVerStrLen is not fixed here taking it as 8
    constexpr uint8_t pendingCompImageSetVerStrLen = 8;
    // ActiveCompVerStrLen is not fixed here taking it as 8
    constexpr uint8_t activeCompVerStrLen = 8;
    // PendingCompVerStrLen is not fixed here taking it as 8
    constexpr uint8_t pendingCompVerStrLen = 8;

    constexpr size_t respLen = sizeof(struct get_firmware_parameters_resp) +
                               activeCompImageSetVerStrLen +
                               pendingCompImageSetVerStrLen +
                               sizeof(struct component_parameter_table) +
                               activeCompVerStrLen + pendingCompVerStrLen;
    std::array<uint8_t, hdrSize + respLen> responseMsg{};
    struct get_firmware_parameters_resp* inResp =
        reinterpret_cast<struct get_firmware_parameters_resp*>(
            responseMsg.data() + hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->capabilities_during_update = 0x0F;
    inResp->comp_count = 1;
    inResp->active_comp_image_set_ver_str_type = 1;
    inResp->active_comp_image_set_ver_str_len = activeCompImageSetVerStrLen;
    inResp->pending_comp_image_set_ver_str_type = 1;
    inResp->pending_comp_image_set_ver_str_len = pendingCompImageSetVerStrLen;

    constexpr uint32_t activeCompImageSetVerStrIndex =
        hdrSize + sizeof(struct get_firmware_parameters_resp);
    // filling default values for ActiveComponentImageSetVersionString
    std::fill_n(responseMsg.data() + activeCompImageSetVerStrIndex,
                activeCompImageSetVerStrLen, 0xFF);

    constexpr uint32_t pendingCompImageSetVerStrIndex =
        hdrSize + sizeof(struct get_firmware_parameters_resp) +
        activeCompImageSetVerStrLen;
    // filling default values for ActiveComponentImageSetVersionString
    std::fill_n(responseMsg.data() + pendingCompImageSetVerStrIndex,
                pendingCompImageSetVerStrLen, 0xFF);

    struct component_parameter_table* inCompData =
        reinterpret_cast<struct component_parameter_table*>(
            responseMsg.data() + hdrSize +
            sizeof(struct get_firmware_parameters_resp) +
            activeCompImageSetVerStrLen + pendingCompImageSetVerStrLen);
    inCompData->comp_classification = 0x0F;
    inCompData->comp_identifier = 0x01;
    inCompData->comp_classification_index = 0x0F;
    inCompData->active_comp_comparison_stamp = 0;
    inCompData->active_comp_ver_str_type = 1;
    inCompData->active_comp_ver_str_len = activeCompVerStrLen;
    inCompData->active_comp_release_date = 0xFF,

    inCompData->pending_comp_comparison_stamp = 0;
    inCompData->pending_comp_ver_str_type = 1;
    inCompData->pending_comp_ver_str_len = pendingCompVerStrLen;
    inCompData->pending_comp_release_date = 0xFF;

    inCompData->comp_activation_methods = 0x0F;
    inCompData->capabilities_during_update = 0x0F;

    constexpr uint32_t activeCompVerStrIndex =
        hdrSize + sizeof(struct get_firmware_parameters_resp) +
        activeCompImageSetVerStrLen + pendingCompImageSetVerStrLen +
        sizeof(struct component_parameter_table);
    std::fill_n(responseMsg.data() + activeCompVerStrIndex, activeCompVerStrLen,
                0xFF);

    constexpr uint32_t pendingCompVerStrIndex =
        activeCompVerStrIndex + activeCompVerStrLen;
    std::fill_n(responseMsg.data() + pendingCompVerStrIndex,
                pendingCompVerStrLen, 0xFF);

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    struct get_firmware_parameters_resp outResp;

    struct variable_field outActiveCompImageSetVerStr;
    std::array<uint8_t, PLDM_FWU_COMP_VER_STR_SIZE_MAX>
        activeCompImageSetVerStr;
    outActiveCompImageSetVerStr.ptr = activeCompImageSetVerStr.data();
    outActiveCompImageSetVerStr.length = PLDM_FWU_COMP_VER_STR_SIZE_MAX;

    struct variable_field outPendingCompImageSetVerStr;
    std::array<uint8_t, PLDM_FWU_COMP_VER_STR_SIZE_MAX>
        pendingCompImageSetVerStr;
    outPendingCompImageSetVerStr.ptr = pendingCompImageSetVerStr.data();
    outPendingCompImageSetVerStr.length = PLDM_FWU_COMP_VER_STR_SIZE_MAX;

    struct component_parameter_table outCompData;
    struct variable_field outActiveCompVerStr;
    std::array<uint8_t, PLDM_FWU_COMP_VER_STR_SIZE_MAX> activeCompVerStr;
    outActiveCompVerStr.ptr = activeCompVerStr.data();
    outActiveCompVerStr.length = PLDM_FWU_COMP_VER_STR_SIZE_MAX;

    struct variable_field outPendingCompVerStr;
    std::array<uint8_t, PLDM_FWU_COMP_VER_STR_SIZE_MAX> pendingCompVerStr;
    outPendingCompVerStr.ptr = pendingCompVerStr.data();
    outPendingCompVerStr.length = PLDM_FWU_COMP_VER_STR_SIZE_MAX;

    auto rc = decode_get_firmware_parameters_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &outResp,
        &outActiveCompImageSetVerStr, &outPendingCompImageSetVerStr,
        &outCompData, &outActiveCompVerStr, &outPendingCompVerStr);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);

    EXPECT_EQ(inResp->capabilities_during_update,
              outResp.capabilities_during_update);
    EXPECT_EQ(inResp->comp_count, outResp.comp_count);
    EXPECT_EQ(inResp->active_comp_image_set_ver_str_type,
              outResp.active_comp_image_set_ver_str_type);
    EXPECT_EQ(inResp->active_comp_image_set_ver_str_len,
              outResp.active_comp_image_set_ver_str_len);
    EXPECT_EQ(true,
              std::equal(activeCompImageSetVerStr.begin(),
                         activeCompImageSetVerStr.begin() +
                             outResp.active_comp_image_set_ver_str_len,
                         responseMsg.data() + activeCompImageSetVerStrIndex));

    EXPECT_EQ(inResp->pending_comp_image_set_ver_str_type,
              outResp.pending_comp_image_set_ver_str_type);
    EXPECT_EQ(inResp->pending_comp_image_set_ver_str_len,
              outResp.pending_comp_image_set_ver_str_len);
    EXPECT_EQ(true,
              std::equal(pendingCompImageSetVerStr.begin(),
                         pendingCompImageSetVerStr.begin() +
                             outResp.pending_comp_image_set_ver_str_len,
                         responseMsg.data() + pendingCompImageSetVerStrIndex));

    EXPECT_EQ(inCompData->comp_classification, outCompData.comp_classification);
    EXPECT_EQ(inCompData->comp_identifier, outCompData.comp_identifier);
    EXPECT_EQ(inCompData->comp_classification_index,
              outCompData.comp_classification_index);
    EXPECT_EQ(inCompData->active_comp_comparison_stamp,
              outCompData.active_comp_comparison_stamp);
    EXPECT_EQ(inCompData->active_comp_ver_str_type,
              outCompData.active_comp_ver_str_type);
    EXPECT_EQ(inCompData->active_comp_ver_str_len,
              outCompData.active_comp_ver_str_len);
    EXPECT_EQ(inCompData->active_comp_release_date,
              outCompData.active_comp_release_date);

    EXPECT_EQ(inCompData->pending_comp_comparison_stamp,
              outCompData.pending_comp_comparison_stamp);
    EXPECT_EQ(inCompData->pending_comp_ver_str_type,
              outCompData.pending_comp_ver_str_type);
    EXPECT_EQ(inCompData->pending_comp_ver_str_len,
              outCompData.pending_comp_ver_str_len);
    EXPECT_EQ(inCompData->pending_comp_release_date,
              outCompData.pending_comp_release_date);

    EXPECT_EQ(inCompData->comp_activation_methods,
              outCompData.comp_activation_methods);
    EXPECT_EQ(inCompData->capabilities_during_update,
              outCompData.capabilities_during_update);
    EXPECT_EQ(true, std::equal(activeCompVerStr.begin(),
                               activeCompVerStr.begin() +
                                   outCompData.active_comp_ver_str_len,
                               responseMsg.data() + activeCompVerStrIndex));
    EXPECT_EQ(true, std::equal(pendingCompVerStr.begin(),
                               pendingCompVerStr.begin() +
                                   outCompData.pending_comp_ver_str_len,
                               responseMsg.data() + pendingCompVerStrIndex));
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
