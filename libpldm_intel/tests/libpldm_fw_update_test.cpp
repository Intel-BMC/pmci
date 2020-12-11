#include "../base.h"
#include "../firmware_update.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

constexpr auto hdrSize = sizeof(pldm_msg_hdr);

TEST(GetStatus, testGoodEncodeRequest)
{
    uint8_t instanceId = 0x01;
    struct pldm_msg msg;
    auto rc = encode_get_status_req(instanceId, &msg);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg.hdr.instance_id, instanceId);
    EXPECT_EQ(msg.hdr.type, PLDM_FWU);
    EXPECT_EQ(msg.hdr.request, PLDM_REQUEST);
    EXPECT_EQ(msg.hdr.command, PLDM_GET_STATUS);
}

TEST(GetStatus, testBadEncodeRequest)
{
    uint8_t instanceId = 0x01;
    auto rc = encode_get_status_req(instanceId, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(GetStatus, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_SUCCESS;
    uint8_t currentState = 0;
    uint8_t previousState = 0;
    uint8_t auxState = 0;
    uint8_t auxStateStatus = 0;
    uint8_t progressPercent = 0;
    uint8_t reasonCode = 0;
    bitfield32_t updateOptionFlagsEnabled = {0};

    std::array<uint8_t, hdrSize + sizeof(struct get_status_resp)> responseMsg{};
    struct get_status_resp* inResp =
        reinterpret_cast<struct get_status_resp*>(responseMsg.data() + hdrSize);
    inResp->aux_state = FD_OPERATION_SUCCESSFUL;
    inResp->aux_state_status = 0x71;
    inResp->current_state = FD_ACTIVATE;
    inResp->previous_state = FD_LEARN_COMPONENTS;
    inResp->progress_percent = 0x44;
    inResp->reason_code = FD_TIMEOUT_LEARN_COMPONENT;
    inResp->update_option_flags_enabled.value = 1;
    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());
    response->hdr.command = PLDM_GET_STATUS;
    response->hdr.request = 0b0;
    response->hdr.datagram = 0b0;
    response->hdr.type = PLDM_FWU;
    response->payload[0] = PLDM_SUCCESS;
    auto rc = decode_get_status_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &currentState,
        &previousState, &auxState, &auxStateStatus, &progressPercent,
        &reasonCode, &updateOptionFlagsEnabled);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);
    EXPECT_EQ(currentState, inResp->current_state);
    EXPECT_EQ(previousState, inResp->previous_state);
    EXPECT_EQ(auxState, inResp->aux_state);
    EXPECT_EQ(auxStateStatus, inResp->aux_state_status);
    EXPECT_EQ(progressPercent, inResp->progress_percent);
    EXPECT_EQ(reasonCode, inResp->reason_code);
    EXPECT_EQ(updateOptionFlagsEnabled.value,
              inResp->update_option_flags_enabled.value);
}

TEST(GetStatus, testBadDecodeResponse)
{
    uint8_t completionCode = PLDM_SUCCESS;
    uint8_t currentState = false;
    uint8_t previousState = false;
    uint8_t auxState = false;
    uint8_t auxStateStatus = false;
    uint8_t progressPercent = 0;
    uint8_t reasonCode = false;
    bitfield32_t updateOptionFlagsEnabled = {0};
    std::array<uint8_t, hdrSize + sizeof(struct get_status_resp)> responseMsg{};
    struct get_status_resp* inResp =
        reinterpret_cast<struct get_status_resp*>(responseMsg.data() + hdrSize);
    inResp->aux_state = 1;
    inResp->aux_state_status = 0x00;
    inResp->current_state = FD_LEARN_COMPONENTS;
    inResp->previous_state = FD_LEARN_COMPONENTS;
    inResp->progress_percent = 0x44;
    inResp->reason_code = FD_TIMEOUT_LEARN_COMPONENT;
    inResp->update_option_flags_enabled.value = 1;
    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());
    response->hdr.command = PLDM_GET_STATUS;
    response->hdr.request = 0b0;
    response->hdr.datagram = 0b0;
    response->hdr.type = PLDM_FWU;
    response->payload[0] = PLDM_ERROR;
    auto rc = decode_get_status_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &currentState,
        &previousState, &auxState, &auxStateStatus, &progressPercent,
        &reasonCode, &updateOptionFlagsEnabled);
    EXPECT_EQ(rc, PLDM_ERROR);
    response->payload[0] = PLDM_SUCCESS;
    inResp->aux_state = 4;
    inResp->aux_state_status = 0x05;
    inResp->current_state = 9;
    inResp->previous_state = 10;
    inResp->progress_percent = 0x44;
    inResp->reason_code = 8;
    inResp->update_option_flags_enabled.value = 1;
    rc = decode_get_status_resp(response, responseMsg.size() - hdrSize,
                                &completionCode, &currentState, &previousState,
                                &auxState, &auxStateStatus, &progressPercent,
                                &reasonCode, &updateOptionFlagsEnabled);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    inResp->reason_code = FD_STATUS_VENDOR_DEFINED_MIN - 1;
    rc = decode_get_status_resp(response, responseMsg.size() - hdrSize,
                                &completionCode, &currentState, &previousState,
                                &auxState, &auxStateStatus, &progressPercent,
                                &reasonCode, &updateOptionFlagsEnabled);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_get_status_resp(NULL, responseMsg.size() - hdrSize,
                                &completionCode, &currentState, &previousState,
                                &auxState, &auxStateStatus, &progressPercent,
                                &reasonCode, &updateOptionFlagsEnabled);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_get_status_resp(response, 0, &completionCode, &currentState,
                                &previousState, &auxState, &auxStateStatus,
                                &progressPercent, &reasonCode,
                                &updateOptionFlagsEnabled);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
}

TEST(CancelUpdate, testGoodEncodeRequest)
{
    uint8_t instanceId = 0x03;
    struct pldm_msg msg;
    auto rc = encode_cancel_update_req(instanceId, &msg);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg.hdr.instance_id, instanceId);
    EXPECT_EQ(msg.hdr.type, PLDM_FWU);
    EXPECT_EQ(msg.hdr.request, PLDM_REQUEST);
    EXPECT_EQ(msg.hdr.command, PLDM_CANCEL_UPDATE);
}

TEST(CancelUpdate, testBadEncodeRequest)
{
    uint8_t instanceId = 0x03;
    auto rc = encode_cancel_update_req(instanceId, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(CancelUpdate, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    bool8_t nonFunctioningComponentIndication = COMPONENTS_FUNCTIONING;
    bitfield64_t nonFunctioningComponentBitmap = {1};

    std::array<uint8_t, hdrSize + sizeof(struct cancel_update_resp)>
        responseMsg{};

    struct cancel_update_resp* inResp =
        reinterpret_cast<struct cancel_update_resp*>(responseMsg.data() +
                                                     hdrSize);

    inResp->completion_code = PLDM_SUCCESS;
    inResp->non_functioning_component_indication = 0;
    inResp->non_functioning_component_bitmap = 1;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    response->hdr.command = PLDM_CANCEL_UPDATE;
    response->hdr.request = 0b0;
    response->hdr.datagram = 0b0;
    response->hdr.type = PLDM_FWU;
    response->payload[0] = PLDM_SUCCESS;

    auto rc = decode_cancel_update_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nonFunctioningComponentIndication, &nonFunctioningComponentBitmap);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);
    EXPECT_EQ(nonFunctioningComponentIndication,
              inResp->non_functioning_component_indication);
    EXPECT_EQ(nonFunctioningComponentBitmap.value,
              htole64(inResp->non_functioning_component_bitmap));
    inResp->non_functioning_component_indication = COMPONENTS_FUNCTIONING;
    nonFunctioningComponentBitmap = {0x5};
    rc = decode_cancel_update_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nonFunctioningComponentIndication, &nonFunctioningComponentBitmap);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(nonFunctioningComponentIndication,
              inResp->non_functioning_component_indication);
    EXPECT_EQ(nonFunctioningComponentBitmap.value, 0x5);
}

TEST(CancelUpdate, testBadDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    bool8_t nonFunctioningComponentIndication = COMPONENTS_NOT_FUNCTIONING;
    bitfield64_t nonFunctioningComponentBitmap = {1};

    std::array<uint8_t, hdrSize + sizeof(struct cancel_update_resp)>
        responseMsg{};

    struct cancel_update_resp* inResp =
        reinterpret_cast<struct cancel_update_resp*>(responseMsg.data() +
                                                     hdrSize);

    inResp->completion_code = PLDM_SUCCESS;
    inResp->non_functioning_component_indication = 1;
    inResp->non_functioning_component_bitmap = 1;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    response->hdr.command = PLDM_CANCEL_UPDATE;
    response->hdr.request = 0b0;
    response->hdr.datagram = 0b0;
    response->hdr.type = PLDM_FWU;
    response->payload[0] = PLDM_SUCCESS;

    auto rc = decode_cancel_update_resp(response, 0, &completionCode,
                                        &nonFunctioningComponentIndication,
                                        &nonFunctioningComponentBitmap);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    response->payload[0] = PLDM_ERROR_INVALID_DATA;
    rc = decode_cancel_update_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nonFunctioningComponentIndication, &nonFunctioningComponentBitmap);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_cancel_update_resp(
        NULL, responseMsg.size() - hdrSize, &completionCode,
        &nonFunctioningComponentIndication, &nonFunctioningComponentBitmap);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_cancel_update_resp(response, responseMsg.size() - hdrSize, NULL,
                                   &nonFunctioningComponentIndication,
                                   &nonFunctioningComponentBitmap);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_cancel_update_resp(response, responseMsg.size() - hdrSize,
                                   &completionCode, NULL,
                                   &nonFunctioningComponentBitmap);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_cancel_update_resp(response, responseMsg.size() - hdrSize,
                                   &completionCode,
                                   &nonFunctioningComponentIndication, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->non_functioning_component_indication = COMPONENTS_FUNCTIONING - 1;
    rc = decode_cancel_update_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nonFunctioningComponentIndication, &nonFunctioningComponentBitmap);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->non_functioning_component_indication =
        COMPONENTS_NOT_FUNCTIONING + 1;
    rc = decode_cancel_update_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nonFunctioningComponentIndication, &nonFunctioningComponentBitmap);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->non_functioning_component_indication = 0x0F;
    rc = decode_cancel_update_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nonFunctioningComponentIndication, &nonFunctioningComponentBitmap);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(VerifyComplete, testGoodEncodeResponse)
{
    uint8_t instanceId = 0x01;
    uint8_t completionCode = PLDM_SUCCESS;
    std::array<uint8_t, (hdrSize + 1)> responseMsg{};
    auto responsePtr = reinterpret_cast<pldm_msg*>(responseMsg.data());
    auto rc =
        encode_verify_complete_resp(instanceId, completionCode, responsePtr);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(responsePtr->hdr.request, PLDM_RESPONSE);
    EXPECT_EQ(responsePtr->hdr.instance_id, instanceId);
    EXPECT_EQ(responsePtr->hdr.type, PLDM_FWU);
    EXPECT_EQ(responsePtr->hdr.command, PLDM_VERIFY_COMPLETE);
    EXPECT_EQ(responsePtr->payload[0], completionCode);
}

TEST(VerifyComplete, testBadEncodeResponse)
{
    uint8_t instanceId = 0x01;
    uint8_t completionCode = PLDM_SUCCESS;
    auto rc = encode_verify_complete_resp(instanceId, completionCode, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(VerifyComplete, testGoodDecodeRequest)
{
    std::array<uint8_t, (hdrSize + 1)> request;
    uint8_t verifyResult = 0;
    auto requestPtr = reinterpret_cast<pldm_msg*>(request.data());
    requestPtr->payload[0] = PLDM_FWU_VERIFY_COMPLETED_WITH_ERROR;
    auto rc = decode_verify_complete_req(requestPtr, &verifyResult);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(verifyResult, PLDM_FWU_VERIFY_COMPLETED_WITH_ERROR);
}

TEST(VerifyComplete, testBadDecodeRequest)
{
    std::array<uint8_t, (hdrSize + 1)> request;
    uint8_t verifyResult = 0;
    auto requestPtr = reinterpret_cast<pldm_msg*>(request.data());
    requestPtr->payload[0] = PLDM_FWU_VERIFY_COMPLETED_WITH_ERROR;
    auto rc = decode_verify_complete_req(NULL, &verifyResult);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    requestPtr->payload[0] = PLDM_FWU_VENDOR_SPEC_STATUS_RANGE_MIN - 1;
    rc = decode_verify_complete_req(requestPtr, &verifyResult);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    requestPtr->payload[0] = PLDM_FWU_VENDOR_SPEC_STATUS_RANGE_MAX + 1;
    rc = decode_verify_complete_req(requestPtr, &verifyResult);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(TransferComplete, testGoodEncodeResponse)
{
    uint8_t instanceId = 0x01;
    uint8_t completionCode = PLDM_SUCCESS;
    std::array<uint8_t, (hdrSize + 1)> responseMsg{};
    auto responsePtr = reinterpret_cast<pldm_msg*>(responseMsg.data());
    auto rc =
        encode_transfer_complete_resp(instanceId, completionCode, responsePtr);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(responsePtr->hdr.request, PLDM_RESPONSE);
    EXPECT_EQ(responsePtr->hdr.instance_id, instanceId);
    EXPECT_EQ(responsePtr->hdr.type, PLDM_FWU);
    EXPECT_EQ(responsePtr->hdr.command, PLDM_TRANSFER_COMPLETE);
    EXPECT_EQ(responsePtr->payload[0], completionCode);
}

TEST(TransferComplete, testBadEncodeResponse)
{
    uint8_t instanceId = 0x01;
    uint8_t completionCode = PLDM_SUCCESS;
    auto rc = encode_transfer_complete_resp(instanceId, completionCode, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(TransferComplete, testGoodDecodeRequest)
{
    std::array<uint8_t, (hdrSize + 1)> request;
    uint8_t transferResult;
    auto requestPtr = reinterpret_cast<pldm_msg*>(request.data());
    requestPtr->payload[0] = PLDM_FWU_TRASFER_SUCCESS;
    auto rc = decode_transfer_complete_req(requestPtr, &transferResult);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(transferResult, PLDM_FWU_TRASFER_SUCCESS);
    requestPtr->payload[0] = PLDM_FWU_VENDOR_TRANSFER_RESULT_RANGE_MIN;
    rc = decode_transfer_complete_req(requestPtr, &transferResult);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(transferResult, PLDM_FWU_VENDOR_TRANSFER_RESULT_RANGE_MIN);
    requestPtr->payload[0] = PLDM_FWU_VENDOR_TRANSFER_RESULT_RANGE_MAX;
    rc = decode_transfer_complete_req(requestPtr, &transferResult);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(transferResult, PLDM_FWU_VENDOR_TRANSFER_RESULT_RANGE_MAX);
}

TEST(TransferComplete, testBadDecodeRequest)
{
    std::array<uint8_t, (hdrSize + 1)> request;
    uint8_t transferResult;
    auto requestPtr = reinterpret_cast<pldm_msg*>(request.data());
    requestPtr->payload[0] = PLDM_FWU_TRASFER_SUCCESS;
    auto rc = decode_transfer_complete_req(NULL, &transferResult);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    requestPtr->payload[0] = PLDM_FWU_VENDOR_TRANSFER_RESULT_RANGE_MIN - 1;
    rc = decode_transfer_complete_req(requestPtr, &transferResult);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    requestPtr->payload[0] = PLDM_FWU_VENDOR_TRANSFER_RESULT_RANGE_MAX + 1;
    rc = decode_transfer_complete_req(requestPtr, &transferResult);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(GetMetaData_GetPackageData, testGoodEncodeResponse)
{
    constexpr uint8_t metaDataLen = 8;
    struct variable_field portionOfMetaData;
    uint8_t instanceID = 0x01;
    struct get_fd_data_resp inResp;
    inResp.completion_code = PLDM_SUCCESS;
    inResp.next_data_transfer_handle = 0xFFAB;
    inResp.transfer_flag = PLDM_START;
    std::array<uint8_t, metaDataLen> metaData{};
    portionOfMetaData.length = metaDataLen;
    portionOfMetaData.ptr = metaData.data();
    std::fill(metaData.data(), metaData.end(), 0xFF);
    std::array<uint8_t, hdrSize + sizeof(struct get_fd_data_resp) + metaDataLen>
        responseMsg{};
    auto responsePtr = reinterpret_cast<pldm_msg*>(responseMsg.data());
    auto rc =
        encode_get_meta_data_resp(instanceID, responseMsg.size() - hdrSize,
                                  responsePtr, &inResp, &portionOfMetaData);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(responsePtr->hdr.request, PLDM_RESPONSE);
    EXPECT_EQ(responsePtr->hdr.instance_id, instanceID);
    EXPECT_EQ(responsePtr->hdr.type, PLDM_FWU);
    EXPECT_EQ(responsePtr->hdr.command, PLDM_GET_META_DATA);
    auto resp = reinterpret_cast<get_fd_data_resp*>(responsePtr->payload);
    EXPECT_EQ(resp->completion_code, inResp.completion_code);
    EXPECT_EQ(resp->next_data_transfer_handle,
              le32toh(inResp.next_data_transfer_handle));
    EXPECT_EQ(resp->transfer_flag, inResp.transfer_flag);
    instanceID = 0x04;
    inResp.completion_code = PLDM_SUCCESS;
    inResp.next_data_transfer_handle = 0xFFDE;
    inResp.transfer_flag = PLDM_END;
    rc = encode_get_package_data_resp(instanceID, responseMsg.size() - hdrSize,
                                      responsePtr, &inResp, &portionOfMetaData);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(responsePtr->hdr.request, PLDM_RESPONSE);
    EXPECT_EQ(responsePtr->hdr.instance_id, instanceID);
    EXPECT_EQ(responsePtr->hdr.type, PLDM_FWU);
    EXPECT_EQ(responsePtr->hdr.command, PLDM_GET_PACKAGE_DATA);
    resp = reinterpret_cast<get_fd_data_resp*>(responsePtr->payload);
    EXPECT_EQ(resp->completion_code, inResp.completion_code);
    EXPECT_EQ(resp->next_data_transfer_handle,
              le32toh(inResp.next_data_transfer_handle));
    EXPECT_EQ(resp->transfer_flag, inResp.transfer_flag);
}

TEST(GetMetaData_GetPackageData, testBadEncodeResponse)
{
    constexpr uint8_t metaDataLen = 8;
    struct variable_field portionOfMetaData;
    uint8_t instanceID = 0x01;
    struct get_fd_data_resp inResp;

    inResp.completion_code = PLDM_SUCCESS;
    inResp.next_data_transfer_handle = 0xFFAB;
    inResp.transfer_flag = PLDM_START;
    std::array<uint8_t, metaDataLen> metaData{};
    portionOfMetaData.ptr = metaData.data();
    portionOfMetaData.length = metaDataLen;
    std::fill(metaData.data(), metaData.end(), 0xFF);
    std::array<uint8_t, hdrSize + sizeof(struct get_fd_data_resp) + metaDataLen>
        responseMsg{};
    auto responsePtr = reinterpret_cast<pldm_msg*>(responseMsg.data());
    auto rc =
        encode_get_meta_data_resp(instanceID, responseMsg.size() - hdrSize,
                                  NULL, &inResp, &portionOfMetaData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    inResp.transfer_flag = 0x6;
    rc = encode_get_meta_data_resp(instanceID, responseMsg.size() - hdrSize,
                                   responsePtr, &inResp, &portionOfMetaData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = encode_get_meta_data_resp(instanceID, 0, responsePtr, &inResp,
                                   &portionOfMetaData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
    inResp.transfer_flag = PLDM_START;
    portionOfMetaData.ptr = NULL;
    rc = encode_get_meta_data_resp(instanceID, responseMsg.size() - hdrSize,
                                   responsePtr, &inResp, &portionOfMetaData);
    EXPECT_EQ(rc, PLDM_ERROR);
}

TEST(GetMetaData_GetPackageData, testGoodDecodeRequest)
{
    uint32_t dataTransferHandle;
    uint8_t transferOperationFlag;
    uint32_t handleIn = 0xFFAB;
    std::array<uint8_t, hdrSize + sizeof(struct get_fd_data_req)> requestMsg{};
    struct get_fd_data_req* request =
        reinterpret_cast<struct get_fd_data_req*>(requestMsg.data() + hdrSize);
    request->data_transfer_handle = htole32(handleIn);
    request->transfer_operation_flag = PLDM_GET_NEXTPART;
    auto requestPtr = reinterpret_cast<pldm_msg*>(requestMsg.data());
    HTOLE32(request->data_transfer_handle);
    auto rc =
        decode_get_meta_data_req(requestPtr, requestMsg.size() - hdrSize,
                                 &dataTransferHandle, &transferOperationFlag);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(dataTransferHandle, handleIn);
    EXPECT_EQ(transferOperationFlag, request->transfer_operation_flag);
}

TEST(GetMetaData_GetPackageData, testBadDecodeRequest)
{
    uint32_t dataTransferHandle;
    uint8_t transferOperationFlag;
    uint32_t handleIn = 0xFFAB;
    std::array<uint8_t, hdrSize + sizeof(struct get_fd_data_req)> requestMsg{};
    struct get_fd_data_req* request =
        reinterpret_cast<struct get_fd_data_req*>(requestMsg.data() + hdrSize);
    request->data_transfer_handle = htole32(handleIn);
    request->transfer_operation_flag = PLDM_GET_NEXTPART;
    auto requestPtr = reinterpret_cast<pldm_msg*>(requestMsg.data());
    auto rc =
        decode_get_meta_data_req(NULL, requestMsg.size() - hdrSize,
                                 &dataTransferHandle, &transferOperationFlag);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_get_meta_data_req(requestPtr, 0, &dataTransferHandle,
                                  &transferOperationFlag);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
    request->transfer_operation_flag = PLDM_GET_FIRSTPART + 1;
    rc = decode_get_meta_data_req(requestPtr, requestMsg.size() - hdrSize,
                                  &dataTransferHandle, &transferOperationFlag);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(QueryDeviceIdentifiers, testGoodEncodeRequest)
{
    std::array<uint8_t, sizeof(pldm_msg_hdr)> requestMsg{};
    auto requestPtr = reinterpret_cast<pldm_msg*>(requestMsg.data());

    uint8_t instanceId = 0x01;

    auto rc = encode_query_device_identifiers_req(
        instanceId, requestPtr, PLDM_QUERY_DEVICE_IDENTIFIERS_REQ_BYTES);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(requestPtr->hdr.request, PLDM_REQUEST);
    EXPECT_EQ(requestPtr->hdr.instance_id, instanceId);
    EXPECT_EQ(requestPtr->hdr.type, PLDM_FWU);
    EXPECT_EQ(requestPtr->hdr.command, PLDM_QUERY_DEVICE_IDENTIFIERS);
}

TEST(QueryDeviceIdentifiers, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_SUCCESS;
    uint32_t deviceIdentifiersLen = 0;
    uint8_t descriptorCount = 0;
    // descriptorDataLen is not fixed here taking it as 6
    constexpr uint8_t descriptorDataLen = 6;
    std::array<uint8_t, descriptorDataLen> descriptorData;
    struct variable_field outDescriptorData;
    outDescriptorData.length = descriptorData.size();
    outDescriptorData.ptr = descriptorData.data();

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
        &deviceIdentifiersLen, &descriptorCount, &outDescriptorData);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);
    EXPECT_EQ(deviceIdentifiersLen, inResp->device_identifiers_len);
    EXPECT_EQ(descriptorCount, inResp->descriptor_count);
    EXPECT_EQ(true,
              std::equal(descriptorData.begin(), descriptorData.end() - 1,
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

TEST(GetFWParams, testGoodDecodeCompImgSetResponse)
{
    // ActiveCompImageSetVerStrLen is not fixed here taking it as 8
    constexpr uint8_t activeCompImageSetVerStrLen = 8;
    // PendingCompImageSetVerStrLen is not fixed here taking it as 8
    constexpr uint8_t pendingCompImageSetVerStrLen = 8;

    constexpr size_t payloadLen = sizeof(struct get_firmware_parameters_resp) +
                                  activeCompImageSetVerStrLen +
                                  pendingCompImageSetVerStrLen;

    std::array<uint8_t, hdrSize + payloadLen> response{};
    struct get_firmware_parameters_resp* inResp =
        reinterpret_cast<struct get_firmware_parameters_resp*>(response.data() +
                                                               hdrSize);
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
    std::fill_n(response.data() + activeCompImageSetVerStrIndex,
                activeCompImageSetVerStrLen, 0xFF);

    constexpr uint32_t pendingCompImageSetVerStrIndex =
        hdrSize + sizeof(struct get_firmware_parameters_resp) +
        activeCompImageSetVerStrLen;
    // filling default values for ActiveComponentImageSetVersionString
    std::fill_n(response.data() + pendingCompImageSetVerStrIndex,
                pendingCompImageSetVerStrLen, 0xFF);

    auto responseMsg = reinterpret_cast<pldm_msg*>(response.data());

    struct get_firmware_parameters_resp outResp;
    struct variable_field outActiveCompImageSetVerStr;
    struct variable_field outPendingCompImageSetVerStr;

    auto rc = decode_get_firmware_parameters_comp_img_set_resp(
        responseMsg, payloadLen, &outResp, &outActiveCompImageSetVerStr,
        &outPendingCompImageSetVerStr);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(inResp->completion_code, PLDM_SUCCESS);

    EXPECT_EQ(inResp->capabilities_during_update,
              outResp.capabilities_during_update);
    EXPECT_EQ(inResp->comp_count, outResp.comp_count);
    EXPECT_EQ(inResp->active_comp_image_set_ver_str_type,
              outResp.active_comp_image_set_ver_str_type);
    EXPECT_EQ(inResp->active_comp_image_set_ver_str_len,
              outResp.active_comp_image_set_ver_str_len);
    EXPECT_EQ(0, memcmp(outActiveCompImageSetVerStr.ptr,
                        response.data() + activeCompImageSetVerStrIndex,
                        outActiveCompImageSetVerStr.length));

    EXPECT_EQ(inResp->pending_comp_image_set_ver_str_type,
              outResp.pending_comp_image_set_ver_str_type);
    EXPECT_EQ(inResp->pending_comp_image_set_ver_str_len,
              outResp.pending_comp_image_set_ver_str_len);
    EXPECT_EQ(0, memcmp(outPendingCompImageSetVerStr.ptr,
                        response.data() + pendingCompImageSetVerStrIndex,
                        outPendingCompImageSetVerStr.length));
}

TEST(GetFWParams, testGoodDecodeCompResponse)
{
    // ActiveCompImageSetVerStrLen is not fixed here taking it as 8
    constexpr uint8_t activeCompVerStrLen = 8;
    // PendingCompImageSetVerStrLen is not fixed here taking it as 8
    constexpr uint8_t pendingCompVerStrLen = 8;

    constexpr size_t payloadLen = sizeof(struct component_parameter_table) +
                                  activeCompVerStrLen + pendingCompVerStrLen;

    std::array<uint8_t, payloadLen> response{};

    struct component_parameter_table* inCompData =
        reinterpret_cast<struct component_parameter_table*>(response.data());

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
        sizeof(struct component_parameter_table);
    std::fill_n(response.data() + activeCompVerStrIndex, activeCompVerStrLen,
                0xFF);

    constexpr uint32_t pendingCompVerStrIndex =
        activeCompVerStrIndex + activeCompVerStrLen;
    std::fill_n(response.data() + pendingCompVerStrIndex, pendingCompVerStrLen,
                0xFF);

    struct component_parameter_table outCompData;
    struct variable_field outActiveCompVerStr;
    struct variable_field outPendingCompVerStr;

    auto rc = decode_get_firmware_parameters_comp_resp(
        response.data(), payloadLen, &outCompData, &outActiveCompVerStr,
        &outPendingCompVerStr);

    EXPECT_EQ(rc, PLDM_SUCCESS);

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

    EXPECT_EQ(0, memcmp(outActiveCompVerStr.ptr,
                        response.data() + activeCompVerStrIndex,
                        outActiveCompVerStr.length));

    EXPECT_EQ(0, memcmp(outPendingCompVerStr.ptr,
                        response.data() + pendingCompVerStrIndex,
                        outPendingCompVerStr.length));
}

TEST(RequestUpdate, testGoodEncodeRequest)
{
    uint8_t instanceId = 0x01;
    // Component Image Set Version String Length is not fixed here taking it as
    // 6
    constexpr uint8_t compImgSetVerStrLen = 6;

    std::array<uint8_t, compImgSetVerStrLen> compImgSetVerStrArr;
    struct variable_field inCompImgSetVerStr;
    inCompImgSetVerStr.ptr = compImgSetVerStrArr.data();
    inCompImgSetVerStr.length = compImgSetVerStrLen;

    struct request_update_req inReq = {};

    inReq.max_transfer_size = 32;
    inReq.no_of_comp = 1;
    inReq.max_outstand_transfer_req = 1;
    inReq.pkg_data_len = 0;
    inReq.comp_image_set_ver_str_type = COMP_VER_STR_TYPE_UNKNOWN;
    inReq.comp_image_set_ver_str_len = compImgSetVerStrLen;

    std::fill(compImgSetVerStrArr.data(), compImgSetVerStrArr.end(), 0xFF);

    std::array<uint8_t, hdrSize + sizeof(struct request_update_req) +
                            compImgSetVerStrLen>
        outReq;

    auto msg = (struct pldm_msg*)outReq.data();

    auto rc = encode_request_update_req(instanceId, msg,
                                        sizeof(struct request_update_req) +
                                            inCompImgSetVerStr.length,
                                        &inReq, &inCompImgSetVerStr);

    auto request = (struct request_update_req*)(outReq.data() + hdrSize);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg->hdr.request, PLDM_REQUEST);
    EXPECT_EQ(msg->hdr.instance_id, instanceId);
    EXPECT_EQ(msg->hdr.type, PLDM_FWU);
    EXPECT_EQ(msg->hdr.command, PLDM_REQUEST_UPDATE);
    EXPECT_EQ(le32toh(request->max_transfer_size), inReq.max_transfer_size);
    EXPECT_EQ(le16toh(request->no_of_comp), inReq.no_of_comp);
    EXPECT_EQ(request->max_outstand_transfer_req,
              inReq.max_outstand_transfer_req);
    EXPECT_EQ(le16toh(request->pkg_data_len), inReq.pkg_data_len);
    EXPECT_EQ(request->comp_image_set_ver_str_type,
              inReq.comp_image_set_ver_str_type);
    EXPECT_EQ(request->comp_image_set_ver_str_len,
              inReq.comp_image_set_ver_str_len);
    EXPECT_EQ(true,
              std::equal(compImgSetVerStrArr.begin(), compImgSetVerStrArr.end(),
                         outReq.data() + hdrSize +
                             sizeof(struct request_update_req)));
}

TEST(RequestUpdate, testBadEncodeRequest)
{
    uint8_t instanceId = 0x01;
    constexpr uint8_t compImgSetVerStrLen = 6;

    std::array<uint8_t, compImgSetVerStrLen> compImgSetVerStrArr;
    struct variable_field inCompImgSetVerStr;
    inCompImgSetVerStr.ptr = compImgSetVerStrArr.data();
    inCompImgSetVerStr.length = compImgSetVerStrLen;

    struct request_update_req inReq = {};

    std::fill(compImgSetVerStrArr.data(), compImgSetVerStrArr.end(), 0xFF);

    std::array<uint8_t, hdrSize + sizeof(struct request_update_req) +
                            compImgSetVerStrLen>
        outReq;

    auto msg = (struct pldm_msg*)outReq.data();

    auto rc = encode_request_update_req(instanceId, 0,
                                        sizeof(struct request_update_req) +
                                            inCompImgSetVerStr.length,
                                        &inReq, &inCompImgSetVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_request_update_req(instanceId, msg, 0, &inReq,
                                   &inCompImgSetVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    rc = encode_request_update_req(instanceId, msg,
                                   sizeof(struct request_update_req) +
                                       inCompImgSetVerStr.length,
                                   NULL, &inCompImgSetVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_request_update_req(instanceId, msg,
                                   sizeof(struct request_update_req) +
                                       inCompImgSetVerStr.length,
                                   &inReq, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inReq.max_transfer_size = 30;
    inReq.no_of_comp = 0;
    inReq.max_outstand_transfer_req = 0;
    inReq.pkg_data_len = 0;
    inReq.comp_image_set_ver_str_type = 10;
    inReq.comp_image_set_ver_str_len = 0;

    rc = encode_request_update_req(instanceId, msg,
                                   sizeof(struct request_update_req) +
                                       inCompImgSetVerStr.length,
                                   &inReq, &inCompImgSetVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    inCompImgSetVerStr.ptr = NULL;
    inCompImgSetVerStr.length = 0;

    rc = encode_request_update_req(instanceId, msg,
                                   sizeof(struct request_update_req) +
                                       inCompImgSetVerStr.length,
                                   &inReq, &inCompImgSetVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
}

TEST(RequestUpdate, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    uint16_t fdMetaDataLen = 0;
    uint8_t fdPkgData = 0;

    std::array<uint8_t, hdrSize + sizeof(struct request_update_resp)>
        responseMsg{};
    struct request_update_resp* inResp =
        reinterpret_cast<struct request_update_resp*>(responseMsg.data() +
                                                      hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->fd_meta_data_len = 0x0F;
    inResp->fd_pkg_data = 0x0F;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc =
        decode_request_update_resp(response, responseMsg.size() - hdrSize,
                                   &completionCode, &fdMetaDataLen, &fdPkgData);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);
    EXPECT_EQ(fdMetaDataLen, htole16(inResp->fd_meta_data_len));
    EXPECT_EQ(fdPkgData, inResp->fd_pkg_data);
}

TEST(RequestUpdate, testBadDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    uint16_t fdMetaDataLen = 0;
    uint8_t fdPkgData = 0;

    std::array<uint8_t, hdrSize + sizeof(struct request_update_resp)>
        responseMsg{};
    struct request_update_resp* inResp =
        reinterpret_cast<struct request_update_resp*>(responseMsg.data() +
                                                      hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->fd_meta_data_len = 0x0F;
    inResp->fd_pkg_data = 0x0F;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc =
        decode_request_update_resp(NULL, responseMsg.size() - hdrSize,
                                   &completionCode, &fdMetaDataLen, &fdPkgData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_request_update_resp(response, 0, &completionCode,
                                    &fdMetaDataLen, &fdPkgData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    rc = decode_request_update_resp(response, responseMsg.size() - hdrSize,
                                    NULL, &fdMetaDataLen, &fdPkgData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_request_update_resp(response, responseMsg.size() - hdrSize,
                                    &completionCode, NULL, &fdPkgData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_request_update_resp(response, responseMsg.size() - hdrSize,
                                    &completionCode, &fdMetaDataLen, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(GetDeviceMetaData, testGoodEncodeRequest)
{
    std::array<uint8_t, hdrSize + sizeof(struct get_device_meta_data_req)>
        requestMsg{};

    auto msg = reinterpret_cast<pldm_msg*>(requestMsg.data());

    auto request = reinterpret_cast<get_device_meta_data_req*>(msg->payload);

    // Random value for data transfer handle
    uint32_t dataTransferHandle = 32;
    uint8_t transferOperationFlag = PLDM_GET_FIRSTPART;

    auto rc = encode_get_device_meta_data_req(
        0, msg, sizeof(struct get_device_meta_data_req), dataTransferHandle,
        transferOperationFlag);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg->hdr.request, PLDM_REQUEST);
    EXPECT_EQ(msg->hdr.instance_id, 0u);
    EXPECT_EQ(msg->hdr.type, PLDM_FWU);
    EXPECT_EQ(msg->hdr.command, PLDM_GET_DEVICE_META_DATA);
    EXPECT_EQ(dataTransferHandle, le32toh(request->data_transfer_handle));
    EXPECT_EQ(transferOperationFlag, request->transfer_operation_flag);
}

TEST(GetDeviceMetaData, testBadEncodeRequest)
{
    std::array<uint8_t, hdrSize + sizeof(struct get_device_meta_data_req)>
        requestMsg{};

    auto msg = reinterpret_cast<pldm_msg*>(requestMsg.data());

    uint32_t dataTransferHandle = 0;
    uint8_t transferOperationFlag = 0;

    auto rc = encode_get_device_meta_data_req(
        0, 0, sizeof(struct get_device_meta_data_req), dataTransferHandle,
        transferOperationFlag);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_get_device_meta_data_req(0, msg, 0, dataTransferHandle,
                                         transferOperationFlag);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_get_device_meta_data_req(
        0, msg, sizeof(struct get_device_meta_data_req), 0,
        transferOperationFlag);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_get_device_meta_data_req(
        0, msg, sizeof(struct get_device_meta_data_req), dataTransferHandle, 0);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    transferOperationFlag = PLDM_GET_FIRSTPART + 1;
    rc = encode_get_device_meta_data_req(
        0, msg, sizeof(struct get_device_meta_data_req), dataTransferHandle,
        transferOperationFlag);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    transferOperationFlag = PLDM_GET_NEXTPART - 1;
    rc = encode_get_device_meta_data_req(
        0, msg, sizeof(struct get_device_meta_data_req), dataTransferHandle,
        transferOperationFlag);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(GetDeviceMetaData, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    uint32_t nextDataTransferHandle = 0;
    uint8_t transferFlag = PLDM_START_AND_END;
    // portionOfMetaDataLen is not fixed here taking it as 6
    constexpr uint8_t portionOfMetaDataLen = 6;
    struct variable_field outPortionMetaData;

    std::array<uint8_t, hdrSize + sizeof(struct get_device_meta_data_resp) +
                            portionOfMetaDataLen>
        responseMsg{};
    struct get_device_meta_data_resp* inResp =
        reinterpret_cast<struct get_device_meta_data_resp*>(responseMsg.data() +
                                                            hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->next_data_transfer_handle = 1;
    inResp->transfer_flag = 0x05;

    // filling portion of meta data
    std::fill(responseMsg.data() + hdrSize +
                  sizeof(struct get_device_meta_data_resp),
              responseMsg.end() - 1, 0xFF);

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_get_device_meta_data_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nextDataTransferHandle, &transferFlag, &outPortionMetaData);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);
    EXPECT_EQ(nextDataTransferHandle,
              htole32(inResp->next_data_transfer_handle));
    EXPECT_EQ(transferFlag, inResp->transfer_flag);
    EXPECT_EQ(0, memcmp(outPortionMetaData.ptr,
                        responseMsg.data() + hdrSize +
                            sizeof(struct get_device_meta_data_resp),
                        outPortionMetaData.length));
}

TEST(GetDeviceMetaData, testBadDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    uint32_t nextDataTransferHandle = 0;
    uint8_t transferFlag = PLDM_START_AND_END;
    constexpr uint8_t portionOfMetaDataLen = 6;

    std::array<uint8_t, portionOfMetaDataLen> portionOfMetaDataArr;
    struct variable_field outPortionMetaData;
    outPortionMetaData.ptr = portionOfMetaDataArr.data();
    outPortionMetaData.length = portionOfMetaDataLen;

    std::array<uint8_t, hdrSize + sizeof(struct get_device_meta_data_resp) +
                            portionOfMetaDataLen>
        responseMsg{};
    struct get_device_meta_data_resp* inResp =
        reinterpret_cast<struct get_device_meta_data_resp*>(responseMsg.data() +
                                                            hdrSize);

    inResp->completion_code = PLDM_SUCCESS;
    inResp->next_data_transfer_handle = 1;
    inResp->transfer_flag = PLDM_START;

    std::fill(portionOfMetaDataArr.data(), portionOfMetaDataArr.end(), 0xFF);

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_get_device_meta_data_resp(
        NULL, responseMsg.size() - hdrSize, &completionCode,
        &nextDataTransferHandle, &transferFlag, &outPortionMetaData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_get_device_meta_data_resp(response, 0, &completionCode,
                                          &nextDataTransferHandle,
                                          &transferFlag, &outPortionMetaData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    rc = decode_get_device_meta_data_resp(
        response, responseMsg.size() - hdrSize, NULL, &nextDataTransferHandle,
        &transferFlag, &outPortionMetaData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_get_device_meta_data_resp(
        response, responseMsg.size() - hdrSize, &completionCode, NULL,
        &transferFlag, &outPortionMetaData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_get_device_meta_data_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nextDataTransferHandle, NULL, &outPortionMetaData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_get_device_meta_data_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nextDataTransferHandle, &transferFlag, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->transfer_flag = PLDM_START - 1;

    rc = decode_get_device_meta_data_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nextDataTransferHandle, &transferFlag, &outPortionMetaData);
    EXPECT_EQ(rc, PLDM_INVALID_TRANSFER_OPERATION_FLAG);

    inResp->transfer_flag = PLDM_START_AND_END + 1;

    rc = decode_get_device_meta_data_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nextDataTransferHandle, &transferFlag, &outPortionMetaData);
    EXPECT_EQ(rc, PLDM_INVALID_TRANSFER_OPERATION_FLAG);

    inResp->transfer_flag = 0x09;

    rc = decode_get_device_meta_data_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nextDataTransferHandle, &transferFlag, &outPortionMetaData);
    EXPECT_EQ(rc, PLDM_INVALID_TRANSFER_OPERATION_FLAG);

    inResp->transfer_flag = 0x01;
    outPortionMetaData.ptr = NULL;
    outPortionMetaData.length = 0;

    rc = decode_get_device_meta_data_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &nextDataTransferHandle, &transferFlag, &outPortionMetaData);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(UpdateComponent, testGoodEncodeRequest)
{
    uint8_t instanceId = 0x01;
    // Component Version String Length is not fixed here taking it as 6
    constexpr uint8_t compVerStrLen = 6;

    std::array<uint8_t, compVerStrLen> compVerStrArr;
    struct variable_field inCompVerStr;
    inCompVerStr.ptr = compVerStrArr.data();
    inCompVerStr.length = compVerStrLen;

    struct update_component_req inReq = {};

    inReq.comp_classification = COMP_OTHER;
    inReq.comp_identifier = 0x01;
    inReq.comp_classification_index = 0x0F;
    inReq.comp_comparison_stamp = 0;
    inReq.comp_image_size = 32;
    inReq.update_option_flags.value = 1;
    inReq.comp_ver_str_type = COMP_ASCII;
    inReq.comp_ver_str_len = compVerStrLen;

    std::fill(compVerStrArr.data(), compVerStrArr.end(), 0xFF);

    std::array<uint8_t,
               hdrSize + sizeof(struct update_component_req) + compVerStrLen>
        outReq;

    auto msg = (struct pldm_msg*)outReq.data();

    auto rc = encode_update_component_req(instanceId, msg,
                                          sizeof(struct update_component_req) +
                                              inCompVerStr.length,
                                          &inReq, &inCompVerStr);

    auto request = (struct update_component_req*)(outReq.data() + hdrSize);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg->hdr.request, PLDM_REQUEST);
    EXPECT_EQ(msg->hdr.instance_id, instanceId);
    EXPECT_EQ(msg->hdr.type, PLDM_FWU);
    EXPECT_EQ(msg->hdr.command, PLDM_UPDATE_COMPONENT);
    EXPECT_EQ(le16toh(request->comp_classification), inReq.comp_classification);
    EXPECT_EQ(le16toh(request->comp_identifier), inReq.comp_identifier);
    EXPECT_EQ(request->comp_classification_index,
              inReq.comp_classification_index);
    EXPECT_EQ(le32toh(request->comp_comparison_stamp),
              inReq.comp_comparison_stamp);
    EXPECT_EQ(le32toh(request->comp_image_size), inReq.comp_image_size);
    EXPECT_EQ(le32toh(request->update_option_flags.value),
              inReq.update_option_flags.value);
    EXPECT_EQ(request->comp_ver_str_type, inReq.comp_ver_str_type);
    EXPECT_EQ(request->comp_ver_str_len, inReq.comp_ver_str_len);
    EXPECT_EQ(true, std::equal(compVerStrArr.begin(), compVerStrArr.end(),
                               outReq.data() + hdrSize +
                                   sizeof(struct update_component_req)));
}

TEST(UpdateComponent, testBadEncodeRequest)
{
    uint8_t instanceId = 0x01;
    constexpr uint8_t compVerStrLen = 6;

    std::array<uint8_t, compVerStrLen> compVerStrArr;
    struct variable_field inCompVerStr;
    inCompVerStr.ptr = compVerStrArr.data();
    inCompVerStr.length = compVerStrLen;

    struct update_component_req inReq = {};

    std::fill(compVerStrArr.data(), compVerStrArr.end(), 0xFF);

    std::array<uint8_t,
               hdrSize + sizeof(struct update_component_req) + compVerStrLen>
        outReq;

    auto msg = (struct pldm_msg*)outReq.data();

    auto rc = encode_update_component_req(instanceId, 0,
                                          sizeof(struct update_component_req) +
                                              inCompVerStr.length,
                                          &inReq, &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_update_component_req(instanceId, msg, 0, &inReq, &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    rc = encode_update_component_req(instanceId, msg,
                                     sizeof(struct update_component_req) +
                                         inCompVerStr.length,
                                     NULL, &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_update_component_req(instanceId, msg,
                                     sizeof(struct update_component_req) +
                                         inCompVerStr.length,
                                     &inReq, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inReq.comp_classification = COMP_UNKNOWN - 1;
    inReq.comp_identifier = 0x01;
    inReq.comp_classification_index = 0x0F;
    inReq.comp_comparison_stamp = 0;
    inReq.comp_image_size = 160;
    inReq.update_option_flags.value = 1;
    inReq.comp_ver_str_type = COMP_VER_STR_TYPE_UNKNOWN - 1;
    inReq.comp_ver_str_len = 0;

    rc = encode_update_component_req(instanceId, msg,
                                     sizeof(struct update_component_req) +
                                         inCompVerStr.length,
                                     &inReq, &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inReq.comp_classification = 0x000F;
    inReq.comp_identifier = 0x00;
    inReq.comp_classification_index = 0x00;
    inReq.comp_comparison_stamp = 10;
    inReq.comp_image_size = 255;
    inReq.update_option_flags.value = 10;
    inReq.comp_ver_str_type = 7;
    inReq.comp_ver_str_len = 1;

    rc = encode_update_component_req(instanceId, msg,
                                     sizeof(struct update_component_req) +
                                         inCompVerStr.length,
                                     &inReq, &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inReq.comp_classification = COMP_SOFTWARE_BUNDLE + 1;
    inReq.comp_identifier = 0x01;
    inReq.comp_classification_index = 0x0F;
    inReq.comp_comparison_stamp = 0;
    inReq.comp_image_size = 161;
    inReq.update_option_flags.value = 1;
    inReq.comp_ver_str_type = COMP_UTF_16BE + 1;
    inReq.comp_ver_str_len = 0;

    rc = encode_update_component_req(instanceId, msg,
                                     sizeof(struct update_component_req) +
                                         inCompVerStr.length,
                                     &inReq, &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inCompVerStr.ptr = NULL;
    inCompVerStr.length = 0;

    rc = encode_update_component_req(instanceId, msg,
                                     sizeof(struct update_component_req) +
                                         inCompVerStr.length,
                                     &inReq, &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(UpdateComponent, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    uint8_t compCompatabilityResp = COMPONENT_CANNOT_BE_UPDATED;
    uint8_t compCompatabilityRespCode = INVALID_COMP_COMPARISON_STAMP;
    bitfield32_t updateOptionFlagsEnabled = {1};
    uint16_t estimatedTimeReqFd = 1;

    std::array<uint8_t, hdrSize + sizeof(struct update_component_resp)>
        responseMsg{};
    struct update_component_resp* inResp =
        reinterpret_cast<struct update_component_resp*>(responseMsg.data() +
                                                        hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->comp_compatability_resp = 1;
    inResp->comp_compatability_resp_code = 3;
    inResp->update_option_flags_enabled.value = 0x01;
    inResp->estimated_time_req_fd = 0x01;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_update_component_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &compCompatabilityResp, &compCompatabilityRespCode,
        &updateOptionFlagsEnabled, &estimatedTimeReqFd);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);
    EXPECT_EQ(compCompatabilityResp, inResp->comp_compatability_resp);
    EXPECT_EQ(compCompatabilityRespCode, inResp->comp_compatability_resp_code);
    EXPECT_EQ(updateOptionFlagsEnabled.value,
              htole32(inResp->update_option_flags_enabled.value));
    EXPECT_EQ(estimatedTimeReqFd, htole16(inResp->estimated_time_req_fd));
}

TEST(UpdateComponent, testBadDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    uint8_t compCompatabilityResp = COMPONENT_CANNOT_BE_UPDATED;
    uint8_t compCompatabilityRespCode = INVALID_COMP_COMPARISON_STAMP;
    bitfield32_t updateOptionFlagsEnabled = {1};
    uint16_t estimatedTimeReqFd = 1;

    std::array<uint8_t, hdrSize + sizeof(struct update_component_resp)>
        responseMsg{};
    struct update_component_resp* inResp =
        reinterpret_cast<struct update_component_resp*>(responseMsg.data() +
                                                        hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->comp_compatability_resp = 1;
    inResp->comp_compatability_resp_code = 3;
    inResp->update_option_flags_enabled.value = 0x01;
    inResp->estimated_time_req_fd = 0x01;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_update_component_resp(
        NULL, responseMsg.size() - hdrSize, &completionCode,
        &compCompatabilityResp, &compCompatabilityRespCode,
        &updateOptionFlagsEnabled, &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_update_component_resp(
        response, 0, &completionCode, &compCompatabilityResp,
        &compCompatabilityRespCode, &updateOptionFlagsEnabled,
        &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    rc = decode_update_component_resp(
        response, responseMsg.size() - hdrSize, NULL, &compCompatabilityResp,
        &compCompatabilityRespCode, &updateOptionFlagsEnabled,
        &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_update_component_resp(
        response, responseMsg.size() - hdrSize, &completionCode, NULL,
        &compCompatabilityRespCode, &updateOptionFlagsEnabled,
        &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_update_component_resp(response, responseMsg.size() - hdrSize,
                                      &completionCode, &compCompatabilityResp,
                                      NULL, &updateOptionFlagsEnabled,
                                      &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_update_component_resp(response, responseMsg.size() - hdrSize,
                                      &completionCode, &compCompatabilityResp,
                                      &compCompatabilityRespCode, NULL,
                                      &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_update_component_resp(response, responseMsg.size() - hdrSize,
                                      &completionCode, &compCompatabilityResp,
                                      &compCompatabilityRespCode,
                                      &updateOptionFlagsEnabled, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_compatability_resp = COMPONENT_CAN_BE_UPDATED - 1;
    rc = decode_update_component_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &compCompatabilityResp, &compCompatabilityRespCode,
        &updateOptionFlagsEnabled, &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_compatability_resp = COMPONENT_CANNOT_BE_UPDATED + 1;
    rc = decode_update_component_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &compCompatabilityResp, &compCompatabilityRespCode,
        &updateOptionFlagsEnabled, &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_compatability_resp = 6;
    rc = decode_update_component_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &compCompatabilityResp, &compCompatabilityRespCode,
        &updateOptionFlagsEnabled, &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_compatability_resp_code =
        FD_VENDOR_COMP_STATUS_CODE_RANGE_MIN - 1;
    rc = decode_update_component_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &compCompatabilityResp, &compCompatabilityRespCode,
        &updateOptionFlagsEnabled, &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_compatability_resp_code =
        FD_VENDOR_COMP_STATUS_CODE_RANGE_MAX + 1;
    rc = decode_update_component_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &compCompatabilityResp, &compCompatabilityRespCode,
        &updateOptionFlagsEnabled, &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_compatability_resp_code = COMP_CAN_BE_UPDATED - 1;
    rc = decode_update_component_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &compCompatabilityResp, &compCompatabilityRespCode,
        &updateOptionFlagsEnabled, &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_compatability_resp_code = 0xFF;
    rc = decode_update_component_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &compCompatabilityResp, &compCompatabilityRespCode,
        &updateOptionFlagsEnabled, &estimatedTimeReqFd);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(ActivateFirmware, testGoodEncodeRequest)
{
    std::array<uint8_t, hdrSize + sizeof(struct activate_firmware_req)>
        requestMsg{};

    auto msg = reinterpret_cast<pldm_msg*>(requestMsg.data());

    auto request = reinterpret_cast<activate_firmware_req*>(msg->payload);

    bool8_t selfContainedActivationReq = CONTAINS_SELF_ACTIVATED_COMPONENTS;

    auto rc = encode_activate_firmware_req(0, msg,
                                           sizeof(struct activate_firmware_req),
                                           selfContainedActivationReq);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg->hdr.request, PLDM_REQUEST);
    EXPECT_EQ(msg->hdr.instance_id, 0u);
    EXPECT_EQ(msg->hdr.type, PLDM_FWU);
    EXPECT_EQ(msg->hdr.command, PLDM_ACTIVATE_FIRMWARE);
    EXPECT_EQ(selfContainedActivationReq,
              request->self_contained_activation_req);
}

TEST(ActivateFirmware, testBadEncodeRequest)
{
    std::array<uint8_t, hdrSize + sizeof(struct activate_firmware_req)>
        requestMsg{};

    auto msg = reinterpret_cast<pldm_msg*>(requestMsg.data());

    bool8_t selfContainedActivationReq =
        NOT_CONTAINING_SELF_ACTIVATED_COMPONENTS;

    auto rc = encode_activate_firmware_req(
        0, 0, sizeof(struct activate_firmware_req), selfContainedActivationReq);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_activate_firmware_req(0, msg, 0, selfContainedActivationReq);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_activate_firmware_req(0, msg,
                                      sizeof(struct activate_firmware_req), 0);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    selfContainedActivationReq = CONTAINS_SELF_ACTIVATED_COMPONENTS + 1;
    rc = encode_activate_firmware_req(0, msg,
                                      sizeof(struct activate_firmware_req),
                                      selfContainedActivationReq);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    selfContainedActivationReq = NOT_CONTAINING_SELF_ACTIVATED_COMPONENTS - 1;
    rc = encode_activate_firmware_req(0, msg,
                                      sizeof(struct activate_firmware_req),
                                      selfContainedActivationReq);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    selfContainedActivationReq = 6;
    rc = encode_activate_firmware_req(0, msg,
                                      sizeof(struct activate_firmware_req),
                                      selfContainedActivationReq);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(ActivateFirmware, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    uint16_t estimatedTimeActivation = 1;

    std::array<uint8_t, hdrSize + sizeof(struct activate_firmware_resp)>
        responseMsg{};
    struct activate_firmware_resp* inResp =
        reinterpret_cast<struct activate_firmware_resp*>(responseMsg.data() +
                                                         hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->estimated_time_activation = 0x01;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_activate_firmware_resp(
        response, responseMsg.size() - hdrSize, &completionCode,
        &estimatedTimeActivation);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);
    EXPECT_EQ(estimatedTimeActivation,
              htole16(inResp->estimated_time_activation));
}

TEST(ActivateFirmware, testBadDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    uint16_t estimatedTimeActivation = 0;

    std::array<uint8_t, hdrSize + sizeof(struct activate_firmware_resp)>
        responseMsg{};
    struct activate_firmware_resp* inResp =
        reinterpret_cast<struct activate_firmware_resp*>(responseMsg.data() +
                                                         hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->estimated_time_activation = 0x00;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_activate_firmware_resp(NULL, responseMsg.size() - hdrSize,
                                            &completionCode,
                                            &estimatedTimeActivation);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_activate_firmware_resp(response, 0, &completionCode,
                                       &estimatedTimeActivation);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    rc = decode_activate_firmware_resp(response, responseMsg.size() - hdrSize,
                                       NULL, &estimatedTimeActivation);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_activate_firmware_resp(response, responseMsg.size() - hdrSize,
                                       &completionCode, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(PassComponentTable, testGoodEncodeRequest)
{
    uint8_t instanceId = 0x01;
    // Component Version String Length is not fixed here taking it as 6
    constexpr uint8_t compVerStrLen = 6;

    std::array<uint8_t, compVerStrLen> compVerStrArr;
    struct variable_field inCompVerStr;
    inCompVerStr.ptr = compVerStrArr.data();
    inCompVerStr.length = compVerStrLen;

    struct pass_component_table_req inReq = {};

    inReq.transfer_flag = PLDM_START;
    inReq.comp_classification = COMP_UNKNOWN;
    inReq.comp_identifier = 0x00;
    inReq.comp_classification_index = 0x00;
    inReq.comp_comparison_stamp = 0;
    inReq.comp_ver_str_type = COMP_VER_STR_TYPE_UNKNOWN;
    inReq.comp_ver_str_len = compVerStrLen;

    std::fill(compVerStrArr.data(), compVerStrArr.end(), 0xFF);

    std::array<uint8_t, hdrSize + sizeof(struct pass_component_table_req) +
                            compVerStrLen>
        outReq;

    auto msg = (struct pldm_msg*)outReq.data();

    auto rc = encode_pass_component_table_req(
        instanceId, msg,
        sizeof(struct pass_component_table_req) + inCompVerStr.length, &inReq,
        &inCompVerStr);

    auto request = (struct pass_component_table_req*)(outReq.data() + hdrSize);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg->hdr.request, PLDM_REQUEST);
    EXPECT_EQ(msg->hdr.instance_id, instanceId);
    EXPECT_EQ(msg->hdr.type, PLDM_FWU);
    EXPECT_EQ(msg->hdr.command, PLDM_PASS_COMPONENT_TABLE);
    EXPECT_EQ(request->transfer_flag, inReq.transfer_flag);
    EXPECT_EQ(le16toh(request->comp_classification), inReq.comp_classification);
    EXPECT_EQ(le16toh(request->comp_identifier), inReq.comp_identifier);
    EXPECT_EQ(request->comp_classification_index,
              inReq.comp_classification_index);
    EXPECT_EQ(le32toh(request->comp_comparison_stamp),
              inReq.comp_comparison_stamp);
    EXPECT_EQ(request->comp_ver_str_type, inReq.comp_ver_str_type);
    EXPECT_EQ(request->comp_ver_str_len, inReq.comp_ver_str_len);
    EXPECT_EQ(true, std::equal(compVerStrArr.begin(), compVerStrArr.end(),
                               outReq.data() + hdrSize +
                                   sizeof(struct pass_component_table_req)));
}

TEST(PassComponentTable, testBadEncodeRequest)
{
    uint8_t instanceId = 0x01;
    constexpr uint8_t compVerStrLen = 6;

    std::array<uint8_t, compVerStrLen> compVerStrArr;
    struct variable_field inCompVerStr;
    inCompVerStr.ptr = compVerStrArr.data();
    inCompVerStr.length = compVerStrLen;

    struct pass_component_table_req inReq = {};

    std::fill(compVerStrArr.data(), compVerStrArr.end(), 0xFF);

    std::array<uint8_t, hdrSize + sizeof(struct pass_component_table_req) +
                            compVerStrLen>
        outReq;

    auto msg = (struct pldm_msg*)outReq.data();

    auto rc = encode_pass_component_table_req(
        instanceId, 0,
        sizeof(struct pass_component_table_req) + inCompVerStr.length, &inReq,
        &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_pass_component_table_req(instanceId, msg, 0, &inReq,
                                         &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    rc = encode_pass_component_table_req(
        instanceId, msg,
        sizeof(struct pass_component_table_req) + inCompVerStr.length, NULL,
        &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_pass_component_table_req(
        instanceId, msg,
        sizeof(struct pass_component_table_req) + inCompVerStr.length, &inReq,
        NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inReq.transfer_flag = PLDM_START;
    inCompVerStr.ptr = NULL;
    inCompVerStr.length = 0;

    rc = encode_pass_component_table_req(
        instanceId, msg,
        sizeof(struct pass_component_table_req) + inCompVerStr.length, &inReq,
        &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inReq.transfer_flag = PLDM_START_AND_END;
    inReq.comp_classification = COMP_SOFTWARE_BUNDLE + 1;
    inReq.comp_identifier = 0x00;
    inReq.comp_classification_index = 0x00;
    inReq.comp_comparison_stamp = 0;
    inReq.comp_ver_str_type = COMP_UTF_16BE + 1;
    inReq.comp_ver_str_len = 0;

    rc = encode_pass_component_table_req(
        instanceId, msg,
        sizeof(struct pass_component_table_req) + inCompVerStr.length, &inReq,
        &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inReq.transfer_flag = 0x4;
    inReq.comp_classification = 0x000E;
    inReq.comp_identifier = 0x00;
    inReq.comp_classification_index = 0x00;
    inReq.comp_comparison_stamp = 0;
    inReq.comp_ver_str_type = 6;
    inReq.comp_ver_str_len = 0;

    rc = encode_pass_component_table_req(
        instanceId, msg,
        sizeof(struct pass_component_table_req) + inCompVerStr.length, &inReq,
        &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inReq.transfer_flag = PLDM_START;
    inReq.comp_classification = COMP_UNKNOWN - 1;
    inReq.comp_identifier = 0x00;
    inReq.comp_classification_index = 0x00;
    inReq.comp_comparison_stamp = 0;
    inReq.comp_ver_str_type = COMP_VER_STR_TYPE_UNKNOWN - 1;
    inReq.comp_ver_str_len = 0;

    rc = encode_pass_component_table_req(
        instanceId, msg,
        sizeof(struct pass_component_table_req) + inCompVerStr.length, &inReq,
        &inCompVerStr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inReq.transfer_flag = PLDM_START - 1;

    rc = encode_pass_component_table_req(
        instanceId, msg,
        sizeof(struct pass_component_table_req) + inCompVerStr.length, &inReq,
        &inCompVerStr);
    EXPECT_EQ(rc, PLDM_INVALID_TRANSFER_OPERATION_FLAG);

    inReq.transfer_flag = PLDM_START_AND_END + 1;

    rc = encode_pass_component_table_req(
        instanceId, msg,
        sizeof(struct pass_component_table_req) + inCompVerStr.length, &inReq,
        &inCompVerStr);
    EXPECT_EQ(rc, PLDM_INVALID_TRANSFER_OPERATION_FLAG);
}

TEST(PassComponentTable, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    uint8_t compResp = COMP_CAN_BE_UPDATEABLE;
    uint8_t compRespCode = COMP_COMPARISON_STAMP_IDENTICAL;

    std::array<uint8_t, hdrSize + sizeof(struct pass_component_table_resp)>
        responseMsg{};
    struct pass_component_table_resp* inResp =
        reinterpret_cast<struct pass_component_table_resp*>(responseMsg.data() +
                                                            hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->comp_resp = 0;
    inResp->comp_resp_code = 1;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_pass_component_table_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &compResp,
        &compRespCode);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);
    EXPECT_EQ(compResp, inResp->comp_resp);
    EXPECT_EQ(compRespCode, inResp->comp_resp_code);
}

TEST(PassComponentTable, testBadDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;
    uint8_t compResp = COMP_MAY_BE_UPDATEABLE;
    uint8_t compRespCode = INVALID_COMP_COMPARISON_STAMP;

    std::array<uint8_t, hdrSize + sizeof(struct pass_component_table_resp)>
        responseMsg{};
    struct pass_component_table_resp* inResp =
        reinterpret_cast<struct pass_component_table_resp*>(responseMsg.data() +
                                                            hdrSize);
    inResp->completion_code = PLDM_SUCCESS;
    inResp->comp_resp = 1;
    inResp->comp_resp_code = 3;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_pass_component_table_resp(
        NULL, responseMsg.size() - hdrSize, &completionCode, &compResp,
        &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_pass_component_table_resp(response, 0, &completionCode,
                                          &compResp, &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    rc = decode_pass_component_table_resp(
        response, responseMsg.size() - hdrSize, NULL, &compResp, &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc =
        decode_pass_component_table_resp(response, responseMsg.size() - hdrSize,
                                         &completionCode, NULL, &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc =
        decode_pass_component_table_resp(response, responseMsg.size() - hdrSize,
                                         &completionCode, &compResp, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_resp = COMP_CAN_BE_UPDATEABLE - 1;
    rc = decode_pass_component_table_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &compResp,
        &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_resp = COMP_MAY_BE_UPDATEABLE + 1;
    rc = decode_pass_component_table_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &compResp,
        &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_resp = 0x09;
    rc = decode_pass_component_table_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &compResp,
        &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_resp_code = FD_VENDOR_COMP_STATUS_CODE_RANGE_MIN - 1;

    rc = decode_pass_component_table_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &compResp,
        &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_resp_code = FD_VENDOR_COMP_STATUS_CODE_RANGE_MAX + 1;

    rc = decode_pass_component_table_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &compResp,
        &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_resp_code = COMP_CAN_BE_UPDATED - 1;

    rc = decode_pass_component_table_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &compResp,
        &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    inResp->comp_resp_code = 0xFF;

    rc = decode_pass_component_table_resp(
        response, responseMsg.size() - hdrSize, &completionCode, &compResp,
        &compRespCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(CancelUpdateComponent, testGoodEncodeRequest)
{
    std::array<uint8_t, sizeof(pldm_msg_hdr)> requestMsg{};
    auto requestPtr = reinterpret_cast<pldm_msg*>(requestMsg.data());

    uint8_t instanceId = 0x01;

    auto rc = encode_cancel_update_component_req(instanceId, requestPtr);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(requestPtr->hdr.request, PLDM_REQUEST);
    EXPECT_EQ(requestPtr->hdr.instance_id, instanceId);
    EXPECT_EQ(requestPtr->hdr.type, PLDM_FWU);
    EXPECT_EQ(requestPtr->hdr.command, PLDM_CANCEL_UPDATE_COMPONENT);
}

TEST(CancelUpdateComponent, testBadEncodeRequest)
{
    uint8_t instanceId = 0x01;

    auto rc = encode_cancel_update_component_req(instanceId, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(CancelUpdateComponent, testGoodDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;

    std::array<uint8_t, hdrSize + sizeof(uint8_t)> responseMsg{};

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_cancel_update_component_resp(
        response, responseMsg.size() - hdrSize, &completionCode);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, PLDM_SUCCESS);
}

TEST(CancelUpdateComponent, testBadDecodeResponse)
{
    uint8_t completionCode = PLDM_ERROR;

    std::array<uint8_t, hdrSize + sizeof(uint8_t)> responseMsg{};

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_cancel_update_component_resp(
        NULL, responseMsg.size() - hdrSize, &completionCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_cancel_update_component_resp(response, 0, &completionCode);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    rc = decode_cancel_update_component_resp(
        response, responseMsg.size() - hdrSize, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(ApplyComplete, testGoodEncodeResponse)
{
    uint8_t instanceId = 0x01;
    uint8_t completionCode = PLDM_ERROR;

    std::array<uint8_t, (hdrSize + 1)> responseMsg{};
    auto responsePtr = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc =
        encode_apply_complete_resp(instanceId, completionCode, responsePtr);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(responsePtr->hdr.request, PLDM_RESPONSE);
    EXPECT_EQ(responsePtr->hdr.instance_id, instanceId);
    EXPECT_EQ(responsePtr->hdr.type, PLDM_FWU);
    EXPECT_EQ(responsePtr->hdr.command, PLDM_APPLY_COMPLETE);
    EXPECT_EQ(responsePtr->payload[0], completionCode);
}

TEST(ApplyComplete, testBadEncodeResponse)
{
    uint8_t instanceId = 0x01;
    uint8_t completionCode = PLDM_ERROR;

    auto rc = encode_apply_complete_resp(instanceId, completionCode, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(ApplyComplete, testGoodDecodeRequest)
{
    uint8_t applyResult = PLDM_FWU_APPLY_SUCCESS;
    bitfield16_t compActivationMethodsModification = {0};

    std::array<uint8_t, hdrSize + sizeof(struct apply_complete_req)>
        requestMsg{};

    struct apply_complete_req* request =
        reinterpret_cast<struct apply_complete_req*>(requestMsg.data() +
                                                     hdrSize);

    request->apply_result = PLDM_FWU_APPLY_SUCCESS;
    request->comp_activation_methods_modification.value = APPLY_AUTOMATIC;

    auto requestIn = reinterpret_cast<pldm_msg*>(requestMsg.data());

    auto rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                        &applyResult,
                                        &compActivationMethodsModification);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(applyResult, request->apply_result);
    EXPECT_EQ(compActivationMethodsModification.value,
              htole16(request->comp_activation_methods_modification.value));
}

TEST(ApplyComplete, testBadDecodeRequest)
{
    uint8_t applyResult = PLDM_FWU_VERIFY_COMPLETED_WITH_ERROR;
    bitfield16_t compActivationMethodsModification = {3};

    std::array<uint8_t, hdrSize + sizeof(struct apply_complete_req)>
        requestMsg{};

    struct apply_complete_req* request =
        reinterpret_cast<struct apply_complete_req*>(requestMsg.data() +
                                                     hdrSize);

    request->apply_result = PLDM_FWU_VERIFY_COMPLETED_WITH_ERROR;
    request->comp_activation_methods_modification.value = APPLY_SYSTEM_REBOOT;

    auto requestIn = reinterpret_cast<pldm_msg*>(requestMsg.data());

    auto rc = decode_apply_complete_req(NULL, requestMsg.size() - hdrSize,
                                        &applyResult,
                                        &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_apply_complete_req(requestIn, 0, &applyResult,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);

    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize, NULL,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                   &applyResult, NULL);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    request->apply_result = PLDM_FWU_APPLY_SUCCESS - 1;
    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                   &applyResult,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    request->apply_result = PLDM_FWU_VENDOR_APPLY_RESULT_RANGE_MIN - 1;
    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                   &applyResult,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    request->apply_result = PLDM_FWU_VENDOR_APPLY_RESULT_RANGE_MAX + 1;
    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                   &applyResult,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    request->apply_result = PLDM_FWU_TIME_OUT - 1;
    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                   &applyResult,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    request->apply_result = PLDM_FWU_APPLY_COMPLETED_WITH_FAILURE + 1;
    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                   &applyResult,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    request->apply_result = 6;
    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                   &applyResult,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    request->comp_activation_methods_modification.value = APPLY_AUTOMATIC - 1;
    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                   &applyResult,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    request->comp_activation_methods_modification.value =
        APPLY_AC_POWER_CYCLE + 1;
    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                   &applyResult,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    request->comp_activation_methods_modification.value = 0xff;
    rc = decode_apply_complete_req(requestIn, requestMsg.size() - hdrSize,
                                   &applyResult,
                                   &compActivationMethodsModification);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
