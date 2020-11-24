#include <string.h>

#include <array>
#include <cstring>
#include <vector>

#include "../base.h"
#include "../utils.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using testing::ElementsAreArray;

constexpr auto hdrSize = sizeof(pldm_msg_hdr);

TEST(PackPLDMMessage, BadPathTest)
{
    struct pldm_header_info hdr;
    struct pldm_header_info* hdr_ptr = NULL;
    pldm_msg_hdr msg{};

    // PLDM header information pointer is NULL
    auto rc = pack_pldm_header(hdr_ptr, &msg);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    // PLDM message pointer is NULL
    rc = pack_pldm_header(&hdr, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    // PLDM header information pointer and PLDM message pointer is NULL
    rc = pack_pldm_header(hdr_ptr, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    // RESERVED message type
    hdr.msg_type = PLDM_RESERVED;
    rc = pack_pldm_header(&hdr, &msg);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    // Instance ID out of range
    hdr.msg_type = PLDM_REQUEST;
    hdr.instance = 33;
    rc = pack_pldm_header(&hdr, &msg);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    // PLDM type out of range
    hdr.msg_type = PLDM_REQUEST;
    hdr.instance = 32;
    hdr.pldm_type = 64;
    rc = pack_pldm_header(&hdr, &msg);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_PLDM_TYPE);
}

TEST(PackPLDMMessage, RequestMessageGoodPath)
{
    struct pldm_header_info hdr;
    pldm_msg_hdr msg{};

    // Message type is REQUEST and lower range of the field values
    hdr.msg_type = PLDM_REQUEST;
    hdr.instance = 0;
    hdr.pldm_type = 0;
    hdr.command = 0;

    auto rc = pack_pldm_header(&hdr, &msg);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg.request, 1);
    EXPECT_EQ(msg.datagram, 0);
    EXPECT_EQ(msg.instance_id, 0);
    EXPECT_EQ(msg.type, 0);
    EXPECT_EQ(msg.command, 0);

    // Message type is REQUEST and upper range of the field values
    hdr.instance = 31;
    hdr.pldm_type = 63;
    hdr.command = 255;

    rc = pack_pldm_header(&hdr, &msg);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg.request, 1);
    EXPECT_EQ(msg.datagram, 0);
    EXPECT_EQ(msg.instance_id, 31);
    EXPECT_EQ(msg.type, 63);
    EXPECT_EQ(msg.command, 255);

    // Message type is PLDM_ASYNC_REQUEST_NOTIFY
    hdr.msg_type = PLDM_ASYNC_REQUEST_NOTIFY;

    rc = pack_pldm_header(&hdr, &msg);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg.request, 1);
    EXPECT_EQ(msg.datagram, 1);
    EXPECT_EQ(msg.instance_id, 31);
    EXPECT_EQ(msg.type, 63);
    EXPECT_EQ(msg.command, 255);
}

TEST(PackPLDMMessage, ResponseMessageGoodPath)
{
    struct pldm_header_info hdr;
    pldm_msg_hdr msg{};

    // Message type is PLDM_RESPONSE and lower range of the field values
    hdr.msg_type = PLDM_RESPONSE;
    hdr.instance = 0;
    hdr.pldm_type = 0;
    hdr.command = 0;

    auto rc = pack_pldm_header(&hdr, &msg);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg.request, 0);
    EXPECT_EQ(msg.datagram, 0);
    EXPECT_EQ(msg.instance_id, 0);
    EXPECT_EQ(msg.type, 0);
    EXPECT_EQ(msg.command, 0);

    // Message type is PLDM_RESPONSE and upper range of the field values
    hdr.instance = 31;
    hdr.pldm_type = 63;
    hdr.command = 255;

    rc = pack_pldm_header(&hdr, &msg);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg.request, 0);
    EXPECT_EQ(msg.datagram, 0);
    EXPECT_EQ(msg.instance_id, 31);
    EXPECT_EQ(msg.type, 63);
    EXPECT_EQ(msg.command, 255);
}

TEST(UnpackPLDMMessage, BadPathTest)
{
    struct pldm_header_info hdr;

    // PLDM message pointer is NULL
    auto rc = unpack_pldm_header(nullptr, &hdr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(UnpackPLDMMessage, RequestMessageGoodPath)
{
    struct pldm_header_info hdr;
    pldm_msg_hdr msg{};

    // Unpack PLDM request message and lower range of field values
    msg.request = 1;
    auto rc = unpack_pldm_header(&msg, &hdr);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(hdr.msg_type, PLDM_REQUEST);
    EXPECT_EQ(hdr.instance, 0);
    EXPECT_EQ(hdr.pldm_type, 0);
    EXPECT_EQ(hdr.command, 0);

    // Unpack PLDM async request message and lower range of field values
    msg.datagram = 1;
    rc = unpack_pldm_header(&msg, &hdr);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(hdr.msg_type, PLDM_ASYNC_REQUEST_NOTIFY);

    // Unpack PLDM request message and upper range of field values
    msg.datagram = 0;
    msg.instance_id = 31;
    msg.type = 63;
    msg.command = 255;
    rc = unpack_pldm_header(&msg, &hdr);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(hdr.msg_type, PLDM_REQUEST);
    EXPECT_EQ(hdr.instance, 31);
    EXPECT_EQ(hdr.pldm_type, 63);
    EXPECT_EQ(hdr.command, 255);
}

TEST(UnpackPLDMMessage, ResponseMessageGoodPath)
{
    struct pldm_header_info hdr;
    pldm_msg_hdr msg{};

    // Unpack PLDM response message and lower range of field values
    auto rc = unpack_pldm_header(&msg, &hdr);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(hdr.msg_type, PLDM_RESPONSE);
    EXPECT_EQ(hdr.instance, 0);
    EXPECT_EQ(hdr.pldm_type, 0);
    EXPECT_EQ(hdr.command, 0);

    // Unpack PLDM response message and upper range of field values
    msg.instance_id = 31;
    msg.type = 63;
    msg.command = 255;
    rc = unpack_pldm_header(&msg, &hdr);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(hdr.msg_type, PLDM_RESPONSE);
    EXPECT_EQ(hdr.instance, 31);
    EXPECT_EQ(hdr.pldm_type, 63);
    EXPECT_EQ(hdr.command, 255);
}

TEST(GetPLDMCommands, testEncodeRequest)
{
    uint8_t pldmType = 0x05;
    ver32_t version{0xFF, 0xFF, 0xFF, 0xFF};
    std::array<uint8_t, sizeof(pldm_msg_hdr) + PLDM_GET_COMMANDS_REQ_BYTES>
        requestMsg{};
    auto request = reinterpret_cast<pldm_msg*>(requestMsg.data());

    auto rc = encode_get_commands_req(0, pldmType, version, request);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(0, memcmp(request->payload, &pldmType, sizeof(pldmType)));
    EXPECT_EQ(0, memcmp(request->payload + sizeof(pldmType), &version,
                        sizeof(version)));
}

TEST(GetPLDMCommands, testDecodeRequest)
{
    uint8_t pldmType = 0x05;
    ver32_t version{0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t pldmTypeOut{};
    ver32_t versionOut{0xFF, 0xFF, 0xFF, 0xFF};
    std::array<uint8_t, hdrSize + PLDM_GET_COMMANDS_REQ_BYTES> requestMsg{};

    memcpy(requestMsg.data() + hdrSize, &pldmType, sizeof(pldmType));
    memcpy(requestMsg.data() + sizeof(pldmType) + hdrSize, &version,
           sizeof(version));

    auto request = reinterpret_cast<pldm_msg*>(requestMsg.data());
    auto rc = decode_get_commands_req(request, requestMsg.size() - hdrSize,
                                      &pldmTypeOut, &versionOut);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(pldmTypeOut, pldmType);
    EXPECT_EQ(0, memcmp(&versionOut, &version, sizeof(version)));
}

TEST(GetPLDMCommands, testEncodeResponse)
{
    uint8_t completionCode = 0;
    std::array<uint8_t, sizeof(pldm_msg_hdr) + PLDM_GET_COMMANDS_RESP_BYTES>
        responseMsg{};
    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());
    std::array<bitfield8_t, PLDM_MAX_CMDS_PER_TYPE / 8> commands{};
    commands[0].byte = 1;
    commands[1].byte = 2;
    commands[2].byte = 3;

    auto rc =
        encode_get_commands_resp(0, PLDM_SUCCESS, commands.data(), response);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    uint8_t* payload_ptr = response->payload;
    EXPECT_EQ(completionCode, payload_ptr[0]);
    EXPECT_EQ(1, payload_ptr[sizeof(completionCode)]);
    EXPECT_EQ(2,
              payload_ptr[sizeof(completionCode) + sizeof(commands[0].byte)]);
    EXPECT_EQ(3, payload_ptr[sizeof(completionCode) + sizeof(commands[0].byte) +
                             sizeof(commands[1].byte)]);
}

TEST(GetPLDMTypes, testEncodeResponse)
{
    uint8_t completionCode = 0;
    std::array<uint8_t, sizeof(pldm_msg_hdr) + PLDM_GET_TYPES_RESP_BYTES>
        responseMsg{};
    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());
    std::array<bitfield8_t, PLDM_MAX_TYPES / 8> types{};
    types[0].byte = 1;
    types[1].byte = 2;
    types[2].byte = 3;

    auto rc = encode_get_types_resp(0, PLDM_SUCCESS, types.data(), response);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    uint8_t* payload_ptr = response->payload;
    EXPECT_EQ(completionCode, payload_ptr[0]);
    EXPECT_EQ(1, payload_ptr[sizeof(completionCode)]);
    EXPECT_EQ(2, payload_ptr[sizeof(completionCode) + sizeof(types[0].byte)]);
    EXPECT_EQ(3, payload_ptr[sizeof(completionCode) + sizeof(types[0].byte) +
                             sizeof(types[1].byte)]);
}

TEST(GetPLDMTypes, testGoodDecodeResponse)
{
    std::array<uint8_t, hdrSize + PLDM_GET_TYPES_RESP_BYTES> responseMsg{};
    responseMsg[1 + hdrSize] = 1;
    responseMsg[2 + hdrSize] = 2;
    responseMsg[3 + hdrSize] = 3;
    std::array<bitfield8_t, PLDM_MAX_TYPES / 8> outTypes{};

    uint8_t completion_code;
    responseMsg[hdrSize] = PLDM_SUCCESS;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_get_types_resp(response, responseMsg.size() - hdrSize,
                                    &completion_code, outTypes.data());

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completion_code, PLDM_SUCCESS);
    EXPECT_EQ(responseMsg[1 + hdrSize], outTypes[0].byte);
    EXPECT_EQ(responseMsg[2 + hdrSize], outTypes[1].byte);
    EXPECT_EQ(responseMsg[3 + hdrSize], outTypes[2].byte);
}

TEST(GetPLDMTypes, testBadDecodeResponse)
{
    std::array<uint8_t, hdrSize + PLDM_GET_TYPES_RESP_BYTES> responseMsg{};
    responseMsg[1 + hdrSize] = 1;
    responseMsg[2 + hdrSize] = 2;
    responseMsg[3 + hdrSize] = 3;
    std::array<bitfield8_t, PLDM_MAX_TYPES / 8> outTypes{};

    uint8_t retcompletion_code = 0;
    responseMsg[hdrSize] = PLDM_SUCCESS;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_get_types_resp(response, responseMsg.size() - hdrSize - 1,
                                    &retcompletion_code, outTypes.data());

    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
}

TEST(GetPLDMCommands, testGoodDecodeResponse)
{
    std::array<uint8_t, hdrSize + PLDM_GET_COMMANDS_RESP_BYTES> responseMsg{};
    responseMsg[1 + hdrSize] = 1;
    responseMsg[2 + hdrSize] = 2;
    responseMsg[3 + hdrSize] = 3;
    std::array<bitfield8_t, PLDM_MAX_CMDS_PER_TYPE / 8> outTypes{};

    uint8_t completion_code;
    responseMsg[hdrSize] = PLDM_SUCCESS;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_get_commands_resp(response, responseMsg.size() - hdrSize,
                                       &completion_code, outTypes.data());

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completion_code, PLDM_SUCCESS);
    EXPECT_EQ(responseMsg[1 + hdrSize], outTypes[0].byte);
    EXPECT_EQ(responseMsg[2 + hdrSize], outTypes[1].byte);
    EXPECT_EQ(responseMsg[3 + hdrSize], outTypes[2].byte);
}

TEST(GetPLDMCommands, testBadDecodeResponse)
{
    std::array<uint8_t, hdrSize + PLDM_GET_COMMANDS_RESP_BYTES> responseMsg{};
    responseMsg[1 + hdrSize] = 1;
    responseMsg[2 + hdrSize] = 2;
    responseMsg[3 + hdrSize] = 3;
    std::array<bitfield8_t, PLDM_MAX_CMDS_PER_TYPE / 8> outTypes{};

    uint8_t retcompletion_code = 0;
    responseMsg[hdrSize] = PLDM_SUCCESS;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc =
        decode_get_commands_resp(response, responseMsg.size() - hdrSize - 1,
                                 &retcompletion_code, outTypes.data());

    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
}

TEST(GetPLDMVersion, testGoodEncodeRequest)
{
    std::array<uint8_t, sizeof(pldm_msg_hdr) + PLDM_GET_VERSION_REQ_BYTES>
        requestMsg{};
    auto request = reinterpret_cast<pldm_msg*>(requestMsg.data());
    uint8_t pldmType = 0x03;
    uint32_t transferHandle = 0x0;
    uint8_t opFlag = 0x01;

    auto rc =
        encode_get_version_req(0, transferHandle, opFlag, pldmType, request);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(
        0, memcmp(request->payload, &transferHandle, sizeof(transferHandle)));
    EXPECT_EQ(0, memcmp(request->payload + sizeof(transferHandle), &opFlag,
                        sizeof(opFlag)));
    EXPECT_EQ(0,
              memcmp(request->payload + sizeof(transferHandle) + sizeof(opFlag),
                     &pldmType, sizeof(pldmType)));
}

TEST(GetPLDMVersion, testBadEncodeRequest)
{
    uint8_t pldmType = 0x03;
    uint32_t transferHandle = 0x0;
    uint8_t opFlag = 0x01;

    auto rc =
        encode_get_version_req(0, transferHandle, opFlag, pldmType, nullptr);

    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(GetPLDMVersion, testEncodeResponseInvalid)
{
    constexpr uint8_t instanceID = 0x12;
    constexpr uint8_t completionCode = PLDM_ERROR;
    constexpr uint32_t nextTransferHandle = 0;
    constexpr uint8_t transferFlag = 0;
    const uint8_t versionData[] = {1, 2, 3, 4, 0xc1, 0xc2, 0xc3, 0xc4};
    const variable_field versionField{versionData, sizeof(versionData)};
    std::array<uint8_t, hdrSize + PLDM_GET_VERSION_RESP_FIXED_BYTES +
                            sizeof(versionData)>
        responseArray{};
    auto msg = reinterpret_cast<struct pldm_msg*>(responseArray.data());

    int rc =
        encode_get_version_resp(instanceID, completionCode, nextTransferHandle,
                                transferFlag, nullptr, msg);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = encode_get_version_resp(instanceID, completionCode, nextTransferHandle,
                                 transferFlag, &versionField, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = encode_get_version_resp(instanceID, completionCode, nextTransferHandle,
                                 transferFlag, nullptr, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(GetPLDMVersion, testEncodeResponse)
{
    uint8_t completionCode = 0;
    uint32_t transferHandle = 0;
    uint8_t flag = PLDM_START_AND_END;
    uint8_t version[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xc1, 0xc2, 0xc3, 0xc4};
    variable_field versionField{version, sizeof(version)};
    std::array<uint8_t, sizeof(pldm_msg_hdr) +
                            PLDM_GET_VERSION_RESP_FIXED_BYTES + sizeof(version)>
        responseMsg{};
    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = encode_get_version_resp(0, PLDM_SUCCESS, 0, PLDM_START_AND_END,
                                      &versionField, response);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completionCode, response->payload[0]);
    EXPECT_EQ(0, memcmp(response->payload + sizeof(response->payload[0]),
                        &transferHandle, sizeof(transferHandle)));
    EXPECT_EQ(0, memcmp(response->payload + sizeof(response->payload[0]) +
                            sizeof(transferHandle),
                        &flag, sizeof(flag)));
    EXPECT_EQ(0, memcmp(response->payload + sizeof(response->payload[0]) +
                            sizeof(transferHandle) + sizeof(flag),
                        &version, sizeof(version)));

    uint8_t* verBytes = response->payload + PLDM_GET_VERSION_RESP_FIXED_BYTES;
    EXPECT_EQ(0, memcmp(&version, verBytes, sizeof(version)));
    rc = encode_get_version_resp(0, PLDM_SUCCESS, 0, 0xFF, &versionField,
                                 response);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    versionField.length = 0;
    rc = encode_get_version_resp(0, PLDM_SUCCESS, 0, 0xFF, &versionField,
                                 response);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    versionField.length = sizeof(version);
    versionField.ptr = NULL;
    rc = encode_get_version_resp(0, PLDM_SUCCESS, 0, 0xFF, &versionField,
                                 response);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(GetPLDMVersion, testDecodeRequest)
{
    std::array<uint8_t, hdrSize + PLDM_GET_VERSION_REQ_BYTES> requestMsg{};
    uint32_t transferHandle = 0x0;
    uint32_t retTransferHandle = 0x0;
    uint8_t flag = PLDM_GET_FIRSTPART;
    uint8_t retFlag = PLDM_GET_FIRSTPART;
    uint8_t pldmType = PLDM_BASE;
    uint8_t retType = PLDM_BASE;

    memcpy(requestMsg.data() + hdrSize, &transferHandle,
           sizeof(transferHandle));
    memcpy(requestMsg.data() + sizeof(transferHandle) + hdrSize, &flag,
           sizeof(flag));
    memcpy(requestMsg.data() + sizeof(transferHandle) + sizeof(flag) + hdrSize,
           &pldmType, sizeof(pldmType));

    auto request = reinterpret_cast<pldm_msg*>(requestMsg.data());

    auto rc = decode_get_version_req(request, requestMsg.size() - hdrSize,
                                     &retTransferHandle, &retFlag, &retType);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(transferHandle, retTransferHandle);
    EXPECT_EQ(flag, retFlag);
    EXPECT_EQ(pldmType, retType);
}

TEST(GetPLDMVersion, testDecodeRequestInvalid)
{
    std::array<uint8_t, hdrSize + PLDM_GET_VERSION_REQ_BYTES> requestMsg{};
    uint32_t retTransferHandle = 0x0;
    uint8_t retFlag = PLDM_GET_FIRSTPART;
    uint8_t retType = PLDM_BASE;
    auto request = reinterpret_cast<pldm_msg*>(requestMsg.data());

    auto rc = decode_get_version_req(request, PLDM_GET_VERSION_REQ_BYTES,
                                     &retTransferHandle, &retFlag, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_get_version_req(request, PLDM_GET_VERSION_REQ_BYTES,
                                &retTransferHandle, nullptr, &retType);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_get_version_req(request, PLDM_GET_VERSION_REQ_BYTES, nullptr,
                                &retFlag, &retType);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_get_version_req(request, ~PLDM_GET_VERSION_REQ_BYTES,
                                &retTransferHandle, &retFlag, &retType);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
    rc = decode_get_version_req(nullptr, PLDM_GET_VERSION_REQ_BYTES,
                                &retTransferHandle, &retFlag, &retType);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(GetPLDMVersion, testDecodeResponseInvalid)
{
    std::array<uint8_t,
               sizeof(pldm_msg_hdr) + PLDM_GET_VERSION_RESP_FIXED_BYTES>
        responseMsg{};
    auto msg = reinterpret_cast<const struct pldm_msg*>(responseMsg.data());
    const size_t payloadLength = PLDM_GET_VERSION_RESP_FIXED_BYTES;
    uint8_t completionCode;
    uint32_t nextTransferHandle;
    uint8_t transferFlag;
    variable_field version;

    auto rc =
        decode_get_version_resp(msg, payloadLength, &completionCode,
                                &nextTransferHandle, &transferFlag, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_get_version_resp(msg, payloadLength, &completionCode,
                                 &nextTransferHandle, nullptr, &version);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_get_version_resp(msg, payloadLength, &completionCode, nullptr,
                                 &transferFlag, &version);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_get_version_resp(msg, payloadLength, nullptr,
                                 &nextTransferHandle, &transferFlag, &version);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_get_version_resp(msg, 1, &completionCode, &nextTransferHandle,
                                 &transferFlag, &version);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
    rc = decode_get_version_resp(nullptr, payloadLength, &completionCode,
                                 &nextTransferHandle, &transferFlag, &version);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(GetPLDMVersion, testDecodeResponse)
{
    uint32_t transferHandle = 0x0;
    uint32_t retTransferHandle = 0x0;
    uint8_t flag = PLDM_START_AND_END;
    uint8_t retFlag = PLDM_START_AND_END;
    uint8_t completionCode = 0;
    uint8_t version[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xc1, 0xc2, 0xc3, 0xc4};
    variable_field versionOut;
    uint8_t completion_code;
    std::array<uint8_t, sizeof(pldm_msg_hdr) +
                            PLDM_GET_VERSION_RESP_FIXED_BYTES + sizeof(version)>
        responseMsg{};

    memcpy(responseMsg.data() + sizeof(completionCode) + hdrSize,
           &transferHandle, sizeof(transferHandle));
    memcpy(responseMsg.data() + sizeof(completionCode) +
               sizeof(transferHandle) + hdrSize,
           &flag, sizeof(flag));
    memcpy(responseMsg.data() + sizeof(completionCode) +
               sizeof(transferHandle) + sizeof(flag) + hdrSize,
           &version, sizeof(version));

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_get_version_resp(response, responseMsg.size() - hdrSize,
                                      &completion_code, &retTransferHandle,
                                      &retFlag, &versionOut);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(transferHandle, retTransferHandle);
    EXPECT_EQ(flag, retFlag);
    EXPECT_EQ(versionOut.length, sizeof(version));
    EXPECT_EQ(0, memcmp(version, versionOut.ptr, sizeof(version)));

    flag = 0xFF;
    memcpy(responseMsg.data() + sizeof(completionCode) +
               sizeof(transferHandle) + hdrSize,
           &flag, sizeof(flag));
    rc = decode_get_version_resp(response, responseMsg.size() - hdrSize,
                                 &completion_code, &retTransferHandle, &retFlag,
                                 &versionOut);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(GetTID, testEncodeRequest)
{
    pldm_msg request{};

    auto rc = encode_get_tid_req(0, &request);
    ASSERT_EQ(rc, PLDM_SUCCESS);
}

TEST(GetTID, testEncodeResponse)
{
    uint8_t completionCode = 0;
    std::array<uint8_t, sizeof(pldm_msg_hdr) + PLDM_GET_TID_RESP_BYTES>
        responseMsg{};
    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());
    uint8_t tid = 1;

    auto rc = encode_get_tid_resp(0, PLDM_SUCCESS, tid, response);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    uint8_t* payload = response->payload;
    EXPECT_EQ(completionCode, payload[0]);
    EXPECT_EQ(1, payload[sizeof(completionCode)]);
}

TEST(GetTID, testDecodeResponse)
{
    std::array<uint8_t, hdrSize + PLDM_GET_TID_RESP_BYTES> responseMsg{};
    responseMsg[1 + hdrSize] = 1;

    uint8_t tid;
    uint8_t completion_code;
    responseMsg[hdrSize] = PLDM_SUCCESS;

    auto response = reinterpret_cast<pldm_msg*>(responseMsg.data());

    auto rc = decode_get_tid_resp(response, responseMsg.size() - hdrSize,
                                  &completion_code, &tid);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(completion_code, PLDM_SUCCESS);
    EXPECT_EQ(tid, 1);
}

TEST(CcOnlyResponse, testEncode)
{
    struct pldm_msg responseMsg;

    auto rc =
        encode_cc_only_resp(0 /*instance id*/, 1 /*pldm type*/, 2 /*command*/,
                            3 /*complection code*/, &responseMsg);
    EXPECT_EQ(rc, PLDM_SUCCESS);

    auto p = reinterpret_cast<uint8_t*>(&responseMsg);
    EXPECT_THAT(std::vector<uint8_t>(p, p + sizeof(responseMsg)),
                ElementsAreArray({0, 1, 2, 3}));

    rc = encode_cc_only_resp(PLDM_INSTANCE_MAX + 1, 1, 2, 3, &responseMsg);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = encode_cc_only_resp(0, 1, 2, 3, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(CcOnlyResponse, testDecodeValid)
{
    std::array<uint8_t, 4> byteData{};
    pldm_completion_codes testCC = PLDM_ERROR_INVALID_DATA;
    struct pldm_msg* msgData =
        reinterpret_cast<struct pldm_msg*>(byteData.data());
    pldm_cc_only_rsp* ccOnlyRsp =
        reinterpret_cast<pldm_cc_only_rsp*>(msgData->payload);
    ccOnlyRsp->completion_code = testCC;

    uint8_t decodedCC = PLDM_SUCCESS;
    int rc = decode_cc_only_resp(msgData, 1, &decodedCC);
    EXPECT_EQ(decodedCC, testCC);
    EXPECT_EQ(rc, PLDM_SUCCESS);

    testCC = PLDM_ERROR_INVALID_PLDM_TYPE;
    ccOnlyRsp->completion_code = testCC;
    rc = decode_cc_only_resp(msgData, 1, &decodedCC);
    EXPECT_EQ(decodedCC, testCC);
    EXPECT_EQ(rc, PLDM_SUCCESS);
}

TEST(CcOnlyResponse, testDecodeInvalid)
{
    std::array<uint8_t, hdrSize + sizeof(uint8_t)> byteData{};
    struct pldm_msg* msgData =
        reinterpret_cast<struct pldm_msg*>(byteData.data());
    uint8_t completion_code = PLDM_ERROR;

    auto rc = decode_cc_only_resp(msgData, 1, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_cc_only_resp(msgData, 0, &completion_code);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
    rc = decode_cc_only_resp(msgData, 0, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_cc_only_resp(nullptr, 1, &completion_code);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_cc_only_resp(nullptr, 1, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_cc_only_resp(nullptr, 0, &completion_code);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_cc_only_resp(nullptr, 0, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(SetTID, encodeRequestValid)
{
    std::array<uint8_t, hdrSize + sizeof(struct pldm_set_tid_req)> reqData{};
    pldm_msg* msg = reinterpret_cast<pldm_msg*>(reqData.data());
    constexpr uint8_t instanceId = 0x12;
    constexpr uint8_t tid = 0x24;

    auto rc = encode_set_tid_req(instanceId, tid, msg);
    EXPECT_EQ(msg->hdr.command, PLDM_SET_TID);
    EXPECT_EQ(msg->hdr.type, PLDM_BASE);
    EXPECT_EQ(msg->hdr.request, 1);
    EXPECT_EQ(msg->hdr.datagram, 0);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg->hdr.instance_id, instanceId);
    pldm_set_tid_req* req =
        reinterpret_cast<pldm_set_tid_req*>(&(msg->payload[0]));
    EXPECT_EQ(req->tid, tid);
}

TEST(SetTID, encodeRequestInvalid)
{
    constexpr uint8_t instanceId = 0x12;
    constexpr uint8_t tid = 0x24;

    auto rc = encode_set_tid_req(instanceId, tid, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(SetTID, encodeResponseValid)
{
    constexpr uint8_t instanceId = 0x12;
    constexpr uint8_t completionCode = PLDM_SUCCESS;
    std::array<uint8_t, hdrSize + sizeof(uint8_t)> rspMsg{};
    pldm_msg* msg = reinterpret_cast<pldm_msg*>(rspMsg.data());

    auto rc = encode_set_tid_resp(instanceId, completionCode, msg);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg->hdr.command, PLDM_SET_TID);
    EXPECT_EQ(msg->hdr.type, PLDM_BASE);
    EXPECT_EQ(msg->hdr.request, 0);
    EXPECT_EQ(msg->hdr.datagram, 0);
    EXPECT_EQ(msg->hdr.instance_id, instanceId);
    pldm_cc_only_rsp* rspData =
        reinterpret_cast<pldm_cc_only_rsp*>(msg->payload);
    EXPECT_EQ(rspData->completion_code, completionCode);
}

TEST(SetTID, encodeResponseInvalid)
{
    constexpr uint8_t instanceId = 0x12;
    constexpr uint8_t completionCode = PLDM_SUCCESS;

    auto rc = encode_set_tid_resp(instanceId, completionCode, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}
TEST(SetTID, decodeRequestValid)
{
    constexpr uint8_t tid = 0x12;
    std::array<uint8_t, hdrSize + sizeof(struct pldm_set_tid_req)> request{};
    pldm_msg* msg = reinterpret_cast<pldm_msg*>(request.data());
    pldm_set_tid_req* setTidReq =
        reinterpret_cast<pldm_set_tid_req*>(msg->payload);
    setTidReq->tid = tid;

    uint8_t decodedTID = 0x00;
    auto rc =
        decode_set_tid_req(msg, sizeof(struct pldm_set_tid_req), &decodedTID);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(decodedTID, tid);
}
TEST(SetTID, decodeRequestInvalid)
{
    std::array<uint8_t, hdrSize + sizeof(struct pldm_set_tid_req)> request{};
    pldm_msg* msg = reinterpret_cast<pldm_msg*>(request.data());
    uint8_t decodedTID = 0x00;

    auto rc = decode_set_tid_req(nullptr, sizeof(struct pldm_set_tid_req),
                                 &decodedTID);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_set_tid_req(nullptr, sizeof(struct pldm_set_tid_req), nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_set_tid_req(nullptr, sizeof(struct pldm_set_tid_req) - 1,
                            &decodedTID);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_set_tid_req(nullptr, sizeof(struct pldm_set_tid_req) - 1,
                            nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);

    rc = decode_set_tid_req(msg, sizeof(struct pldm_set_tid_req), nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_set_tid_req(msg, sizeof(struct pldm_set_tid_req) - 1,
                            &decodedTID);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
    rc = decode_set_tid_req(msg, sizeof(struct pldm_set_tid_req) - 1, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(SetTID, decodeResponseValid)
{
    std::array<uint8_t, hdrSize + sizeof(uint8_t)> rspArray{};
    pldm_msg* rspMsg = reinterpret_cast<pldm_msg*>(rspArray.data());
    uint8_t completionCode = PLDM_SUCCESS;
    pldm_set_tid_rsp* rspSetTID =
        reinterpret_cast<pldm_set_tid_rsp*>(rspMsg->payload);
    rspSetTID->completion_code = completionCode;

    uint8_t decodedCC = PLDM_ERROR;
    auto rc = decode_set_tid_resp(rspMsg, sizeof(pldm_set_tid_rsp), &decodedCC);
    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(decodedCC, completionCode);
}

TEST(SetTID, decodeResponseInvalid)
{
    std::array<uint8_t, hdrSize + sizeof(uint8_t)> rspArray{};
    pldm_msg* rspMsg = reinterpret_cast<pldm_msg*>(rspArray.data());
    uint8_t decodedCC = PLDM_ERROR;

    auto rc = decode_set_tid_resp(rspMsg, sizeof(pldm_set_tid_rsp), nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_set_tid_resp(rspMsg, sizeof(pldm_set_tid_rsp) - 1, &decodedCC);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_LENGTH);
    rc = decode_set_tid_resp(rspMsg, sizeof(pldm_set_tid_rsp) - 1, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_set_tid_resp(nullptr, sizeof(pldm_set_tid_rsp), &decodedCC);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_set_tid_resp(nullptr, sizeof(pldm_set_tid_rsp), nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_set_tid_resp(nullptr, sizeof(pldm_set_tid_rsp) - 1, &decodedCC);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
    rc = decode_set_tid_resp(nullptr, sizeof(pldm_set_tid_rsp) - 1, nullptr);
    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

TEST(HeaderOnlyRequest, encodeHeaderOnlyRequestValid)
{
    std::array<uint8_t, hdrSize> reqData{};
    pldm_msg* msg = reinterpret_cast<pldm_msg*>(reqData.data());
    constexpr uint8_t instanceID = 0x0B;
    constexpr uint8_t pldmType = PLDM_BASE;
    constexpr uint8_t command = PLDM_GET_TID;

    auto rc = encode_header_only_request(instanceID, pldmType, command, msg);

    EXPECT_EQ(rc, PLDM_SUCCESS);
    EXPECT_EQ(msg->hdr.command, command);
    EXPECT_EQ(msg->hdr.type, pldmType);
    EXPECT_EQ(msg->hdr.request, 1);
    EXPECT_EQ(msg->hdr.datagram, 0);
    EXPECT_EQ(msg->hdr.instance_id, instanceID);
}

TEST(HeaderOnlyRequest, encodeHeaderOnlyRequestInvalid)
{
    constexpr uint8_t instanceID = 0x0B;
    constexpr uint8_t pldmType = PLDM_BASE;
    constexpr uint8_t command = PLDM_GET_TID;

    auto rc = encode_header_only_request(instanceID, pldmType, command, NULL);

    EXPECT_EQ(rc, PLDM_ERROR_INVALID_DATA);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
