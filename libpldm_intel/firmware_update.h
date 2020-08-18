#ifndef FW_UPDATE_H
#define FW_UPDATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "base.h"

/* inventory commands */
#define PLDM_QUERY_DEVICE_IDENTIFIERS 0x01
#define PLDM_GET_FIRMWARE_PARAMENTERS 0x02

/* update commands */
#define PLDM_REQUEST_UPDATE 0x10
#define PLDM_GET_PACKAGE_DATA 0x11
#define PLDM_GET_DEVICE_META_DATA 0x12
#define PLDM_PASS_COMPONENT_TABLE 0x13
#define PLDM_UPDATE_COMPONENT 0x14
#define PLDM_REQUEST_FIRMWARE_DATA 0x15
#define PLDM_TRANSFER_COMPLETE 0x16
#define PLDM_VERIFY_COMPLETE 0x17
#define PLDM_APPLY_COMPLETE 0x18
#define PLDM_GET_META_DATA 0x19
#define PLDM_ACTIVATE_FIRMWARE 0x1A
#define PLDM_GET_STATUS 0x1B
#define PLDM_CANCEL_UPDATE_COMPONENT 0x1C
#define PLDM_CANCEL_UPDATE 0x1D

/** @struct query_device_identifiers_resp
 *
 *  Structure representing query device identifiers response.
 */
struct query_device_identifiers_resp {
	uint8_t completion_code;
	uint32_t device_identifiers_len;
	uint8_t descriptor_count;
} __attribute__((packed));

/* QueryDeviceIdentifiers */

/** @brief Create a PLDM request message for QueryDeviceIdentifiers
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_query_device_identifiers_req(const uint8_t instance_id,
					struct pldm_msg *msg);

/** @brief Decode a QueryDeviceIdentifiers response message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - Pointer to response msg's PLDM completion code
 *  @param[out] device_identifiers_len - Pointer to device identifiers length
 *  @param[out] descriptor_count - Pointer to descriptor count
 *  @param[out] descriptor_count - Pointer to descriptor count
 *  @param[out] descriptor_data - Pointer to descriptor data
 *  @return pldm_completion_codes
 */
int decode_query_device_identifiers_resp(const struct pldm_msg *msg,
					 const size_t payload_length,
					 uint8_t *completion_code,
					 uint32_t *device_identifiers_len,
					 uint8_t *descriptor_count,
					 uint8_t *descriptor_data);

#ifdef __cplusplus
}
#endif

#endif // End of FW_UPDATE_H
