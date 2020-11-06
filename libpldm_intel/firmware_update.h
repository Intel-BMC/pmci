#ifndef FW_UPDATE_H
#define FW_UPDATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "base.h"
#include "utils.h"

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

#define PLDM_GET_FIRMWARE_PARAMENTERS_REQ_BYTES 0
#define PLDM_FWU_COMP_VER_STR_SIZE_MAX 256

#define PLDM_QUERY_DEVICE_IDENTIFIERS_REQ_BYTES 0
// descriptor type 2 byte, length 2 bytes and data 1 byte min.
#define PLDM_FWU_MIN_DESCRIPTOR_IDENTIFIERS_LEN 5

/** @brief PLDM FWU codes for Self Contained Activation Request
 */
enum self_contained_activation_req {
	NOT_CONTAINING_SELF_ACTIVATED_COMPONENTS = 0,
	CONTAINS_SELF_ACTIVATED_COMPONENTS = 1
};

/** @struct query_device_identifiers_resp
 *
 *  Structure representing query device identifiers response.
 */
struct query_device_identifiers_resp {
	uint8_t completion_code;
	uint32_t device_identifiers_len;
	uint8_t descriptor_count;
} __attribute__((packed));

/** @struct get_firmware_parameters_resp
 *
 *  Structure representing component parameter table entries.
 */
struct component_parameter_table {
	uint16_t comp_classification;
	uint16_t comp_identifier;
	uint8_t comp_classification_index;
	uint32_t active_comp_comparison_stamp;
	uint8_t active_comp_ver_str_type;
	uint8_t active_comp_ver_str_len;
	uint64_t active_comp_release_date;
	uint32_t pending_comp_comparison_stamp;
	uint8_t pending_comp_ver_str_type;
	uint8_t pending_comp_ver_str_len;
	uint64_t pending_comp_release_date;
	uint16_t comp_activation_methods;
	uint32_t capabilities_during_update;
} __attribute__((packed));

/** @struct get_firmware_parameters_resp
 *
 *  Structure representing get firmware parameters response.
 */
struct get_firmware_parameters_resp {
	uint8_t completion_code;
	uint32_t capabilities_during_update;
	uint16_t comp_count;
	uint8_t active_comp_image_set_ver_str_type;
	uint8_t active_comp_image_set_ver_str_len;
	uint8_t pending_comp_image_set_ver_str_type;
	uint8_t pending_comp_image_set_ver_str_len;
} __attribute__((packed));

/* @struct request_update_req
 *
 *  Structure representing Request Update request
 */
struct request_update_req {
	uint32_t max_transfer_size;
	uint16_t no_of_comp;
	uint8_t max_outstand_transfer_req;
	uint16_t pkg_data_len;
	uint8_t comp_image_set_ver_str_type;
	uint8_t comp_image_set_ver_str_len;
} __attribute__((packed));

/* @struct request_update_resp
 *
 *  Structure representing Request Update response
 */
struct request_update_resp {
	uint8_t completion_code;
	uint16_t fd_meta_data_len;
	uint8_t fd_pkg_data;
} __attribute__((packed));

/* QueryDeviceIdentifiers */

/** @brief Create a PLDM request message for QueryDeviceIdentifiers
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @param[in] payload_length - Length of the request message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_query_device_identifiers_req(const uint8_t instance_id,
					struct pldm_msg *msg,
					const size_t payload_length);

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
 *  @param[out] descriptor_data - Pointer to descriptor data
 *  @return pldm_completion_codes
 */
int decode_query_device_identifiers_resp(
    const struct pldm_msg *msg, const size_t payload_length,
    uint8_t *completion_code, uint32_t *device_identifiers_len,
    uint8_t *descriptor_count, struct variable_field *descriptor_data);

/* GetFirmwareParameters */

/** @brief Create a PLDM request message for GetFirmwareParameters
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @param[in] payload_length - Length of the request message payload
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_firmware_parameters_req(const uint8_t instance_id,
				       struct pldm_msg *msg,
				       const size_t payload_length);

/** @brief Decode a GetFirmwareParameters component image set response
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] resp_data - Pointer to get firmware parameters response
 *  @param[out] active_comp_image_set_ver_str - Pointer to active component
 * image set version string
 *  @param[out] pending_comp_image_set_ver_str - Pointer to pending component
 * image set version string
 *  @return pldm_completion_codes
 */
int decode_get_firmware_parameters_comp_img_set_resp(
    const struct pldm_msg *msg, const size_t payload_length,
    struct get_firmware_parameters_resp *resp_data,
    struct variable_field *active_comp_image_set_ver_str,
    struct variable_field *pending_comp_image_set_ver_str);

/** @brief Decode a GetFirmwareParameters component response
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] component_data - Pointer to component parameter table
 *  @param[out] active_comp_ver_str - Pointer to active component version string
 *  @param[out] pending_comp_ver_str - Pointer to pending component version
 * string
 *  @return pldm_completion_codes
 */
int decode_get_firmware_parameters_comp_resp(
    uint8_t *msg, const size_t payload_length,
    struct component_parameter_table *component_data,
    struct variable_field *active_comp_ver_str,
    struct variable_field *pending_comp_ver_str);

/** @brief Create a PLDM request message for RequestUpdate
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @param[in] data - Pointer for RequestUpdate Request
 *  @param[in] comp_img_set_ver_str - Pointer which holds image set
 * information
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_request_update_req(const uint8_t instance_id, struct pldm_msg *msg,
			      const size_t payload_length,
			      struct request_update_req *data,
			      struct variable_field *comp_img_set_ver_str);

/** @brief Decode a RequestUpdate response message
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
 *  @param[out] fd_meta_data_len - Pointer which holds length of FD meta data
 *  @param[out] fd_pkg_data - Pointer which holds package data
 * information
 *  @return pldm_completion_codes
 */
int decode_request_update_resp(const struct pldm_msg *msg,
			       const size_t payload_length,
			       uint8_t *completion_code,
			       uint16_t *fd_meta_data_len,
			       uint8_t *fd_pkg_data);

/* GetDeviceMetaData */

/* @struct get_device_meta_data_req
 *
 *  Structure representing Get Device Meta Data request
 */
struct get_device_meta_data_req {
	uint32_t data_transfer_handle;
	uint8_t transfer_operation_flag;
} __attribute__((packed));

/* @struct get_device_meta_data_resp
 *
 *  Structure representing Get Device Meta Data response
 */
struct get_device_meta_data_resp {
	uint8_t completion_code;
	uint32_t next_data_transfer_handle;
	uint8_t transfer_flag;
} __attribute__((packed));

/** @brief Create a PLDM request message for GetDeviceMetaData
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @param[in] data_transfer_handle - A handle that is used to identify a
 * package data transfer
 *  @param[in] transfer_operation_flag - The operation flag that indiates
 * whether this is the start of the transfer
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_device_meta_data_req(const uint8_t instance_id,
				    struct pldm_msg *msg,
				    const size_t payload_length,
				    const uint32_t data_transfer_handle,
				    const uint8_t transfer_operation_flag);

/** @brief Decode a GetDeviceMetaData response message
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
 *  @param[out] next_data_transfer_handle - Pointer to next data transfer handle
 *  @param[out] transfer_flag - Pointer to transfer flag
 *  @param[out] portion_of_meta_data - Pointer to portion of meta data
 *  @return pldm_completion_codes
 */
int decode_get_device_meta_data_resp(
    const struct pldm_msg *msg, const size_t payload_length,
    uint8_t *completion_code, uint32_t *next_data_transfer_handle,
    uint8_t *transfer_flag, struct variable_field *portion_of_meta_data);

/*ActivateFirmware*/

/* @struct activate_firmware_req
 *
 *  Structure representing Activate Firmware request
 */
struct activate_firmware_req {
	bool8_t self_contained_activation_req;
} __attribute__((packed));

/* @struct activate_firmware_resp
 *
 *  Structure representing Activate Firmware response
 */
struct activate_firmware_resp {
	uint8_t completion_code;
	uint16_t estimated_time_activation;
} __attribute__((packed));

/** @brief Create a PLDM request message for ActivateFirmware
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @param[in] self_contained_activation_req returns True if FD shall activate
 * all self-contained components and returns False if FD shall not activate any
 * self-contained components.
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_activate_firmware_req(const uint8_t instance_id,
				 struct pldm_msg *msg,
				 const size_t payload_length,
				 const bool8_t self_contained_activation_req);

/** @brief Decode a ActivateFirmware response message
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
 *  @param[out] estimated_time_activation - Pointer to Estimated Time For Self
 * Contained Activation request firmware data information
 *  @return pldm_completion_codes
 */
int decode_activate_firmware_resp(const struct pldm_msg *msg,
				  const size_t payload_length,
				  uint8_t *completion_code,
				  uint16_t *estimated_time_activation);

#ifdef __cplusplus
}
#endif

#endif // End of FW_UPDATE_H
