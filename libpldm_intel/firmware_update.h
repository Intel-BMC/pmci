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

#define PLDM_FWU_BASELINE_TRANSFER_SIZE 32
#define MIN_OUTSTANDING_REQ 1
#define PLDM_GET_FIRMWARE_PARAMENTERS_REQ_BYTES 0
#define PLDM_FWU_COMP_VER_STR_SIZE_MAX 256

#define PLDM_QUERY_DEVICE_IDENTIFIERS_REQ_BYTES 0
// descriptor type 2 byte, length 2 bytes and data 1 byte min.
#define PLDM_FWU_MIN_DESCRIPTOR_IDENTIFIERS_LEN 5
/* Maximum progress percentage value*/
#define FW_UPDATE_MAX_PROGRESS_PERCENT 0x65

/** @brief PLDM FW update error completion codes
 */
enum fw_update_error_completion_codes {
	NOT_IN_UPDATE_MODE = 0x80,
	ALREADY_IN_UPDATE_MODE = 0x81,
	DATA_OUT_OF_RANGE = 0x82,
	INVALID_TRANSFER_LENGTH = 0x83,
	INVALID_STATE_FOR_COMMAND = 0x84,
	INCOMPLETE_UPDATE = 0x85,
	BUSY_IN_BACKGROUND = 0x86,
	CANCEL_PENDING = 0x87,
	COMMAND_NOT_EXPECTED = 0x88,
	RETRY_REQUEST_FW_DATA = 0x89,
	UNABLE_TO_INITIATE_UPDATE = 0x8A,
	ACTIVATION_NOT_REQUIRED = 0x8B,
	SELF_CONTAINED_ACTIVATION_NOT_PERMITTED = 0x8C,
	NO_DEVICE_METADATA = 0x8D,
	RETRY_REQUEST_UPDATE = 0x8E,
	NO_PACKAGE_DATA = 0x8F,
	INVALID_DATA_TRANSFER_HANDLE = 0x90,
	INVALID_TRANSFER_OPERATION_FLAG = 0x91
};

/** @brief PLDM FWU values for Component Version String Type or Component Image
 * Set Version String Type
 */
enum comp_type {
	COMP_VER_STR_TYPE_UNKNOWN = 0,
	COMP_ASCII = 1,
	COMP_UTF_8 = 2,
	COMP_UTF_16 = 3,
	COMP_UTF_16LE = 4,
	COMP_UTF_16BE = 5
};

/** @brief PLDM FWU common values for Component Response Code and Component
 * Compatibility Response Code
 */
enum comp_code {
	COMP_CAN_BE_UPDATED = 0x00,
	COMP_COMPARISON_STAMP_IDENTICAL = 0x01,
	COMP_COMPARISON_STAMP_LOWER = 0x02,
	INVALID_COMP_COMPARISON_STAMP = 0x03,
	COMP_CONFLICT = 0x04,
	COMP_PREREQUISITES = 0x05,
	COMP_NOT_SUPPORTED = 0x06,
	COMP_SECURITY_RESTRICTIONS = 0x07,
	INCOMPLETE_COMP_IMAGE_SET = 0x08,
	COMP_VER_STR_IDENTICAL = 0x0A,
	COMP_VER_STR_LOWER = 0x0B,
	FD_VENDOR_COMP_STATUS_CODE_RANGE_MIN = 0xD0,
	FD_VENDOR_COMP_STATUS_CODE_RANGE_MAX = 0xEF
};

/** @brief PLDM Firmware Update States
 */
enum pldm_firmware_update_state {
	FD_IDLE = 0,
	FD_LEARN_COMPONENTS = 1,
	FD_READY_XFER = 2,
	FD_DOWNLOAD = 3,
	FD_VERIFY = 4,
	FD_APPLY = 5,
	FD_ACTIVATE = 6
};

/** @brief PLDM Firmware Update AuxStates
 */
enum pldm_firmware_update_aux_state {
	FD_OPERATION_IN_PROGRESS = 0,
	FD_OPERATION_SUCCESSFUL = 1,
	FD_OPERATION_FAILED = 2,
	FD_WAIT = 3
};

/** @brief PLDM Firmware Update AuxStateStatus
 */
enum pldm_firmware_update_aux_state_status {
	FD_AUX_STATE_IN_PROGRESS_OR_SUCCESS = 0x00,
	FD_TIMEOUT = 0x09,
	FD_GENERIC_ERROR = 0x0A,
	FD_VENDOR_DEFINED_STATUS_CODE_START = 0x70,
	FD_VENDOR_DEFINED_STATUS_CODE_END = 0xEF
};

/** @brief PLDM Firmware Update ReasonCode
 */
enum pldm_firmware_update_reason_code {
	FD_INITIALIZATION = 0,
	FD_ACTIVATE_FW_RECEIVED = 1,
	FD_CANCEL_UPDATE_RECEIVED = 2,
	FD_TIMEOUT_LEARN_COMPONENT = 3,
	FD_TIMEOUT_READY_XFER = 4,
	FD_TIMEOUT_DOWNLOAD = 5,
	FD_STATUS_VENDOR_DEFINED_MIN = 200,
	FD_STATUS_VENDOR_DEFINED_MAX = 255
};

#define UPDATE_OPTION_FLAGS_ENABLED_MASK 0x1

/** @brief PLDM FWU codes for Transfer Result
 */
enum pldm_fwu_transfer_result {
	PLDM_FWU_TRASFER_SUCCESS = 0x00,
	PLDM_FWU_TRANSFER_COMPLETE_WITH_ERROR = 0x02,
	PLDM_FWU_FD_ABORTED_TRANSFER = 0x03,
	PLDM_FWU_VENDOR_TRANSFER_RESULT_RANGE_MIN = 0x70,
	PLDM_FWU_VENDOR_TRANSFER_RESULT_RANGE_MAX = 0x8F
};

/**@brief PLDM FWU common error codes
 */
enum pldm_fwu_common_error_code {
	PLDM_FWU_TIME_OUT = 0x09,
	PLDM_FWU_GENERIC_ERROR = 0x0A
};

/**@brief PLDM FWU result of the Verify stage
 */
enum pldm_fwu_verify_result {
	PLDM_FWU_VERIFY_SUCCESS = 0x00,
	PLDM_FWU_VERIFY_COMPLETED_WITH_FAILURE = 0x01,
	PLDM_FWU_VERIFY_COMPLETED_WITH_ERROR = 0x02,
	PLDM_FWU_VENDOR_SPEC_STATUS_RANGE_MIN = 0x90,
	PLDM_FWU_VENDOR_SPEC_STATUS_RANGE_MAX = 0xAF
};

/**@brief PLDM FWU result of the Apply Result
 */
enum pldm_fwu_apply_result {
	PLDM_FWU_APPLY_SUCCESS = 0x00,
	PLDM_FWU_APPLY_SUCCESS_WITH_ACTIVATION_METHOD = 0x01,
	PLDM_FWU_APPLY_COMPLETED_WITH_FAILURE = 0x02,
	PLDM_FWU_VENDOR_APPLY_RESULT_RANGE_MIN = 0xB0,
	PLDM_FWU_VENDOR_APPLY_RESULT_RANGE_MAX = 0xCF
};

/** @brief PLDM FWU values for Component Activation Methods Modification
 */
enum comp_activation_methods_modification {
	APPLY_AUTOMATIC = 0,
	APPLY_SELF_CONTAINED = 1,
	APPLY_MEDIUM_SPECIFIC_RESET = 2,
	APPLY_SYSTEM_REBOOT = 3,
	APPLY_DC_POWER_CYCLE = 4,
	APPLY_AC_POWER_CYCLE = 5
};

/** @brief PLDM FWU values for Component Classification
 */
enum comp_classification {
	COMP_UNKNOWN = 0x0000,
	COMP_OTHER = 0x0001,
	COMP_DRIVER = 0x0002,
	COMP_CONFIGURATION_SOFTWARE = 0x0003,
	COMP_APPLICATION_SOFTWARE = 0x0004,
	COMP_INSTRUMENTATION = 0x0005,
	COMP_FIRMWARE_OR_BIOS = 0x0006,
	COMP_DIAGNOSTIC_SOFTWARE = 0x0007,
	COMP_OPERATING_SYSTEM = 0x0008,
	COMP_MIDDLEWARE = 0x0009,
	COMP_FIRMWARE = 0x000A,
	COMP_BIOS_OR_FCODE = 0x000B,
	COMP_SUPPORT_OR_SERVICEPACK = 0x000C,
	COMP_SOFTWARE_BUNDLE = 0x000D
};

/** @brief PLDM FWU codes for Component Compatibility Response
 */
enum comp_compatability_resp {
	COMPONENT_CAN_BE_UPDATED = 0,
	COMPONENT_CANNOT_BE_UPDATED = 1
};

/** @brief PLDM FWU codes for Component Compatibility Response Code
 */
enum comp_compatability_resp_code {
	NO_RESPONSE_CODE = 0x0,
	COMPATABILITY_COMPARISON_STAMP_IDENTICAL = 0x01,
	COMPATABILITY_COMPARISON_STAMP_LOWER = 0x02,
	INVALID_COMPATABILITY_COMPARISON_STAMP = 0x03,
	COMPATABILITY_CONFLICT = 0x04,
	COMPATABILITY_PREREQUISITES = 0x05,
	COMPATABILITY_NOT_SUPPORTED = 0x06,
	COMPATABILITY_SECURITY_RESTRICTIONS = 0x07,
	INCOMPLETE_COMPONENT_IMAGE_SET = 0x08,
	COMPATABILITY_NO_MATCH = 0x09,
	COMPATABILITY_VER_STR_IDENTICAL = 0x0A,
	COMPATABILITY_VER_STR_LOWER = 0x0B
};

/** @brief PLDM FWU codes for Component Response
 */
enum comp_resp { COMP_CAN_BE_UPDATEABLE = 0, COMP_MAY_BE_UPDATEABLE = 1 };

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

/** @struct cancel_update_resp
 *
 *  Structure representing CancelUpdate response.
 */
struct cancel_update_resp {
	uint8_t completion_code;
	bool8_t non_functioning_component_indication;
	uint64_t non_functioning_component_bitmap;
};

/* @struct get_fd_data_req
 *
 *  Structure representing GetMetaData/GetPackageData request
 */
struct get_fd_data_req {
	uint32_t data_transfer_handle;
	uint8_t transfer_operation_flag;
} __attribute__((packed));

/* @struct get_fd_data_resp
 *
 *  Structure representing GetMetaData/GetPackageData response
 */
struct get_fd_data_resp {
	uint8_t completion_code;
	uint32_t next_data_transfer_handle;
	uint8_t transfer_flag;
} __attribute__((packed));

/** @struct get_status_resp
 *
 *  Structure representing GetStatus response.
 */
struct get_status_resp {
	uint8_t completion_code;
	uint8_t current_state;
	uint8_t previous_state;
	uint8_t aux_state;
	uint8_t aux_state_status;
	uint8_t progress_percent;
	uint8_t reason_code;
	bitfield32_t update_option_flags_enabled;
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
    const uint8_t *msg, const size_t payload_length,
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
			      const struct request_update_req *data,
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
 *  @param[in] transfer_operation_flag - The operation flag that indicates
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

/*UpdateComponent*/

/* @struct update_component_req
 *
 *  Structure representing Update Component request
 */
struct update_component_req {
	uint16_t comp_classification;
	uint16_t comp_identifier;
	uint8_t comp_classification_index;
	uint32_t comp_comparison_stamp;
	uint32_t comp_image_size;
	uint32_t update_option_flags;
	uint8_t comp_ver_str_type;
	uint8_t comp_ver_str_len;
} __attribute__((packed));

/* @struct update_component_resp
 *
 *  Structure representing Update Component response
 */
struct update_component_resp {
	uint8_t completion_code;
	uint8_t comp_compatability_resp;
	uint8_t comp_compatability_resp_code;
	uint32_t update_option_flags_enabled;
	uint16_t estimated_time_req_fd;
} __attribute__((packed));

/** @brief Create a PLDM request message for UpdateComponent
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @param[in] data - Pointer for UpdateComponent Request
 *  @param[in] comp_ver_str - Pointer to component version string
 * information
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_update_component_req(const uint8_t instance_id, struct pldm_msg *msg,
				const size_t payload_length,
				const struct update_component_req *data,
				struct variable_field *comp_ver_str);

/** @brief Decode a UpdateComponent response message
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
 *  @param[out] comp_compatability_resp - Pointer to component compatability
 * response
 *  @param[out] comp_compatability_resp_code - Pointer to component
 * compatability response code
 *  @param[out] update_option_flags_enabled - Pointer to update option flags
 * enabled
 *  @param[out] estimated_time_req_fd - Pointer to estimated time before sending
 * request firmware data information
 *  @return pldm_completion_codes
 */
int decode_update_component_resp(const struct pldm_msg *msg,
				 const size_t payload_length,
				 uint8_t *completion_code,
				 uint8_t *comp_compatability_resp,
				 uint8_t *comp_compatability_resp_code,
				 uint32_t *update_option_flags_enabled,
				 uint16_t *estimated_time_req_fd);

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

/*PassComponentTable*/

/* @struct pass_component_table_req
 *
 *  Structure representing Pass Component Table Request
 */
struct pass_component_table_req {
	uint8_t transfer_flag;
	uint16_t comp_classification;
	uint16_t comp_identifier;
	uint8_t comp_classification_index;
	uint32_t comp_comparison_stamp;
	uint8_t comp_ver_str_type;
	uint8_t comp_ver_str_len;
} __attribute__((packed));

/* @struct pass_component_table_resp
 *
 *  Structure representing Pass Component Table response
 */
struct pass_component_table_resp {
	uint8_t completion_code;
	uint8_t comp_resp;
	uint8_t comp_resp_code;
} __attribute__((packed));

/** @brief Create a PLDM request message for PassComponentTable
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @param[in] payload_length - Length of request message payload
 *  @param[in] data - Pointer for PassComponentTable Request
 *  @param[in] comp_ver_str - Pointer to component version string
 * information
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_pass_component_table_req(const uint8_t instance_id,
				    struct pldm_msg *msg,
				    const size_t payload_length,
				    const struct pass_component_table_req *data,
				    struct variable_field *comp_ver_str);

/** @brief Decode a PassComponentTable response message
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
 *  @param[out] comp_resp - Pointer to component response
 *  @param[out] comp_resp_code - Pointer to component response code
 * information
 *  @return pldm_completion_codes
 */
int decode_pass_component_table_resp(const struct pldm_msg *msg,
				     const size_t payload_length,
				     uint8_t *completion_code,
				     uint8_t *comp_resp,
				     uint8_t *comp_resp_code);

/* CancelUpdateComponent */

/** @brief Create a PLDM request message for CancelUpdateComponent
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_cancel_update_component_req(const uint8_t instance_id,
				       struct pldm_msg *msg);

/** @brief Decode a CancelUpdateComponent response message
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
 *  @return pldm_completion_codes
 */
int decode_cancel_update_component_resp(const struct pldm_msg *msg,
					const size_t payload_length,
					uint8_t *completion_code);

/** @brief Create a PLDM request message for CancelUpdate
 *
 *	@param[in] instance_id - Message's instance id
 *	@param[in,out] msg - Message will be written to this
 *	@return pldm_completion_codes
 *	@note  Caller is responsible for memory alloc and dealloc of param
 *		   'msg.payload'
 */
int encode_cancel_update_req(const uint8_t instance_id, struct pldm_msg *msg);

/** @brief Decode a CancelUpdate response message
 *
 *	Note:
 *	* If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *	* If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *	@param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *	@param[out] completion_code - Pointer to response msg's PLDM completion
 *code
 *	@param[out] non_functioning_component_indication - Pointer to non
 *funcional component indication
 *	@param[out] non_functioning_component_bitmap - Pointer to non functional
 *component bitmap state
 *	@return pldm_completion_codes
 */
int decode_cancel_update_resp(const struct pldm_msg *msg,
			      const size_t payload_len,
			      uint8_t *completion_code,
			      bool8_t *non_functioning_component_indication,
			      uint64_t *non_functioning_component_bitmap);

/** @brief Create a PLDM response message for VerifyComplete
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - completion code
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_verify_complete_resp(const uint8_t instance_id,
				const uint8_t completion_code,
				struct pldm_msg *msg);

/** @brief Decode a VerifyComplete request message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] verify_result - pointer to VerifyResult from FD
 *  @return pldm_completion_codes
 */
int decode_verify_complete_req(const struct pldm_msg *msg,
			       uint8_t *verify_result);

/** @brief Create a PLDM response message for TransferComplete
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - completion code
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_transfer_complete_resp(const uint8_t instance_id,
				  const uint8_t completion_code,
				  struct pldm_msg *msg);

/** @brief Decode a TransferComplete request message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - request message
 *  @param[out] transfer_result - Pointer to TransferResult
 *  @return pldm_completion_codes
 */
int decode_transfer_complete_req(const struct pldm_msg *msg,
				 uint8_t *transfer_result);

/** @brief Create a PLDM response message for GetPackageData
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] payload_length - Length of response message payload
 *  @param[in,out] msg - Message will be written to this
 *  @param[in] data - pointer to response data
 *  @param[in] portion_of_meta_data - pointer to package data
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_package_data_resp(const uint8_t instance_id,
				 const size_t payload_length,
				 struct pldm_msg *msg,
				 struct get_fd_data_resp *data,
				 struct variable_field *portion_of_meta_data);

/** @brief Decode a GetPackageData request message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Request message
 *  @param[in] payload_length - Length of Request message payload
 *  @param[out] data_transfer_handle - Pointer to data transfer handle
 *  @param[out] transfer_operation_flag - Pointer to transfer operation flag
 *  @return pldm_completion_codes
 */
int decode_get_pacakge_data_req(const struct pldm_msg *msg,
				const size_t payload_length,
				uint32_t *data_transfer_handle,
				uint8_t *transfer_operation_flag);

/** @brief Create a PLDM response message for GetMetaData
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] payload_length - Length of response message payload
 *  @param[in,out] msg - Message will be written to this
 *  @param[in] data - pointer to response data
 *  @param[in] portion_of_meta_data - pointer to package data
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_get_meta_data_resp(const uint8_t instance_id,
			      const size_t payload_length, struct pldm_msg *msg,
			      struct get_fd_data_resp *data,
			      struct variable_field *portion_of_meta_data);

/** @brief Decode a GetMetaData request message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - request message
 *  @param[in] payload_length - Length of request message payload
 *  @param[out] data_transfer_handle - Pointer to data transfer handle
 *  @param[out] transfer_operation_flag - Pointer to transfer operation flag
 *  @return pldm_completion_codes
 */
int decode_get_meta_data_req(const struct pldm_msg *msg,
			     const size_t payload_length,
			     uint32_t *data_transfer_handle,
			     uint8_t *transfer_operation_flag);

/** @brief Create a PLDM request message for GetStatus
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *		   'msg.payload'
 */
int encode_get_status_req(const uint8_t instance_id, struct pldm_msg *msg);

/** @brief Decode a GetStatus response message
 *
 *  Note:
 *	* If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *	* If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of response message payload
 *  @param[out] completion_code - Pointer to response msg's PLDM completion
 *code
 *  @param[out] current_state - Pointer to current state machine state
 *  @param[out] previous_state - Pointer to previous different state machine
 * state
 *  @param[out] aux_state - Pointer to current operation state
 *  @param[out] aux_state_status - Pointer to aux state status
 *  @param[out] progress_percent - Pointer to current progress percentage
 *  @param[out] reason_code - Pointer to reason for entering current state
 *  @param[out] update_option_flags_enabled - Pointer to
 *updateOptionFlagsEnabled
 *  @return pldm_completion_codes
 */
int decode_get_status_resp(const struct pldm_msg *msg,
			   const size_t payload_length,
			   uint8_t *completion_code, uint8_t *current_state,
			   uint8_t *previous_state, uint8_t *aux_state,
			   uint8_t *aux_state_status, uint8_t *progress_percent,
			   uint8_t *reason_code,
			   bitfield32_t *update_option_flags_enabled);
/*ApplyComplete*/

/** @struct apply_complete_req
 *
 *  Structure representing Apply Complete request.
 */
struct apply_complete_req {
	uint8_t apply_result;
	uint16_t comp_activation_methods_modification;
} __attribute__((packed));

/** @brief Create a PLDM response message for ApplyComplete
 *
 *  @param[in] instance_id - Message's instance id
 *  @param[in] completion_code - completion code
 *  @param[in,out] msg - Message will be written to this
 *  @return pldm_completion_codes
 *  @note  Caller is responsible for memory alloc and dealloc of param
 *         'msg.payload'
 */
int encode_apply_complete_resp(const uint8_t instance_id,
			       const uint8_t completion_code,
			       struct pldm_msg *msg);

/** @brief Decode ApplyComplete request message
 *
 *  Note:
 *  * If the return value is not PLDM_SUCCESS, it represents a
 * transport layer error.
 *  * If the completion_code value is not PLDM_SUCCESS, it represents a
 * protocol layer error and all the out-parameters are invalid.
 *
 *  @param[in] msg - Response message
 *  @param[in] payload_length - Length of request message payload
 *  @param[in] apply_result - pointer to ApplyResult from FD
 *  @param[in] comp_activation_methods_modification - pointer to Component
 * Activation Methods Modification
 *  @return pldm_completion_codes
 */
int decode_apply_complete_req(const struct pldm_msg *msg,
			      const size_t payload_length,
			      uint8_t *apply_result,
			      uint16_t *comp_activation_methods_modification);

#ifdef __cplusplus
}
#endif

#endif // End of FW_UPDATE_H
