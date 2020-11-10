#include <endian.h>
#include <string.h>

#include "firmware_update.h"

/** @brief Check validity of VerifyResult in VerifyComplete request
 *
 *	@param[in] verify_result - VerifyResult
 *	@return validity
 */
static bool validate_verify_result(const uint8_t verify_result)
{
	switch (verify_result) {
	case PLDM_FWU_VERIFY_SUCCESS:
	case PLDM_FWU_VERIFY_COMPLETED_WITH_FAILURE:
	case PLDM_FWU_VERIFY_COMPLETED_WITH_ERROR:
	case PLDM_FWU_TIME_OUT:
	case PLDM_FWU_GENERIC_ERROR:
		return true;
	default:
		if (verify_result >= PLDM_FWU_VENDOR_SPEC_STATUS_RANGE_MIN &&
		    verify_result <= PLDM_FWU_VENDOR_SPEC_STATUS_RANGE_MAX) {
			return true;
		}
		return false;
	}
}

int encode_query_device_identifiers_req(const uint8_t instance_id,
					struct pldm_msg *msg,
					const size_t payload_length)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != PLDM_QUERY_DEVICE_IDENTIFIERS_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = {0};
	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_FWU;
	header.command = PLDM_QUERY_DEVICE_IDENTIFIERS;
	int rc = pack_pldm_header(&header, &(msg->hdr));
	if (PLDM_SUCCESS != rc) {
		return rc;
	}

	return PLDM_SUCCESS;
}

int decode_query_device_identifiers_resp(const struct pldm_msg *msg,
					 const size_t payload_length,
					 uint8_t *completion_code,
					 uint32_t *device_identifiers_len,
					 uint8_t *descriptor_count,
					 struct variable_field *descriptor_data)
{
	if (msg == NULL || completion_code == NULL ||
	    device_identifiers_len == NULL || descriptor_count == NULL ||
	    descriptor_data == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return *completion_code;
	}

	if (payload_length < sizeof(struct query_device_identifiers_resp)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct query_device_identifiers_resp *response =
	    (struct query_device_identifiers_resp *)msg->payload;
	*device_identifiers_len = htole32(response->device_identifiers_len);

	if (*device_identifiers_len < PLDM_FWU_MIN_DESCRIPTOR_IDENTIFIERS_LEN) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	size_t resp_len = sizeof(struct query_device_identifiers_resp);

	if (payload_length != resp_len + *device_identifiers_len) {
		return PLDM_ERROR_INVALID_LENGTH;
	}
	*descriptor_count = response->descriptor_count;

	if (*descriptor_count == 0) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (descriptor_data->length < *device_identifiers_len) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memset(descriptor_data->ptr, 0, descriptor_data->length);
	memcpy(descriptor_data->ptr, msg->payload + resp_len,
	       *device_identifiers_len);

	return PLDM_SUCCESS;
}

int encode_get_firmware_parameters_req(const uint8_t instance_id,
				       struct pldm_msg *msg,
				       const size_t payload_length)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != PLDM_GET_FIRMWARE_PARAMENTERS_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = {0};
	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_FWU;
	header.command = PLDM_GET_FIRMWARE_PARAMENTERS;
	int rc = pack_pldm_header(&header, &(msg->hdr));
	if (PLDM_SUCCESS != rc) {
		return rc;
	}

	return PLDM_SUCCESS;
}

int decode_get_firmware_parameters_comp_img_set_resp(
    const struct pldm_msg *msg, const size_t payload_length,
    struct get_firmware_parameters_resp *resp_data,
    struct variable_field *active_comp_image_set_ver_str,
    struct variable_field *pending_comp_image_set_ver_str)
{
	if (msg == NULL || resp_data == NULL ||
	    active_comp_image_set_ver_str == NULL ||
	    pending_comp_image_set_ver_str == NULL) {

		return PLDM_ERROR_INVALID_DATA;
	}

	const size_t min_resp_len = sizeof(struct get_firmware_parameters_resp);

	if (payload_length < min_resp_len) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct get_firmware_parameters_resp *response =
	    (struct get_firmware_parameters_resp *)msg->payload;

	if (PLDM_SUCCESS != response->completion_code) {
		return response->completion_code;
	}

	if (response->active_comp_image_set_ver_str_len == 0) {
		return PLDM_ERROR_INVALID_DATA;
	}

	size_t resp_len = sizeof(struct get_firmware_parameters_resp) +
			  response->active_comp_image_set_ver_str_len +
			  response->pending_comp_image_set_ver_str_len;

	if (payload_length < resp_len) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	resp_data->capabilities_during_update =
	    htole32(response->capabilities_during_update);
	resp_data->comp_count = htole16(response->comp_count);

	if (resp_data->comp_count == 0) {
		return PLDM_ERROR;
	}

	resp_data->active_comp_image_set_ver_str_type =
	    response->active_comp_image_set_ver_str_type;
	resp_data->active_comp_image_set_ver_str_len =
	    response->active_comp_image_set_ver_str_len;
	resp_data->pending_comp_image_set_ver_str_type =
	    response->pending_comp_image_set_ver_str_type;
	resp_data->pending_comp_image_set_ver_str_len =
	    response->pending_comp_image_set_ver_str_len;

	active_comp_image_set_ver_str->ptr =
	    msg->payload + sizeof(struct get_firmware_parameters_resp);
	active_comp_image_set_ver_str->length =
	    resp_data->active_comp_image_set_ver_str_len;

	if (resp_data->pending_comp_image_set_ver_str_len != 0) {
		pending_comp_image_set_ver_str->ptr =
		    msg->payload + sizeof(struct get_firmware_parameters_resp) +
		    resp_data->active_comp_image_set_ver_str_len;
		pending_comp_image_set_ver_str->length =
		    resp_data->pending_comp_image_set_ver_str_len;
	}

	return PLDM_SUCCESS;
}

int decode_get_firmware_parameters_comp_resp(
    const uint8_t *msg, const size_t payload_length,
    struct component_parameter_table *component_data,
    struct variable_field *active_comp_ver_str,
    struct variable_field *pending_comp_ver_str)
{
	if (msg == NULL || component_data == NULL ||
	    active_comp_ver_str == NULL || pending_comp_ver_str == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length < sizeof(struct component_parameter_table)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct component_parameter_table *component_resp =
	    (struct component_parameter_table *)(msg);
	if (component_resp->active_comp_ver_str_len == 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	size_t resp_len = sizeof(struct component_parameter_table) +
			  component_resp->active_comp_ver_str_len +
			  component_resp->pending_comp_ver_str_len;

	if (payload_length < resp_len) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	component_data->comp_classification =
	    htole16(component_resp->comp_classification);
	component_data->comp_identifier =
	    htole16(component_resp->comp_identifier);
	component_data->comp_classification_index =
	    component_resp->comp_classification_index;
	component_data->active_comp_comparison_stamp =
	    htole32(component_resp->active_comp_comparison_stamp);
	component_data->active_comp_ver_str_type =
	    component_resp->active_comp_ver_str_type;
	component_data->active_comp_ver_str_len =
	    component_resp->active_comp_ver_str_len;
	component_data->active_comp_release_date =
	    htole64(component_resp->active_comp_release_date);
	component_data->pending_comp_comparison_stamp =
	    htole32(component_resp->pending_comp_comparison_stamp);
	component_data->pending_comp_ver_str_type =
	    component_resp->pending_comp_ver_str_type;
	component_data->pending_comp_ver_str_len =
	    component_resp->pending_comp_ver_str_len;
	component_data->pending_comp_release_date =
	    htole64(component_resp->pending_comp_release_date);
	component_data->comp_activation_methods =
	    htole16(component_resp->comp_activation_methods);
	component_data->capabilities_during_update =
	    htole16(component_resp->capabilities_during_update);

	active_comp_ver_str->ptr =
	    msg + sizeof(struct component_parameter_table);
	active_comp_ver_str->length = component_resp->active_comp_ver_str_len;

	if (component_resp->pending_comp_ver_str_len != 0) {

		pending_comp_ver_str->ptr =
		    msg + sizeof(struct component_parameter_table) +
		    component_resp->active_comp_ver_str_len;
		pending_comp_ver_str->length =
		    component_resp->pending_comp_ver_str_len;
	}
	return PLDM_SUCCESS;
}

/*RequestUpdate Encode Request API */
int encode_request_update_req(const uint8_t instance_id, struct pldm_msg *msg,
			      const size_t payload_length,
			      struct request_update_req *data,
			      struct variable_field *comp_img_set_ver_str)
{
	if (msg == NULL || data == NULL || comp_img_set_ver_str == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.pldm_type = PLDM_FWU;
	header.command = PLDM_REQUEST_UPDATE;
	pack_pldm_header(&header, &(msg->hdr));

	int rc = pack_pldm_header(&header, &(msg->hdr));
	if (PLDM_SUCCESS != rc) {
		return rc;
	}

	if (payload_length < sizeof(struct request_update_req)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	memcpy(msg->payload, data, sizeof(struct request_update_req));

	if (payload_length <
	    sizeof(struct request_update_req) + comp_img_set_ver_str->length) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	if (comp_img_set_ver_str->ptr == NULL) {
		return PLDM_ERROR;
	}
	memcpy(msg->payload + sizeof(struct request_update_req),
	       comp_img_set_ver_str->ptr, comp_img_set_ver_str->length);

	return PLDM_SUCCESS;
}

/*RequestUpdate decode Response API */
int decode_request_update_resp(const struct pldm_msg *msg,
			       const size_t payload_length,
			       uint8_t *completion_code,
			       uint16_t *fd_meta_data_len, uint8_t *fd_pkg_data)
{
	if (msg == NULL || completion_code == NULL ||
	    fd_meta_data_len == NULL || fd_pkg_data == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return *completion_code;
	}
	size_t resp_len = sizeof(struct request_update_resp);

	if (payload_length != resp_len) {
		return PLDM_ERROR_INVALID_LENGTH;
	}
	struct request_update_resp *response =
	    (struct request_update_resp *)msg->payload;
	*fd_meta_data_len = htole16(response->fd_meta_data_len);

	*fd_pkg_data = response->fd_pkg_data;

	return PLDM_SUCCESS;
}

int encode_get_device_meta_data_req(const uint8_t instance_id,
				    struct pldm_msg *msg,
				    const size_t payload_length,
				    const uint32_t data_transfer_handle,
				    const uint8_t transfer_operation_flag)
{
	if (msg == NULL || data_transfer_handle == NULL ||
	    transfer_operation_flag == NULL || msg->payload == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != sizeof(struct get_device_meta_data_req)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.pldm_type = PLDM_FWU;
	header.command = PLDM_GET_DEVICE_META_DATA;

	int rc = pack_pldm_header(&header, &(msg->hdr));
	if (PLDM_SUCCESS != rc) {
		return rc;
	}

	struct get_device_meta_data_req *request =
	    (struct get_device_meta_data_req *)msg->payload;

	request->data_transfer_handle = htole32(data_transfer_handle);

	if (!check_transfer_operation_flag_valid(transfer_operation_flag)) {
		return PLDM_INVALID_TRANSFER_OPERATION_FLAG;
	}

	request->transfer_operation_flag = transfer_operation_flag;

	return PLDM_SUCCESS;
}

int decode_get_device_meta_data_resp(
    const struct pldm_msg *msg, const size_t payload_length,
    uint8_t *completion_code, uint32_t *next_data_transfer_handle,
    uint8_t *transfer_flag, struct variable_field *portion_of_meta_data)
{
	if (msg == NULL || completion_code == NULL ||
	    next_data_transfer_handle == NULL || transfer_flag == NULL ||
	    portion_of_meta_data == NULL || msg->payload == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];

	if (*completion_code != PLDM_SUCCESS) {
		return *completion_code;
	}

	if (payload_length < sizeof(struct get_device_meta_data_resp)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct get_device_meta_data_resp *response =
	    (struct get_device_meta_data_resp *)msg->payload;

	*next_data_transfer_handle =
	    le32toh(response->next_data_transfer_handle);

	if (!check_transfer_flag_valid(response->transfer_flag)) {
		return PLDM_INVALID_TRANSFER_OPERATION_FLAG;
	}

	*transfer_flag = response->transfer_flag;

	portion_of_meta_data->ptr =
	    msg->payload + sizeof(struct get_device_meta_data_resp);
	portion_of_meta_data->length =
	    payload_length - sizeof(struct get_device_meta_data_resp);

	return PLDM_SUCCESS;
}

int encode_activate_firmware_req(const uint8_t instance_id,
				 struct pldm_msg *msg,
				 const size_t payload_length,
				 const bool8_t self_contained_activation_req)
{
	if (msg == NULL || self_contained_activation_req == NULL ||
	    msg->payload == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != sizeof(struct activate_firmware_req)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.pldm_type = PLDM_FWU;
	header.command = PLDM_ACTIVATE_FIRMWARE;

	int rc = pack_pldm_header(&header, &(msg->hdr));
	if (PLDM_SUCCESS != rc) {
		return rc;
	}

	struct activate_firmware_req *request =
	    (struct activate_firmware_req *)msg->payload;

	if (self_contained_activation_req !=
		NOT_CONTAINING_SELF_ACTIVATED_COMPONENTS &&
	    self_contained_activation_req !=
		CONTAINS_SELF_ACTIVATED_COMPONENTS) {
		return PLDM_ERROR_INVALID_DATA;
	}

	request->self_contained_activation_req = self_contained_activation_req;

	return PLDM_SUCCESS;
}

int decode_activate_firmware_resp(const struct pldm_msg *msg,
				  const size_t payload_length,
				  uint8_t *completion_code,
				  uint16_t *estimated_time_activation)
{
	if (msg == NULL || completion_code == NULL ||
	    estimated_time_activation == NULL || msg->payload == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];

	if (*completion_code != PLDM_SUCCESS) {
		return *completion_code;
	}

	if (payload_length != sizeof(struct activate_firmware_resp)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct activate_firmware_resp *response =
	    (struct activate_firmware_resp *)msg->payload;

	*estimated_time_activation =
	    le32toh(response->estimated_time_activation);

	return PLDM_SUCCESS;
}

/*PassComponentTable*/

/** @brief Check whether Component Classification is valid
 *
 *  @return true if is from below mentioned values, false if not
 */
static bool check_comp_classification_valid(const uint16_t comp_classification)
{
	switch (comp_classification) {
	case COMP_UNKNOWN:
	case COMP_OTHER:
	case COMP_DRIVER:
	case COMP_CONFIGURATION_SOFTWARE:
	case COMP_APPLICATION_SOFTWARE:
	case COMP_INSTRUMENTATION:
	case COMP_FIRMWARE_OR_BIOS:
	case COMP_DIAGNOSTIC_SOFTWARE:
	case COMP_OPERATING_SYSTEM:
	case COMP_MIDDLEWARE:
	case COMP_FIRMWARE:
	case COMP_BIOS_OR_FCODE:
	case COMP_SUPPORT_OR_SERVICEPACK:
	case COMP_SOFTWARE_BUNDLE:
		return true;

	default:
		return false;
	}
}

/** @brief Check whether Component Version String Type is valid
 *
 *  @return true if is from below mentioned values, false if not
 */
static bool check_comp_ver_str_type_valid(const uint8_t comp_ver_str_type)
{
	switch (comp_ver_str_type) {
	case COMP_VER_STR_TYPE_UNKNOWN:
	case COMP_ASCII:
	case COMP_UTF_8:
	case COMP_UTF_16:
	case COMP_UTF_16LE:
	case COMP_UTF_16BE:
		return true;

	default:
		return false;
	}
}

/** @brief Check whether Component Response Code is valid
 *
 *  @return true if is from below mentioned values, false if not
 */
static bool check_resp_code_valid(const uint8_t comp_resp_code)
{
	switch (comp_resp_code) {
	case COMP_CAN_BE_UPDATED:
	case COMP_COMPARISON_STAMP_IDENTICAL:
	case COMP_COMPARISON_STAMP_LOWER:
	case INVALID_COMP_COMPARISON_STAMP:
	case COMP_CONFLICT:
	case COMP_PREREQUISITES:
	case COMP_NOT_SUPPORTED:
	case COMP_SECURITY_RESTRICTIONS:
	case INCOMPLETE_COMP_IMAGE_SET:
	case COMP_VER_STR_IDENTICAL:
	case COMP_VER_STR_LOWER:
		return true;

	default:
		return false;
	}
}

/*PassComponentTable Encode Request API */
int encode_pass_component_table_req(const uint8_t instance_id,
				    struct pldm_msg *msg,
				    const size_t payload_length,
				    const struct pass_component_table_req *data,
				    struct variable_field *comp_ver_str)
{
	if (msg == NULL || data == NULL || comp_ver_str == NULL ||
	    msg->payload == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length < sizeof(struct pass_component_table_req)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.pldm_type = PLDM_FWU;
	header.command = PLDM_PASS_COMPONENT_TABLE;

	int rc = pack_pldm_header(&header, &(msg->hdr));
	if (PLDM_SUCCESS != rc) {
		return rc;
	}

	if (!check_transfer_flag_valid(data->transfer_flag)) {
		return PLDM_INVALID_TRANSFER_OPERATION_FLAG;
	}

	if (!check_comp_classification_valid(
		htole16(data->comp_classification))) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (!check_comp_ver_str_type_valid(data->comp_ver_str_type)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	memcpy(msg->payload, data, sizeof(struct pass_component_table_req));

	if (payload_length !=
	    sizeof(struct pass_component_table_req) + comp_ver_str->length) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	if (comp_ver_str->ptr == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	memcpy(msg->payload + sizeof(struct pass_component_table_req),
	       comp_ver_str->ptr, comp_ver_str->length);

	return PLDM_SUCCESS;
}

/*PassComponentTable decode Response API */
int decode_pass_component_table_resp(const struct pldm_msg *msg,
				     const size_t payload_length,
				     uint8_t *completion_code,
				     uint8_t *comp_resp,
				     uint8_t *comp_resp_code)
{
	if (msg == NULL || completion_code == NULL || comp_resp == NULL ||
	    comp_resp_code == NULL || msg->payload == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];

	if (*completion_code != PLDM_SUCCESS) {
		return *completion_code;
	}

	if (payload_length != sizeof(struct pass_component_table_resp)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pass_component_table_resp *response =
	    (struct pass_component_table_resp *)msg->payload;

	if (response->comp_resp != COMP_CAN_BE_UPDATEABLE &&
	    response->comp_resp != COMP_MAY_BE_UPDATEABLE) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*comp_resp = response->comp_resp;

	if (!check_resp_code_valid(response->comp_resp_code)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*comp_resp_code = response->comp_resp_code;

	return PLDM_SUCCESS;
}

/** @brief Check whether Component Compatibility Response Code is valid
 *
 *  @return true if is from below mentioned values, false if not
 */
static bool
check_compatability_resp_code_valid(const uint8_t comp_compatability_resp_code)
{
	switch (comp_compatability_resp_code) {
	case NO_RESPONSE_CODE:
	case COMPATABILITY_COMPARISON_STAMP_IDENTICAL:
	case COMPATABILITY_COMPARISON_STAMP_LOWER:
	case INVALID_COMPATABILITY_COMPARISON_STAMP:
	case COMPATABILITY_CONFLICT:
	case COMPATABILITY_PREREQUISITES:
	case COMPATABILITY_NOT_SUPPORTED:
	case COMPATABILITY_SECURITY_RESTRICTIONS:
	case INCOMPLETE_COMPONENT_IMAGE_SET:
	case COMPATABILITY_NO_MATCH:
	case COMPATABILITY_VER_STR_IDENTICAL:
	case COMPATABILITY_VER_STR_LOWER:
		return true;

	default:
		return false;
	}
}

int encode_update_component_req(const uint8_t instance_id, struct pldm_msg *msg,
				const size_t payload_length,
				const struct update_component_req *data,
				struct variable_field *comp_ver_str)
{
	if (msg == NULL || data == NULL || comp_ver_str == NULL ||
	    msg->payload == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length < sizeof(struct update_component_req)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.pldm_type = PLDM_FWU;
	header.command = PLDM_UPDATE_COMPONENT;

	int rc = pack_pldm_header(&header, &(msg->hdr));
	if (PLDM_SUCCESS != rc) {
		return rc;
	}

	if (!check_comp_classification_valid(
		htole16(data->comp_classification))) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (!check_comp_ver_str_type_valid(data->comp_ver_str_type)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	memcpy(msg->payload, data, sizeof(struct update_component_req));

	if (payload_length !=
	    sizeof(struct update_component_req) + comp_ver_str->length) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	if (comp_ver_str->ptr == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	memcpy(msg->payload + sizeof(struct update_component_req),
	       comp_ver_str->ptr, comp_ver_str->length);

	return PLDM_SUCCESS;
}

int decode_update_component_resp(const struct pldm_msg *msg,
				 const size_t payload_length,
				 uint8_t *completion_code,
				 uint8_t *comp_compatability_resp,
				 uint8_t *comp_compatability_resp_code,
				 uint32_t *update_option_flags_enabled,
				 uint16_t *estimated_time_req_fd)
{
	if (msg == NULL || completion_code == NULL ||
	    comp_compatability_resp == NULL ||
	    comp_compatability_resp_code == NULL ||
	    update_option_flags_enabled == NULL ||
	    estimated_time_req_fd == NULL || msg->payload == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];

	if (*completion_code != PLDM_SUCCESS) {
		return *completion_code;
	}

	if (payload_length != sizeof(struct update_component_resp)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct update_component_resp *response =
	    (struct update_component_resp *)msg->payload;

	if (response->comp_compatability_resp != COMPONENT_CAN_BE_UPDATED &&
	    response->comp_compatability_resp != COMPONENT_CANNOT_BE_UPDATED) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*comp_compatability_resp = response->comp_compatability_resp;

	if (!check_compatability_resp_code_valid(
		response->comp_compatability_resp_code)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*comp_compatability_resp_code = response->comp_compatability_resp_code;

	*update_option_flags_enabled =
	    le32toh(response->update_option_flags_enabled);

	*estimated_time_req_fd = le16toh(response->estimated_time_req_fd);

	return PLDM_SUCCESS;
}

/*CancelUpdateComponent*/

/*CancelUpdateComponent Encode Request API */
int encode_cancel_update_component_req(const uint8_t instance_id,
				       struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	return (encode_header_only_request(instance_id, PLDM_FWU,
					   PLDM_CANCEL_UPDATE_COMPONENT, msg));
}

/*CancelUpdateComponent decode Response API */
int decode_cancel_update_component_resp(const struct pldm_msg *msg,
					const size_t payload_length,
					uint8_t *completion_code)
{
	if (msg == NULL || completion_code == NULL || msg->payload == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	return (decode_cc_only_resp(msg, payload_length, completion_code));
}

int encode_cancel_update_req(const uint8_t instance_id, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	return (encode_header_only_request(instance_id, PLDM_FWU,
					   PLDM_CANCEL_UPDATE, msg));
}

int decode_cancel_update_resp(const struct pldm_msg *msg,
			      const size_t payload_len,
			      uint8_t *completion_code,
			      bool8_t *non_functioning_component_indication,
			      uint64_t *non_functioning_component_bitmap)
{
	if (msg == NULL || completion_code == NULL ||
	    non_functioning_component_indication == NULL ||
	    non_functioning_component_bitmap == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return *completion_code;
	}
	if (payload_len != sizeof(struct cancel_update_resp)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}
	struct cancel_update_resp *response =
	    (struct cancel_update_resp *)msg->payload;
	if (response == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	*non_functioning_component_indication =
	    (response->non_functioning_component_indication == 0) ? false
								  : true;
	if (*non_functioning_component_indication) {
		*non_functioning_component_bitmap =
		    le64toh(response->non_functioning_component_bitmap);
	}
	return PLDM_SUCCESS;
}
int encode_verify_complete_resp(const uint8_t instance_id,
				const uint8_t completion_code,
				struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	return (encode_cc_only_resp(instance_id, PLDM_FWU, PLDM_VERIFY_COMPLETE,
				    completion_code, msg));
}

int decode_verify_complete_req(const struct pldm_msg *msg,
			       uint8_t *verify_result)
{
	if (msg == NULL || verify_result == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (!validate_verify_result(msg->payload[0])) {
		return PLDM_ERROR_INVALID_DATA;
	}
	*verify_result = msg->payload[0];
	return PLDM_SUCCESS;
}
