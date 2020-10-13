#include <endian.h>
#include <string.h>

#include "firmware_update.h"

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

int decode_get_firmware_parameters_resp(
    const struct pldm_msg *msg, const size_t payload_length,
    uint8_t *completion_code, struct get_firmware_parameters_resp *resp_data,
    struct variable_field *active_comp_image_set_ver_str,
    struct variable_field *pending_comp_image_set_ver_str,
    struct component_parameter_table *component_data,
    struct variable_field *active_comp_ver_str,
    struct variable_field *pending_comp_ver_str)
{
	if (msg == NULL || completion_code == NULL || resp_data == NULL ||
	    active_comp_image_set_ver_str == NULL ||
	    pending_comp_image_set_ver_str == NULL || component_data == NULL ||
	    active_comp_ver_str == NULL || pending_comp_ver_str == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	const size_t min_resp_len = sizeof(struct get_firmware_parameters_resp);

	if (payload_length < min_resp_len) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return *completion_code;
	}

	struct get_firmware_parameters_resp *response =
	    (struct get_firmware_parameters_resp *)msg->payload;

	if (response->active_comp_image_set_ver_str_len == 0) {
		return PLDM_ERROR_INVALID_DATA;
	}

	size_t resp_len = sizeof(struct get_firmware_parameters_resp) +
			  response->active_comp_image_set_ver_str_len +
			  response->pending_comp_image_set_ver_str_len;

	if (payload_length <
	    resp_len + sizeof(struct component_parameter_table)) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct component_parameter_table *component_resp =
	    (struct component_parameter_table *)(msg->payload + resp_len);

	if (component_resp->active_comp_ver_str_len == 0) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	resp_len += sizeof(struct component_parameter_table) +
		    component_resp->active_comp_ver_str_len +
		    component_resp->pending_comp_ver_str_len;

	if (payload_length != resp_len) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	resp_data->capabilities_during_update =
	    htole32(response->capabilities_during_update);
	resp_data->comp_count = htole16(response->comp_count);
	resp_data->active_comp_image_set_ver_str_type =
	    response->active_comp_image_set_ver_str_type;
	resp_data->active_comp_image_set_ver_str_len =
	    response->active_comp_image_set_ver_str_len;
	resp_data->pending_comp_image_set_ver_str_type =
	    response->pending_comp_image_set_ver_str_type;
	resp_data->pending_comp_image_set_ver_str_len =
	    response->pending_comp_image_set_ver_str_len;

	// 1 extra byte for appending null at the end
	if (active_comp_image_set_ver_str->length <
	    response->active_comp_image_set_ver_str_len + 1) {
		return PLDM_ERROR;
	}
	memset(active_comp_image_set_ver_str->ptr, 0,
	       active_comp_image_set_ver_str->length);
	memcpy(active_comp_image_set_ver_str->ptr,
	       msg->payload + sizeof(struct get_firmware_parameters_resp),
	       resp_data->active_comp_image_set_ver_str_len);

	if (resp_data->pending_comp_image_set_ver_str_len != 0) {
		// 1 extra byte for appending null at the end
		if (pending_comp_image_set_ver_str->length <
		    response->pending_comp_image_set_ver_str_len + 1) {
			return PLDM_ERROR;
		}

		memset(pending_comp_image_set_ver_str->ptr, 0,
		       pending_comp_image_set_ver_str->length);
		memcpy(pending_comp_image_set_ver_str->ptr,
		       msg->payload +
			   sizeof(struct get_firmware_parameters_resp) +
			   resp_data->active_comp_image_set_ver_str_len,
		       resp_data->pending_comp_image_set_ver_str_len);
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

	// 1 extra byte for appending null at the end
	if (active_comp_ver_str->length <
	    component_resp->active_comp_ver_str_len + 1) {
		return PLDM_ERROR;
	}
	memset(active_comp_ver_str->ptr, 0, active_comp_ver_str->length);
	memcpy(active_comp_ver_str->ptr,
	       msg->payload + sizeof(struct get_firmware_parameters_resp) +
		   response->active_comp_image_set_ver_str_len +
		   response->pending_comp_image_set_ver_str_len +
		   sizeof(struct component_parameter_table),
	       component_resp->active_comp_ver_str_len);

	if (component_resp->pending_comp_ver_str_len != 0) {
		// 1 extra byte for appending null at the end
		if (pending_comp_ver_str->length <
		    component_resp->pending_comp_ver_str_len + 1) {
			return PLDM_ERROR;
		}

		memset(pending_comp_ver_str->ptr, 0,
		       pending_comp_ver_str->length);
		memcpy(pending_comp_ver_str->ptr,
		       msg->payload +
			   sizeof(struct get_firmware_parameters_resp) +
			   response->active_comp_image_set_ver_str_len +
			   response->pending_comp_image_set_ver_str_len +
			   sizeof(struct component_parameter_table) +
			   component_resp->active_comp_ver_str_len,
		       component_resp->pending_comp_ver_str_len);
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