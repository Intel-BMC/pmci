#include <endian.h>
#include <stdbool.h>
#include <string.h>

#include "base.h"

int encode_pldm_header(const uint8_t instance_id, const uint8_t pldm_type,
		       const uint8_t command, const uint8_t msg_type,
		       struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	header.msg_type = msg_type;
	header.instance = instance_id;
	header.pldm_type = pldm_type;
	header.command = command;
	return (pack_pldm_header(&header, &(msg->hdr)));
}

int pack_pldm_header(const struct pldm_header_info *hdr,
		     struct pldm_msg_hdr *msg)
{
	if (msg == NULL || hdr == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (hdr->msg_type != PLDM_RESPONSE && hdr->msg_type != PLDM_REQUEST &&
	    hdr->msg_type != PLDM_ASYNC_REQUEST_NOTIFY) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (hdr->instance > PLDM_INSTANCE_MAX) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (hdr->pldm_type > (PLDM_MAX_TYPES - 1)) {
		return PLDM_ERROR_INVALID_PLDM_TYPE;
	}

	uint8_t datagram = (hdr->msg_type == PLDM_ASYNC_REQUEST_NOTIFY) ? 1 : 0;

	if (hdr->msg_type == PLDM_RESPONSE) {
		msg->request = PLDM_RESPONSE;
	} else if (hdr->msg_type == PLDM_REQUEST ||
		   hdr->msg_type == PLDM_ASYNC_REQUEST_NOTIFY) {
		msg->request = PLDM_REQUEST;
	}
	msg->datagram = datagram;
	msg->reserved = 0;
	msg->instance_id = hdr->instance;
	msg->header_ver = PLDM_CURRENT_VERSION;
	msg->type = hdr->pldm_type;
	msg->command = hdr->command;

	return PLDM_SUCCESS;
}

int unpack_pldm_header(const struct pldm_msg_hdr *msg,
		       struct pldm_header_info *hdr)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (msg->request == PLDM_RESPONSE) {
		hdr->msg_type = PLDM_RESPONSE;
	} else {
		hdr->msg_type =
		    msg->datagram ? PLDM_ASYNC_REQUEST_NOTIFY : PLDM_REQUEST;
	}

	hdr->instance = msg->instance_id;
	hdr->pldm_type = msg->type;
	hdr->command = msg->command;

	return PLDM_SUCCESS;
}

int encode_get_types_req(uint8_t instance_id, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.command = PLDM_GET_PLDM_TYPES;
	pack_pldm_header(&header, &(msg->hdr));

	return PLDM_SUCCESS;
}

static bool8_t convert_version(const ver32_t *version_src, ver32_t *version_dst)
{
	if (version_src == NULL || version_dst == NULL) {
		return false;
	}
	version_dst->major = version_src->alpha;
	version_dst->minor = version_src->update;
	version_dst->update = version_src->minor;
	version_dst->alpha = version_src->major;
	return true;
}

int encode_get_commands_req(uint8_t instance_id, uint8_t type, ver32_t version,
			    struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.command = PLDM_GET_PLDM_COMMANDS;
	pack_pldm_header(&header, &(msg->hdr));

	struct pldm_get_commands_req *request =
	    (struct pldm_get_commands_req *)msg->payload;

	request->type = type;
	// Version in packet is LE and struct ver32_t is reverse order and hence
	// BE.
	if (!convert_version(&version, &request->version)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	return PLDM_SUCCESS;
}

int encode_get_types_resp(uint8_t instance_id, uint8_t completion_code,
			  const bitfield8_t *types, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_get_types_resp *response =
	    (struct pldm_get_types_resp *)msg->payload;

	response->completion_code = completion_code;
	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.command = PLDM_GET_PLDM_TYPES;
	pack_pldm_header(&header, &(msg->hdr));

	if (response->completion_code == PLDM_SUCCESS) {
		if (types == NULL) {
			return PLDM_ERROR_INVALID_DATA;
		}
		memcpy(response->types, types, PLDM_MAX_TYPES / 8);
	}

	return PLDM_SUCCESS;
}

int decode_get_commands_req(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *type, ver32_t *version)
{
	if (msg == NULL || type == NULL || version == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (payload_length != PLDM_GET_COMMANDS_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_commands_req *request =
	    (struct pldm_get_commands_req *)msg->payload;
	*type = request->type;
	// Version in packet is LE and struct ver32_t is reverse order and hence
	// BE
	if (!convert_version(&request->version, version)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	return PLDM_SUCCESS;
}

int encode_get_commands_resp(uint8_t instance_id, uint8_t completion_code,
			     const bitfield8_t *commands, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_get_commands_resp *response =
	    (struct pldm_get_commands_resp *)msg->payload;
	response->completion_code = completion_code;

	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.command = PLDM_GET_PLDM_COMMANDS;
	pack_pldm_header(&header, &(msg->hdr));

	if (response->completion_code == PLDM_SUCCESS) {
		if (commands == NULL) {
			return PLDM_ERROR_INVALID_DATA;
		}
		memcpy(response->commands, commands,
		       PLDM_MAX_CMDS_PER_TYPE / 8);
	}

	return PLDM_SUCCESS;
}

int decode_get_types_resp(const struct pldm_msg *msg, size_t payload_length,
			  uint8_t *completion_code, bitfield8_t *types)
{
	if (msg == NULL || types == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != PLDM_GET_TYPES_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_types_resp *response =
	    (struct pldm_get_types_resp *)msg->payload;

	memcpy(types, response->types, PLDM_MAX_TYPES / 8);

	return PLDM_SUCCESS;
}

int decode_get_commands_resp(const struct pldm_msg *msg, size_t payload_length,
			     uint8_t *completion_code, bitfield8_t *commands)
{
	if (msg == NULL || commands == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != PLDM_GET_COMMANDS_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_commands_resp *response =
	    (struct pldm_get_commands_resp *)msg->payload;

	memcpy(&(commands->byte), response->commands,
	       PLDM_MAX_CMDS_PER_TYPE / 8);

	return PLDM_SUCCESS;
}

int encode_get_version_req(uint8_t instance_id, uint32_t transfer_handle,
			   uint8_t transfer_opflag, uint8_t type,
			   struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;

	if (NULL == msg) {
		return PLDM_ERROR_INVALID_DATA;
	}

	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_BASE;
	header.command = PLDM_GET_PLDM_VERSION;

	if ((rc = pack_pldm_header(&header, &(msg->hdr))) > PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_version_req *request =
	    (struct pldm_get_version_req *)msg->payload;
	transfer_handle = htole32(transfer_handle);
	request->transfer_handle = transfer_handle;
	request->transfer_opflag = transfer_opflag;
	request->type = type;

	return PLDM_SUCCESS;
}

int encode_get_version_resp(const uint8_t instance_id,
			    const uint8_t completion_code,
			    const uint32_t next_transfer_handle,
			    const uint8_t transfer_flag,
			    const struct variable_field *version_data,
			    struct pldm_msg *msg)
{
	if (NULL == version_data || NULL == msg) {
		return PLDM_ERROR_INVALID_DATA;
	}

	int rc = PLDM_SUCCESS;
	struct pldm_header_info header = {0};
	header.msg_type = PLDM_RESPONSE;
	header.instance = instance_id;
	header.pldm_type = PLDM_BASE;
	header.command = PLDM_GET_PLDM_VERSION;
	if ((rc = pack_pldm_header(&header, &(msg->hdr))) != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_get_version_resp *response =
	    (struct pldm_get_version_resp *)msg->payload;

	response->completion_code = completion_code;
	if (response->completion_code != PLDM_SUCCESS) {
		return PLDM_SUCCESS;
	}

	if (!check_transfer_flag_valid(transfer_flag)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (version_data->ptr == NULL || version_data->length == 0) {
		return PLDM_ERROR_INVALID_DATA;
	}

	response->next_transfer_handle = htole32(next_transfer_handle);
	response->transfer_flag = transfer_flag;
	memcpy(response->version_data, version_data->ptr, version_data->length);

	return PLDM_SUCCESS;
}

int decode_get_version_req(const struct pldm_msg *msg,
			   const size_t payload_length,
			   uint32_t *transfer_handle, uint8_t *transfer_opflag,
			   uint8_t *type)
{
	if (NULL == msg || NULL == transfer_handle || NULL == transfer_opflag ||
	    NULL == type) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (payload_length != PLDM_GET_VERSION_REQ_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_version_req *request =
	    (struct pldm_get_version_req *)msg->payload;
	if (!check_transfer_operation_flag_valid(request->transfer_opflag)) {
		return PLDM_ERROR_INVALID_DATA;
	}
	*transfer_handle = le32toh(request->transfer_handle);
	*transfer_opflag = request->transfer_opflag;
	*type = request->type;
	return PLDM_SUCCESS;
}

int decode_get_version_resp(const struct pldm_msg *msg, size_t payload_length,
			    uint8_t *completion_code,
			    uint32_t *next_transfer_handle,
			    uint8_t *transfer_flag,
			    struct variable_field *version)
{
	if (msg == NULL || next_transfer_handle == NULL ||
	    transfer_flag == NULL || completion_code == NULL ||
	    version == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length < PLDM_GET_VERSION_RESP_FIXED_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_version_resp *response =
	    (struct pldm_get_version_resp *)msg->payload;
	*next_transfer_handle = le32toh(response->next_transfer_handle);
	*transfer_flag = response->transfer_flag;

	if (!check_transfer_flag_valid(*transfer_flag)) {
		return PLDM_ERROR_INVALID_DATA;
	}

	version->length = payload_length - PLDM_GET_VERSION_RESP_FIXED_BYTES;
	version->ptr = response->version_data;

	return PLDM_SUCCESS;
}

int encode_get_tid_req(uint8_t instance_id, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_REQUEST;
	header.command = PLDM_GET_TID;
	pack_pldm_header(&header, &(msg->hdr));

	return PLDM_SUCCESS;
}
int encode_get_tid_resp(uint8_t instance_id, uint8_t completion_code,
			uint8_t tid, struct pldm_msg *msg)
{
	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	struct pldm_get_tid_resp *response =
	    (struct pldm_get_tid_resp *)msg->payload;

	response->completion_code = completion_code;
	struct pldm_header_info header = {0};
	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.command = PLDM_GET_TID;
	pack_pldm_header(&header, &(msg->hdr));

	response->tid = tid;

	return PLDM_SUCCESS;
}

int decode_get_tid_resp(const struct pldm_msg *msg, size_t payload_length,
			uint8_t *completion_code, uint8_t *tid)
{
	if (msg == NULL || tid == NULL || completion_code == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	*completion_code = msg->payload[0];
	if (PLDM_SUCCESS != *completion_code) {
		return PLDM_SUCCESS;
	}

	if (payload_length != PLDM_GET_TID_RESP_BYTES) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_get_tid_resp *response =
	    (struct pldm_get_tid_resp *)msg->payload;

	*tid = response->tid;

	return PLDM_SUCCESS;
}

int encode_cc_only_resp(uint8_t instance_id, uint8_t type, uint8_t command,
			uint8_t cc, struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};

	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}

	header.instance = instance_id;
	header.msg_type = PLDM_RESPONSE;
	header.pldm_type = type;
	header.command = command;
	int rc = pack_pldm_header(&header, &msg->hdr);
	if (rc != PLDM_SUCCESS) {
		return rc;
	}

	msg->payload[0] = cc;

	return PLDM_SUCCESS;
}

int decode_cc_only_resp(const struct pldm_msg *msg, const size_t payload_length,
			uint8_t *completion_code)
{
	if (NULL == msg || NULL == completion_code) {
		return PLDM_ERROR_INVALID_DATA;
	}
	if (sizeof(uint8_t) != payload_length) {
		return PLDM_ERROR_INVALID_LENGTH;
	}
	struct pldm_cc_only_rsp *rsp =
	    (struct pldm_cc_only_rsp *)(msg->payload);
	*completion_code = rsp->completion_code;

	return PLDM_SUCCESS;
}

int encode_set_tid_req(const uint8_t instance_id, const uint8_t tid,
		       struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;

	if (NULL == msg) {
		return PLDM_ERROR_INVALID_DATA;
	}

	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = PLDM_BASE;
	header.command = PLDM_SET_TID;

	if ((rc = pack_pldm_header(&header, &(msg->hdr))) != PLDM_SUCCESS) {
		return rc;
	}

	struct pldm_set_tid_req *request =
	    (struct pldm_set_tid_req *)msg->payload;
	request->tid = tid;

	return PLDM_SUCCESS;
}

int decode_set_tid_req(const struct pldm_msg *msg, const size_t payload_length,
		       uint8_t *tid)
{
	if (NULL == msg || NULL == tid) {
		return PLDM_ERROR_INVALID_DATA;
	}

	if (sizeof(struct pldm_set_tid_req) != payload_length) {
		return PLDM_ERROR_INVALID_LENGTH;
	}

	struct pldm_set_tid_req *request =
	    (struct pldm_set_tid_req *)msg->payload;
	*tid = request->tid;

	return PLDM_SUCCESS;
}

int encode_header_only_request(const uint8_t instance_id,
			       const uint8_t pldm_type, const uint8_t command,
			       struct pldm_msg *msg)
{
	struct pldm_header_info header = {0};
	int rc = PLDM_SUCCESS;

	if (msg == NULL) {
		return PLDM_ERROR_INVALID_DATA;
	}
	header.msg_type = PLDM_REQUEST;
	header.instance = instance_id;
	header.pldm_type = pldm_type;
	header.command = command;

	rc = pack_pldm_header(&header, &(msg->hdr));

	return rc;
}
