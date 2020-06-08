/*
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

/**
 * @file mctpw.h
 * @brief API for MCTP wrapper library. The library hides underlying MCTP
 * implementation from client. Implementation will use dbus API exposed by mctp
 * daemon. MCTP wrapper can handle any MCTP messages types (including vendor
 * defined message types) except MCTP control messages that must be handled in
 * mctp service process.
 */

#ifndef MCTPW_H
#define MCTPW_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _VERSION 0x010101

typedef uint8_t mctpw_eid_t;

typedef enum
{
    mctp_over_smbus = 0x01,
    mctp_over_pcie_vdm = 0x02,
    mctp_over_usb = 0x03,
    mctp_over_kcs = 0x04,
    mctp_over_serial = 0x05,
    vendor_defined = 0xFF,
} mctpw_binding_type_t;

typedef enum
{
    /** @brief Platform Level Data Model over MCTP */
    pldm = 0x01,
    /** @brief NC-SI over MCTP */
    ncsi = 0x02,
    /** @brief Ethernet over MCTP */
    ethernet = 0x03,
    /** @brief NVM Express Management Messages over MCTP */
    nvme_mgmt_msg = 0x04,
    /** @brief Security Protocol and Data Model over MCTP */
    spdm = 0x05,
    /** @brief Vendor Defined PCI */
    vdpci = 0x7E,
    /** @brief Vendor Defined IANA */
    vdiana = 0x7F,
} mctpw_message_type_t;

typedef struct
{
    uint8_t uuid[16];
    uint16_t network_id;
    uint16_t vendor_type[8];
    uint8_t vendor_type_count;
    bool mctp_control;
    bool pldm;
    bool ncsi;
    bool ethernet;
    bool nvme_mgmt_msg;
    bool spdm;
    bool vdpci;
    bool vdiana;
} mctpw_endpoint_properties_t;

typedef void (*mctpw_reconfiguration_callback_t)(void* client_context);

typedef void (*mctpw_receive_message_callback_t)(
    void* client_context, mctpw_eid_t* src_eid, uint8_t tag_owner, uint8_t tag,
    uint8_t* payload, unsigned payload_length, int error);

/**
 * @brief Helper function to locate MCTP bus for given binding.
 * User can iterate buses starting from index 0
 * to locate all busses of given binding type
 * @param binding_type Requested binding type
 * @param bus_index Index of bus
 * @param mctpw_bus_handle handle to bus returned on success
 * @return 0 if success or negative error code
 */
int mctpw_find_bus_by_binding_type(mctpw_binding_type_t binding_type,
                                   unsigned bus_index, void** mctpw_bus_handle);

/**
 * @brief Register client on the bus for specyfic message type.
 * If message type is vendor defined parameters vendor_id, vendor_message_type,
 * vendor_message_type_mask are valid and should be provided, otherwise these
 * parameters are ignored.
 * @param mctpw_bus_handle bus handle @see mctpw_find_bus_by_binding_type()
 * @param type specifies message type to use for Rx/Tx
 * @param vendor_id vendor identifier(for Intel: 0x8086)
 * @param receive_requests indicates that client is responder for a certain
 * message_type
 * @param vendor_message_type vendor message type
 * @param vendor_message_type_mask vendor message type mask
 * @param nc_cb Callback function for network change notification,
 *              can be NULL if client doesn't support notifications
 * @param rx_cb Callback function for receive messages,
 *              can be NULL if client doesn't support async rx
 * @param client_context if success set to client context data
 * @return 0 if success or negative error code
 */
int mctpw_register_client(void* mctpw_bus_handle, mctpw_message_type_t type,
                          uint32_t vendor_id, bool receive_requests,
                          uint16_t vendor_message_type,
                          uint16_t vendor_message_type_mask,
                          mctpw_reconfiguration_callback_t nc_cb,
                          mctpw_receive_message_callback_t rx_cb,
                          void** client_context);
/**
 * @brief Unregister client and release all resources.
 * @param client_context Pointer to client context
 */
void mctpw_unregister_client(void* client_context);

/**
 * @brief Get list of all endpoints on the bus.
 * @param client_context Pointer to client context
 * @param eids Table to write endpoint list
 * @param num input:number of entries in the eids table,
 *            output:number of entries already written to eids table
 * @return 0 if success
 *         >0 number of eids not written due to lack of space in the table
 *         or negative error code
 */
int mctpw_get_endpoint_list(void* client_context, mctpw_eid_t* eids,
                            unsigned* num);

/**
 * @brief Get list of all endpoints supporting message type client is registered
 * for.
 * @param client_context Pointer to client context
 * @param eids Table to write endpoint list
 * @param num input:number of entries in the eids table,
 *            output:number of entries already written to eids table
 * @return 0 if success
 *         >0 number of eids not written due to lack of space in the table
 *         or negative error code
 */
int mctpw_get_matching_endpoint_list(void* client_context, mctpw_eid_t* eids,
                                     unsigned* num);

/**
 * @brief Get endpoint properties.
 * @param client_context Pointer to client context
 * @param eid eid of endpoint
 * @param properties pointer to mctpw_endpoint_properties_t structure for output
 * @return 0 if success or negative error code
 */
int mctpw_get_endpoint_properties(void* client_context, mctpw_eid_t eid,
                                  mctpw_endpoint_properties_t* properties);

/**
 * @brief Send mctp payload to specyfic endpoint on the bus.
 * @note Payload start right after 4 byte MCTP header.
 * Message type encoded in payload must much exactly the message used when
 * registering client otherwise this massage will be rejected.
 * @param client_context Pointer to client context
 * @param dst_eid destination endpoint eid
 * @param tag_owner - indicates if this is request (tag_owner = 1) or reply
 *                    message (tag_owner = 0)
 * @param tag - numeric tag in rage 0..7 be used to identify messages,
 *              when sending reply this must be same as received tag.
 * @param datagram_flag if true datagram is send and no response is expected
 * @param payload pointer to buffer contains payload
 * @param payload_length length of payload
 * @return 0 if success or negative error code
 */
int mctpw_send_message(void* client_context, mctpw_eid_t dst_eid,
                       uint8_t tag_owner, uint8_t tag, bool datagram_flag,
                       uint8_t* payload, unsigned payload_length);

/**
 * @brief Send mctp payload to specyfic endpoint on the bus and receive
 * response. This is blocking function, it sends message and waits for response.
 * Bus is blocked for time of message exchange. Rx callbacks are not invoked.
 * @note tag_owner and tag are generated automatically and not need to be
 * specified.
 * @param client_context Pointer to client context
 * @param dst_eid destination endpoint eid
 * @param request_payload pointer to payload buffer
 * @param request_payload_length length of payload
 * @param response_payload response buffer pointer
 * @param response_payload_length input:length of buffer
 *                                output:message length
 * @param timeout timeout in ms
 * @return 0 if success or negative error code
 */
int mctpw_send_receive_atomic_message(void* client_context, mctpw_eid_t dst_eid,
                                      uint8_t* request_payload,
                                      unsigned request_payload_length,
                                      uint8_t* response_payload,
                                      unsigned* response_payload_length,
                                      unsigned timeout);

#ifdef __cplusplus
}
#endif
#endif // MCTPW_H
