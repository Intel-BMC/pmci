#pragma once

#include "utils/pcie/PCIeTestBase.hpp"

#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <map>

#include "libmctp-msgtypes.h"

struct MessageHelpers
{
    struct mctp_ctrl_resp_get_routing_table_entry
    {
        get_routing_table_entry entry;
        uint16_t bdf;
    } __attribute__((__packed__));

    static inline mctp_ctrl_resp_get_routing_table_entry*
        getEntryArray(mctp_ctrl_resp_get_routing_table* response)
    {
        auto ptr = reinterpret_cast<uint8_t*>(response);
        return reinterpret_cast<mctp_ctrl_resp_get_routing_table_entry*>(
            &ptr[sizeof(*response)]);
    }

    static inline msg_type_entry*
        getTypeArray(mctp_ctrl_resp_get_msg_type_support* response)
    {
        auto ptr = reinterpret_cast<uint8_t*>(response);
        return reinterpret_cast<msg_type_entry*>(&ptr[sizeof(*response)]);
    }
};

static const std::map<uint8_t, std::string> msgTypeToPropertyName{
    {MCTP_MESSAGE_TYPE_MCTP_CTRL, "MctpControl"},
    {MCTP_MESSAGE_TYPE_PLDM, "PLDM"},
    {MCTP_MESSAGE_TYPE_NCSI, "NCSI"},
    {MCTP_MESSAGE_TYPE_ETHERNET, "Ethernet"},
    {MCTP_MESSAGE_TYPE_NVME, "NVMeMgmtMsg"},
    {MCTP_MESSAGE_TYPE_SPDM, "SPDM"},
    {MCTP_MESSAGE_TYPE_VDPCI, "VDPCI"},
    {MCTP_MESSAGE_TYPE_VDIANA, "VDIANA"}};

class PCIeDiscoveredTestBase : public PCIeTestBase, public MessageHelpers
{
  public:
    static constexpr uint16_t busOwnerBdf = 0xBEEF;
    static constexpr uint8_t assignedEid = 0x99;

    PCIeDiscoveredTestBase()
    {
        discoveryFlow();
    }

    void discoveryFlow()
    {
        schedule([&]() {
            auto response =
                binding->backdoor
                    .prepareCtrlResponse<mctp_ctrl_resp_discovery_notify>(
                        mctp_astpcie_pkt_private{PCIE_ROUTE_TO_RC, 0});
            response.payload->completion_code = MCTP_CTRL_CC_SUCCESS;
            binding->backdoor.rx(response);
        });

        schedule([&]() {
            auto request =
                binding->backdoor.prepareCtrlRequest<mctp_ctrl_msg_hdr>(
                    MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY, {0, 0},
                    {PCIE_BROADCAST_FROM_RC, busOwnerBdf});
            binding->backdoor.rx(request);
        });

        auto sendDiscovery = makePromise<mctp_ctrl_resp_endpoint_discovery>();
        schedule([&]() {
            auto request =
                binding->backdoor.prepareCtrlRequest<mctp_ctrl_msg_hdr>(
                    MCTP_CTRL_CMD_ENDPOINT_DISCOVERY, {0, 0},
                    {PCIE_BROADCAST_FROM_RC, busOwnerBdf});
            binding->backdoor.rx(request);
        });

        auto discoveryDone = makePromise<void>();
        schedule([&]() {
            auto request =
                binding->backdoor.prepareCtrlRequest<mctp_ctrl_cmd_set_eid>(
                    MCTP_CTRL_CMD_SET_ENDPOINT_ID, {0, 0},
                    {PCIE_ROUTE_BY_ID, busOwnerBdf});
            request.payload->eid = assignedEid;
            request.payload->operation = set_eid;
            binding->backdoor.rx(request);

            discoveryDone.promise.set_value();
        });

        waitFor(discoveryDone.future);
    }

    struct RoutingTableParam
    {
        uint16_t bdf;
        uint8_t eid;
        uint8_t entryTypesMask;
    };

    void provideRoutingTable(const std::vector<RoutingTableParam> entries)
    {
        binding->backdoor.onOutgoingCtrlCommand(
            MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES, [this, entries]() {
                const uint8_t ENDPOINT_COUNT =
                    static_cast<uint8_t>(entries.size());
                const size_t TABLE_SIZE =
                    sizeof(mctp_ctrl_resp_get_routing_table_entry) *
                    ENDPOINT_COUNT;

                auto response =
                    binding->backdoor
                        .prepareCtrlResponse<mctp_ctrl_resp_get_routing_table>(
                            {}, TABLE_SIZE);

                response.payload->completion_code = MCTP_CTRL_CC_SUCCESS;
                response.payload->number_of_entries = ENDPOINT_COUNT;
                response.payload->next_entry_handle = 0xff;

                auto populateEntry =
                    [&](const RoutingTableParam& params,
                        mctp_ctrl_resp_get_routing_table_entry& tableEntry) {
                        auto& entry = tableEntry.entry;
                        entry.phys_address_size = sizeof(tableEntry.bdf);
                        entry.phys_transport_binding_id = MCTP_BINDING_PCIE;
                        entry.eid_range_size = 1;

                        tableEntry.bdf = htobe16(params.bdf);
                        entry.starting_eid = params.eid;
                        entry.entry_type = params.entryTypesMask;
                    };

                mctp_ctrl_resp_get_routing_table_entry* ptrEntryDest =
                    getEntryArray(response.payload);
                for (const RoutingTableParam& entrySrc : entries)
                {
                    populateEntry(entrySrc, *ptrEntryDest++);
                }

                binding->backdoor.rx(response);
            });
    }

    void provideMessageTypes(const uint8_t eid,
                             const std::vector<uint8_t>& types)
    {
        binding->backdoor.onOutgoingCtrlCommand(
            MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT, eid, [this, types]() {
                const uint8_t MSG_TYPE_COUNT =
                    static_cast<uint8_t>(types.size());
                const size_t TABLE_SIZE =
                    sizeof(msg_type_entry) * MSG_TYPE_COUNT;

                auto response = binding->backdoor.prepareCtrlResponse<
                    mctp_ctrl_resp_get_msg_type_support>({}, TABLE_SIZE);

                response.payload->completion_code = MCTP_CTRL_CC_SUCCESS;
                response.payload->msg_type_count = MSG_TYPE_COUNT;

                msg_type_entry* ptrTypeDest = getTypeArray(response.payload);
                for (const uint8_t typeSrc : types)
                {
                    *ptrTypeDest++ = msg_type_entry{typeSrc};
                }

                binding->backdoor.rx(response);
            });
    }

    void provideUuid(const uint8_t eid, const std::string uuidStr)
    {
        binding->backdoor.onOutgoingCtrlCommand(
            MCTP_CTRL_CMD_GET_ENDPOINT_UUID, eid, [this, uuidStr]() {
                auto response =
                    binding->backdoor
                        .prepareCtrlResponse<mctp_ctrl_resp_get_uuid>();

                boost::uuids::uuid uuid =
                    boost::lexical_cast<boost::uuids::uuid>(uuidStr);
                response.payload->completion_code = MCTP_CTRL_CC_SUCCESS;
                response.payload->uuid = *reinterpret_cast<guid_t*>(&uuid.data);

                binding->backdoor.rx(response);
            });
    }
};
