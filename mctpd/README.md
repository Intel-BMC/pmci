# MCTP Daemon
This component implements MCTP Base Specification DSP0236(MCTP Base
Specification), DSP0237(MCTP SMBus/I2C Transport Binding Specification) and
DSP0238(MCTP PCIe VDM Transport Binding Specification).

## Overview
MCTP service is responsible for discovering endpoints in the network (either as
a bus owner or by querying routing table from bus owner). This also provides
mechanisms(D-Bus methods) for upper layer applications to transmit and receive
MCTP packets.

## MCTP Over SMBus support(As MCTP bus owner)
Supports
1. Seperate instances on different physical bus
2. Device discovery
3. Hotplug device discovery
4. 'Pull Model - Support to initiate MCTP message for an endpoint' MCTP message
   support
5. Device watcher to handle rogue/buggy device
6. MCTP supported device list filter

### Assumptions
1. Bus Owners to have a statically allocated pool of EIDs
2. SMBus ARP Master is out of scope for this document
3. PLDM, Intel Vendor Defined Messages and other MCTP Message Types are out of
   scope

### Device Discovery
BMC takes statically configurations(EID pool, bus path etc..) exposed by
`entity-manager` or by JSON file. BMC scans those buses for MCTP capable devices
and executes the bus owner responsibilities of EID assignment and device
capability discovery.

### MCTP Control Commands Supported on SMBus Binding

| **MCTP Control command**               | **Command Code** | **Requester** | **Responder** | **Comments**                                                                                                            |
| -------------------------------------- | ---------------- | ------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Set Endpoint ID**                    | 0x01             | Supported     | N/A           | Allocated Endpoint IDs to MCTP Endpoints. Allocation of pool to bridges is not supported. Clause 12.3 in DPS0236 v1.3.0 |
| **Get Endpoint ID**                    | 0x02             | Supported     | Supported     | Generates and responds to Get EID command. Clause 12.4 in DPS0236 v1.3.0                                                |
| **Get Endpoint UUID**                  | 0x03             | Supported     | N/A           | Queries a device’s UUID available in the same network. Clause 12.5 in DPS0236 v1.3.0                                    |
| **Get MCTP Version Support**           | 0x04             | Supported     | Supported     | Clause 12.6 in DPS0236 v1.3.0                                                                                           |
| **Get Message Type Support**           | 0x05             | Supported     | Supported     | Clause 12.7 in DPS0236 v1.3.0                                                                                           |
| **Get Vendor Defined Message Support** | 0x06             | Supported     | Supported     | Clause 12.8 in DPS0236 v1.3.0                                                                                           |

### I2C Multiplexer Support
BMC needs to keep the I2C Mux channel open for the endpoint devices to send the
responses. In addition, "pull model" MCTP message support(Mux channels need to
be opened for MCTP messages originating from the endpoint to reach BMC) is
implemented using `ReserveBandwidth` and `ReleaseBandwidth` D-Bus method calls
(Usecase: PLDM firmware update).

## MCTP over PCIe VDM(As MCTP endpoint)
Supports
1. Discovery by a bus owner on the PCIe bus
2. MCTP communication with other endpoints on PCIe bus
3. Support for MCTP VDM PCI message format

### MCTP Control commands supported in PCIe endpoint

| **MCTP Control command**               | **Command Code** | **Requester** | **Responder** | **Comments**                                                                                                                                         |
| -------------------------------------- | ---------------- | ------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Set Endpoint ID**                    | 0x01             | N/A           | Supported     | Accepts EID set by PCIe Bus Owner. Clause 12.3 in DPS0236 v1.3.0                                                                                     |
| **Get Endpoint ID**                    | 0x02             | N/A           | Supported     | Accepts incoming Get EID commands and responds appropriately. Clause 12.4 in DPS0236 v1.3.0                                                          |
| **Get Endpoint UUID**                  | 0x03             | Supported     | N/A           | Queries a device’s UUID available in the same network. Clause 12.5 in DPS0236 v1.3.0                                                                 |
| **Get MCTP Version Support**           | 0x04             | N/A           | Supported     | Clause 12.6 in DPS0236 v1.3.0                                                                                                                        |
| **Get Message Type Support**           | 0x05             | Supported     | Supported     | Support for discovering a device’s MCTP capabilities as well as allow discovery of BMC’s supported MCTP Message Types. Clause 12.7 in DPS0236 v1.3.0 |
| **Get Vendor Defined Message Support** | 0x06             | N/A           | Supported     | Allow discovery of BMC’s supported Vendor Defined MCTP Message Types. Clause 12.8 in DPS0236 v1.3.0                                                  |
| **Get Routing Table Entries**          | 0x0A             | Supported     | N/A           | Used for discovery of neighboring MCTP Endpoints. Clause 12.12 in DPS0236 v1.3.0                                                                     |
| **Prepare for Endpoint Discovery**     | 0x0B             | N/A           | Supported     | Responds to Bus Owner’s prepare for Endpoint Discovery command. Clause 12.13 in DPS0236 v1.3.0                                                       |
| **Endpoint Discovery**                 | 0x0C             | N/A           | Supported     | Responds to Bus Owner’s Endpoint Discovery command. Clause 12.14 in DPS0236 v1.3.0                                                                   |
| **Discovery Notify**                   | 0x0D             | Supported     | N/A           | Clause 12.15 in DPS0236 v1.3.0                                                                                                                       |

## Standalone Build
To build the package do the following
1. mkdir build
2. cd build
3. cmake -DBUILD_STANDALONE=ON -DMCTPD_BUILD_UT=ON ../
4. make

## TODO Items
1. MCTP bridging