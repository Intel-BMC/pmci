## MCTP Emulator

## Overview
This repo exists to support MCTP to all upper layer applications in PMCI stack.
The upper layers for example are SPDM, PLDM, Intel VDMs like telemetry,
Crash Dump etc.

This is meant to be a mock up for upper layers to use until their
actual target hardware is available.

Anyone who find this useful for there upper layer application can
contribute to this daemon.

## Usage details:
This daemon will get compiled only if debug-tweaks are enabled.

Daemon exposes D-Bus methods / properties / signals for MCTP devices or MCTP
Endpoint. Upper layers can emulate MCTP Message TX and RX using MCTP Emulator.
It will expose following objects.
1. Base object
2. MCTP Endpoints

#### Base object
Exposed under the path `/xyz/openbmc_project/mctp` with the following
interfaces.
1. `xyz.openbmc_project.MCTP.Base` which exposes all the common properties
needed.
2. `xyz.openbmc_project.MCTP.SupportedMessageTypes` which exposes the message
types supported.
3. `SendMctpMessagePayload` method call can send MCTP request. This uses the
raw request bytes and the corresponding responses from
configurations/req_resp.json.

#### Endpoint object
Exposed under the path `/xyz/openbmc_project/mctp/device/<eid>` with the
following interfaces.
1. `xyz.openbmc_project.MCTP.SupportedMessageTypes` which exposes supported MCTP
message types for the discovered MCTP Endpoint.
2. `xyz.openbmc_project.MCTP.Endpoint` which exposes properties like UUID and
endpoint mode (to identify Bus Owner or Bridge or Endpoint) for the MCTP
Endpoint.

The json files used for configuration will be installed under
/usr/share/mctp-emulator/ folder in the BMC. To dynamically modify this config
file in run time, please mount /usr as rw partition in overlay fs
(by running rw.sh) and modify.
