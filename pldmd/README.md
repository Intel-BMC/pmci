# PLDM Daemon
This component implements PLDM Requester functionalities.

## Overview
This component implements PLDM types as per below table.

| PLDM Type                                                                                                                                   | Supports                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------  | ---------------------------------------------------------------------------------------------------------------------------------- |
| PLDM Messaging Control and Discovery – [DSP0240 v1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0240_1.0.0.pdf)     | Implements requester functionality.<br>Discovery of PLDM Terminus, PLDM Types support and the commands supported by PLDM terminus. |
| PLDM for SMBIOS – [DSP0246 v1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0246_1.0.0.pdf)                          | Not supported                                                                                                                      |
| PLDM for Platform Monitoring and Control – [DSP0248 v1.2.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0248_1.2.0.pdf) | Implements requester functionality.<br>Monitoring and control commands to support sensors and effecters.                           |
| PLDM for BIOS Control and Configuration – [DSP0247 v1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0247_1.0.0.pdf)  | Not supported                                                                                                                      |
| PLDM for FRU Data – [DSP0257 v1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0257_1.0.0.pdf)                        | Implements requester functionality.<br>PLDM FRU commands to read/write FRU fields of terminus                                      |
| PLDM for Firmware Update – [DSP0267 v1.0.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0267_1.0.1.pdf)                 | Implements requester functionality.<br>Implements UA (Update Agent) functionality                                                  |
| PLDM for Redfish Device Enablement – [DSP0218 v1.1.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0218_1.1.0.pdf)       | Not supported                                                                                                                      |
| Reserved                                                                                                                                    | Not supported                                                                                                                      |
| OEM Specific                                                                                                                                | Not supported                                                                                                                      |

This daemon makes use of `mctpwplus` library to communicate with transport
layer(MCTP) and `libpldm_intel` library for for encoding/decoding PLDM commands
and PDR parsing. Current implementation includes mapping to MCTP transport
alone. `mctpwplus` indicates any change(addition/removal) in MCTP network to
PLDM daemon and exposes tx/rx to send/receive the PLDM message.

## PLDM Base
PLDM Base facilitate the discovery of PLDM capabilities of a device. BMC relies
on the PLDM Base command set to further trigger PLDM Type specific
functionalities, for example: a device can indicate which PLDM Types are
supported using the Get PLDM Types response and BMC will use the response to
trigger supported PLDM Type commands.

## PLDM for Platform Monitoring and Control
The PLDM M&C implements:
* Support Central Platform Descriptor Record (PDR) Repository called PrimaryPDR
  repository, which can hold aggregation of all PDR information within
  the PLDM subsystem.
* Provide a way to monitor the PLDM Numeric Sensors and expose the values to
  the D-Bus, so the other applications can use it.
* Provide a way to monitor the PLDM State Sensors and expose the state set
  values and state change to other applications.
* Provide a way to read and expose the PLDM Numeric Effecters to other
  applications. Also, provide a mechanism to update the exposed Numeric
  Effecter value.
* Provide a way to read and expose the PLDM State Effecters to other
  applications. Also, provide a mechanism to update the exposed Numeric Effecter
  state.
* Log a redfish event on the state sensor state change.

### Supported PDRs
1. Numeric Sensor PDR
2. State Sensor PDR
3. Numeric Effecter PDR
4. State Effecter PDR
5. Terminus Locator PDR
6. Entity Association
7. FRU Record Set PDR
8. Sensor Auxiliary Names PDR
9. Effecter Auxiliary Names PDR
10. Entity Auxiliary Names PDR

### Supported Numeric Sensors
1. Temperature sensor
2. Current sensor
3. Voltage sensor
4. Power sensor

### Supported State Sensors
D-Bus interfaces are supported for any state sensors irrespective of the
State Set ID and State Set Values that the sensor supports. But the redfish
events for State Sensor state change will be supported for the following
State IDs only.
1. Operational Fault Status
__Note:__ Composite State Sensors are not supported.

### Supported Numeric Effecters
1. Time Effecter
2. Current Effecter
3. Voltage Effecter
4. Power Effecter

### Supported State Effecters
D-Bus interfaces are supported for any state effecter irrespective of the
State Set ID and State Set Values that the effecter supports.
__Note:__ Composite State Effecters are not supported.

### Design
* The PLDM service should perform device discovery and trigger Platform
  Monitoring and Control for the devices that support this PLDM Type.
* M&C is responsible for fetching the device PDRs.
* BMC can create a system hierarchy based on Entity Association PDR and expose
  the same on D-Bus.
* The sensors and effecters from the PDRs need to be parsed and enabled. The
  same should be monitored for any value change and expose it on D-Bus.
* Interested client can use `DumpPDR` D-Bus method under interface
  `xyz.openbmc_project.PLDM.PDR` and object path
  `/xyz/openbmc_project/system/<TID>` to extract PLDM device PDR.

The following figure illustrates the internals of PLDM M&C.

             |---------------------|
             |  Terminus Init      |
             |---------|-----------|
                       |
                       |
             |---------v-----------|
             |  Platform M&C Init  |          |----------------------------------------|
             |---------|-----------|          |    * Read full PDR repo                |
                       |                      |    * Parse each PDR                    |
                       |                      |    * Create system hierarchy using     |
             |---------v-----------|          |      Entity Association PDR            |
             |     PDR Manager     |--------->|    * Expose entity information along   |
             |---------|-----------|          |      with system hierarchy             |
                       |                      |    * Expose DumpPDR method under       |
                       |                      |      PLDM.PDR interface                |
                       |                      |----------------------------------------|
                       |
             |---------|----------------------------------------------------------------------------|
             |  Loop n times: For each Numeric Sensor in the PDR                                    |
             |---------|----------------------------------------------------------------------------|
             |         |                                                                            |
             |  |------v---------|            |--------------------------------------------------|  |
             |  | Numeric Sensor |            |    * Enable numeric sensor                       |  |
             |  | Handler Init   |----------->|    * Extract sensor details like thresholds      |  |
             |  |------|---------|            |      data from Numeric Sensor PDR                |  |
             A         |                      |    * Calculate sensor value from sensor reading  |  V
             |  |------v--------|             |    * Provide API to trigger sensor value refresh |  |
             |  | Add Sensor to |             |    * Expose Sensor.Value, Sensor.Threshold and   |  |
             |  | sensor poll   |------|      |      Decorator interfaces                        |  |
             |  | coroutine     |      |      |--------------------------------------------------|  |
             |  |------|--------|      |                                                            |
             |         |               |                     /\                                     |
             |         |               |                    /  \                                    |
             |---------|---------------|-------------------/    \-----------------------------------|
                       |               |                   \    /
                       |               |                    \  /
                       |               |                     \/
                       |               |
                       |               |
                       |               |
                       |               |                                                                 |------------------------------------------------------------------------------|
                       |               |                                                                 |  Loop with condition: For each initialized Numeric/State sensor              |
                       |               |                                                                 |------------------------------------------------------------------------------|
                       |               |                                                                 |                                                                              |
                       |               |                                                                 |  |------------------|     |----------------------------------------------|   |
                       |               |                                                                 |  | Poll all sensors |     |   * Trigger Numeric/State sensor read        |   |
                       |               |------------------------------------------------------------------->| coroutine        |---->|     API on every poll interval               |   |
                       |                                                                                 A  |----------A-------|     |   * sensor value will be refreshed in        |   v
                       |                                                                                 |             |             |     sequential manner (eg: NumericSensor1    |   |
                       |                                                                                 |             |             |     -> NumericSensor2 -> StateSensor1->...)  |   |
                       |                                                                                 |             |             |----------------------------------------------|   |
                       |                                                                                 |             |                                                                |
                       |                                                                                 |             |                   /\                                           |
                       |                                                                                 |             |                  /  \                                          |
                       |                                                                                 |-------------|-----------------/  = \-----------------------------------------|
                       |                                                                                               |                 \    /
                       |                                                                                               |                  \  /
                       |                                                                                               |                   \/
                       |                                                                                               |
             |---------|----------------------------------------------------------------------------|                  |
             |  Loop n times: For each State Sensor in the PDR                                      |                  |
             |---------|----------------------------------------------------------------------------|                  |
             |         |               |------------------------------------------------------------|------------------|
             |  |------v---------|     |      |--------------------------------------------------|  |
             |  | State Sensor   |     |      |    * Enable state sensor                         |  |
             |  | Handler Init   |-----|----->|    * Extract sensor details like state set ID,   |  |
             |  |------|---------|     |      |      possible states from State Sensor PDR       |  |
             A         |               |      |    * Provide API to trigger sensor state change  |  V
             |  |------v--------|      |      |      refresh                                     |  |
             |  | Add Sensor to |      |      |    * Expose Sensor.State and Decorator           |  |
             |  | sensor poll   |------|      |      interfaces                                  |  |
             |  | coroutine     |             |    * Add redfish log for any state sensor state  |  |
             |  |------|--------|             |      change                                      |  |
             |         |                      |                                                  |  |
             |         |                      |--------------------------------------------------|  |
             |         |                                     /\                                     |
             |         |                                    /  \                                    |
             |---------|-----------------------------------/    \-----------------------------------|
                       |                                   \    /
                       |                                    \  /
                       |                                     \/
                       |
                       |
             |---------|----------------------------------------------------------------------------|
             |  Loop n times: For each Numeric Effecter in the PDR                                  |
             |---------|----------------------------------------------------------------------------|
             |         |                                                                            |
             |  |------v-----------|          |--------------------------------------------------|  |
             |  | Numeric Effecter |          |    * Enable Numeric Effecter                     |  |
             |  | Handler Init     |--------->|    * Extract sensor details like max-settable    |  |
             |  |------|-----------|          |      and min-settable from Numeric Effecter PDR  |  |
             A         |                      |    * Calculate effecter value from effecter      |  V
             |         |                      |      reading                                     |  |
             |         |                      |    * Calculate settable value from user input    |  |
             |         |                      |    * Expose Effecter.Value, Effecter.SetEffecter |  |
             |         |                      |      and Decorator interfaces                    |  |
             |         |                      |--------------------------------------------------|  |
             |         |                                     /\                                     |
             |         |                                    /  \                                    |
             |---------|-----------------------------------/    \-----------------------------------|
                       |                                   \    /
                       |                                    \  /
                       |                                     \/
                       |
                       |
             |---------|----------------------------------------------------------------------------|
             |  Loop n times: For each State Effecter in the PDR                                    |
             |---------|----------------------------------------------------------------------------|
             |         |                                                                            |
             |  |------v-----------|          |--------------------------------------------------|  |
             |  | State Effecter   |          |    * Enable State Effecter                       |  |
             |  | Handler Init     |--------->|    * Extract Effecter details like State Set ID, |  |
             |  |------------------|          |      possible states from State Effecter PDR     |  |
             A                                |    * Expose Effecter.State, Effecter.SetEffecter |  V
             |                                |      and Decorator interfaces                    |  |
             |                                |--------------------------------------------------|  |
             |                                               /\                                     |
             |                                              /  \                                    |
             |---------------------------------------------/    \-----------------------------------|
                                                           \    /
                                                            \  /
                                                             \/

### System Hierarchy
If the PLDM terminus supports Entity Association PDR, it will be used to create
a system hierarchy to the PLDM terminus.

The below diagram shows the PLDM terminus (Add-in-Card) having another
associated entity (Processor). Also, the hierarchy shows the sensors
and effecters associated to each entity.

__Note:__ The Entity name (Add-in-card) and sensor/effecter name
(NumericSensor1) varies as per Auxiliary name PDR. The sensor/effecter names
will have TID append at the end to avoid duplicate names when more than one
PLDM terminus has same name. If The PLDM terminus doesn't support Auxiliary
name PDRs, BMC will assign dummy names as per the following format.
* Entity - \<EntityType\>\_\<EntityInstanceNumber\>\_\<EntityContainerID\>
* Sensor - PLDM\_Sensor\_\<SensorID\>\_\<TID\>
* Effecter - PLDM\_Effecter\_\<EffecterID\>\_\<TID\>

        /xyz/openbmc_project/system
        |_/xyz/openbmc_project/system/<TID>
          |_/xyz/openbmc_project/system/<TID>/Add-in-card
          |  |_/xyz/openbmc_project/system/<TID>/Add-in-card/NumericSensor1_<TID>
          |  |_/xyz/openbmc_project/system/<TID>/Add-in-card/StateSensor1_<TID>
          |  |_/xyz/openbmc_project/system/<TID>/Add-in-card/StateSensor2_<TID>
          |  |_/xyz/openbmc_project/system/<TID>/Add-in-card/NumericEffecter1_<TID>
          |  |_/xyz/openbmc_project/system/<TID>/Add-in-card/StateEffecter1_<TID>
          |_/xyz/openbmc_project/system/<TID>/Add-in-card/Processor
              |_/xyz/openbmc_project/system/<TID>/Add-in-card/Processor/NumericSensor1_<TID>
              |_/xyz/openbmc_project/system/<TID>/Add-in-card/Processor/NumericSensor2_<TID>
              |_/xyz/openbmc_project/system/<TID>/Add-in-card/Processor/StateEffecter1_<TID>

`PLDM.Entity`, `PLDM.NumericSensor`, `PLDM.StateSensor`, `PLDM.NumericEffecter`,
`PLDM.StateEffecter` interfaces shall be exposed by entity, sensors or
effecters of the system hierarchy.

### Numeric Sensors
BMC supports thermal, power, current and voltage numeric sensors. Each sensor
type will expose `Sensor.Value`, `State.Decorator.Availability`,
`State.Decorator.OperationalStatus` and `Sensor.Threshold` interfaces as per
`phosphor-dbus-interfaces`. `Sensor.Threshold` interface will send threshold
crossing event (D-Bus signal) if sensor values are crossed. The sensor units
can be decoded from the sensor object paths as per Table 1.

                                  Table 1
    |--------------|------------------------------------|------------------|
    | Sensor Type  |     Base Object path               |   Sensor unit    |
    |--------------|------------------------------------|------------------|
    | Thermal      |     /xyz/openbmc_project/sensors   |  Degree Celsius  |
    |              |     /temperature                   |                  |
    |--------------|------------------------------------|------------------|
    | Power        |     /xyz/openbmc_project/sensors   |   Watt           |
    |              |     /power                         |                  |
    |--------------|------------------------------------|------------------|
    | Current      |    /xyz/openbmc_project/sensors    |   Ampere         |
    |              |      /current                      |                  |
    |--------------|------------------------------------|------------------|
    | Voltage      |  /xyz/openbmc_project/sensors      |   Volts          |
    |              |      /voltage                      |                  |
    |--------------|------------------------------------|------------------|

### State Sensors
BMC exposes `Sensor.State`, `State.Decorator.Availability` and
`State.Decorator.OperationalStatus` interfaces under the D-Bus object path
`/xyz/openbmc_project/pldm/<TID>/state_sensor/<SensorName>`. The `Sensor.State`
interface exposes D-Bus properties `StateSetId`, `PossibleStates`,`PreviousState`
and `CurrentState` properties. PLDM service will log any state sensor state
change as a redfish event log.

### PLDM Sensor Operational State
The Available property under `State.Decorator.Availability` interface and
Functional property under `State.Decorator.OperationalStatus` interfaces
are mapped to PLDM numeric and state sensor operational state, refer
below table 2.

                                 Table 2
    |-------------------------------|----------------|--------------------|
    | PLDM Sensor Operational State |   Available    |   Functional       |
    |-------------------------------|----------------|--------------------|
    |      Enabled                  |   True         | True (Can be false |
    |                               |                | in case of error)  |
    |-------------------------------|----------------|--------------------|
    |      Disabled                 |   True         |  False             |
    |                               |                |                    |
    |-------------------------------|----------------|--------------------|
    |      Unavailable              |   False        |  False             |
    |                               |                |                    |
    |-------------------------------|----------------|--------------------|

__Note:__ Other PLDM sensor operational states (`statusUnknown`, `failed`,
`initializing`, `shuttingDown` and `inTest`) are not supported.

### Numeric Effecters
* BMC supports time, power, current and voltage numeric sensors.
* Each sensors type will expose `Effecter.Value`,
  `State.Decorator.Availability`, `State.Decorator.OperationalStatus` and
  `Effecter.SetEffecter`.
* `Effecter.Value` interface exposes `MaxValue`, `MinValue` and `Value`
  properties.
* `Effecter.SetNumericEffecter` interface exposes `SetEffecter` D-Bus method to
  set Numeric Effecter value.

The effecter units can be decoded from the effecter object paths as per Table 3.

                                Table 3
    |----------------|-------------------------------|--------------------|
    | Effecter Type  | Base Object path              |   Effecter unit    |
    |----------------|-------------------------------|--------------------|
    |    Time        | /xyz/openbmc_project/pldm     |   Seconds          |
    |                | /<TID>/effecter/time          |                    |
    |----------------|-------------------------------|--------------------|
    |    Power       | /xyz/openbmc_project/pldm     |   Watt             |
    |                | /<TID>/effecter/power         |                    |
    |----------------|-------------------------------|--------------------|
    |    Current     | /xyz/openbmc_project/pldm     |   Ampere           |
    |                | /<TID>/effecter/current       |                    |
    |----------------|-------------------------------|--------------------|
    |    Voltage     | /xyz/openbmc_project/pldm     |   Volts            |
    |                | /<TID>/effecter/voltage       |                    |
    |----------------|-------------------------------|--------------------|

### State Effecters
BMC exposes the `Effecter.State`, `State.Decorator.Availability` and
`State.Decorator.OperationalStatus` interfaces under the D-Bus object path
`/xyz/openbmc_project/pldm/<TID>/state_effecter/<EffecterName>`.
The `Effecter.State` interface exposes the D-Bus properties `StateSetId`
`PossibleStates`, `PendingState` and `CurrentState` properties.
`Effecter.SetStateEffecter` interfaces expose `SetEffecter` D-Bus method to set
State Effecter state.

### PLDM Effecter Operational State
The Available property under `State.Decorator.Availability` interface and
Functional property under `State.Decorator.OperationalStatus` interfaces are
mapped to PLDM effecter operational state, refer below table 4.

                                  Table 4
    |---------------------------------|----------------|--------------------|
    | PLDM Effecter Operational State |   Available    |   Functional       |
    |---------------------------------|----------------|--------------------|
    |    Enabled-updatePending        |   True         | True (Can be false |
    |    Enabled-noUpdatePending      |                | in case of error)  |
    |---------------------------------|----------------|--------------------|
    |      Disabled                   |   True         |  False             |
    |                                 |                |                    |
    |---------------------------------|----------------|--------------------|
    |      Unavailable                |   False        |  False             |
    |                                 |                |                    |
    |---------------------------------|----------------|--------------------|

__Note:__ Other PLDM effecter operational states (`statusUnknown`, `failed`,
`initializing`, `shuttingDown` and `inTest`) are not supported.

### D-Bus Interfaces
Below table provides the D-Bus interface details.

     |-------------------------------|----------------------------|------------------------------------|
     | Interface                     |   Description              |     Methods/Properties             |
     |-------------------------------|----------------------------|------------------------------------|
     |    xyz.openbmc_project.       |   Implement to provide     |     Properties:                    |
     |     PLDM.Entity               |   PLDM entity information  |      Name: EntityContainerID       |
     |                               |                            |      Type: uint16                  |
     |                               |                            |      Description: The containerID  |
     |                               |                            |      for the entity                |
     |                               |                            |                                    |
     |                               |                            |      Name: EnityInstanceNumber     |
     |                               |                            |      Type: uint16                  |
     |                               |                            |      Description: The instance     |
     |                               |                            |      number of the entity          |
     |                               |                            |                                    |
     |                               |                            |      Name: EnityType               |
     |                               |                            |      Type: uint16                  |
     |                               |                            |      Description: The type         |
     |                               |                            |      of the entity                 |
     |-------------------------------|----------------------------|------------------------------------|
     |      xyz.openbmc_project.     |  Implement to provide PLDM |    TBD (e.g.: Sensor details       |
     |      PLDM.NumericSensor       |  Numeric Sensor information|        from PDR)                   |
     |                               |                            |                                    |
     |-------------------------------|----------------------------|------------------------------------|
     |      xyz.openbmc_project.     |  Implement to provide PLDM |    TBD (e.g.: Sensor details       |
     |      PLDM.StateSensor         |  State Sensor information  |        from PDR)                   |
     |                               |                            |                                    |
     |-------------------------------|----------------------------|------------------------------------|
     |      xyz.openbmc_project.     |  Implement to provide PLDM |    TBD (e.g.: Effecter details     |
     |      PLDM.NumericEffecter     |  Numeric Effecter          |        from PDR)                   |
     |                               |  information               |                                    |
     |-------------------------------|----------------------------|------------------------------------|
     |      xyz.openbmc_project.     |  Implement to provide PLDM |    TBD (e.g.: Effecter details     |
     |      PLDM.StateEffecter       |  Numeric State             |        from PDR)                   |
     |                               |  information               |                                    |
     |-------------------------------|----------------------------|------------------------------------|
     |      xyz.openbmc_project.     |  Implement to provide      |  For more details refer            |
     |      Sensor.Value             |  Numeric sensor readings   |  [phosphor-dbus-interfaces]        |
     |                               |                            |  (https://github.com/openbmc/      |
     |                               |                            |  phosphor-dbus-interfaces/blob/    |
     |                               |                            |  master/xyz/openbmc_project/       |
     |                               |                            |  Sensor/Value.interface.yaml)      |
     |-------------------------------|----------------------------|------------------------------------|
     |      xyz.openbmc_project.     |  Implement to provide      |  For more details refer            |
     |      Sensor.Threshold.        |  critical class sensor     |  [phosphor-dbus-interfaces]        |
     |      Critical                 |  thresholds for numeric    |  (https://github.com/openbmc/      |
     |                               |  sensors                   |  phosphor-dbus-interfaces/blob/    |
     |                               |                            |  master/xyz/openbmc_project/Sensor |
     |                               |                            |  /Threshold/Critical.interface.    |
     |                               |                            |  yaml)                             |
     |-------------------------------|----------------------------|------------------------------------|
     |      xyz.openbmc_project.     |  Implement to provide      |  For more details refer            |
     |      Sensor.Threshold.Warning |  warning class sensor      |  [phosphor-dbus-interfaces]        |
     |                               |  thresholds                |  (https://github.com/openbmc/      |
     |                               |                            |  phosphor-dbus-interfaces/blob/    |
     |                               |                            |  master/xyz/openbmc_project/Sensor |
     |                               |                            |  /Threshold/Warning.interface.     |
     |                               |                            |  yaml)                             |
     |-------------------------------|----------------------------|------------------------------------|
     |      xyz.openbmc_project.     |  Implement to indicate the |  For more details refer            |
     |      Sensor.Decorator.        |  availability status of    |  [phosphor-dbus-interfaces]        |
     |      Availability             |  the object                |  (https://github.com/openbmc/      |
     |                               |                            |  phosphor-dbus-interfaces/blob/    |
     |                               |                            |  master/xyz/openbmc_project/State  |
     |                               |                            |  /Decorator/Availability.          |
     |                               |                            |  interface.yaml)                   |
     |-------------------------------|----------------------------|------------------------------------|
     |      xyz.openbmc_project.     |  Implement to indicate the |  For more details refer            |
     |      Sensor.Decorator.        |  Operational status of     |  [phosphor-dbus-interfaces]        |
     |      OperationalStatus        |  the object                |  (https://github.com/openbmc/      |
     |                               |                            |  phosphor-dbus-interfaces/blob/    |
     |                               |                            |  master/xyz/openbmc_project/State  |
     |                               |                            |  /Decorator/OperationalStatus.     |
     |                               |                            |  interface.yaml)                   |
     |-------------------------------|----------------------------|------------------------------------|
     |    xyz.openbmc_project.       |   Implement to provide     |     Properties:                    |
     |     Sensor.State              |   State Sensor information |      Name: CurrentState            |
     |                               |                            |      Type: uint8                   |
     |                               |                            |      Description: Represent most   |
     |                               |                            |      recently assessed state       |
     |                               |                            |      of the state sensor           |
     |                               |                            |                                    |
     |                               |                            |      Name: PreviousState           |
     |                               |                            |      Type: uint8                   |
     |                               |                            |      Description: Represents state |
     |                               |                            |      that the CurrentState was     |
     |                               |                            |      entered from                  |
     |                               |                            |                                    |
     |                               |                            |      Name: StateSetID              |
     |                               |                            |      Type: uint16                  |
     |                               |                            |      Description: A numeric value  |
     |                               |                            |      that identifies the PLDM      |
     |                               |                            |      State Set that is used with   |
     |                               |                            |      this sensor                   |
     |                               |                            |                                    |
     |                               |                            |      Name: PossibleStates          |
     |                               |                            |      Type: array[uint8]            |
     |                               |                            |      Description: A numeric value  |
     |                               |                            |      that identifies the PLDM      |
     |                               |                            |      State Set values that are     |
     |                               |                            |      used with this sensor         |
     |-------------------------------|----------------------------|------------------------------------|
     |    xyz.openbmc_project.       |   Implement to provide     |     Properties:                    |
     |     Effecter.Value            |   numeric effecter value   |      Name: MaxValue                |
     |                               |   information              |      Type: double                  |
     |                               |                            |      Description: The maximum      |
     |                               |                            |      legal setting value that the  |
     |                               |                            |      effecter accepts              |
     |                               |                            |                                    |
     |                               |                            |      Name: MinValue                |
     |                               |                            |      Type: double                  |
     |                               |                            |      Description: The minimum      |
     |                               |                            |      legal setting value that the  |
     |                               |                            |      effecter accepts              |
     |                               |                            |                                    |
     |                               |                            |      Name: Value                   |
     |                               |                            |      Type: double                  |
     |                               |                            |      Description: The present      |
     |                               |                            |      numeric value setting of      |
     |                               |                            |      the effecter                  |
     |-------------------------------|----------------------------|------------------------------------|
     |    xyz.openbmc_project.       |   Implement to provide     |     Method:                        |
     |    Effecter.                  |   numeric effecter update  |     Name: SetEffecter              |
     |    SetNumericEffecter         |   mechanism                |     Description: Set the effecter  |
     |                               |                            |     value                          |
     |                               |                            |     Parameters:                    |
     |                               |                            |                                    |
     |                               |                            |      Name: Value                   |
     |                               |                            |      Type: double                  |
     |                               |                            |      Description: The setting      |
     |                               |                            |      value of numeric effecter     |
     |                               |                            |      being requested               |
     |-------------------------------|----------------------------|------------------------------------|
     |    xyz.openbmc_project.       |   Implement to provide     |     Properties:                    |
     |     Effecter.State            |   State effecter State     |      Name: CurrentState            |
     |                               |   information              |      Type: uint8                   |
     |                               |                            |      Description: The present      |
     |                               |                            |      state of the effecter         |
     |                               |                            |                                    |
     |                               |                            |      Name: PendingState            |
     |                               |                            |      Type: double                  |
     |                               |                            |      Description: If the value of  |
     |                               |                            |      effecter has an updatePending,|
     |                               |                            |      this field returns the value  |
     |                               |                            |      for the requested state that  |
     |                               |                            |      is presently being processed. |
     |                               |                            |      Otherwise, this field returns |
     |                               |                            |      the present state of the      |
     |                               |                            |       effecter.                    |
     |                               |                            |                                    |
     |                               |                            |      Name: StateSetID              |
     |                               |                            |      Type: uint16                  |
     |                               |                            |      Description: A numeric value  |
     |                               |                            |      that identifies the PLDM      |
     |                               |                            |      State Set that is used with   |
     |                               |                            |      this effecter                 |
     |                               |                            |                                    |
     |                               |                            |      Name: PossibleStates          |
     |                               |                            |      Type: array[uint8]            |
     |                               |                            |      Description: A numeric value  |
     |                               |                            |      that identifies the PLDM      |
     |                               |                            |      State Set value that is used  |
     |                               |                            |      with this effecter            |
     |-------------------------------|----------------------------|------------------------------------|
     |    xyz.openbmc_project.       |   Implement to provide     |     Method:                        |
     |    Effecter.                  |   a state effecter update  |     Name: SetEffecter              |
     |    SetStateEffecter           |   mechanism                |     Description: Set the effecter  |
     |                               |                            |     state                          |
     |                               |                            |     Parameters:                    |
     |                               |                            |                                    |
     |                               |                            |      Name: State                   |
     |                               |                            |      Type: uint8_t                 |
     |                               |                            |      Description: The setting      |
     |                               |                            |      value of state effecter       |
     |                               |                            |      being requested               |
     |-------------------------------|----------------------------|------------------------------------|

### Sensor Polling
PLDM service will read each sensor value on every poll interval and update the
D-Bus interfaces accordingly. Each sensor will be polled in a sequential manner
on every poll interval. Current configured value of poll interval is 500ms. If
the PLDM service identifies a new device, then sensor polling will be paused
temporarily to give priority for device initialisation. Also, sensor polling
will be paused when a PLDM firmware update is initiated.

## PLDM for Firmware Update
This component implements
* Firmware update for the devices (add-in cards or on-board devices), which
  supports the PLDM firmware update.
* Firmware update for multiple devices of same type sequentially.
* Expose information of PLDM Firmware update capable devices.
* PLDM Firmware update over MCTP Transport.

### Out of Scope
1. Image signature or signing verification must be done in Firmware Device (FD)
   side and BMC (Update Agent) will just perform compatible check as per the
   DSP0267 spec.
   __Note__: BMC may elect to verify overall image signature, if needed.
   i.e. BMC vendor, can do additional sign of the PLDM image to make sure only
   those approved / verified are allowed to do update. This is extra step and
   is not replacement to image signature or signing verification done by
   Firmware Device (FD).
2. Bundled firmware update (Single PLDM update package, containing multiple
   firmware component images - Say PSU, NIC firmware etc.) support is out of
   scope.

### Overview
This design is compliant to DSP0267 version 1.0.1 and holds good when moving
to next version DSP0267(1.1.0).

This specification identifies a common method to use PLDM messaging to transfer
one or more component images to the Firmware Device (FD) within the PLDM
subsystem and thereby avoids the use of host operating system-based tools and
utilities. The basic format that is used for sending the PLDM messages is
defined in DSP0240. The format that is used for carrying the PLDM messages over
a particular transport or medium is given in companion documents to the base
specification. For example, DSP0241 defines how the PLDM messages are formatted
and sent using MCTP as the transport.

The FD is the minimum hardware unit that the PLDM-based firmware update is
applied to and with which the Update Agent (UA) communicates to accomplish the
update. The Firmware Update Package for an FD contains an individual component
image or a group of component images that is known as a component image set.
This firmware update package is processed to update each firmware component of
the FD during the PLDM update.

Each type of FD has a globally unique identity, which can be used to distinguish
it from other types of FDs. A device identifier record consists of a set of
device descriptors, which are typically based on industry standard definitions,
and is used to describe an FD type. For example, the descriptors for PCI devices
include PCI Vendor ID and PCI Device ID.

            Figure: High level architecture flow of FW update (through PLDM)

      PLDM FWU   |----------|     |----------|     |-------------------|      |---------------|
    ------------>| Redfish  |---->| Redfish  |---->|    OpenBMC        |----->|Add-In Card(FD)|
      Package    | Client   |     | Interface|     |                   |      |---------------|
                 |----------|     |----------|     |   |-----------|   |
                                                   |   | Redfish   |   |
                                                   |   | daemon    |   |      |----------------|
                                                   |   |-----|-----|   |----->|On Board device |
                                                   |         |         |      |----------------|
                                                   |   |-----|-----|   |
                                                   |   |  PLDM FW  |   |
                                                   |   | Daemon(UA)|   |
                                                   |   |-----------|   |
                                                   |-------------------|

### Design
PLDM daemon gets the list of PLDM capable devices from transport layer(like
MCTP) and checks if the devices support PLDM firmware update
by running PLDM base commands. When a PLDM capable device is added or removed
dynamically, PLDM daemon will be notified by transport layer. For the newly
added device PLDM daemon runs the base commands to check PLDM capabilities.
PLDM daemon deletes the resources allocated for the removed device.

The FD is the minimum hardware unit that the PLDM-based firmware update is
applied to and with which the Update Agent (UA) communicates to accomplish the
update.

PLDM daemon sends inventory commands to each FD.
As per DSP0267 version 1.0.1, there are two inventory commands,

* __QueryDeviceIdentifiers__: This command is used by the UA to obtain the
  firmware identifiers for the FD.

* __GetFirmwareParameters__: This command is used by the UA to acquire the
  component details such as classification types and corresponding versions of
  the FD.

Inventory information is exposed to D-Bus and D-Bus objects will be described
in the later sections.

                         Figure: High Level PLDM Firmware Update Flow

                 PLDM                                     Software Manager               Redfish Update Service
                  |                                               |                                  |
            |-----| 1. PLDM daemon queries the transport service  |                                  |
            |     |    (like MCTP) to determine PLDM capable      |                        |---------|
            |     |    devices,                                   |                        |    User | initiates
            |     | 2. Execute PLDM device discovery commands for |                        |    FWU  | ( Post Method)
            |     |    each device and verify the PLDM FW update  |                        |-------->|
            |     |    support.                                   |                                  |
            |     | 3. Execute inventory commands for each FD and |                                  |
            |---->|    expose information over D-Bus for upper    |                                  |
                  |    layer consumption.                         |                                  |
                  |                                               |                                  |
                  |                                               | PLDM FWU package                 |
                  |                                               |<---------------------------------|
                  |                                               |  kept in / tmp / images          |
                  |                                               |                                  |
                  |                                               |                                  |
                  |                                  |------------|                                  |
                  |                                  |     Verify | PLDM                             |
                  |                                  |    package | header                           |
                  |                                  | identifier |                                  |
                  |                                  |----------->|                                  |
                  |                                               |                                  |
                  |                                               |                                  |
                  |  Initiate update by D-Bus method call         |                                  |
                  |<----------------------------------------------|                                  |
                  |                                               |                                  |
            |-----|                                               |                                  |
            |     | Parse the package and find out target device  |                                  |
            |     | using device descriptors.                     |                                  |
            |---->|                                               |                                  |
                  |                                               |                                  |
            |-----|                                               |                                  |
            |     | Run sequence of firmware update commands      |                                  |
            |     | as described in spec DSP0267(1.0.1)           |                                  |
            |---->|                                               |                                  |
                  |                                               |                                  |
                  | Update the firmware activation status and     |                                  |
                  |---------------------------------------------->|                                  |
                  | progress percentage to software-manager with  |                                  |
                  |  D-Bus calls                                  |                                  |
                  |                                               |                                  |
                  |                                               |                                  |

User interfaces (like Redfish) are used to upload the PLDM package to the staging
area of BMC. Software-manager listens to the changes on staging area and
validates the image for PLDM type. It then exposes a D-Bus object that will be
described in the later sections. Once verification is done, it notifies the PLDM
daemon with a method call to initiate the firmware update.

PLDM Daemon proceeds to parse the firmware package header. It determines the
target device by matching the package provided device descriptors with the ones
obtained by query device identifiers command.

BMC runs a sequence of firmware update commands to target FD as described in the
sections 6.4 and 6.5 Of DSP0240(1.0.1).

There are three additional commands which UA can send to FD,
* `Get Status`– Sending this command to the FD, BMC can know the status of the
  update at any time.
* `Cancel Update Component`- Sending this command to the FD, BMC can cancel the
  update of current component.
* `Cancel Update` - Sending this command to the FD, BMC can cancel the update.

If the firmware update is successful, FD goes for reset.

### PLDM Firmware Update Package
The PLDM firmware update package contains two major sections:
* __Firmware Package Header__: It is required to describe the firmware devices
  that the package is intended to update and component images that the firmware
  update package contains.
* __Firmware Package Payload__: It contains the individual component images
  that can be transferred to the firmware devices.

More details of the PLDM package is described in section 7 of DSP0267.

                 Figure: PLDM Firmware Update Package

                    |---------      |----   |--------------------------------|
                    |               |       |    Package Header Information  |
                    |    Firmware   |       |--------------------------------|
                    |    Package----|       |    Firmware Device ID Records  |
                    |    Header     |       |     & Descriptors              |
                    |               |       |--------------------------------|
      Firmware      |               |       |   Component Image Information  |
      Update -------|               |-------|--------------------------------|
      Package       |               |       |       Component Image 1        |
                    |    Firmware   |       |--------------------------------|
                    |    Package----|       |       Component Image 2        |
                    |    Payload    |       |--------------------------------|
                    |               |       |              ...               |
                    |               |       |--------------------------------|
                    |               |       |        Component Y             |
                    |---------      |----   |--------------------------------|

### PLDM FW Update D-Bus Interfaces Overview and Hierarchy
The below are the objects exposed by PLDM daemon on discovery of PLDM FW update
capable devices. These will be picked by redfish automatically.

Object path: `/xyz/openbmc_project/software/<entity_name>`
Entity name will be taken from PLDM FRU data.
Example: /`xyz/openbmc_project/software/NIC0`
Interfaces:
1. `xyz.openbmc_project.Software.Activation`, which describes firmware update
   activation status. There could be some devices which supports inventory
   command, but does not support PLDM firmware update. Activation property can
   be used to determine whether the device supports firmware update or not.
2. `xyz.openbmc_project.Software.Version`, which describes the version
   of the firmware image.
3. `xyz.openbmc_project.Association.Definitions`, which defines the
   association of the FD with the inventory item.

Below D-Bus object will be exposed by software-manager, when the PLDM image is
uploaded for firmware update.

Service: `xyz.openbmc_project.Software.BMC.Updater`
object path: `/xyz/openbmc_project/software/<ImageHash>`
Interfaces:
1. `xyz.openbmc_project.Software.Activation`, which describes firmware update
   activation status.
2. `xyz.openbmc_project.Software.Version`, which describes the version of the
   firmware image.
3. `xyz.openbmc_project.Software.ActivationProgress`, which shows the firmware
   update progress.
4. `xyz.openbmc_project.Software.ImageTargets `, which shows the list of target
   devices which the user intends to update. ImageTargets property is an array
   of strings. Redfish updates this property based on the httpPushUri arguments.
   Software-manager passes it to pldmd in the method StartFWUpdate as an
   argument. PLDM daemon uses ImageTargets to identity the target firmware
   device.

__Note__: If ImageTargets is empty, PLDM daemon updates all the devices for
which device descriptors are matched.

The below are the D-Bus objects exposed by PLDM daemon to give additional
information to the user which can help during validation.

    /xyz/openbmc_project/pldm/fwu
    |--xyz.openbmc_project.PLDM.FWU.FWUBase
    |
    |__/xyz/openbmc_project/pldm/fwu/<TerminusID>
      |
      |__/xyz/openbmc_project/pldm/fwu/<TerminusID>/deviceDescriptors
      |  |--xyz.openbmc_project.PLDM.FWU.PCIDescriptor
      |  |--xyz.openbmc_project.PLDM.FWU.IANADescriptor
      |  |--xyz.openbmc_project.PLDM.FWU.PnPDescriptor
      |  |--xyz.openbmc_project.PLDM.FWU.ACPIDescriptor
      |
      |__/xyz/openbmc_project/pldm/fwu/<TerminusID>/componentImageSetInfo
      |  |--xyz.openbmc_project.PLDM.FWU.ActiveComponentImageSetInfo
      |  |--xyz.openbmc_project.PLDM.FWU.PendingComponentImageSetInfo
      |
    |__/xyz/openbmc_project/pldm/fwu/<TerminusID>/componentImageSetInfo/component_<component_no>
       |--xyz.openbmc_project.PLDM.FWU.ActiveComponentInfo
       |--xyz.openbmc_project.PLDM.FWU.PendingComponentInfo
       |--xyz.openbmc_project.PLDM.FWU.ComponentActivationMethods
       |--xyz.openbmc_project.PLDM.FWU.CapabilitiesDuringUpdate

__Note__:
Descriptor for a device can be defined by one of the following (PCI Vendor ID,
IANA Enterprise ID, UUID, PnP Vendor ID, or ACPI Vendor ID) and the
corresponding descriptor's interface is exposed by the Device Descriptors
object. No new UUID descriptor interface is defined as the existing UUID
interface will be used.

### FW Update Base
It is exposed by the object `/xyz/openbmc_project/pldm/fwu` with the
following interface,

* `xyz.openbmc_project.pldm.FWUBase` exposes a method "StartFWUpdate" by which
  PLDM FWU can be initiated. PLDM firmware image path and target firmware update
  devices are passed as arguments to this method.

Each FW update capable device information is exposed by the object
`/xyz/openbmc_project/pldm/fwu/<TerminusID>`.
It will have the following objects,
1. Device Descriptors
2. Component Image Set Information
3. Component Image Information (Each component is exposed as an object)

### Device Descriptors
Device Descriptors are exposed under the object path
`/xyz/openbmc_project/pldm/fwu/deviceDescriptors` with one of the
following interfaces.
1. `xyz.openbmc_project.PLDM.FWU.PCIDescriptor`, which exposes the PCI device
   descriptors. If the FD is a PCI device, then this interface will be exposed
   by the device descriptors object.
2. `xyz.openbmc_project.PLDM.FWU.IANADescriptor`, which exposes the IANA
   descriptor properties. If FD have IANA Enterprise ID as the descriptor type,
   then this interface will be exposed by the device descriptors object.
3. `xyz.openbmc_project.PLDM.FWU.PnPDescriptor`, which exposes the PnP
   descriptor properties. If FD have PnP vendor ID as the descriptor type, then
   this interface will be exposed by the device descriptors object.
4. `xyz.openbmc_project.PLDM.FWU.ACPIDescriptor`, which exposes the ACPI
   descriptor properties. If FD have ACPI vendor ID as the descriptor type, then
   this interface will be exposed by the device descriptors object.

### Component Image Set Information
Component Image Set Info is exposed under the object path
`/xyz/openbmc_project/pldm/fwu/componentImageSetInfo` with the following
interface.
1. `xyz.openbmc_project.PLDM.FWU.ActiveComponentImageSetInfo`, which exposes the
   active component image set properties.
2. `xyz.openbmc_project.PLDM.FWU.PendingComponentImageSetInfo`, which exposes
   the pending component image set properties.

### Component Image Information
Component Image Info is exposed under the object path
`/xyz/openbmc_project/pldm/fwu/componentImageSetInfo/componentInfo_<component_no>`
with the following interface
1. `xyz.openbmc_project.PLDM.FWU.ActiveComponentInfo`, which exposes the
   component image properties.
2. `xyz.openbmc_project.PLDM.FWU.PendingComponentInfo`, which exposes the
   pending component image properties.
3. `xyz.openbmc_project.PLDM.FWU.CapabilitiesDuringUpdate`, which exposes the
   capabilities of the component during update.
4. `xyz.openbmc_project.PLDM.FWU.ComponentActivationMethods`, which exposes the
   component activation methods.

## PLDM for FRU
The PLDM FRU implements:
* PLDM Command - GetFRUTableMetadata Requester
* PLDM Command - GetFRURecordTable Requester
* PLDM Command - SetFRURecordTable Requester

### Proposed Design
After the device discovery the Platform FRU initialization will be triggered.
FRU is responsible for fetching the device inventory records that provide
platform asset information including part number, serial number and
manufacturer. The FRU Record Table typically resides in a non-volatile memory
accessible by the management controller and contains one or more FRU records.
BMC can create FRU objects based on PLDM terminus, which supports FRU
specification and expose the same on D-Bus. The FRU inventory records from the
terminus need to be parsed and enabled and should be allowed to set via the
setFRU method using D-Bus call.

The following figure illustrates the internals of PLDM FRU:

                    /\                           |---------------|
                   /  \                          |    PLDM FRU   |
                  /    \                         |     Init      |
                 /      \                        |---------------|
                / First  \                               |
               /Invocation\<-----------------------------|
               \    ?     /                              |
                \        /                               | [TID]
                 \      /                                |
                  \    /                                 |
                   \  /                                  |
                    \/                                   V
                     |                                   /\
                     |                                  /  \
                     |                                 /    \
                     |                                /      \                         |--------------|
                     |                        [No]   /Get FRU \                        | User invokes |
               [YES] |                     |--------/ Metadata \ <-----------|         |  Set FRU     |
                     |                     |        \   Done?  /             |         |--------------|
                     |                     |         \        /              |                |
                     |                     |          \      /               |                |
                     |                     |           \    /                |                |
                     |                     |            \  /                 |                |
                     |                     |             \/                  |                |
                     |                     |              |                  |                |
                     |                     |        [YES] |                  |                |
                     |                     |              |          Re-query FRU data        | [TID]
                     |                     |              V          for verification         |
                     |                     |              /\                 |                |
                     |                     |             /  \                |                |
                     V                     |            /    \               |                V
               |---------------|           |           /      \              |         |----------------|
               |  Expose Set   |           |          /        \             |         |    Set FRU     |
               | FRU Interface |           |  [No]   / Get FRU  \            |---------|    Commands    |
               |---------------|           |<-------/   Table    \                     |----------------|
                                           |        \ data done? /
                                           |         \          /
                                           |          \        /
                                           |           \      /
                                           |            \    /
                                           |             \  /
                                           |              \/
                                           |               |
                                           |         [YES] |
                                           |               |
                                           |               V
                                           |       |---------------|
                                           |       |  Expose FRU   |
                                           |       | Data on D-Bus |
                                           |       |---------------|
                                           |
                                           V
                                    |-------------|
                                    | FRU Object  |
                                    | Path/[TID]  |
                                    | Not created |
                                    |-------------|

1. PLDM FRU Init:
    * FRU init exposes `xyz.openbmc_project.PLDM.SetFRU` interface under
      `/xyz/openbmc_project/pldm/fru` object path.
    * It also exposes FRU properties under `/xyz/openbmc_project/pldm/fru/tid`
      object path on PLDM Get FRU commands success.
      In case of failure, the path is not created.
2. Get FRU Metadata Command: (2-4 have Get FRU commands and flow)
    * Fetch and store FRUTableMaximum size, FRUTableLength and Checksum
      with TID map for further check.
3. Get FRU Record Table data Command:
    * Check for transfer flag for multipart transfer.
    * Get final FRU record table.
    * Calculate and verify CRC with metadata checksum.
    * Parsing FRU table for getting each TLV.
    * Add FRU objects to D-bus representation.
4. Expose FRU data on D-bus:
    * Populate FRU properties under `xyz.openbmc_project.Inventory.Source.PLDM.FRU`
5. User invokes SetFRU D-bus method that internally invokes `SetFRU` commands:
    * Send Set FRU table data using SetFRU method,
      `busctl call xyz.openbmc_project.pldm xyz/openbmc_project/pldm/fru xyz.openbmc_project.PLDM.SetFRU SetFRU yay tid array_of_general_to_EM_records`
    * Re-query FRU data via PLDM Get commands and update the FRU fields
      accordingly.
    * If [TID] found in terminus FRU map, then clear all TID information from
      maps and re-create interface with new FRU details.
    * If [TID] not found in terminus FRU map, then continue with Get FRU
      commands and initialize FRU interface for the first time via `SetFRU`.
    * PLDM Get FRU commands are used to verify whether new FRU details are
      updated well under FRU interface. In case of failure, the path with TID is
      not created.

### FRU Object Paths
If the PLDM terminus supports FRU specification, it will be used to create
the object paths of the terminus. The below diagram shows PLDM terminus
(Add-in-Card) having FRU information. FRU information for each PLDM terminus is
located under `xyz.openbmc_project.Inventory.Source.PLDM.FRU` interface.

                 busctl tree xyz.openbmc_project.pldm
                 └─/xyz
                 └─/xyz/openbmc_project
                 ├─/xyz/openbmc_project/pldm
                 │ ├─/xyz/openbmc_project/pldm/fru
                 │ │ ├─/xyz/openbmc_project/pldm/fru/4
                 │ │ └─/xyz/openbmc_project/pldm/fru/5

The FRU object path exposes `SetFRU` method.

    busctl introspect xyz.openbmc_project.pldm /xyz/openbmc_project/pldm/fru
    xyz.openbmc_project.PLDM.SetFRU
    .SetFRU                               method    yay       i            -

### D-Bus Interfaces
FRU D-Bus interface details are described in `phosphor-dbus-interfaces`.
https://github.com/openbmc/phosphor-dbus-interfaces/blob/master/xyz/openbmc_project/Inventory/Source/PLDM/FRU.interface.yaml

## Future Enhancement
* OEM FRU representation of PLDM terminus
* IPMI FRU to PLDM FRU mapping
* EEPROM based PLDM FRU
* Set FRU on field basis