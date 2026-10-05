---
name: p10-zstack-restore-recovery
description: CC2674P10/Z-Stack 3 existing-network recovery when a validated coordinator restore succeeds but the radio hangs during final startup or the MR4U USB/UART bridge becomes one-way or unresponsive.
---

# CC2674P10 Z-Stack restore recovery — resume the restored network, do not reform it

Use this skill for SMLIGHT/other CC2674P10 coordinators when an existing Zigbee network has already been restored into Z-Stack NVRAM, identity/security tables validate, but the coordinator fails specifically at the final network-start transition. The canonical cross-project migration policy remains `analienx/config:skills/zigbee-coordinator-migration/SKILL.md`; this file is the P10-specific implementation specialization.

## Known failure signature

The recovery observation on 2026-10-01 is narrow:

- coordinator backup parsing/restore succeeds;
- PAN ID, extended PAN ID, channel, coordinator IEEE, network key and restored security records are present as expected;
- a soft reset succeeds and the radio still answers normal ZNP requests;
- Zigbee2MQTT/zigbee-herdsman then calls `ZDO_STARTUP_FROM_APP`;
- the CC2674P10 stops responding or fails to reach coordinator state during that transition;
- a later `APP_CNF_BDB_START_COMMISSIONING(mode=0x00)` attempt over Ethernet resumed the restored network on the affected P10; transport/Core context differed from the failed USB startup.

Treat this as a recovery path for this exact failure class, not as a blanket replacement for every healthy Z-Stack startup.

**Evidence boundary updated 2026-10-04:** mode-0 resumption succeeded over Ethernet, while a later USB attempt timed out. Transport/Core context changed, so this is not proof of an isolated BDB root cause or a universal mode-0 fix. A subsequently running coordinator developed progressive AF/ZDO/SYS timeouts; that runtime failure is a separate decision branch. A simple USB RTS pulse failed, but reviewed **USB ROM BSL entry → ping/chip ID → explicit ROM reset** recovered normal SYS/NV and outbound ZDO without flashing or NV changes. Read [bounded USB hardware recovery](references/usb-hardware-recovery.md) for the exact reset-only contract before adding automation or acting on an unresponsive USB radio. Do not reissue commissioning commands until bidirectional SYS traffic is proven.

Current zigbee-herdsman restore flow writes the restored NVRAM, resets, and then calls `beginStartup()`, which uses `ZDO_STARTUP_FROM_APP` when the adapter is not already `ZB_COORD`. TI BDB guidance distinguishes network formation from initialization/resumption of an already restored network. Do not silently convert a restored-network recovery into a new formation attempt.

**Later runtime limit, 2026-10-05:** the detector fired without HA shutdown.
The exact original USB reset-only script was retested unchanged: ROM PING timed
out and independent normal SYS was **0/3**, no version. Experimental SYNCH/pin
pacing and bridge reset also failed; they are not prerequisites of the handoff.
Always probe normal SYS/NV after the original script, even on ROM error or missing
stdout; do not repeat the known failed simple RTS pulse on a reviewed episode.
Ethernet is not required for this USB procedure. Preserve the unresolved latch
and evidence rather than replaying backups or implying the radio recovered.
See the reference above for the exact sequence and acceptance limits.

References:
- zigbee-herdsman Z-Stack manager: https://github.com/Koenkk/zigbee-herdsman/blob/master/src/adapter/z-stack/adapter/manager.ts
- TI BDB discussion covering restored-network initialization and `BDB_COMMISSIONING_NETWORK_RESTORED`: https://e2e.ti.com/support/wireless-connectivity/zigbee-thread-group/zigbee-and-thread/f/zigbee-thread-forum/1126199/launchxl-cc26x2r1-app_cnf_bdb_commissioning_notification-0x08-bdb_commissioning_formation_failure
- zigpy-znp ZNP/NVRAM implementation: https://github.com/zigpy/zigpy-znp/blob/dev/zigpy_znp/api.py

## Non-negotiable invariants

1. Exactly one coordinator carrying the production PAN/extended PAN/network key/IEEE may be powered as an active Zigbee coordinator.
2. Preserve the untouched source coordinator and all verified cold backups until production acceptance is complete.
3. Do not change PAN ID, extended PAN ID, channel, network key or coordinator IEEE as a workaround.
4. Do not delete `database.db` or `coordinator_backup.json` to force a clean start.
5. Do not mass reset/re-pair devices while this startup failure remains unresolved.
6. Preserve a transmit frame counter safely above the highest counter already emitted by any coordinator that has carried this network identity.
7. Never use BDB `mode=0x04` (network formation) as the recovery action for the already restored production network.
8. Python/direct protocol libraries are preferred. Raw MT bytes are diagnostic reference only; do not build the recovery around ad-hoc terminal byte injection when a typed ZNP call is available.

## Recovery decision gate

Before changing startup behavior, prove that the failure is after restore rather than during restore.

Capture/read back, without printing secrets:

- `SYS_PING` and `SYS_VERSION`;
- `UTIL_GET_DEVICE_INFO` state;
- `STARTUP_OPTION`;
- `BDBNODEISONANETWORK` if available on the target firmware;
- `NIB` including PAN ID, extended PAN ID, logical channel, network state/update ID;
- `HAS_CONFIGURED_ZSTACK3`;
- active and alternate network-key descriptors by fingerprint only;
- network security material/frame counter;
- address/security/TCLK table capacities and populated-entry counts;
- restored device/link-key counts;
- effective coordinator IEEE.

If identity, key fingerprints, table counts or counter state do not match the intended backup, STOP. Fix the restore evidence first. The BDB resume path must not be used to hide a malformed restore.

## Preferred P10 resume sequence

With Zigbee2MQTT stopped and every other copied coordinator physically isolated:

1. Complete the already-reviewed restore of the intended network into P10 NVRAM.
2. Read back the restored identity/security state and record redacted fingerprints/counts.
3. Soft-reset the P10.
4. Reconnect to ZNP and verify `SYS_PING` before any network-start command.
5. Do **not** call `ZDO_STARTUP_FROM_APP` for the affected failure signature.
6. Send `APP_CNF_BDB_START_COMMISSIONING` with `mode=0x00`.
7. Observe callbacks/state transitions rather than treating the SRSP alone as success.
8. Require coordinator state (`ZDO_STATE_CHANGE_IND = 0x09` / StartedAsCoordinator) and, when emitted by the firmware, BDB status `0x0D` (`BDB_COMMISSIONING_NETWORK_RESTORED`).
9. Immediately verify the radio still answers `SYS_PING`, then re-read NIB/network identity and security counter state.
10. Cold power-cycle the P10 once while the old coordinator remains isolated, reconnect, and prove the same coordinator/network state survives.
11. Only after these gates pass may Zigbee2MQTT become the radio client.

A raw MT reference for `APP_CNF_BDB_START_COMMISSIONING(mode=0x00)` may be used only to verify framing during protocol debugging:

```text
request:  FE 01 2F 05 00 2B
expected SRSP status byte: success
```

Do not treat that SRSP as the acceptance gate; the state-change/BDB notification and post-command liveness are the important evidence.

## Prevent Zigbee2MQTT from repeating the failing restore/start loop

Before starting Zigbee2MQTT after a successful manual recovery, ensure the P10 already represents the intended configured network:

- `HAS_CONFIGURED_ZSTACK3` is set correctly;
- NIB PAN/extended PAN/channel match the Zigbee2MQTT configuration;
- active/alternate network-key fingerprints match;
- the effective coordinator IEEE is correct;
- the adapter is already in coordinator state;
- `coordinator_backup.json` and `database.db` remain preserved.

The desired first application start is a **resume/attach to an already running restored coordinator**, not another destructive restore attempt. Inspect the first logs. If herdsman decides to restore/recommission again, STOP and diagnose the strategy mismatch rather than allowing another blind cycle.

## Post-restore transport failure on PoE-powered MR4U

A successful network restore and a healthy USB enumeration do **not** prove that the P10 command path is usable. A confirmed 2026-10-01 failure mode on an MR4U powered by PoE presented as a one-way bridge:

- the MR4U enumerated normally as its USB device identity and exposed both CDC ACM interfaces;
- the P10-facing interface could be opened at the expected baud rate;
- valid unsolicited ZNP frames such as `ZDO srcRtgInd` arrived from the radio, proving **P10 → host** transport and live Zigbee RF reception;
- `SYS_PING` requests from the host received no SRSP, and Zigbee2MQTT failed with `SRSP - SYS - ping after 6000ms`;
- a normal ZNP `SYS_RESET_REQ(type=SOFT)` produced no reset response and did not restore command traffic;
- restarting Home Assistant did not fix the condition because the MR4U itself remained powered through PoE.

Treat this as a **command-path failure signature**, not as evidence that the restored NVRAM or backup is wrong. Unsolicited traffic alone cannot distinguish a bridge fault from a radio that no longer services requests. Record transport, Core firmware and reset context before attributing a cause.

### Diagnose directionality before rewriting anything

With Zigbee2MQTT stopped:

1. Confirm the expected persistent `/dev/serial/by-id` path resolves to the intended P10 CDC ACM interface.
2. Inspect `dmesg` for the physical USB path, not only tty names. Distinguish:
   - normal enumeration followed by a bare `USB disconnect`;
   - explicit host `reset ... using xhci-hcd`;
   - descriptor errors such as `-71`;
   - hub disable/over-current messages.
3. Check sysfs port state, `disable`, and `over_current_count`. Do not infer over-current from a disconnect when the counter remains zero.
4. Send a read-only `SYS_PING`.
5. If `SYS_PING` times out, capture incoming MT traffic for several seconds before concluding the radio is dead.
6. If valid unsolicited ZNP frames arrive while all host-originated SREQs time out, classify the condition as **one-way radio→host transport**.
7. Do not repeat restore, erase NVRAM, change PAN/channel/key/IEEE, or mass re-pair devices merely to cure this symptom.

A phone drawing charge current from a USB port is not a valid USB-data test. A charge-only or damaged cable can provide VBUS with no D+/D− data path. When testing the HA port, use a known data-capable device/cable and require an actual kernel USB attach/enumeration event.

### HA reboot is not an MR4U reboot when PoE remains present

On a PoE-powered MR4U used in USB communication mode, restarting or even power-cycling the Home Assistant host can leave the MR4U ESP32-S3/USB↔UART bridge continuously powered. Therefore a bridge latch can survive the HA restart.

When a cold power-cycle is selected for this signature, keep Zigbee2MQTT stopped and remove **all MR4U power**:

1. disconnect the MR4U USB cable;
2. remove PoE/power so the MR4U has no remaining power source;
3. allow the unit to become fully unpowered;
4. restore PoE/power and let the MR4U boot;
5. reconnect USB;
6. wait for the stable by-id P10 interface;
7. require a successful `SYS_PING` before starting Zigbee2MQTT.

In the confirmed incident, the first post-power-cycle pings could still time out during early boot; a valid ping response appeared a few seconds later. Do not declare failure on the first immediate probe if USB has only just enumerated.

A later 2026-10-03 incident on coordinator firmware 20240716 was not cleared by the reported physical power-cycle. Re-entering USB mode also preceded recovery, without an explicit management-UI radio-reset action. Such a mode transition can change transport or implicitly reset hardware; do not claim it proves either a bridge-only fault or an isolated reset fix. If SYS remains unresponsive, stop here and use the bounded hardware-recovery gate rather than repeatedly cycling power or restoring NVRAM.

Only after bidirectional ZNP traffic is restored should Zigbee2MQTT be started again. If Zigbee2MQTT then passes adapter initialization and resumes publishing live production-device traffic, keep the restored NVRAM intact.

### USB topology and unrelated peripheral faults

Linux bus numbers are not interchangeable with physical labels such as “USB2 port” and “USB3 port.” Map the actual device to its xHCI controller and physical path. Two low/full-speed USB devices may sit on different xHCI controllers even though both are using USB 2 signaling.

If another peripheral reports errors such as `disabled by hub (EMI?), re-enabling...`, record it, but do not automatically attribute the coordinator failure to that device when it is on a different xHCI controller. Isolate one variable at a time.

For Zigbee coordinators, prefer USB 2 signaling/ports where practical to reduce 2.4 GHz interference from USB 3 SuperSpeed activity, but still diagnose the observed physical path rather than relying on port color or assumptions.

### Return diagnostics to production settings

During recovery it is reasonable to set the Zigbee2MQTT add-on to manual boot and temporarily enable narrow debug namespaces. Before closing the incident:

- restore add-on boot policy to its intended production value (normally automatic for an always-on coordinator);
- preserve the prior watchdog policy unless there is a separate reason to change it;
- set `advanced.log_level: info`;
- inspect `advanced.log_namespaced_levels`: a global `info` does **not** suppress namespaces explicitly pinned to `debug`;
- change temporary namespace-level `debug` overrides back to `info`;
- keep `log_debug_to_mqtt_frontend: false` unless debug forwarding is explicitly needed;
- restart Zigbee2MQTT once and verify new log timestamps contain no debug flood.

Do not confuse old debug lines retained in the add-on log with logging from the newly restarted process; compare timestamps/container start time.

## If BDB mode 0x00 does not recover the P10

Do not jump to hardware replacement or mass re-pairing. Escalate in this order:

These writer lanes require responsive bidirectional ZNP and evidence of a restore/state mismatch. A local SYS timeout on a previously working network is not permission to rewrite NVRAM; first follow the transport/hardware branch above.

### Lane A — independent NVRAM writer

Use a clean, separately reviewed `zigpy-znp` restore path to write the same intended network state. This is valuable because its NVRAM serialization and migration handling differ from zigbee-herdsman. After write/reset, apply the same readback and BDB-resume gates above.

A CC2674P10 community case has demonstrated that `zigpy radio znp restore` can restore PAN/extended PAN/channel/IEEE/network key and return existing devices without re-pairing. That does not prove every P10 network is healthy afterward; run the full acceptance suite.

### Lane B — differential NVRAM restore

If an independent writer also fails, isolate the offending NVRAM class instead of changing network identity:

1. identity/NIB + network key + security material/frame counter;
2. add TCLK seed;
3. add address manager entries;
4. add security manager/APS key data;
5. add TCLK/device/child state.

After each layer: reset → BDB mode 0x00 → coordinator state → ping → readback.

If a layer introduces the failure, binary-search entries within that layer. Look for invalid/duplicate address-manager rows, inconsistent AMI/key references, TCLK seed/shift issues, malformed device records or table-layout/firmware incompatibilities.

## Acceptance after the P10 boots

Booting is necessary but not sufficient. Before declaring recovery complete, measure the actual production network:

- fresh inbound reports across representative routers/end devices;
- outbound unicast;
- groupcast;
- metering;
- important Home Assistant automations;
- controlled join/rejoin;
- offline-device rate;
- `MAC_NO_ACK`, `NWK_NO_ROUTE`, many-to-one/source-route failures over comparable windows;
- adapter liveness/restarts and Zigbee2MQTT process health.

Do not dismiss sustained route failures merely because the coordinator is online. Conversely, do not revert a proven P10 startup recovery merely because unrelated historical route counters exist; compare equivalent windows and functional behavior.

## Evidence and handoff

Record only redacted/fingerprinted evidence in Git:

- firmware revision and Z-Stack version;
- restore writer/version;
- device/link-key counts;
- table capacities/populated counts;
- coordinator state transitions;
- whether `startupFromApp` was skipped;
- BDB mode/status;
- liveness/readback before and after cold boot;
- acceptance metrics;
- exact failure point if a gate fails.

Never publish the real network key, coordinator/device IEEE inventory, private backup, HA add-on options or secret-bearing NVRAM dumps.
