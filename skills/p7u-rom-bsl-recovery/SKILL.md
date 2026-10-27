---
name: p7u-rom-bsl-recovery
description: Restore a confirmed SLZB-06P7U CC2652P7 USB ZNP/SRSP hard hang. Priority-1 evidence-preserving TI ROM bootloader round-trip to existing firmware, with no flash or power cycle, followed by real Z2M device-MQTT verification.
---

# P7U first-line production hard-hang recovery

**Read the canonical detailed procedure before any physical action:** [HANG_RECOVERY_RUNBOOK.md](../../coordinators/slzb-06p7u/HANG_RECOVERY_RUNBOOK.md).

## Selection

Choose this only for **proven local ZNP/SRSP failure** affecting the sole SLZB-06P7U; not ordinary unreachable routers or a slow network map. Prefer restoration of household service before longer root-cause repair. **Do not** begin with Zigbee-only/ESP-only restart loops; they failed on 27-Oct-2026, when the TI ROM BSL round-trip recovered.

## One-shot guarded sequence

1. Freeze prior F2, passive host, Z2M/MQTT logs and verified DB/coordinator NV/security backups; no serial owner, no OTA, disabled watchdog/guard. Pin CC2652P7 device, SMLIGHT management MAC/OS, USB by-id path and vendor JS SHA/command map.
2. Create **new per-incident** locked and fsynced **consumed-before-send** marker. With exclusive USB access, source-verified SMLIGHT **CMD_ZB_BSL=2**, then read-only TI ROM SYNC/CHIP_ID **0xf000** and optional limited APP/CCFG CRC. Close the ROM serial port. No erase/download/NV writes.
3. Create another durable intent, then verified SMLIGHT **CMD_ZB_RST=1** into unchanged existing APP (not an ESP reset or factory reset).
4. Create a separate host-start intent, start **one** existing Z2M owner and verify completed herdsman/SYS/AF/ZDO startup, MQTT connection and **new authenticated non-retained MQTT device reports from multiple devices**. Interpret Supervisor API timeouts by checking actual state; no blind retry.
5. Record result privately; do not replay consumed historical commands/scripts. If any gate fails, **STOP** and inspect, don't reflexively flash, power-cycle or re-form the network.

No **CMD_HARD_RESET=9**, no stock restore, no stale counter replay, no additional ZNP owner while serving. Flash is a **separate conditional decision** requiring new source-pinned image, full protected-sector and counter verification, operator approval and exact readback.

## What success means

The 27-Oct physical incident: ordinary Zigbee restart failed at AF-register; ESP restart failed at SYS ping; entering TI ROM BSL, checking ROM and rebooting **unchanged R4** succeeded. Live independent MQTT v5 subscriber: **24 non-retained device messages across five devices in 5.7 seconds**; Z2M Supervisor started and container had zero restarts. **No flash, NV writes or external power removal.**

This makes an APP runtime/NPI/UART-state lock or ESP/radio reset-bridge sequencing plausible, **not proven**. Focus engineering on actual BSL-vs-normal-reset hardware differences, first missing SRSP, radio RX/MT enqueue/dequeue/UART TX and independent ESP bridge counters. F2 lost its most important pre-hang window; don't call missing/unsupported F2 metrics zero.

Relevant issues: [#143 recovery](https://github.com/analienx/Zigbee-Coordinator/issues/143#issuecomment-6438517051), [#144 diagnostics](https://github.com/analienx/Zigbee-Coordinator/issues/144#issuecomment-6436979523).
