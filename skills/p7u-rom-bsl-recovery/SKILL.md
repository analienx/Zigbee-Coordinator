---
name: p7u-rom-bsl-recovery
description: Recover a confirmed SLZB-06P7U CC2652P7 USB ZNP/SRSP hang through a qualified no-write ROM round-trip and retained startup. Verify fresh device traffic; network restoration and firmware flashing are separate tasks.
metadata:
  version: "2.0.0"
---

# P7U USB hang recovery

Read [the maintained runbook](../../coordinators/slzb-06p7u/HANG_RECOVERY_RUNBOOK.md)
before physical actions. Use existing task authorization; this skill grants no
additional device permissions. Preserve a healthy running service during source,
Git or skill maintenance.

**Since 1 November 2026 the production host is the official Zigbee2MQTT app on
V54 firmware.** Capture hang evidence with
`tools/p7u_official_delivery.py hang --stop-z2m` (review F1). The runbook's
custom-host start steps (sections C and D) are not re-qualified for the official
app. Follow the host-change note at the top of the runbook. Never bypass an
operator owner check to make a capture run.

## Select the operation

Confirm adapter-local SRSP failure and lost fresh device traffic. Individual
offline devices, NWK_NO_ROUTE or a stale F2 sample alone do not establish a hang.
Resolve the current owner and device identity from read-only evidence. P10/MR4U
and missing-network restoration use different procedures.

## Qualified sequence

1. Freeze F2/passive logs and verified network/security backups before reset.
   Require the sole host stopped, no other UART holder or OTA, disabled recovery
   automation, and the lifecycle lock. Pin USB, management MAC/OS and API source.
2. Use the qualified writer's order: **open the pinned USB port before BSL entry**,
   then issue one source-verified BSL action. On the qualified OS this is
   `CMD_ZB_BSL=2`. Keep the port open for ROM SYNC, chip ID `0xf000` and bounded
   read-only CRCs checked against the actual installed-image receipts. Close ROM.
3. For retained R4 requiring native readiness, open the qualified startup observer
   before the one application boot (`CMD_ZB_RST=1`). Verify a fresh reset indication,
   pristine source-bound B1 checkpoints and retained IEEE/key identity. Request
   non-forming startup once and prove native READY/state9 before closing the port.
   An already observed READY with incomplete terminal proof permits read-only
   completion through the qualified operator, not repeated startup.
4. Start the installed compatible host once, then verify full herdsman startup,
   MQTT and fresh non-retained reports from at least three devices. For F2 v4.3
   delivery, verify three durable minor3 records with advancing counters, all20
   progress/all18 response-stage fields and a valid journal chain/manifest.

Each side effect needs its own fsynced consumed-before-send intent. Reuse qualified
source and fresh plans; historical one-shot scripts contain consumed state. An
ambiguous ACK requires state inspection. A failed gate stops that operation.

Do not substitute Core-first restart loops, intentional DTR/RTS experiments,
transport-mode changes, `CMD_HARD_RESET=9`, NV replay or a firmware flash. Leave
automatic recovery disabled. No second serial owner may run alongside Z2M.

The 28-Oct result proves this sequence restores initial service without rewriting
APP/AC000/NV/CCFG. It does not prove the startup or historical SRSP hang cured.
Missing or skipped F2 observations remain missing, never zero.
Track recovery in [#143](https://github.com/analienx/Zigbee-Coordinator/issues/143)
and root-cause diagnostics in [#144](https://github.com/analienx/Zigbee-Coordinator/issues/144).
