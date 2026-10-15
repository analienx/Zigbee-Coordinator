# R2 first on the only P7U

This plan supersedes the spare-unit/R1-first sequence for issue #80. There is
**one P7U and no spare**. R2 can be the first custom firmware; R1 is not a required
intermediate flash. Physical qualification remains open. This document does not
authorize a reset, erase or flash.

**Current implementation update:** [NV5_RECOVERY.md](NV5_RECOVERY.md) provides the separate raw backup, timing probe, five-sector preparation and original-NV restoration tool. [APPLICATION_CONTRACT_V2.md](APPLICATION_CONTRACT_V2.md) jointly expands the app writer and paired stock cleanup to 24 sectors. Physical proof remains pending. The [essential milestone policy](../../slzb-06p7/ti832/phase0/R2_ACCEPTANCE_MATRIX.md) separates the first small trial from household migration and optional features.

## Candidate changes

CAP192 explicitly sets `MAX_RTG_SRC_ENTRIES=192`, `MAX_NEIGHBOR_ENTRIES=64`, `CONCENTRATOR_ENABLE=1`,
`CONCENTRATOR_ROUTE_CACHE=1` and `CONCENTRATOR_DISCOVERY_TIME=60` in the compiler
options. TC 192, direct children 96, routing 128 and route requests 16 are unchanged.
The 64-neighbor allocation restores the original P7 CAP192 target. Earlier MG24
evidence recorded 26/26 occupancy and churn (#19/#28); occupancy alone did not
establish causation, but retaining TI's 16-entry default misses the intended
capacity. Neighbors represent direct radio neighbors, not all mesh routers.

[TI's pinned SDK network guide](https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/8.32.00.07/exports/docs/zigbee/html/zigbee/network_configuration.html)
recommends source-route capacity covering the network's nodes and caching when RAM
permits. The true/true/60 concentrator defaults also match
[Koenkk's coordinator patch](https://github.com/Koenkk/Z-Stack-firmware/blob/58dda33d834ef09132427cb41721d7d68e11a7a6/coordinator/Z-Stack_3.x.0/firmware.patch).
The repository-pinned herdsman commit `0968f979d558874b17396c96b66382d4236bbdcd`
does not configure these NV items during normal startup. Its per-device route
discovery is not periodic many-to-one discovery.

The fixed source-route table grows from 96 to 1,536 bytes (+1,440 SRAM), and the
neighbor table grows from 448 to 1,792 bytes (+1,344 SRAM): +2,784 bytes together.
Relay lists
also allocate heap as routes are learned. A successful link or unused heap region
does not qualify memory under load. Native CI checks the actual linked capacity
constants and table size, and separately checks compiler defaults. Concentrator
globals use TI compressed startup initialization and are subsequently loaded from
NV: compiled defaults are **not a runtime NV readback**. Before a network trial,
read NV items enable `0x32`, discovery `0x33`, cache `0x36` and confirm 1/60/1.

The linked TI neighbor routines use the configured count, and Link Status sends
multiple frames; 64 does not require one oversized frame. A separate inherited
32-bit broadcast-hold mask indexes **association slots**, not neighbors. The
96-child profile therefore still needs explicit testing of `0xFFFF` broadcasts
to sleepy children at association slot 32 or later. Increasing neighbor capacity
does not resolve or worsen that limitation; do not infer full sleepy-broadcast
capacity from the table-size audit.

## Before any write

1. Identify the actual unit: board revision, installed SLZB-OS, full ESP management
   MAC, radio/bridge identity and stock `SYS_PING`/`SYS_VERSION`. Stop its Zigbee
   service and isolate it from the operational network before changing radio mode.
   Never target the active MR4U/P10 or Home Assistant installation.
2. Prove stock app -> ROM BSL -> stock app -> ROM BSL on this unit. Check wafer,
   flash size, installed CCFG/backdoor and IEEE fingerprints each time. Establish
   the physical recovery connection, including access to the TI debug pads if the
   host bridge fails. Do not deliberately corrupt the app to test this escape path.
3. Save private, same-device original bytes before NV preparation: preferably the
   entire 704 KiB radio image, plus a separately identified five-page NV snapshot and
   installed 88-byte CCFG. Repeat the reads and compare hashes/ROM CRCs; retain an
   independently verified off-device copy and a complete logical coordinator
   backup. Inspection receipts contain CRCs/digests, **not these recovery bytes**.
4. Verify the installed application is recoverable with the exact stock image.
   The pinned official 20240710 image is not evidence of what is installed. Keep
   the old network quiescent after backup; restoring stale counters while the same
   keys continue transmitting is unsafe. Use fresh network keys for the R2 trial.

Repeated BSL entry proves access, not successful recovery from a failed flash.
Actual app rollback remains an unchecked physical gate until performed. If any
required backup or recovery path cannot be established, stop before writing.

## Deliberate NV5 preparation

R2 NV5 occupies exactly five 8 KiB sectors: `0xA4000`, `0xA6000`, `0xA8000`,
`0xAA000`, `0xAC000`. Stock NV2 overlaps the last two. `0xAE000` is the protected
CCFG sector and is never part of NV initialization.

The application writer neither erases nor restores NV. Its R2 **initial-install**
path reads all 40,960 NV bytes during inspection, binds their digest/blank status
to approval, rejects nonblank/missing evidence before a network BSL reset, and
rereads all five pages before the first application erase. A nonblank stock unit
therefore remains blocked; there is no automatic conversion or wipe. R1 and
stock-app rollback retain their existing nonblank-NV behavior.

If NV5 is not already entirely FF, a separate reviewed, identity-bound NV operation
must follow the backups above. The separate `p7u_nv_recovery.py` implements it
with verified original/copy backups and a fresh approval plan; see
[NV5_RECOVERY.md](NV5_RECOVERY.md). Do not use a generic bank-erase flasher or
weaken the application allowlist. The blank
gate is deliberately unsuitable for updating an already formed NV5 network.

Stock application rollback restores firmware only. Once R2 has initialized NV5,
returning to the old NV2 network additionally needs a validated restoration of the
original NV layout/state (or a coordinated logical restore). Simply booting stock
over R2 NV5 does not establish recovery of the old network.

## First R2 trial and rollback

Use a fresh native-matched candidate and paired stock cleanup plan. The historical
RC1 tag/archive predates the review fixes and must not be selected. Keep the exact
24-sector application allowlist, sector CRC verification, vector sector last and
unchanged installed CCFG/IEEE checks. A future image beyond `0x30000` requires a
joint update/review of candidate writing and stock tail cleanup; do not remove the
guard. This boundary is a recovery contract, not exhaustion of silicon flash.

After the separate NV prerequisite is satisfied and a concrete write is approved:
flash R2, verify ZNP, reenter ROM BSL, perform actual stock app rollback and verify
stock ZNP plus BSL reentry. Record firmware rollback separately from original
network-state recovery. A later R2 reinstall must satisfy the NV prerequisite
again; stock app rollback does not make NV5 blank.

Then grow a fresh disposable network in stages from a few representative devices
toward the intended 60+ routers/100+ devices. Observe routed delivery, AF failures,
Z2M timeouts and the current free-heap trend. Add deeper instrumentation only if
these measurements reveal a problem. Check counter persistence across orderly
restarts. Defer destructive power-cut and failure-injection tests on the only unit
until ordinary recovery is established. Hardware/RF wiring, sustained capacity,
power-loss recovery and coordinated NWK key rotation remain unqualified.
