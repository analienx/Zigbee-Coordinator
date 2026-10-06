# T832 R6 candidate — NV capacity contract

R5 is withdrawn from deployment. Production remains on restored vendor
20240716 over TCP; this assignment performs no HA, radio or ESP changes.

This branch is a separate NVLAB/minimal-control experiment. Latest PR #40
proposes a fast 112-key diagnostic with the original five-page geometry.
Do not silently replace that deployed-layout proposal with these enlarged
profiles: moving NVS requires an independently proved migration/restore.
The lab also characterizes five-page/112-key operation across explicit
synthetic child-table occupancies. These assumptions are not a replay of
the private household backup and do not settle real-device sufficiency.

R6 BASE starts from pristine pinned TI 8.32 and the pinned P10 project seed.
Only restore/key-management APIs, explicit persistent capacities and the
coherent compiler/linker/SysConfig NV allocation change. UART completion,
MAC queues, routes, concentrator policy and ISR stack keep their TI defaults.
DIAG uses the same BASE policy and adds the established bounded recorder,
startup/task/UART/NWK/fault observations and an NV POD observer. Recovery
reformat (`NVOCMP_RECOVER_FROM_COMPACT_FAILURE`) is OFF; it is a destructive
**RECOVERY_POLICY**, not an innocuous correctness fix.

## Profiles and evidence

`production-demand`: 128 Trust Center records, 103 current keys + 25 reserve,
75 child/device-list limit (+1 parent slot), four default binding slots,
213 TI-derived address-manager entries. `capacity-400`: 400 TC records and
485 addresses. `profiles.json` binds both, including 2.3 KiB other NV,
25% live-data growth and two reserved compaction/headroom pages.
The estimate is a floor. GitHub Actions runs TI's actual unmodified NVOCMP
algorithm on a Linux flash backend with synthetic table-sized records,
full population, repeated updates, extra item create/update/delete, forced
compaction and fresh-process reopening. Interrupted compaction preserves
the fixture at selected physical program/erase boundaries. This does not
model partial electrical writes, TI's NVS driver or the complete live ZStack.
No household keys, IDs or raw pages enter public artifacts.

The five-page/400-key negative control requires incomplete population,
create API failure, reads that still work, and BADLENGTH on an exhausted
tiny update. It reproduces the capacity failure class, not the exact vendor
layout or a proven unique cause of the live R5 incident. Vendor 20260311
reported 400 existing records; its integration must not be assumed identical.

All compilation, tests, audit and packaging run in GitHub-hosted Actions
against the same exact candidate SHA. A successful build proves effective
capacity assertions, internal NVS index0/base/size, linker NV region,
minimum 8 KiB free SRAM and CCFG BSL/vector checks. Canonical SLZB BIN is
packaged there with OUT, HEX, map, generated config, schema, host tools,
hashes and provenance. Format equivalence does not prove uploader behavior.

## R6 diagnostic semantics

Capability bit28 identifies pristine TI callback completion; bit29 identifies
the deferred NV POD topology. Bit14's legacy timed NV events are absent.
Clear bit5:
frame-bound wire-finished completion is unavailable on this baseline.
The original write callback retains NPI completion and shadow ownership
ends there. Public TX_BEGIN/TX_FINISHED events count physical UART activity
without attributing a queued frame. Pipeline stages9/10 and wire boot
milestones4/5 are unavailable; boot milestones6/7 record SYS/ZDO driver
callbacks. Host receipt of the actual response remains necessary.

NV hot-path hooks store a fixed POD snapshot (<=128 bytes), counters,
first failure, last request/status, init action and page offsets/states.
They call no clock, gate, allocation, formatting, flash or NV API.
The MT task copies only a committed snapshot under a bounded critical
section, then records/exports outside it, before UART export suppression.
NV space is a RAM topology estimate at the last API boundary; never a
fresh flash scan. POD and fatal RAM remain inspectable if telemetry stalls.

New schema2 event kinds46..50: NV_TOPOLOGY, NV_SPACE, NV_COUNTERS,
NV_RESULT and NPI_WRITE_COMPLETE. Existing IDs remain stable.

## Targeted bench gate before another household flash

1. Use a spare P10, pinned candidate BIN and private disposable fixture.
   Verify uploader readback/erase extent and recovery BSL; do not assume
   that excluding NV bytes preserves NV through the uploader.
2. Boot BASE; prove ping/version and neutral STARTUP_OPTION writes through
   legacy, extended and direct NV APIs. Populate/restore the chosen profile,
   repeat counter/key updates, compact and reboot, verify all items.
3. Repeat on matched DIAG; capture boot and NV topology/status, UART events
   and host-visible SYS/ZDO responses. Compare BASE/DIAG functional results.
4. On the household coordinator, any future authorized attempt requires a
   new backup/quiescence receipt, exact firmware identity, rollback image,
   private key/address inventory and a recovery operator. Preserve P001
   latches; do not reuse its one-shot upload/reset permits.
5. After restoring NV, use BDB_START_COMMISSIONING(mode0) and prove state9
   with the original IEEE/network. Initialize hasConfigured only if absent
   after independent length confirmation. Do not add a reflexive P10 reset.

No hardware acceptance, flashing, restore success or soak result is claimed
by hosted CI. Short targeted bench checks gate progress; a 72-hour wait is
not required to implement or review this candidate.
