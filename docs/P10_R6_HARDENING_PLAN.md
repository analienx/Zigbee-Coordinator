# CC2674P10 R6 Firmware Hardening Plan

> Status: **offline implementation / no production flash**
>
> Production stays on the recovered SMLIGHT 20240716 image.
>
> R5 / T832-DIAG-R0 is **superseded as a deployable candidate**. Its artifacts remain forensic evidence and must not be rewritten.

## 0. Purpose

R6 is not "R5 with fixes".

R5 combined several independent dimensions:

- TI 8.32 P10 integration;
- coordinator/large-network capacity tuning;
- extended MT/NV support;
- a custom NPI UART completion policy;
- NV recovery policy;
- diagnostic instrumentation;
- MR4U board adaptation.

The first hardware deployment exposed a real NV-write failure before the intended long-duration coordinator-hang experiment could begin.

R6 therefore changes the engineering method:

1. prove the **persistent-storage contract** first;
2. prove the **behavior-minimal coordinator control** second;
3. isolate **transport changes** as independent experiments;
4. add diagnostics only after the functional control is proven;
5. make the exact device-upload image the canonical CI artifact.

No R6 build is production-eligible merely because it compiles or passes host unit tests.

---

# 1. Facts established by the R5 incident

## 1.1 R5 NV failure signature

On the exact R5 image:

- legacy SYS OSAL NV write returned `0x0A / NV_OPER_FAILED`;
- extended OSAL NV write returned `0x0A / NV_OPER_FAILED`;
- direct extended NVINTF write returned `0x05 / NVINTF_BADLENGTH`;
- reads still succeeded;
- diagnostic boot state reported `NVOCMP_NORMAL_RESUME`.

The direct BADLENGTH result is not evidence that the tiny test payload was actually too long.

In TI NVOCMP, `NVOCMP_addItem()` can return BADLENGTH after:

1. no destination page can accept the requested record;
2. compaction is attempted;
3. compaction still cannot provide the requested bytes;
4. there was no lower-level fatal flash-write error to report instead.

For R6, treat the R5 failure as:

> **No usable writable NV destination / insufficient compactable NV space until disproven.**

## 1.2 Same hardware succeeds on vendor 20240716

After rollback on the same P10:

- SYS_PING succeeded;
- SYS_VERSION identified 20240716;
- the same neutral NV write returned success.

This removes the following as primary explanations:

- failed P10 flash controller;
- generic FAPI failure;
- generic supply-voltage inability to write;
- permanently damaged NVS sectors.

The defect is firmware/configuration/integration-specific.

## 1.3 Five pages are not themselves the discovered bug

The original post-incident hypothesis over-weighted R5's project-seed correction from `NVOCMP_NVPAGES=2` to `5`.

Further source review shows:

- TI's CC13x4/CC26x4 linker contract uses five pages for the P10-class project;
- P10 SysConfig internal NVS is `0xFD800..0x100000`, size `0x2800`;
- the P10 erase sector used by this project is 0x800 bytes;
- the TI 8.33 P10 project seed contains an inconsistent linker build option that says 2 even though the compiler/linker contract says 5.

Therefore the R5 correction to five pages is reasonable.

The remaining question is whether **five 2-KiB pages are sufficient for the capacity policy R5 imported**.

## 1.4 8.30 and 8.32 do not contain different NVOCMP implementations

Exact source hashes show TI 8.30 and 8.32 use the same:

- `nvocmp.c`;
- `nvocmp.h`;
- `nvintf.h`.

The critical 7.41 -> 8.30 functions relevant to this incident are also functionally unchanged:

- init;
- destination-page selection;
- item creation;
- page compaction;
- write API.

Do not design the next experiment around an assumed "8.32 NVOCMP rewrite".

## 1.5 The capacity/NVS contract is now the P0 concern

R5 inherited a P10 Trust Center limit of:

`ZDSECMGR_TC_DEVICE_MAX = 400`

TI's own NV sizing model assigns:

- 27 bytes per Trust Center device entry;
- 23 bytes per direct-device-list entry;
- 19 bytes per address-manager entry;
- approximately 2.3 KiB for less variable NV items.

The TCLK component alone at 400 is:

`400 * 27 = 10,800 bytes`

which is already larger than the complete five-page / 10,240-byte P10 NVS region before other items or compaction reserve.

That does **not** prove "400 is the R5 root cause" because there is important counter-evidence:

- the preflash SMLIGHT 20260311 firmware returned real length-20 items for TCLK sub-IDs through 399;
- TI MT source shows `SYS_NV_LENGTH` delegates to the active NV backend's `getItemLen()`, so those were real NV items rather than a synthetic capacity response;
- SMLIGHT publicly positions its P10 firmware for up to 400 devices.

The correct R6 conclusion is:

> The effective SMLIGHT P10 storage contract differs from the pristine TI five-page contract in a material way, or the public large-network P10 configuration contains an upstream integration defect. R6 must make that contract explicit and testable instead of assuming Koenkk/SMLIGHT capacity settings are portable.

---

# 2. R6 evidence/confidence model

Use these confidence labels in code reviews and issue updates.

| Hypothesis | Current confidence | R6 discriminator |
|---|---:|---|
| R5 had no writable NV destination / insufficient compactable space | high | reproduce with real NVOCMP host harness and page snapshots |
| Five pages is intrinsically wrong for P10 | low | exact TI generated config says five is valid default |
| R5 imported capacity values inconsistent with its NVS allocation | high | generated NV budget + host initialization |
| `ZDSECMGR_TC_DEVICE_MAX=400` alone is the root cause | medium/unknown | compare 400 with matched large NVS vs 400 with 5 pages |
| SMLIGHT 20260311 uses a materially different NV layout/backend | medium-high inference | vendor image/runtime geometry extraction |
| 8.32 NVOCMP algorithm regression | low | 8.30/8.32 sources are identical |
| Original long-runtime AF→ZDO→SYS hang is UART/NPI related | medium | transport-only A/B matrix |
| Original hang is NV compaction/runtime pressure related | medium | R6 diagnostic telemetry + soak |
| Original hang is routing/MTO load alone | lower | resource counters + stable transport/NV controls |

Do not promote an item to "root cause" until one controlled variant changes that one dimension and reproduces/removes the failure.

---

# 3. New build ladder

The old T830-KCTRL -> T832-KCTRL -> KDIAG ladder is replaced for the immediate work by the following.

## R6-NVLAB-D

Purpose: prove the persistent-storage contract for **production demand**, without a production network.

Characteristics:

- TI 8.32 NVOCMP source;
- production-like compiled security/address/device capacities;
- NVS size generated from budget, not inherited;
- no diagnostic UART;
- no MR4U production deployment;
- host/Linux NVOCMP harness plus sacrificial P10 validation.

"D" means demand-derived, not a fixed 128-slot promise.

A first candidate may land near 128 TCLK entries because the current backup contains about 103 link keys, but CI owns the final number.

## R6-NVLAB-400

Purpose: determine what storage contract is actually required to make a 400-device P10 configuration valid.

Characteristics:

- `ZDSECMGR_TC_DEVICE_MAX=400`;
- NVS region deliberately expanded;
- full NV sizing model;
- stress/fault-injection only;
- no assumption that this is the eventual production profile.

This tells us whether "400 + enough NVS" is clean and separates capacity from other R5 changes.

## R6-BASE

Purpose: first behavior-minimal custom coordinator candidate.

Contains only:

- MR4U board/RF/CCFG adaptation;
- exact restore-required MT/NV/security APIs;
- demand-derived capacities;
- proven NVS allocation;
- explicit build identity;
- TI upstream transport behavior unless separately justified.

Does **not** contain:

- diagnostics;
- speculative routing changes;
- SMLIGHT low-level UART/DMA/FIFO modifications;
- automatic watchdog logic;
- `NVOCMP_RECOVER_FROM_COMPACT_FAILURE` by default;
- broad Koenkk tuning copied merely because it exists upstream.

## R6-TXFIN

Purpose: isolate the Koenkk-style NPI `UART2_EVENT_TX_FINISHED` completion policy.

It is exactly R6-BASE plus that one transport delta and any minimum plumbing necessary to implement it.

This exists because transport completion semantics are highly relevant to the original hang, but they must no longer be mixed with the storage fix.

## R6-DIAG

Purpose: observe whichever functional control is selected after the bench matrix.

It must inherit the exact functional policy from the chosen control.

Only evidence-producing changes are permitted.

---

# 4. Persistent-storage contract

## 4.1 One generated source of truth

Create a machine-readable storage manifest generated from the actual compiled configuration.

Minimum fields:

```yaml
nv_backend:
  config_index:
  driver:
  sector_size:
  region_base:
  region_size:
  page_count:
  storage_pages:
  compaction_pages:
capacity:
  tclk:
  install_code:
  direct_devices:
  address_manager:
  bindings:
  groups:
estimated_nv:
  tclk_bytes:
  direct_device_bytes:
  address_manager_bytes:
  fixed_other_bytes:
  explicit_other_tables:
  total_estimated:
  usable_active_bytes:
  estimated_headroom:
generated:
  linker_nv_base:
  linker_nv_size:
  compiler_nv_pages:
  sysconfig_region_base:
  sysconfig_region_size:
```

All geometry fields must agree.

The build fails if any of these disagree:

- compiler `NVOCMP_NVPAGES`;
- linker preprocessing value;
- linker FLASH/NV region;
- generated `NVS_config[0]`;
- SysConfig internal NVS base/size;
- actual NVS sector size expected by NVOCMP.

## 4.2 NVS index must be proven from generated C

Do not accept "NVS1 is listed first in .syscfg" as proof.

Parse the generated `ti_drivers_config.c` and assert:

- the NVOCMP index resolves to the intended internal-flash object;
- its region base and region size equal the manifest;
- its sector size is the expected P10 erase sector;
- no external NVS object silently became index zero.

Emit this result in CI.

## 4.3 Budget must include all capacity-coupled NV

At minimum model TI's documented components:

```
NWK_MAX_DEVICE_LIST      * 23
ZDSECMGR_TC_DEVICE_MAX   * 27
NWK_MAX_ADDRESSES        * 19
other NV                 ~ 2.3 KiB baseline
```

Then extend the model from exact target source to include every other table whose size changes with compile-time capacity, including where applicable:

- TCLK install-code table;
- group table;
- binding table;
- network security material;
- commissioning/configuration records;
- address-manager records;
- device-manager records;
- any target-specific vendor additions.

Do not double-count entries that are alternative representations of the same storage.

Every formula must link to the exact target SDK source or TI sizing documentation.

## 4.4 Compaction is part of capacity, not spare luxury

NVOCMP is copy-on-write/compaction storage.

R6 must distinguish:

- raw region bytes;
- page metadata;
- storage-page bytes;
- the transfer/compaction destination page;
- currently free bytes;
- maximum transient bytes required for an update;
- reclaimable inactive records.

A configuration does not pass merely because the sum of active item payloads is smaller than the raw region.

## 4.5 Do not hardcode 128 or 400 in policy

Profiles are generated from requirements.

### Demand profile

Inputs:

- fresh backup link-key count;
- fresh device-record count;
- direct-child count;
- groups;
- bindings;
- explicit growth reserve.

Reserve must be declared **before** test results are inspected.

Candidate reserve policy to evaluate:

- security records: current count + 20–25%;
- direct children: measured high-water + explicit minimum reserve;
- groups/bindings: current demand + named future reserve;
- routing tables: RAM-only demand based on observed topology/load, not NV capacity.

If the generated budget says the default five-page region is insufficient, enlarge the region.

### 400 profile

If retaining SMLIGHT-class 400-device capability is desired, size NVS to that policy.

Do not force the 400 profile into five pages.

The P10 has enough total flash to evaluate larger reservations, but any enlarged region requires coordinated changes to:

- application flash limit;
- NV base;
- NV size;
- compiler page count;
- SysConfig NVS region;
- image/static audit;
- management-upload preservation assumptions.

Initial lab points may include 8 pages (16 KiB) and 16 pages (32 KiB), but these are **experiments**, not accepted values.

The generated budget and stress results determine the final profile.

---

# 5. Host-side NVOCMP CI harness

This is the most important new R6 gate.

TI NVOCMP already contains a Linux/host path. Use the real driver, not a hand-written approximation.

## 5.1 Harness inputs

For each candidate configuration, feed:

- exact `NVOCMP_NVPAGES`;
- exact page size;
- exact capacity macros;
- exact NV item definitions and sizes;
- production-demand fixture counts;
- optional sanitized raw page fixture.

## 5.2 Required scenarios

### A. Empty first boot

- initialize NV;
- execute the same table-initialization pattern as coordinator startup;
- create fixed coordinator NV items;
- verify every create succeeds;
- record free bytes and page topology.

### B. Production-like restore

- populate security/device/address data at current production counts;
- update commissioning/network items;
- verify all creates/updates;
- close/reopen storage;
- verify every item.

### C. Capacity boundary

Run demand from current requirement through configured maximum.

The build must show exactly where capacity fails and prove the configured maximum is below that failure boundary with reserve.

### D. Churn

Repeatedly update representative high-churn items:

- frame counters/security material;
- NIB/configuration;
- startup/config flags;
- address/security records.

Require compactions to occur.

No write may return:

- BADLENGTH due to no destination;
- NV_OPER_FAILED;
- fatal flash state.

### E. Delete/recreate

Delete and recreate extended items around compaction boundaries.

### F. Reboot/reopen

After each workload epoch:

- close storage;
- reopen;
- run sanity checks;
- validate all expected active records;
- validate no duplicate-active corruption.

## 5.3 Fault injection

Instrument the host NVS backend so the test runner can terminate or inject failure after every selected:

- header write;
- data write;
- active/inactive mark;
- page-state transition;
- compact-header write;
- sector erase.

For each injection point:

1. persist the interrupted image;
2. restart NVOCMP;
3. record the recovered page topology;
4. verify whether data remains recoverable;
5. repeat with recovery policy OFF and ON.

This turns `NVOCMP_RECOVER_FROM_COMPACT_FAILURE` into a measured policy rather than folklore.

## 5.4 Required outputs

CI artifact:

`nv-contract-report.json`

Minimum content:

- configuration hash;
- geometry;
- item-count/byte budget;
- free bytes after init;
- free bytes after production-like restore;
- minimum free bytes during churn;
- compaction count;
- maximum compaction duration in host test;
- injected-failure matrix;
- first failing capacity;
- selected production capacity;
- pass/fail.

---

# 6. Runtime NV hard gate on hardware

The host harness is necessary but not sufficient.

On sacrificial P10 hardware expose a temporary diagnostic command/readout that reports:

- NVS sector size;
- region size;
- effective NV page count;
- head page;
- tail/XDST page;
- active page;
- active offset;
- per-page state;
- per-page end/used offset;
- free NV from the official API;
- last NV operation;
- last compaction result;
- fatal/non-fatal NV failure flags.

Do not periodically write this telemetry to NV.

## Hardware acceptance

Before any household backup is restored:

1. cold boot;
2. create a disposable network/config fixture;
3. verify neutral existing-item update;
4. create a new extended item;
5. update it;
6. delete/recreate it;
7. force enough churn to compact;
8. power-cycle;
9. verify all expected records.

Then repeat with a production-shaped sanitized fixture.

A candidate that cannot pass NV write/compaction independently never reaches transport or Zigbee soak testing.

---

# 7. Reclassify coordinator patches

R6 patch classes:

| Class | Meaning |
|---|---|
| BOARD | required by MR4U physical hardware |
| PROTOCOL_COMPAT | required for ZNP/herdsman API compatibility |
| STORAGE_CONTRACT | capacity/NVS changes proven by generated budget |
| TRANSPORT_EXPERIMENT | one isolated NPI/UART behavior change |
| RAM_CAPACITY | measured runtime capacity, no persistence effect |
| RECOVERY_POLICY | behavior after corruption/failure |
| DIAGNOSTIC | evidence only |
| BUILD_ID | provenance only |
| FIX | prohibited from controls until mechanism is proven |

Every changed line must have one class.

## 7.1 NVOCMP recovery reclassification

Move:

`NVOCMP_RECOVER_FROM_COMPACT_FAILURE`

from REQUIRED_CORRECTNESS to:

`RECOVERY_POLICY`

Reason:

When enabled, TI permits recovery from collection/compaction failure by reformatting NV pages. That can improve availability while destroying the exact page evidence required for diagnosis.

Policy:

- OFF in R6-NVLAB baseline;
- OFF in the first R6-BASE;
- OFF in the first evidence-oriented R6-DIAG;
- ON only in a dedicated fault-injection matrix;
- final production choice made from measured results.

## 7.2 Extended NV/security MT support

Keep only commands required by the exact production herdsman backup/restore path.

Continue to support:

- `FEATURE_NVEXID`;
- security-key management needed by the restore tooling.

Document each required MT command from the actual herdsman transcript.

## 7.3 Large-network parameters

Do not copy Koenkk's whole preinclude.

Separate:

### Persistent

Examples:

- Trust Center security capacity;
- device/address capacities where persisted.

These are governed by STORAGE_CONTRACT.

### RAM-only or primarily runtime

Examples:

- route table;
- source-route table;
- route requests;
- neighbor table;
- MAC queues.

These are governed by measured RAM/runtime demand.

A huge RAM reserve is not automatically harmful on P10, but it changes workload/timing and therefore must not contaminate the first functional control without a reason.

---

# 8. Transport causality matrix

The original household incident remains a separate problem from R5 NV exhaustion.

TI 8.30 contains relevant UART2 fixes, including a write race in callback/blocking modes. 8.30 and 8.32 share the corrected driver generation.

Run transport experiments only after NV contract is green.

## T0 — upstream functional transport

R6-BASE with the upstream TI NPI/UART path for the selected SDK.

Purpose:

- establish whether the custom TX completion patch is necessary at all on the corrected TI driver generation.

## T1 — TX_FINISHED only

R6-TXFIN.

Only semantic delta:

- subscribe to `UART2_EVENT_TX_FINISHED`;
- do not signal NPI completion until final byte leaves hardware.

No table, NV, queue or diagnostic changes are allowed in the same comparison.

## T2 — optional SMLIGHT-like low-level experiments

Only if T0/T1 results justify them.

One dimension per build:

- ring size;
- FIFO threshold;
- priority;
- abstraction bypass;
- baud.

Do not recreate SMLIGHT 20260311 as one opaque bundle.

## 8.1 8.30 vs 8.32 role

Because 8.30/8.32 share NVOCMP source and corrected UART2 lineage:

- use 8.30 vs 8.32 as a **Core SDK / generated integration** comparator;
- do not describe it as a different Zigbee/NV stack generation.

If they differ, diff the exact linked/generated code.

---

# 9. R6-DIAG architecture

## 9.1 Fix the RX high-water bug

R5 recorded UART RX high-water before `NPITLUART_readIsrBuf()` updated `TransportRxLen`.

R6 sequence must be equivalent to:

```c
copied = NPITLUART_readIsrBuf(size);
diag_rx(copied, TransportRxLen);

if (copied != size) {
    diag_rx_overflow(size, TransportRxLen);
}
```

Define the metric precisely:

- RX bytes = accepted/copied bytes;
- overflow attempted bytes = callback size;
- high-water = post-copy occupancy.

Add a source-level regression test using the actual no-flow-control callback sequence.

## 9.2 Sampling must be independent of export

R5 generated important HEALTH/RESOURCE state inside the export poller.

When normal traffic or transport remained busy, export was correctly blocked — but sampling stopped too.

R6 separates:

`sample locally -> store sticky/max/latest -> export when safe`

Sampling continues while UART export is blocked.

At minimum retain:

- normal-pending oldest age;
- max normal-pending count;
- transport-active age;
- last MT progress;
- last NPI progress;
- last Z-Stack progress;
- AF outstanding/max;
- export-block reason and start time;
- NV free-space low-water;
- last compaction result.

## 9.3 NV instrumentation must not perturb NV hot paths

Do not call a general recorder that:

- obtains timestamps;
- enters critical sections;
- formats frames;
- exports UART data

from inside NVOCMP compaction.

Inside NVOCMP use a tiny static POD snapshot/update only.

Example:

```c
struct NvDiagPod {
    uint8_t event;
    uint8_t act_page;
    uint8_t tail_page;
    uint8_t fail_f;
    uint8_t fail_w;
    uint16_t act_offset;
    uint16_t dst_free;
    uint32_t sequence;
};
```

Copy/export it later from a normal task context.

## 9.4 Heap fragmentation metric

R5's largest-free-block path calls a full heap scan under a critical section.

First R6-DIAG:

- keep cheap allocation-failure counters;
- keep current/free/min heap if inexpensive;
- disable largest-free-block scan.

Only re-enable after measuring worst-case latency on fragmented P10 heap.

## 9.5 Terminal evidence

The normal diagnostic AREQ uses the same UART that may be part of the original failure.

Keep the RAM event ring and sticky first fault, but accept its limitation.

If a future run ends in abrupt UART silence without useful precursor, next evidence tier is:

- SWD/JTAG bench capture;
- side-band MR4U bridge state;
- external logic analyzer / UART observation.

Do not add periodic NV diagnostic writes while NV is under investigation.

---

# 10. Canonical artifact pipeline

R5 build CI proved OUT/HEX and deployment tooling later created the exact SLZB container.

R6 removes that split.

One workflow must produce the only flashable artifact.

Pipeline:

```
pinned source
-> generated SysConfig
-> compiled OUT/ELF
-> HEX
-> exact MR4U/SMLIGHT upload BIN
-> static flash-map audit
-> CCFG audit
-> NVS exclusion audit
-> hashes
-> signed/immutable manifest
```

## Required manifest hashes

- source commit;
- SDK archive/source hash;
- compiler;
- SysConfig;
- generated config;
- linker command;
- map;
- OUT;
- HEX;
- SLZB BIN.

## Container audit

Prove:

- every application byte equals HEX;
- only documented wrapper/padding bytes are added;
- CCFG is preserved;
- no upload payload writes into the reserved NV range;
- segment addresses are explicit;
- exact target is CC2674P10.

## Management uploader hardware test

On a sacrificial P10:

1. fill reserved NVS with known non-secret test pattern/state;
2. raw-read/hash the region;
3. flash through the **same SLZB-OS management path** with `eraseNVM=0`;
4. raw-read/hash;
5. prove preservation semantics.

Do not infer management erase behavior from a different flasher implementation.

---

# 11. Recovery and restore acceptance

Direct SYS_VERSION is authoritative for P10 application identity when SLZB-OS metadata disagrees.

Preserve the successful recovery rule discovered after R5:

If a restored vendor/custom ZNP has:

- correct coordinator IEEE;
- correct network NV;
- `getDeviceInfo.state = 0`;

then do not reflexively perform another P10 hardware reset.

First:

1. establish ZNP liveness;
2. use restored-network `BDB_START_COMMISSIONING(mode=0)`;
3. require SRSP success;
4. require state-change 9;
5. require same coordinator IEEE;
6. initialize/read back herdsman `hasConfigured=0x55` only if missing;
7. start Zigbee2MQTT.

Never use formation mode merely to make startup succeed.

---

# 12. Sacrificial-hardware gate

A spare/sacrificial P10 is now a mandatory stage before the household MR4U.

Minimum test campaign:

## Boot/reset

- 50 warm resets;
- 20 cold boots;
- direct SYS_PING/SYS_VERSION after each;
- BSL recovery verified.

## NV

- full R6-NVLAB hardware suite;
- production-shaped restore;
- repeated compactions;
- repeated neutral writes;
- power interruption around compaction;
- persistence check.

## Transport

For each T0/T1 variant:

- sustained MT ping/version loop;
- AF/ZDO mixed request load;
- large reply traffic;
- UART saturation burst below protocol limits;
- host disconnect/reconnect;
- MR4U bridge reconnect.

## Zigbee lab

Disposable network:

- coordinator start;
- router join;
- end-device join;
- permit join close;
- unicast;
- group;
- ZDO management;
- source-route activity where feasible.

No production identity or key material is needed for the earliest tests.

---

# 13. Production entry gate

A candidate can be marked `PRODUCTION_FLASH_ELIGIBLE=true` only when all of the following pass:

- storage manifest internally consistent;
- host NV contract suite green;
- compaction/fault-injection suite green for chosen policy;
- sacrificial P10 NV suite green;
- exact flashable SLZB BIN built in canonical CI;
- management erase/preserve behavior proven;
- board/RF/CCFG/BSL audit green;
- restore transcript green on disposable or sanitized production-shaped fixture;
- transport control selected from T0/T1 evidence;
- no diagnostics in the first production functional control;
- rollback image/hash present;
- fresh production backup generated immediately before deployment;
- join closed;
- one-shot flash permit bound to exact image/target.

The first production control then gets:

- 24 h ordinary-use observation;
- >=72 h or >=3× historical failure interval;
- longer soak before declaring a permanent fix.

A short green run is not proof.

---

# 14. Recommended implementation order

1. Freeze R5 as forensic evidence.
2. Add generated NV storage manifest.
3. Add static generated-NVS/index/linker consistency checks.
4. Build host NVOCMP harness using TI's real driver.
5. Reproduce the five-page + large-capacity failure.
6. Determine the minimum clean demand-derived NVS profile with reserve.
7. Build and test the explicit 400-capacity large-NVS comparator.
8. Decide production capacity/storage contract.
9. Build R6-BASE with no diagnostics and minimal behavior changes.
10. Build R6-TXFIN as the single transport A/B.
11. Qualify both on sacrificial P10.
12. Select functional control.
13. Build R6-DIAG from that exact control.
14. Run diagnostic bench campaign.
15. Only then consider one production deployment.

No step after 5 should proceed on an assumed root cause if the host harness does not reproduce the failure.

---

# 15. Concrete implementation deliverables

## New tooling

Suggested files:

```
firmware/p10/nv_contract.yaml
firmware/p10/gen_nv_contract.py
firmware/p10/validate_generated_nvs.py
firmware/p10/nvlab/
    README.md
    build_host_nv.py
    nv_workload.c
    fault_inject_backend.c
    fixtures/
firmware/p10/r6_manifest.json
docs/P10_R6_HARDENING_PLAN.md
```

Reuse existing T832 audit/package tooling where it is already correct.

Do not fork duplicate flash/container parsers without a reason.

## CI jobs

Suggested jobs:

```
source-provenance
generated-config-audit
nv-budget
nvlab-normal
nvlab-churn
nvlab-fault-injection
host-tests
build
linked-image-audit
slzb-package
artifact-provenance
```

Hardware jobs remain separate and cannot be faked by hosted CI.

---

# 16. Explicit no-go items

Do not:

- reflash R5;
- call five pages the root cause;
- call 400 alone the root cause before controlled reproduction;
- reduce 400 to 128 without also validating total NVS budget;
- enlarge NVS without coordinated linker/SysConfig/compiler changes;
- copy the whole Koenkk preinclude again;
- enable `NVOCMP_RECOVER_FROM_COMPACT_FAILURE` as an untested "correctness" patch;
- mix TX_FINISHED, table tuning and diagnostics in one first control;
- use `ha_info.zb_version` as sole firmware identity;
- write periodic diagnostics into the NV subsystem under investigation;
- build one artifact and flash a separately transformed artifact without the final container being CI-bound;
- use the household network to discover basic storage-layout defects.

---

# 17. Exit criteria for the R6 research phase

The hardening phase is complete only when we can answer all of these with artifacts rather than assumptions:

1. What exact NVS backend/index/base/size/pages does our P10 firmware use?
2. What exact persistent byte budget follows from every chosen capacity macro?
3. What is free NV immediately after first boot?
4. What is free NV after a production-shaped restore?
5. Can the configuration survive repeated copy-on-write updates and compaction?
6. What happens at each interrupted compaction stage?
7. Does recovery policy improve recovery without hiding unacceptable data loss?
8. Does the exact SLZB management upload preserve the intended NV region?
9. Is upstream TI transport stable under stress?
10. Does TX_FINISHED change failure rate or semantics when isolated?
11. Can diagnostics observe the failure without becoming a material scheduler/NV/UART perturbation?
12. Can the candidate be restored and started without a new Zigbee network?

Until those are answered, firmware work remains lab work.

---

# 18. Bottom line

R5 failed for a useful reason: it exposed that our firmware plan treated "large-network capacity" and "NV allocation" as separate concerns.

They are one contract.

The next design is therefore:

```
prove NV geometry
    ->
prove persistent capacity budget
    ->
prove real NVOCMP lifecycle
    ->
prove behavior-minimal coordinator
    ->
isolate transport semantics
    ->
add low-observer diagnostics
    ->
sacrificial hardware
    ->
one controlled production candidate
```

That sequence preserves the original root-cause goal while preventing another deployment from failing on a basic storage-capacity mismatch before the coordinator-hang experiment even begins.
