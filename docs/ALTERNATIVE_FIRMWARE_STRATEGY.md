# mr4u-p10 — Alternative Firmware Strategy

> Status: **planning / hardening only**
>
> This document defines the controlled firmware path to use if the SMLIGHT 20240716 baseline does not become the final production choice.
>
> It is intentionally separate from the incident history. The goal is to isolate **where the CC2674P10 hang is introduced**, not merely to produce another firmware that “seems stable”.

> **Post-R5 amendment (2026-10-06):** the immediate implementation path is now governed by
> [P10_R6_HARDENING_PLAN.md](./P10_R6_HARDENING_PLAN.md).
>
> R5 exposed a firmware-side NV write failure before the intended long-soak experiment.
> The R6 plan makes the persistent-storage contract a hard Gate 0, separates capacity/NVS,
> transport semantics and diagnostics into independent variants, and supersedes the earlier
> assumption that `NVOCMP_NVPAGES 2 -> 5` was itself the leading defect.
>
> Until the R6 NV contract is bench-proven, the earlier T830-KCTRL/T832-KCTRL production
> sequence below is **historical planning context, not flash authorization**.

---

# 1. Current evidence that constrains the design

The observed SMLIGHT 20260311 failure progressed:

```
healthy operation
-> AF SRSP timeouts
-> ZDO management SRSP timeouts
-> SYS_VERSION timeout
-> SYS_PING timeout
```

Recovery evidence:

- restarting Zigbee2MQTT did not recover it;
- serial reopen did not recover it;
- raw ZNP `SYS_PING` returned no bytes;
- raw ZNP `SYS_RESET_REQ` was not serviced;
- SLZB-OS hardware-level **Zigbee radio restart** recovered the P10;
- after that reset, the P10 answered valid ZNP `SYS_PING` over the MR4U Ethernet ZNP endpoint.

Therefore the incident is **not** proven to be a reflash-only brick and does not require persistent NVS corruption as an explanation.

Highest-value failure domains now are:

1. NPI/UART2 transport state and completion semantics;
2. NVOCMP compaction / failure recovery;
3. OSAL / RTOS heap, task or interrupt state;
4. AF/MAC/ZDO resource exhaustion;
5. route/MTO traffic as a trigger or accelerator;
6. MR4U reset-domain / bridge sequencing.

---

# 2. Why “one custom firmware” is not sufficient

A single custom image based on TI 8.30 cannot separate:

- a TI Core SDK regression;
- a Z-Stack coordinator configuration issue;
- a Koenkk patch interaction;
- a SMLIGHT-specific UART/DMA/NPI change;
- MR4U board adaptation;
- capacity tuning.

The custom-firmware path must therefore use a **controlled ladder**.

---

# 3. Recommended firmware ladder

## V24 — SMLIGHT 20240716

Purpose: black-box historical vendor baseline.

Properties:

- SMLIGHT production release;
- SDK 7.41 lineage;
- 115200 baud;
- predates the 20260311 low-level UART/DMA/NPI optimization set.

Important:

- useful for regression testing;
- **not assumed to be the permanent fix**;
- exact P10 compiled capacity must be verified after flash, before production restore.

---

## T830-LAB — pristine TI 8.30 reference

Base:

- SimpleLink Low Power F2 SDK 8.30.01.01;
- official CC2674P10 ZNP project;
- TI Clang 3.2.2 LTS;
- TI-RTOS7;
- verified MR4U board adaptation.

Purpose:

- prove deterministic toolchain;
- prove MR4U pin/RF/CCFG adaptation;
- prove ZNP transport;
- prove recovery/BSL path;
- establish the unmodified TI behavior.

This is **bench-only**.

Do not use it as the first production control because pure TI defaults omit coordinator-specific behavior that historical evidence shows is important.

---

## T830-KCTRL — TI 8.30 coordinator control

This is the **first custom production control**.

Base:

```
TI SDK 8.30.01.01
+ official CC2674P10 ZNP project
+ reviewed Koenkk coordinator patch set
+ MR4U board adaptation
+ measured production capacities
```

Purpose:

- remove SMLIGHT 20260311 downstream changes;
- retain known coordinator correctness/stability behavior;
- establish whether the network remains stable on the first official TI P10 SDK generation.

---

## T832-KCTRL — TI 8.32 coordinator control

This is the **critical second control**.

Base:

```
TI SDK 8.32.00.07
+ exactly the same logical coordinator patch manifest as T830-KCTRL
+ exactly the same MR4U board adaptation
+ exactly the same capacity policy
+ no SMLIGHT 20260311 low-level transport modifications
```

Purpose:

- isolate TI 8.30 -> 8.32 from SMLIGHT downstream modifications.

TI states that SDK 8.32 contains only Wi-SUN updates compared with 8.31, and 8.31 states other components are unchanged from 8.30.01.01. That makes this comparator especially valuable: if T830-KCTRL and T832-KCTRL differ in behavior, investigate actual generated source/driver/build differences rather than assuming a Zigbee stack generation change.

---

## T832-KDIAG — diagnostic control

Functionally identical to T832-KCTRL.

Adds evidence only:

- NPI/UART2 state;
- NVOCMP state;
- heap/stack/resource watermarks;
- fault/error breadcrumbs;
- route/MTO counters.

No behavior-changing “fixes” are allowed.

If T830-KCTRL fails while T832-KCTRL does not, create **T830-KDIAG** instead and instrument the failing branch.

---

# 4. Why SMLIGHT 20250325 is not the preferred midpoint

SMLIGHT 20250325 is valuable forensic evidence because it sits on SDK 8.30, but the vendor marks it test/dev and warns about PAN-ID / commissioning behavior.

That introduces extra variables:

- migration semantics;
- NVS layout / state;
- commissioning behavior;
- vendor-specific configuration.

Therefore:

> Do not make SMLIGHT 20250325 the primary production midpoint unless a later question specifically requires its black-box behavior.

The cleaner midpoint is T830-KCTRL, where every source difference is known.

---

# 5. Exact coordinator patch philosophy

Do not copy Koenkk wholesale.

Every change applied to TI upstream must be classified into one of:

| Class | Meaning |
|---|---|
| REQUIRED_CORRECTNESS | Required for correct ZNP/coordinator semantics |
| RESTORE_COMPAT | Required by current backup/restore tooling |
| CAPACITY | Measured production demand |
| LARGE_NETWORK_BASELINE | Existing known coordinator behavior kept identical across controls |
| BOARD | MR4U hardware adaptation |
| BUILD_ID | provenance only |
| DIAGNOSTIC | only in diagnostic builds |
| EXPERIMENTAL_FIX | forbidden from control builds |

A control build fails review if any modified line has no class.

---

# 6. Required correctness / compatibility items

## 6.1 NVOCMP recovery

Enable:

`NVOCMP_RECOVER_FROM_COMPACT_FAILURE`

TI documents this as customer-enabled behavior and disabled by default.

Historical TI/Koenkk investigation found it was one of two changes required to eliminate a long-uptime crash family.

This is not considered speculative tuning. It is coordinator reliability behavior with direct historical evidence.

---

## 6.2 NPI UART2 completion semantics

Do **not** use “write callback means TX complete”.

TI UART2 documentation explicitly distinguishes:

- write callback: data accepted/transferred from application perspective;
- `UART2_EVENT_TX_FINISHED`: final byte actually shifted out of hardware.

The coordinator transport must not clear TX state or signal NPI completion before `UART2_EVENT_TX_FINISHED`.

The reviewed Koenkk coordinator lineage explicitly subscribes to that event.

This is a correctness requirement, not a performance optimization.

---

## 6.3 Extended NV/security MT support

Retain the reviewed support required by current migration/backup tooling, including the exact equivalents of:

- `FEATURE_NVEXID`;
- `MT_SYS_KEY_MANAGEMENT`;

and any other MT commands proven necessary by the exact herdsman restore transcript.

Do not enable unrelated MT debug commands by default.

---

# 7. Large-network baseline

For T830-KCTRL and T832-KCTRL, use the **same logical coordinator configuration**.

Known Koenkk 20250321 reference points include:

- MAC TX data: 50;
- MAC TX max: 80;
- MAC RX max: 50;
- source routes: 250;
- route requests: 40;
- routing table: 150;
- direct-device list: 75;
- P10 Trust Center target: 400;
- neighbor table: 50;
- MTO concentrator enabled;
- `MTO_RREQ_LIMIT_TIME = 5000`;
- UART ISR buffer increased relative to the prior line.

These are reference values, **not blind final values**.

Final control capacities must be generated from:

```
fresh backup demand
+ explicit reserve policy
+ linker/static-RAM proof
+ runtime headroom proof
```

The exact same resulting values must be used in T830-KCTRL and T832-KCTRL.

---

# 8. Production capacity policy

Current private recovery evidence:

- 102 coordinator device records;
- 101 link-key records.

Minimum restore requirement:

- TCLK capacity >= 101.

Operational target:

- choose a value >= current demand + explicit reserve;
- prefer a round capacity target only after RAM accounting;
- no table is increased solely because P10 has “lots of RAM”.

For every table record:

```
measured demand
chosen value
reserve
bytes per entry
static RAM cost
NVS cost
reason
```

Required categories:

- Trust Center / link-key records;
- address manager / device records;
- neighbor entries;
- direct children;
- routing entries;
- source routes;
- route requests;
- groups;
- bindings;
- AF/MAC buffers.

---

# 9. Build reproducibility

Each control build must have:

- exact SDK archive hash;
- exact TI source commit/package provenance;
- exact SysConfig version;
- exact TI Clang version/hash;
- exact Koenkk source tag/commit used only as patch reference;
- generated patch manifest;
- MR4U board manifest;
- generated SysConfig diff;
- linker map;
- ELF/OUT hash;
- HEX hash;
- BIN hash;
- CCFG decode;
- NVS layout;
- capacity evidence;
- build timestamp UTC;
- build ID.

Suggested IDs:

```
T830-KCTRL-R0
T832-KCTRL-R0
T832-KDIAG-D0
```

No image is flashed if it cannot be mapped back to one commit and one manifest.

---

# 10. Patch-porting method

Never apply an old giant patch with fuzz.

For each upstream SDK:

1. start from pristine TI source;
2. extract the relevant Koenkk hunk semantically;
3. port the change to the target source version;
4. record original and resulting hunk hashes;
5. classify the change;
6. compile;
7. diff generated source;
8. review the final source, not just patch success.

A patch that applies cleanly can still be semantically wrong after SDK changes.

---

# 11. 8.30 vs 8.32 control invariants

The following must be identical between T830-KCTRL and T832-KCTRL unless the SDK API forces an adaptation:

- network capacities;
- routing/MTO parameters;
- MAC/AF buffers;
- NPI logical state machine;
- UART baud;
- flow control;
- MR4U DIO mapping;
- RF frontend configuration;
- TX power;
- CCFG recovery behavior;
- NVS logical allocation policy;
- ZNP feature flags;
- compiler optimization policy;
- diagnostics: none.

Any forced SDK-specific change is recorded in a dedicated **SDK_DELTA** manifest.

This file becomes the entire interpretation surface for T830 -> T832.

---

# 12. SMLIGHT 20260311 comparator

SMLIGHT publicly describes 20260311 as SDK 8.32.00.07 plus low-level changes including:

- removal of a UART abstraction layer;
- P7/P10 RX/TX ring-buffer changes;
- NPI task-stack optimization;
- DMA/UART priority tuning;
- FIFO-threshold tuning;
- custom reset handler / reboot-reason tracking.

These changes must **not** be copied into T832-KCTRL.

That is the point of T832-KCTRL.

If T832-KCTRL is stable and SMLIGHT 20260311 hangs under equivalent exposure, the strongest remaining difference is SMLIGHT downstream integration.

---

# 13. Decision matrix

| V24 | T830-KCTRL | T832-KCTRL | SMLIGHT 20260311 | Interpretation |
|---|---|---|---|---|
| stable | stable | stable | hangs | strongest evidence for SMLIGHT downstream integration |
| stable | stable | hangs | hangs | TI Core SDK 8.32 / SDK-specific interaction becomes primary |
| stable | hangs | hangs | hangs | common TI/Koenkk coordinator path or production workload |
| hangs | stable | stable | hangs | vendor integrations differ; 7.41 black-box and 20260311 both suspect |
| hangs | hangs | stable | hangs | unusual SDK-boundary result; inspect 7.41/8.30 common behavior |
| stable | stable | stable | stable | exposure mismatch; extend soak before conclusion |

Do not interpret one short run as proof.

---

# 14. Diagnostic architecture

## 14.1 NPI/UART2 first

Capture:

- RX callback count;
- write callback count;
- TX_FINISHED event count;
- TX_BEGIN event count;
- last event;
- TxActive state;
- RxActive state;
- ISR/ring-buffer fill high-water;
- UART error flags;
- DMA active/status;
- last MT command received;
- last SRSP completed;
- age since last successful TX_FINISHED.

Most important failure discriminator:

> Does the ZNP application stop, or does only the NPI UART path stop completing?

---

## 14.2 NVOCMP second

Capture:

- compaction start count;
- compaction success count;
- compaction failure count;
- recovery path count;
- active page;
- page usage/free bytes where available;
- last NV operation class;
- time since last compaction.

Do not continuously write diagnostic data to NVS.

---

## 14.3 memory/task evidence

Capture:

- free OSAL heap;
- minimum free heap;
- allocation failures;
- largest free block if cheap;
- NPI task stack high-water;
- Z-Stack task stack high-water;
- system/HWI stack high-water;
- pending message queue depth.

---

## 14.4 network-resource evidence

Capture:

- AF pending sends;
- AF failures by status;
- MAC buffer failures;
- ZDO pending management requests;
- route table usage;
- source-route usage;
- route-request usage;
- MTO request rate;
- route-record rate;
- broadcast rate.

These correlate production load with the internal failure path.

---

# 15. Fault breadcrumb

The terminal state cannot service MT commands, so live polling alone is insufficient.

Keep a small crash breadcrumb outside normal periodic NVS writes:

```
magic
schema
boot_count
reset_reason
uptime
fault_class
last_mt_cmd
last_mt_complete
last_uart_event
tx_active
heap_free
heap_min
alloc_fail
nv_compact_count
nv_compact_fail
af_pending
last_event_ring[16]
pc/lr/sp if exception
crc
```

Preferred order:

1. noinit / retained RAM if suitable;
2. fault-only flash/NVS write;
3. debugger extraction in bench runs.

---

# 16. Watchdog policy

Do not enable an automatic watchdog in the first diagnostic build.

A watchdog would improve availability while destroying root-cause evidence.

Sequence:

1. reproduce and capture;
2. classify;
3. implement a targeted fix;
4. then consider watchdog as secondary containment.

---

# 17. Reset-domain evidence

At every future F3/F4:

- R0: restart/reopen host software;
- R1: one bounded ZNP `SYS_RESET_REQ`;
- R2: SLZB-OS hardware radio reset;
- R3: full P10/MR4U power removal if R2 fails;
- R4: same-image reflash only after evidence capture;
- R5: erase/reflash/restore only as last resort.

Record the first recovery level that succeeds.

This is part of the diagnosis.

---

# 18. Acceptance sequence for custom firmware

## Offline

- build manifest complete;
- static image audit;
- CCFG audit;
- NVS overlap audit;
- capacity proof;
- patch classification complete;
- rollback image present;
- fresh backup present.

## Isolated radio

- 20/20 SYS_PING;
- 20/20 SYS_VERSION;
- controlled reset;
- hardware radio reset;
- cold boot;
- BSL recovery;
- disposable Zigbee smoke.

## Production restore

- exact identity;
- security count;
- channel;
- restore without formation;
- representative traffic;
- no F1 during settle.

## Soak

- 24h normal;
- >=72h or >=3x known failure interval;
- 7d final confidence for a candidate intended for production.

---

# 19. Preferred implementation order

1. Complete V24 black-box A/B.
2. Build T830-LAB.
3. Build T830-KCTRL.
4. Bench qualify.
5. Production soak T830-KCTRL.
6. Build T832-KCTRL from the **same control manifest**.
7. Bench qualify.
8. Production soak T832-KCTRL.
9. Only after a failing boundary is identified, build the matching diagnostic variant.
10. Only after a mechanism is classified, create a fix branch.

Do not build all variants before the first control result; later work should remain evidence-driven.

---

# 20. Branch discipline

Suggested branches:

```
exp/mr4u-p10-ti830-lab-r0
exp/mr4u-p10-ti830-kctrl-r0
exp/mr4u-p10-ti832-kctrl-r0
exp/mr4u-p10-ti832-kdiag-d0
fix/mr4u-p10-<proven-mechanism>
```

No diagnostic or fix changes are merged into the control branch.

---

# 21. Bottom line

The preferred alternative-firmware path is **not**:

```
SMLIGHT fails -> build random TI firmware -> hope
```

It is:

```
SMLIGHT 20240716 black-box baseline
        |
        v
TI 8.30 + reviewed coordinator control
        |
        v
TI 8.32 + identical coordinator control
        |
        v
compare with SMLIGHT 20260311
        |
        v
instrument only the failing boundary
        |
        v
targeted fix
```

That sequence maximizes information from every production flash and minimizes the chance of “fixing” the symptom while losing the root cause.


---

# 22. Escape from Z-Stack entirely

The T830/T832 control path is the best near-term engineering route because it preserves the current network and gives us source-level control, but it still runs Z-Stack.

A separate long-term track should therefore exist for **changing the Zigbee stack itself**.

## 22.1 TI F3 / ZBOSS

TI's newer SimpleLink Low Power F3 Zigbee solution uses ZBOSS on CC23xx / CC27xx. TI has publicly confirmed that the older F2 family remains Z-Stack-based.

This is the cleanest future TI-family escape from the F2/Z-Stack architecture.

Current blockers for this production network:

- CC2674P10 itself is an F2/Z-Stack target, not an F3/ZBOSS target;
- Zigbee2MQTT currently marks ZBOSS adapter support experimental;
- documented ZBOSS adapter support currently focuses on Nordic nRF52 and ESP32-C6/H2 NCP firmware;
- Zigbee2MQTT currently lacks ZBOSS coordinator backup/restore support;
- documented missing functions include install-code support, Inter-PAN and channel changes without re-pairing.

Therefore do not treat ZBOSS as an immediate migration target for the existing ~100-device production network.

### Re-evaluation gate

Re-open this track when all are true:

- production-supported ZBOSS coordinator hardware/firmware exists with sufficient large-network capacity;
- Zigbee2MQTT ZBOSS adapter is no longer experimental for our required features;
- coordinator backup/restore is supported;
- security/network identity migration can be tested without mass re-pairing;
- large-network routing/neighbor behavior can be demonstrated under a topology comparable to ours.

At that point perform a second-network soak before production migration.

## 22.2 Raw IEEE 802.15.4 coprocessor + host Zigbee stack

The CC2674P10 radio hardware supports IEEE 802.15.4, so a theoretically cleaner architecture is:

```
P10: RF + MAC / thin RCP
Host: NWK + APS + ZDO + Trust Center + routing + coordinator state
```

This removes embedded Z-Stack/ZNP from the P10.

Advantages:

- host-side memory and observability;
- no opaque embedded Zigbee routing/resource tables;
- state can be persisted and inspected on the host;
- coordinator crashes become ordinary host-process failures rather than radio-NVM failures;
- easier instrumentation and recovery.

But this is not a firmware tweak. It is effectively a new coordinator stack.

Required work includes:

- raw 802.15.4/RCP protocol;
- herdsman adapter;
- Zigbee PRO NWK implementation/integration;
- APS;
- ZDO;
- Trust Center/security;
- source routing;
- commissioning;
- Green Power;
- inter-PAN;
- backup/restore;
- compatibility testing.

TI 15.4-Stack does not replace these Zigbee layers.

Treat this only as a research architecture unless an existing portable host Zigbee stack can be integrated cleanly.

## 22.3 Decision

Near term:

```
20240716 baseline
-> T830-KCTRL
-> T832-KCTRL
-> diagnose/fix
```

Medium/long term:

```
monitor F3/ZBOSS maturity
-> lab second network
-> migration only after backup/security support is production-grade
```

Research-only maximum-control path:

```
raw 802.15.4 RCP
-> host-side Zigbee coordinator stack
```

Do not mix the non-Z-Stack research track into the current production recovery experiments.


---

# 22. Escape path: move Zigbee stack off the radio

The long-term strategy must not assume that the coordinator must remain a full on-radio Zigbee stack.

The most important alternative discovered during research is **Zigbee-on-Host (ZOH)**.

Architecture:

```
Zigbee2MQTT / host
  -> Zigbee NWK + APS + Trust Center + routing/state
  -> Spinel STREAM_RAW
  -> OpenThread RCP firmware
  -> 802.15.4 radio
```

This removes the ZNP/Z-Stack coordinator application from the radio entirely.

## 22.1 Why this directly addresses issue #73

The observed failure terminates in ZNP command starvation:

```
AF -> ZDO -> SYS -> no SYS_PING
```

ZOH has no ZNP command processor and no Zigbee NVOCMP application state on the radio.

The radio performs only the low-level RCP/802.15.4 role while the large and inspectable Zigbee state lives on the host.

This is therefore the strongest architectural test of whether the failure is caused by:

- TI radio/MAC hardware/driver itself; or
- the Z-Stack/ZNP coordinator application layered on it.

## 22.2 Immediate lab hardware: SLZB-06P7

Koenkk's public OpenThread-TI RCP firmware explicitly supports:

- SMLIGHT SLZB-06P7;
- SMLIGHT SLZB-07P7;
- other P7-class TI adapters.

We already own/use the SLZB-06P7 as historical hardware.

Therefore the first ZOH experiment should use the 06P7 rather than modifying the production MR4U/P10.

Planned lab sequence:

1. flash the supported OpenThread RCP image to the isolated 06P7;
2. run Zigbee2MQTT with `adapter: zoh`;
3. form a disposable network;
4. add representative routers/end devices;
5. test groups, management traffic and high-router-count behavior;
6. inspect host-side persistence and failure recovery;
7. stress the host stack without any production-network risk.

## 22.3 Current ZOH maturity

ZOH remains experimental.

Current project status states:

- high CI coverage;
- stress testing pending;
- TI firmware stability testing ongoing;
- live-network usage pending;
- breaking changes still possible.

Current zigbee-herdsman reports:

```
ZoHAdapter.supportsBackup() == false
```

but the adapter also explicitly says the stack handles persistence internally.

ZOH already persists host-side network state, frame counters and application link keys and has tests for restart/save/load behavior.

Therefore the missing production migration feature is best framed as:

> implement and review an Open Coordinator Backup importer/exporter for the ZOH host-side context

rather than “invent backup for the radio”.

This is a potentially smaller task than maintaining a custom Zigbee coordinator firmware.

## 22.4 CC2674P10 RCP status

Koenkk's public OpenThread-TI RCP firmware currently does **not** support CC2674P10.

Issue #9 was answered explicitly by the maintainer: P10 is not supported.

Therefore:

- do not plan to flash a public ZOH RCP image onto MR4U/P10;
- use 06P7 for the first ZOH lab;
- treat a P10 RCP build/port as a separate engineering task only after ZOH itself proves useful.

A P10 RCP port would still have a much smaller responsibility surface than a full Z-Stack coordinator image.

## 22.5 Alternative non-Z-Stack production candidates

### deCONZ / ConBee III

Current Zigbee2MQTT documentation still lists deCONZ among recommended adapter families.

Current zigbee-herdsman code now includes:

- `supportsBackup() == true`;
- Open Coordinator Backup parsing;
- restore-state handling.

However current deCONZ backup export still has:

```
devices: []
```

so full per-device link-key migration from our Z-Stack backup is not yet proven.

Use only after a sacrificial cross-stack restore test.

### ZBOSS

Available experimentally on Nordic and ESP32-C6/H2 platforms.

Current blockers:

- experimental status;
- `supportsBackup() == false`;
- incomplete feature support including install codes, channel migration and Inter-PAN.

Not the preferred immediate production escape.

### NXP / ZiGate

Historically unmaintained in Zigbee2MQTT, but 2026 development has resumed with experimental Open Coordinator Backup support built on newer openlumi ZiGate firmware.

Track, but do not choose as the next production target.

## 22.6 Two-track strategy

The coordinator program is now intentionally split:

### Track A — current P10 stabilization

```
SMLIGHT 20240716
-> T830-KCTRL
-> T832-KCTRL
-> diagnostic build
```

### Track B — architecture escape

```
SLZB-06P7
-> OpenThread RCP
-> Zigbee-on-Host
-> OCB importer
-> large-network stress
-> production decision
```

Track B should begin as a lab project even if Track A appears stable, because it tests the entire architectural assumption behind on-radio Zigbee coordinator stacks.
