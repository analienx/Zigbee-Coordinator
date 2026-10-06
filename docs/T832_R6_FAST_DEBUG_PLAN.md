# T832 R6 fast debug firmware plan

## Goal

Produce a **working CC2674P10 diagnostic firmware** as quickly as possible after the R5 NV write failure. This plan deliberately avoids long soak periods as a release gate. The immediate objective is:

1. boot the existing household coordinator state;
2. preserve normal NV read/write/compact behavior;
3. retain the R5 hang diagnostics;
4. flash once after deterministic bench/CI proof;
5. immediately exercise the live network and reproduce the original AF -> ZDO -> SYS degradation if possible.

The current production coordinator stays on the vendor 20240716 image until the R6 image passes the deterministic gates below.

## Root cause found in R5

R5 combined:

- fixed CC2674P10 NVOCMP storage: **5 x 2 KiB = 10,240 bytes**;
- `ZDSECMGR_TC_DEVICE_MAX=400`;
- TI startup code that iterates every Trust Center slot and calls
  `osal_nv_item_init_ex(ZCD_NV_EX_TCLK_TABLE, i, sizeof(APSME_TCLinkKeyNVEntry_t), ...)`.

In SDK 8.32, `APSME_TCLinkKeyNVEntry_t` is 20 bytes. NVOCMP adds a 7-byte item header. Therefore 400 pre-initialized TCLK slots require at least:

```
400 * (20 + 7) = 10,800 bytes
```

That exceeds the **entire** 10,240-byte NV region before NIB, network keys,
commissioning state, counters, address/security items and other NV are counted.

TI's NV wrapper compounds the failure: `osal_nv_item_init_ex()` only maps an
exact `NVINTF_FAILURE` result to `NV_OPER_FAILED`; an out-of-space
`NVINTF_BADLENGTH` result from NVOCMP can therefore be reported upward as if
the item had been initialized. R5 can consequently boot far enough to report
`NVOCMP_NORMAL_RESUME` while later writes fail.

This explains the observed discriminator:

- reads work;
- legacy write -> `NV_OPER_FAILED`;
- direct NVINTF write -> `NVINTF_BADLENGTH`;
- same write succeeds immediately after rollback to vendor 20240716.

## R6 design

### 1. Preserve the existing P10 NV geometry

R6 keeps:

- `NVOCMP_NVPAGES=5`;
- internal NVS base `0xFD800`;
- region size `0x2800`.

Do **not** make the earlier experimental 16-page / 32-KiB change the default.
Moving the base to `0xF8000` changes page numbering and creates a migration
problem for the existing vendor 5-page state. That is unnecessary for a debug
build whose purpose is to observe the original runtime fault.

A 32-KiB variant remains a fallback only if a real fixture proves the 5-page
layout cannot support the current restored network with a sane Trust Center
capacity.

### 2. Bound Trust Center capacity for the diagnostic build

Set `ZDSECMGR_TC_DEVICE_MAX=112`.

Current backup evidence was rechecked live and contains exactly 103 link keys across 104 devices, so 112 adds only nine spare persistent slots while preventing the boot-time table initialization from consuming
the entire NV region.

Minimum TCLK allocation at 112 slots:

```
112 * 27 = 3,024 bytes
```

That leaves 7,216 gross bytes for the rest of NV before compaction overhead.

This is a **diagnostic-build limit**, not a claim that 112 is the ideal final
production capacity.

### 3. Add NV capacity telemetry

R6 records:

- after NVOCMP init: free NV bytes plus packed `actPage/tailPage`;
- on the actual out-of-space allocation path: the same topology as a critical
  NV fault.

The diagnostics remain RAM/UART-only and do not persist telemetry into NV.

### 4. Deterministic release gates only

R6 is ready for the next controlled hardware upload when all of these pass:

- manifest/build contract;
- real linked image and map;
- 5-page `FLASH_NV` geometry;
- no application/CCFG/NV overlap;
- TCLK capacity regression test;
- NV telemetry hooks linked;
- host diagnostic harness;
- exact build identity/decoder compatibility;
- **NV fixture lifecycle**:
  - boot an existing-network fixture;
  - read an existing item;
  - update an existing item;
  - create a new item;
  - force/trigger compaction;
  - reboot;
  - verify all expected items persist;
  - verify non-zero write headroom remains.

No 72-hour soak is required before the next diagnostic flash.

## Hardware loop after deterministic proof

1. take one fresh backup immediately before upload;
2. stop Z2M and obtain sole P10 ownership;
3. upload the exact R6 image once;
4. verify R6 identity and SYS ping/version;
5. immediately verify NV:
   - existing read;
   - neutral update;
   - new temporary diagnostic item if the MT surface permits it;
   - free-space telemetry remains sane;
6. start the original network;
7. verify real AF/ZDO/SYS and device traffic;
8. begin active reproduction/stress of the original coordinator hang.

If R6 writes fail, stop and use the emitted page/free-space evidence to fix the
NV path offline. Do not wait.

If R6 writes work but the original hang disappears, treat that as an A/B result
because KCTRL still changes UART completion/NV recovery/capacity behavior.

If the original hang reproduces, capture the R5/R6 diagnostic pipeline evidence
immediately and move to the narrowest identified subsystem.

## Follow-up causality matrix

Only after R6 is a functioning debug firmware:

- compare TI 7.41/vendor-era behavior with 8.30/8.32 where useful;
- specifically isolate the TI UART2 7.41 -> 8.30 changes from the custom
  `UART2_EVENT_TX_FINISHED` completion semantics;
- use T830/T832 as targeted A/B builds, not as mandatory long-running release
  stages.

## Current branch

`fix/t832-r6-nv-capacity`

The branch intentionally prioritizes a working diagnostic image over broad
production hardening.
