# R12 ADR — firmware-only startup forensics using reset-retained AUX RAM

**Status:** A0 HOST PROTOTYPE IMPLEMENTED AND TESTED — **NOT A FIRMWARE IMAGE; NOT FLASHABLE; LIVE AUX OWNERSHIP/RESET RETENTION UNPROVEN**
**Date:** 2026-10-09 · **Owner:** Zigbee-Coordinator R12 candidate · **Incident:** [home-assistant-stack #73](https://github.com/analienx/home-assistant-stack/issues/73)  
**Baseline:** shipped R11-DIAG `156fe563ba5e6eb3d15c56b21ec9aabfda882096`, revision `8320052`, binary SHA-256 `13d69fb126b0cad0e5f362d01b8fcb4d78d7a417c75eb36d6dbbaa38266ed36e`.

## Decision in one paragraph

**Do not pursue an external SWD probe.** The operator has no usable debugger. R11 already records 8 startup boundaries in *ordinary CPU SRAM* but exports the record through its **periodic MT task**. The startup command itself enters BDB **synchronously on that same MT task**, and the two real R11 failures ended with no post-start received bytes. Therefore polling the existing exporter faster, or asking for a debugger, is not an adequate primary next test. The most promising **unproven** hardware-free solution is to write a compact, non-sensitive checkpoint into the CC2674P10's existing **4 KB AUX/Sensor Controller RAM**, which TI says is *not zeroed between system resets*. Following an **SLZB radio-only reset that retains AUX RAM**, the recovered firmware could export that checkpoint through normal ZNP before another startup. No persistent Zigbee NV changes would be needed **by the observer**. The critical qualification is that the actual MR4U reset pin, AUX power/clock domain and firmware ownership must demonstrably satisfy the retention assumption.

## Direct evidence: two guarded R11 startup failures

| Evidence | Prior run (after genuine cold power) | New operator-requested run (after SLZB radio reset) |
|---|---|---|
| Proven radio image | R11 8320052 | Same R11 8320052 |
| Preflight | Original identity/key, 103 keys + 103 address rows, security/counter floors, state 0 | Same facts freshly read; `startup_option=00`, `bdb_on_network=01`, network counter 350300652 at floor |
| Issued operation | One `ZDO.startupFromApp(100)` | **One** `ZDO.startupFromApp(100)` |
| Request timestamp (UTC) | 20:05:53.589 | 21:03:35.365 |
| Last valid ZNP response | Immediately before startup | `osalNvReadExt` 21:03:35.364 |
| Response to startup | Timeout at 20:06:33.591 | Timeout at 21:04:15.369 |
| After request | Zero received ZNP frames; passive follow-up zero | Zero received ZNP frames; subsequent SYS probe zero |
| Later network acceptance | **No** | **No** |
| Final network status | Terminal SYS hang | Terminal SYS hang, 0/3 ping and 0 version |

The second run's original raw metadata remains **private**:
`C:\Workspace\.analienx\sonoff-private\recovery\p10-r11-debug-20261009\stages\resume-retained-existing-89c7bf28e182\znp-capture.private.jsonl`,
SHA-256 `afe81f0f763bcbbe01af05506a4a3fe740883cdc0aba53d2d07c968b1a306ffd` (1,058,053 bytes, 8,399 records; 2,802 received frames **before** startup; 0 after).

**R11 STARTUP_V1 kind 52** last observed 21:03:20.655 UTC, about 15 seconds before the request: generation=1, entry mask=1, exit mask=1, last_site=1 (`main.initNV`), phase=exit, status=0, valid=status. This only proves main NV initialization returned on boot. It **does not** prove R11 site2..8 hooks did not execute after `startupFromApp`, because the export path went silent.

The worker's `verification_check=startup_flags` is the **last verification label**, **not** a discovered fatal NV condition; the worker actually failed `phase=resume` after its single mutation command (startup SREQ). No custom NV/flash writes, Zigbee2MQTT start, additional reset or repeat startup were authorized/performed in the second attempt. The sealed previous R11 trial remains blocked; the separate one-shot receipt cannot be replayed.

## Why R11's export path is structurally blind at the most important point

Pinned TI source analysis already exists at `firmware/t832/r6/M0.md`:
- `M0c`, `TI SDK @6499c3f:source/ti/zstack/mt/mt_zdo.c:1862–1889`: `MT_ZdoStartupFromApp` calls `bdb_StartCommissioning(BDB_COMMISSIONING_MODE_NWK_FORMATION)` **inline on the MT task**, *before* it queues the SRSP. The SREQ payload's `startdelay=100` is **ignored by this handler**. `100` is Herdsman's host convention, not a TI MT-side startup-delay knob.
- `bdb.c:918ff/986–1077`: original `bdbNodeIsOnANetwork` leads to `ZDOInitDevice(0)` via restored-network initialization, possibly into `ZDApp_RestoreNetworkState` / `NLME_RestoreFromNV` **inside this call chain**.
- `apply_diag.py:237–268`: MT startup diagnostics already bracket `bdb_StartCommissioning` with stages 2/3 and SRSP-queue stage 4, but they are **ring/MT-exporter observations**, not a synchronous transport witness.
- `firmware/t832/r6/r11_ext_export.inc`: `T832R11Ext_tryExport` runs from `T832Diag_exportPoll` via normal MT-task scheduling, respecting transport/busy gates and 5-second export cadence. All 7 frames captured in the latest attempt were **pre-start**.

**Interpretation:** SRSP silence may be caused by the MT task not returning from the synchronous BDB/ZDO/NLME path. This is the strongest *execution-path explanation*, not yet identification of the internal blocking function or proof of a CPU fault. UART/NPI driver failure, deadlock, failed NVS read/compaction and stack resource problems remain alternatives. The 103-key readback proves security data availability, **not** semantically valid restored NIB and all internal runtime invariants. Do not generalize this startup failure to the separate long-running AF→ZDO→SYS degradation without new evidence.

## Critical new / confirmed chip capability — AUX RAM (candidate, not proof)

TI CC2674P10 datasheet Rev. B, §8.4 (printed page 49): **system SRAM is zero-initialized on boot**. It separately states that **4 KB Sensor Controller RAM is CPU-accessible and not cleared to zero between system resets**. See the [official TI datasheet](https://www.ti.com/lit/ds/symlink/cc2674p10.pdf). TI's [CC13x4/CC26x4 memory map](https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/latest/exports/docs/dmm/dmm_user_guide/html/memory/memory_map.html) places AUX RAM at **`0x400E0000`**, capacity **`0x1000`** bytes. This aligns with pinned SDK `hw_memmap.h:92` in `firmware/t832/r6/M0.md`.

Prior M0 explicitly identified this possibility but labeled it **UNPROVEN**:
`M0.md` §“`.noinit` erasure, SCE SRAM, linker”. The exact R11 linker map has no named AUX/SCE region and no literal `0x400E...` placement, but this is **weak negative evidence** only. Drivers or runtime can access MMIO AUX RAM without a linked section. **ZNP/SysConfig ownership, AUX clocks, debugger and SLZB reset-class retention are not yet demonstrated.**

TI Sensor Controller Studio docs say the System CPU can access AUX peripherals and that the AUX domain has a separate power/clock lifecycle. TI's general AUX-as-RAM guidance warns that back-to-back writes may stall the application CPU if the peripheral bus buffer fills, and recommends a readback after writes. This is a **real perturbation risk**; it is not inherently safe just because the memory is on-chip.

**Reset distinction:** `SLZB-OS > Zigbee restart` visibly resets the P10 and restores ZNP, but we have **not proved** whether that specific pin/reset/voltage sequence preserves AUX contents. The R12 firmware must independently report the reset cause, and the retention test must use the **same** restart path. A complete PoE/USB power loss or chip Shutdown must be treated as **non-retaining**. An invalid/empty record is **inconclusive**, never “startup hook not reached”.

## Proposed R12-A: minimal, independent crash breadcrumb

1. **Ownership and power gate BEFORE compilation:** inspect the *exact* TI SDK 8.32.00.07 ZNP project, generated SysConfig, board/power drivers, and full linked map for any Sensor Controller/AUX RAM consumers, power transitions and reserved windows. Require explicit proof of an unused bounded **fixed-size** 64–128 byte AUX range. Do **not** assume “top 128 bytes free” or place data at an invented address before this check. Confirm the AUX clock/power state when the hooks execute. If ownership cannot be proved, `AUX_CONFLICT_BLOCKED`.
2. **Observer schema (numeric only):** magic+schema, exact firmware build ID, controlled attempt ID, boot epoch, reset cause, last milestone ID/phase, optional status, monotonically increasing sequence, checksummed commit word. No IEEE, device list, NIB bytes, network keys, raw buffers, addresses or PRNG state. Fixed-width, bounded and verifiable. Use **two alternating commit slots**: invalidate intended target, write the payload, CRC, *commit marker last*, read it back to drain the AUX bus; select the newest CRC-valid committed slot after reset. Handle sequence wrap/torn writes explicitly. No mutex, memory allocation, UART I/O, NVOCMP or driver init from critical startup hooks.
3. **Instrument the synchronous call chain, not only periodic MT:** add the minimal events immediately **before and after** `MT_ZdoStartupFromApp` → `bdb_StartCommissioning`; restored-network decision, entry/return `ZDOInitDevice`, `ZDApp_ReadNetworkRestoreState`, `NLME_InitNV`, `NLME_RestoreFromNV`, `ZDApp_SecInit`, `ZDApp_NetworkInit`, and MT SRSP queue/state9 where reachable. Prefer 10–14 distinguished milestones over elaborate queue telemetry. Each hook writes one bounded slot; ordinary R11 MT export stays as secondary context. Avoid altering Zigbee branching or return values.
4. **Boot-before-overwrite reader:** on the **next** firmware boot, validate the retained old record **before** startup hook writes can overwrite it and before any verified AUX consumer initializes. Copy only numeric fields to ordinary SRAM, associate the early reset-source observation, and expose a new **post-reset diagnostic** via the existing MT/DEBUG parser **once ZNP is responsive again**. The restored machine should not attempt another Zigbee startup to deliver the trace. Do not clear the retained record until the host acknowledges a matching build/epoch receipt, and never clear on a failed export.
5. **Collector and evidence:** extend the existing private ZNP capture decoder to recognize a unique R12 retained event (new event/schema ID; no collision with R11 ID51–53) and compare: pre-start R11 boot event, R12 retained boundary, radio reset source, firmware exact ID, CRC, attempt nonce and report timestamps. Store raw privately; publish only sanitized milestone/outcome/digest.
6. **No built-in auto-recovery in first revision:** do **not** start a watchdog auto-reset loop or alter boot/network formation policy; the operator's SLZB **radio-only reset** is the known recovery action if the single sealed test blocks. An automatic reboot could destroy the opportunity to delimit the failure and corrupt one-shot ownership accounting.

### Minimal milestone success criteria

For the **first** R12 candidate, a successful diagnosis requires:
- Retained record survives the **actual SLZB radio-only reset**, not just a simulator/RTOS callback.
- On that next boot, the MT/ZNP path is available **without starting the original Zigbee network**.
- Exported record names an entry/exit boundary strictly later than the boot-time `main.initNV` frame, with valid CRC, build and epoch. A boundary whose **exit is missing** identifies a **suspect synchronous interval**, not necessarily the exact instruction where the CPU is stuck.
- Any exception/fault/RTOS attribution is still speculative unless supported independently by the firmware's error hooks and reset cause.
- Post-reset 103 keys and counters are still intact before anyone treats the coordinator as restored. CI/simulator PASS never qualifies a live network.

### Two stages; explicit stop conditions

**R12-A0 feasibility and reset-survival proof** *(no restored-network startup)*:
- GitHub-hosted source/ownership/CCFG/NVS/hosted-build gates for **one** minimal candidate; distinguish “build passes” from “flash approved”.
- Before **any** firmware deployment: independently audit current original coordinator backup, physical NV geometry, protected 103-key table and counter floors. The radio is currently hung, so a separately authorized **radio-only reset** will be needed for a fresh preflight; no such operation is authorized by this ADR.
- If the candidate is later explicitly approved and flashed, verify image, read-only NV, and first valid AUX marker. Then (only in a separately controlled smoke phase) issue **one** SLZB radio restart *without* `startupFromApp`; verify the retained AUX marker and reset cause are recovered through ZNP. If retention fails, STOP, no original-network startup.
- If startup/boot itself touches another AUX owner, crashes, requires unsafe clock override, or an AUTOCLEAR callback erases the record, abandon AUX and reassess; no speculative writes to household NV.

**R12-A1 single restored-network reproduction** *(only after A0 successful and new user authority)*:
- Fresh exact firmware+Z2M image gates, full key/address/counter validation, Z2M stopped/watchdog off, single operator/incident owner and unique one-shot ledger.
- One `startupFromApp` only. If state9 comes up, verify full original network/security and cautiously enable Z2M with health acceptance. If UART stops, no further ZNP probes that mutate; preserve metadata; issue a separate, operator-controlled **radio-only reset** to retrieve retained R12 trace; *no power-off* before retrieval.
- Failed, malformed, missing, mismatched or ambiguous retained trace is **INCONCLUSIVE**. Never “repair” by erasing NV or re-pairing routers. Freeze repeated startup attempts until hypotheses are revised.

## Evaluated alternatives and what they cannot prove

| Option | Value | Limitation / decision |
|---|---|---|
| Repeat R11 `startupFromApp` after reset | Already independently reproduced twice | **Reject**; same 40 s silence and no new localization |
| Faster R11 MT debug exports | Fine while MT executes | **Insufficient** while inline BDB call prevents MT schedule/return |
| Direct UART sends inside ZStack | Could emit a pre-block breadcrumb | Risks NPI framing/concurrency/critical-section deadlock; cannot guarantee TX completion. Secondary path only after a dedicated transport proof |
| Volatile `.noinit` in main SRAM | Simple linker change | **Not proven to survive** CC2674P10 reset; datasheet says SRAM boot zero-init. Do not assume |
| AUX/SCE 4 KB retained RAM | **Promising on-chip, flash-free post-reset witness** | **First choice for feasibility study**, subject to ownership, clock and actual reset survival |
| Dedicated flash scratch sector / NV writes | Could survive power cycle | New erase/wear/layout risks with 103-key original network. **Not approved** |
| External SWD/JTAG | Direct PC and RAM | **Not available to this operator; not a viable plan** |
| Auto watchdog restart | Can recover CPU from deadlock | Risks losing the failure epoch and repeating startup. **Defer** |

## Unresolved questions / exact work for next agent

- Determine whether the pinned TI ZNP, board configuration, driverlib and power manager ever use SCE RAM or shut down the AUX domain in this binary. “No AUX linker symbol” is not a substitute.
- Confirm permitted CPU writes/reads and memory barriers **on CC2674P10** (not just a CC26x2-era guide), including AUX bus-buffer stall behavior in RTOS task/ISR contexts. Establish a small bounded cycle-cost budget.
- Prove what SLZB OS `Radiomodule reset: CC2674P10` asserts physically and whether reset cause is PIN_RESET; direct `SysCtrlResetSourceGet()` value is needed on real hardware.
- Confirm earliest safe **pre-overwrite** boot read; if the AUX domain is not yet clocked, move only the *reader* to the first safe point while showing no earlier SDK/SCE write can erase the record.
- Design a hosted C test with exact wire payload + two-slot write/interruption, CRC/magic/build/boot mismatches, false older record, wrap, simulated pin-reset vs power-loss and no-secret payload. **Hardware retention remains unproven by this test.**
- Version one new R12 diagnostic event while preserving R11 id51/52/53, build and measure against the **exact** TI 8.32 source, linker and NVS/CCFG. No candidate artifact from this ADR may be flashed.

## References (source authority and provenance)

- `firmware/t832/r6/M0.md` §M0c and §M0d: pinned TI/hardcoded Herdsman source call graph and early AUX feasibility caveats.
- `firmware/t832/r6/r11_startup.h`: actual 8-site 20-byte volatile SRAM POD, no reset retention.
- `firmware/t832/r6/r11_ext_export.inc`: MT-only R11 startup export.
- `firmware/t832/apply_diag.py:237–268`: MT handler in-band instrumentation.
- Official TI CC2674P10 Rev B, §8.4: [datasheet PDF](https://www.ti.com/lit/ds/symlink/cc2674p10.pdf).
- TI CC13x4/CC26x4 [AUX memory map](https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/latest/exports/docs/dmm/dmm_user_guide/html/memory/memory_map.html).
- TI [Sensor Controller Studio / AUX domain overview](https://software-dl.ti.com/lprf/sensor_controller_studio/docs/cc13x0_cc26x0_help/html/sc_intro.html).
- [HA incident #73](https://github.com/analienx/home-assistant-stack/issues/73#issuecomment-6089268857) for private evidence references and immutable R11 trial outcome.

**Operational lock at writing:** P10 last inspected terminally silent after the second startup; Z2M stopped/error, watchdog off; original network not accepted. **No new device mutation authorized or performed by this document.**

## R12-A0 host-only implementation checkpoint (9 October 2026)

**Code exists; target integration and a flashable image do not.** This is an
important distinction: the user authorized moving forward with R12, not
erasing/rebuilding an unprotected Zigbee network.

- `firmware/t832/r12/r12_aux_trace.{h,c}`: standalone **80-byte**,
  two alternating 40-byte AUX-journal slots; eight data words, CRC32, and
  commit magic written last. The writer reads back after each word to drain
  the MMIO bridge. There is **no physical AUX address or target I/O** in
  these files; a caller must provide an independently qualified volatile
  window. No UART, flash, Zigbee NV, heap allocation or automatic reset.
- Each record carries build ID, attempt ID, boot epoch, monotonically
  increasing sequence, numeric site and phase, flags, status/context, CRC32.
  The reader rejects half-circle/duplicate sequence ambiguity and wrong
  build; the writer refuses to replace a record from a different attempt or
  boot epoch before a separate acknowledgment/arming mechanism exists.
  **No re-arm/clear protocol yet exists**, deliberately avoiding silent loss
  of previous-crash evidence.
- `test_r12_aux_trace.c`: real host C executable tests for clean slate,
  sequential commit, preserved PIN_RESET simulation, torn alternate slot,
  corrupted slot, erased power-loss simulation, unknown build,
  cross-epoch/attempt clobber rejection, invalid parameters and wraparound.
  These are software simulations, **not physical proof** of MR4U AUX survival.
- `firmware/t832/r12/r12_source_audit.py`: source inspector pinned to TI
  SDK `6499c3f...` and project seed `87ff5b6...`. A full local
  sparse checkout of those exact commits was analyzed. **ZNP source and
  ZNP SysConfig contain zero direct AUX-RAM usage references.** The
  `PowerCC26X2` subsystem does manage AUX resources, so the audit
  deliberately reports `AUX_OWNERSHIP_AND_RESET_UNPROVEN`.
  No named AUX-RAM linker section in exact R11 MAP is **not proof** of
  runtime exclusivity, clock availability or reset survival.
- `test_r12_source_audit.py` includes negative cases: inserted ZNP AUX
  reference is detected; wrong memory base/missing Power module/bad source
  checkout are rejected; empty references never turn into GO automatically.
- `.github/workflows/t832-r12-aux-a0.yml` compiles the C recorder with
  `-Wall -Wextra -Werror -Wconversion -pedantic`, runs host regressions,
  tests source-gate behavior, and performs an independently hosted pinned
  TI source audit. It intentionally expects **blocked hardware status** and
  does **not** publish any target firmware, flash script, or authorization.

**Remaining implementation gap:** qualify exact SCE/AUX SRAM ownership and
power transitions in the linked P10 image; establish a reserved 80-byte
window and earliest safe post-reset reader. Only then wire firmware startup
hooks and boot-time MT export, produce a distinct R12-A0 image, and validate
its signed/hash-pinned build. First hardware step after backup would be a
**reset-retention A0 smoke with no original-network startup**, not another
blind R11 replay. Distinguish original 103 security key/address/counter
checks from the independent diagnostic persistence check.

**No flash, reset, network startup, NV modification or Zigbee2MQTT start was
performed by the A0 implementation.** The installed radio remains on the
last observed R11 diagnostic image and still unresponsive since the final
operator-requested startup failure.
