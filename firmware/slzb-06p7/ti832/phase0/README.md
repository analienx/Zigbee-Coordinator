# G0 — SLZB-06P7 TI 8.32 firmware parity: frozen source audit

**Status: `G0_SOURCE_FROZEN` — source inventory only.** Audit date: 2026-10-12.
**No P7 firmware code, artifact, board integration, migration, host-side driver or flash was created by G0.**
No private keys, frame counters, live coordinator credentials or raw network backups may enter this public repo.

## Authority and immutable refs

| Authority | Exact source commit | Role |
| --- | --- | --- |
| Repository main before P7 | [`a48fa9de`](https://github.com/analienx/Zigbee-Coordinator/commit/a48fa9deda36a9fc44624fcd142d5fa1533a449a) | New P7 branch base; preserve existing P10 code |
| P10 [PR #60](https://github.com/analienx/Zigbee-Coordinator/pull/60) | [`b273044f`](https://github.com/analienx/Zigbee-Coordinator/commit/b273044f17c88fbde26d9e9b946ab559a1d1b675) | Consolidated CAP192 reference; not production qualified |
| P10 R7 [#43](https://github.com/analienx/Zigbee-Coordinator/pull/43) | `3d8129da` | Vendor NVS geometry correction |
| P10 R8 [#44](https://github.com/analienx/Zigbee-Coordinator/pull/44) | `eb850bf8` | Interrupted-compaction recovery |
| P10 R9 [#45](https://github.com/analienx/Zigbee-Coordinator/pull/45) | `07a24fef` | CRC/duplicate and readback correctness |
| P10 R10 [#46](https://github.com/analienx/Zigbee-Coordinator/pull/46) | `904ef791` | Reject unsafe NV startup |
| P10 R11 [#47](https://github.com/analienx/Zigbee-Coordinator/pull/47) | `156fe563` | Bounded DEBUG telemetry and startup/NV traces |
| P10 R12 [#51](https://github.com/analienx/Zigbee-Coordinator/pull/51) | `94e50916` | Experimental retained startup traces |
| P10 A1 [#52](https://github.com/analienx/Zigbee-Coordinator/pull/52) | `c6dcca59` | Guarded A0-to-A1 transition and kind55 |
| [TI F2 SDK](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk) | `6499c3f53fc5fb5806213be695450a7b43fbaf3d` | Pinned C/RTOS source |
| [TI Z-Stack examples](https://github.com/TexasInstruments/simplelink-zstack-examples) | `87ff5b638b632050228a7504f35cf3b95581c278` | P10 and LP_CC1352P7_4 reference projects |

Exact host/toolchain lock recorded from the PR #60 real-build workflow: **CCS 12.8.0.00012**, **TI ARM Clang 3.2.2.LTS**, **SysConfig 1.21.1.3772**, **XDCTools 3.62.01.16**; pinned **zigbee-herdsman 10.9.1** at commit `0968f979d558874b17396c96b66382d4236bbdcd`. The upstream workflow redirects CCS-bundled SysConfig 1.21.0 to its required 1.21.1 standalone install. These are **P10 source-build authority**, not a proven P7 compiler result.

Source ownership: `feature-parity.json` is the *normative feature ledger*; this page is the explanatory analysis. A reference code SHA is **not** a hash of a firmware binary. Firmware revision `2026101104` identifies the P10 CAP192 source candidate, not any installed P7 firmware.

## Scope and method (Phase 0 G0)

1. Inspect the actual source of P10 `firmware/t832/min/build_min_real.py` and its six imported patch modules; map its strict SDK file allowlist, configs, protocol and NPI failure stages.
2. Reconcile P10 consolidated PR #60 to earlier CAP192 PR #55–59 without importing each draft's changes twice. Inspect the source references and native C fault-test entrypoints; separate tested-source claims from on-device results.
3. Traverse the *other* P10 branch R7→R8→R9→R10→R11→R12→A1; classify inherited NV correctness and telemetry instead of assuming PR #60 contains them.
4. Verify the shared TI source SHA includes an `LP_CC1352P7_4` ZNP example. This is **not** yet a SMLIGHT CC2652P7 board-pin/RF/BSL certification.
5. Freeze one explicit disposition and one acceptance claim for **every F01–F17 and D01–D19**. `P10_ONLY_WITH_ALTERNATIVE` and `RESEARCH_GATE` are unresolved requirements, *not* approval to omit functionality.
6. Lock the hazardous boundaries: no flash or production network changes in source audit; private security recovery material never in repository/CI.
7. Run the read-only G0 manifest validator and negative controls using GitHub Actions; do not conflate CI inventory success with P7 compilation or RF acceptance.

The `F` class denotes 17 CAP192 runtime, transport, storage, observability and build requirements.
The `D` class denotes 19 R7–R12 inherited storage/diagnostic/forensic and tooling requirements.
All 36 have `p7_implemented=false`, `p7_tested=false`, `release_qualified=false`; this is deliberate.

## What the P10 source actually modifies

`build_min_real.py` asserts an **exact 18-file TI SDK delta and 2-file TI examples delta**. These files are independently enumerated in the manifest (`cap192_source_delta`), and the validator rejects an incomplete/different list.

| Domain | Verified TI source edit sites | Requirement IDs |
| --- | --- | --- |
| ZNP option and ABI | `znp_cnf.opts`, `mt_version.c`, `mt_sys.c` | F01, F02, F13 |
| Capacity and network persistence | `nwk_globals.c`, `zd_app.c`, `cc13x4...ticlang.cmd`, P10 `znp.syscfg`, P10 `projectspec` | F03–F07, F16 |
| UART and frame transport | `npi_tl_uart.c/.h`, `npi_config.h`, `npi_tl.c` | F08, F09, F11 |
| Queue ownership and scheduling | `npi_task.c/.h`, `npi_client_mt.c` | F10–F13 |
| AF and RX observability/recovery | `mt_af.c`, `npi_rxbuf.c/.h`, `npi_frame_mt.c`, `npi_frame.h` | F14, F15 |
| Upstream, audit and packaging | `firmware/t832/min/build_min_real.py`, `harden_real.py`, GitHub Actions, native C fault-test scripts | F16, F17 |

CAP192 application geometry from linked P10 evidence: flash 190,260 bytes; linked SRAM usage 80,838 including 32,768-byte OSAL heap; NVS `0xF9800..0x100000` (13 × 2KiB).
Capacity *intent*: TC192 / NWK96 / addresses298 theoretical / route128 / source128 / neighbors64 / RREQ16 / source hops16 / conflict8 / NWK waiting16, scheduled8, confirmed8, total24. **Not physical proof of 192 joined/operational devices.**

P7 stock TI linker (same pinned SDK) is different: flash `0..0xB0000`, app `0..0xAA000`, NV `0xAA000..0xAE000` (two 8KiB sectors), last flash/CCFG sector `0xAE000..0xB0000`, ordinary SRAM `0x24000`. Stock projectspec is `LP_CC1352P7_4` targeting CC1352P7, not an actual SLZB-06P7 production board. Its allocator flags `HEAPMGR_CONFIG=0x80` / `HEAPMGR_SIZE=0x00` are **not** the P10 fixed 32KiB setting. These observations define *Phase 1/3 investigations*, not an approved P7 physical layout.

## Protocol evidence and exact diagnostics contract

CAP192's MT `SYS 0xF0` is a zero-payload SREQ `0x21,0xF0`, answered as SRSP `0x61,0xF0` with **102 data bytes**:
`version=2 (u8), flags (u8, allowed mask 0x07), 25 x uint32 little-endian`.
The 25 counter names **and order** are in `feature-parity.json.host_protocol.mt_sys_f0.counters`, matched to `npi_diag_decode.py`.
Flag bits: priority-SRSP queue; retry-pending; UART transport-busy. RX overflow and AF failure fields are post-first-15 additions. "UART accepted" must never be interpreted as physical UART TX completion or Zigbee delivery.

**Different ABI:** R11/R12 uses `T832D2:` framed DEBUG AREQ (schema 2, 20-byte event records; event kinds 1–53 R11, 54 R12, 55 A1) with a separate decoder and host parse rules. These are not an interchangeable or backward-compatible SYS-F0 v2 extension. P7 runtime must preserve SYS-F0 separately; forensic DEBUG should be enabled only in DIAG, with bounded transport cost.

### Source-native regression targets inherited from P10 PR #60

| Exact existing reference test | Documented bounded checks |
| --- | --- |
| `tests/t832_npi_ownership_faults.py` | 512 allocation/ownership iterations |
| `tests/t832_npi_transport_faults.py` | 256 UART rejected-write/retry/SRSP scheduling iterations |
| `tests/t832_npi_stackmsg_diag_faults.py` | 128 stack-message/queue paths |
| `tests/t832_npi_af_status_faults.py` | 512 AF return/instrumentation cases |
| `tests/t832_npi_rx_overflow_faults.py` | 256 overflow/resync cases |
| `firmware/t832/min/npi_diag_decode.py --selftest` | versioned strict 102-byte decoder |
| `tests/test_t832_nv_sector_plan.py` | negative Intel HEX and NV/CCFG boundary checks |

These are source/mock native tests and strict image audits. Exact-head real CCS build success is reported for the P10 source-changing commit `ddc352e4`, run [38170556655](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38170556655). That evidence is **not** a P7 build, physical P10 RF soak, or a guarantee that the source of a newer downstream commit was compiled if it changes compiler inputs.

## Cross-lineage conflict decisions (frozen for implementation)

| Conflict | Required P7 decision |
| --- | --- |
| CAP192 NVS 13×2KiB vs R11 vendor-profile 15×2KiB vs P7 8KiB sectors | No address/page count copied from either P10 line. Derive P7 NV driver, linker and SysConfig geometry, flash erase operations, effective 192-key capacity and migration. |
| CAP192 NPI overflow recovery vs R11 `NPI_TRAP` diagnostic for fatal overflow | Runtime must not reintroduce the fatal busy trap to collect diagnostics. DIAG may record an overflow but must preserve safe parser recovery, or document alternative if impossible. |
| CAP192 SYS F0 telemetry vs R11/R12 DEBUG exporter | Separate namespace and decoder; benchmark DIAG load, rate-limit fairly, require explicit protocol-capability semantics. |
| R10 startup preservation guard vs CAP192 synchronous NIB-before-state9 | Apply both semantics only after P7 call-path proof; never report commissioned state for missing NIB, and never destructively reformat unknown nonblank NV. |
| R12 fixed 80-byte AUX MMIO `0x400E0FB0..0x400E0FFF` | **Unproven even on P10** and not portable as an address to P7. NO MMIO port. Research owned retained RAM/reset domain or redesign optional trace. |
| R12 A1 event55 is recorder-arm witness vs commissioned-network evidence | Do not conflate them. P7 can implement schema/parser source logic offline; on-device arming requires retained-memory proof and rollback. |
| P10 32KiB OSAL heap vs P7 automatic allocator config | Preserve allocator/recovery behavior, *not literal heap constants*; use actual P7 linked symbols and stress. |
| P10 separate CCFG mapped at 0x50000000 vs P7 last flash sector | P7 image and erase auditor must protect last 8KiB CCFG sector and bootloader; no bank erase. |
| UART TX_DONE on P10 vs unverified P7 UART2 + ESP32 bridge | Prove the exact P7 driver callback and electrical bridge; never retry a previously accepted but unacknowledged frame. |

## Unresolved findings that Phase 0 must not disguise

1. **P10 issue [#53](https://github.com/analienx/Zigbee-Coordinator/issues/53):** NIB and address-manager disappeared after a no-erase SMLIGHT flash transition. Physical erase and logical NV-index failure are *not distinguished*. A green image-boundary audit alone cannot prove preservation.
2. **P10 AF `0x11`** is an observed submission failure, not a diagnosis of the exact APS/NWK queue. Source counters do not solve internal buffer attribution. No unjustified AF/route-buffer capacity increase.
3. **P10 PR #60** is a source candidate without full spare-radio bridge/RF soak; host accepted UART writes do not prove delivery.
4. **P7 CC2652P7 board** details (PCB/PA RF switch/UART/BSL/ESP revisions) were not verified in G0. The TI `LP_CC1352P7_4` is a compiler target baseline only.
5. **P7 192-key NV capacity**, driver max sector count, RAM budget, GPRAM/cache safety and same-layout restore have no test evidence yet.
6. **R12 retained AUX** requires physical ownership/clock/reset proof on any hardware; no direct address transfer.
7. **Local unpublished P10 files/worktrees:** read-only RDC confirmed Zephyrus has `C:\\Workspace\\repos\\Zigbee-Coordinator` (primary HEAD currently `exp/mr4u-p10-ti832-kctrl-r0`) and separate `zigbee-t832-min-v4-m0m2`, `zigbee-t832-r11-diag` and `zigbee-t832-a1-diagnostic` worktree metadata. This establishes local checkout existence, **not** a clean Git working tree or absence of unpublished commits/diffs; shell Git status was blocked by the runner ownership router. A local uncommitted delta is **not** silently treated as the frozen authority.

Also, source reviews uncovered a still-open SRSP allocation failure: when OSAL cannot allocate a response, the present P10 has no allocation-free response fallback. This is a *documented functional limitation*, not a solved feature. All such limitations remain in the parity/hardening backlog.

## G0 release decision and exact handoff

**G0_SOURCE_FROZEN** when all 36 entries are pinned and unique, protocol field order matches, 18+2 touched-source inventory is exact, inherited NV/DIAG branches are accounted for, and ten negative validator mutations are rejected. These are bookkeeping and provenance gates only.

Next stage **G1 P7 BOARD_PROFILE**, followed by **G2 VANILLA_COMPILER_BASELINE**. Required first evidence:
- Read-only vendor firmware/board wiring pin/PA/BSL/config inventory (no flash/reset).
- Pinned vanilla `LP_CC1352P7_4` compiler build; controlled P7-specific board adaptation after actual hardware map.
- P7 8KiB NVS plus last-sector CCFG memory geometry from real generated linker map; no premature capacity/migration.
- Traceability updates to `feature-parity.json`, never marking `p7_implemented=true` based solely on intent or docs.

**G0 never authorizes production or spare flashing**, nor HA/Zigbee2MQTT restarts, network reformation, NV writes, re-pairing, or serial ownership changes. User approval for Phase 1 implementation and later isolated hardware use are separate.

Commands for source-only checking:

```sh
python3 firmware/slzb-06p7/ti832/phase0/validate_inventory.py --selftest
```

Reference development design: `SLZB-06P7_TI832_P10_Feature_Parity_Implementation_Plan_2026-10-12.md` produced during planning (not committed as part of the source ledger).
