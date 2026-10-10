# T832-R12 DIAG — implementation and independent code-review findings

**Scope:** CC2674P10 / SMLIGHT MR4U, pinned TI SDK 8.32.00.07
`6499c3f53fc5fb5806213be695450a7b43fbaf3d`; ZNP seed
`87ff5b638b632050228a7504f35cf3b95581c278`. Existing R11 security,
NVS layout and USB/UART policies are **immutable** as the baseline.

**Reviewed path:** standalone R12 two-slot retained recorder → previous-boot
reader → post-R11 exact-source patch → R11 MT exporter kind 54 → strict host
parser → native toolchain and no-flash packaging. Check review claims against
the actual source diff and CI artifacts, not this narrative alone.

## Fixed during R12 code review

| Severity | Problem | Correction / independent negative evidence |
|---|---|---|
| High | First R12 boot could see arbitrary, nonzero AUX bytes left by an earlier image, never arm and therefore record nothing | Add `R12Aux_initializeVirgin`: format 80 bytes only when no R12 magic in **either** slot; refuse erasing intact/damaged records; host C tests populate garbage, valid and CRC-corrupted old slots |
| High | Boot-to-boot output could be overwritten by new events before export | `T832R12_boot` reads into ordinary RAM before site1; a valid prior record disables all subsequent AUX writes; cross-attempt/epoch write refusal; live export repeats only after MT accepts |
| Medium | R12 kind54 group omitted successful vs failed `NLME_RestoreFromNV` | Retain *bounded* (0/1) NLME result in high byte of part3, with lower byte the new boot's reset source; parser tests accept 0/1 and reject foreign context |
| Medium | A seemingly valid CRC could contain impossible site/phase | R12 validation checks nonzero site and phase 0..2 before treating slot as evidence; new CRC-valid-but-semantic-invalid test |
| High | R11 MT-dependent exporter cannot emit while synchronous startup is blocked | R12 markers go to retained AUX candidate during inline MT→BDB and deeper restored-network calls; an independently controlled **radio-only** reset is needed to read them, and normal MT export then reports old record |
| High | New series could accidentally lose 103-key, counter, CCFG or NVS geometry safety gates | R12 target CI first runs exact R11 operation-aware, NV-lab and vendor-layout audits, then adds R12 diagnostic hooks. CI hashes `nvocmp.c`, `znp_cnf.opts`, and the linker command before/after R12 source patch. R12 packager reuses audited R11 gate and produces separate explicitly **flash_authorized=false** manifest |
| Medium | R12 frame could be interpreted as an R11 event or corrupted mixed frame accepted | Distinct kind 54, version/part/count/identity/phase/reset validation and 10 Python negative tests; legacy 51–53 parsing retained |

## Exact on-device source changes (R12 atop R11)

- `r12_integrate.py` asserts exact SDK anchors. Four synchronized copies of
  `r11_startup.h` gain `r12_target.h` and bridge `T832R11_enter/exit/confirm`
  to bounded AUX checkpoints (sites 1..8).
- `main.c` invokes `T832R12_boot` after `Board_initGeneral` and before
  actual `main.initNV` (thus before site1). It records reset-source metadata
  from the existing CC26x4 register, not from an invented host clock.
- `zd_app.c` instruments the direct `NLME_RestoreFromNV` invocation (site9)
  without changing the function's return, Zigbee status branches or restore
  policy. `mt_zdo.c` instruments the original synchronous
  `bdb_StartCommissioning()` (site10), surrounding the existing function.
- `r11_ext_export.inc` adds a priority *post-reset* kind54 group via the
  already bounded `T832R11_sendGroup` mechanism (one 4-record group per
  opportunity, repeated no sooner than 60s on accepted send). It never
  circumvents MT transport or in-flight command gates.
- Firmware revision changes **8320052 → 8320062**. Host-pinned firmware build
  ID is still sourced from the actual immutable Git commit; product identity
  and recovery CCFG controls remain the R11 baseline.

## Findings that REMAIN BLOCKING for live flash / original network acceptance

1. **AUX physical ownership and clocks — not proven.** The literal window
   `0x400E0FB0..0x400E0FFF` (80 bytes, top of 4 KB) is a **candidate,
   not an approved allocation**. Pinned ZNP/SysConfig contains no direct AUX
   RAM consumers, but TI power/ROM/driver/Sensor Controller ownership cannot
   be ruled out by source text or a linker map without qualification. An
   inaccessible AUX clock at `Board_initGeneral`/startup time could crash
   the CPU; building successfully cannot exclude this. Hardware access
   therefore remains prohibited.
2. **SLZB radio-only reset retention — not proven.** TI documents Sensor
   Controller RAM non-zeroing between certain resets, but we have no live
   marker readback on the actual MR4U P10. Do not equate simulation with a
   reset-retention test or infer a missing entry means code never reached it.
3. **No operator-authorized on-device A0 smoke yet.** Following a verified,
   original cold coordinator backup and independent 103-key/address/counter
   readback, first bench acceptance would exercise R12 reset retention
   **without restored Zigbee network startup**. Only after it passes may a
   separately sealed single A1 startup be considered.
4. **No in-firmware recovery or auto-reset.** Correct by design: R12 is
   instrumentation, **not** the Zigbee hang fix. A radio-only reset after
   a future authorized failed startup would be needed to retrieve its trace.
5. **Security and functional acceptance remain distinct.** Preserved 103
   cryptographic associations in NV do not prove a valid restored NIB or
   operational routing. A successful debug frame alone is never a healthy
   Zigbee network.
6. **Native CI must pass before claiming a built artifact.** A source-level
   patch and hosted C regression are not a TI CCS linker/map/CCFG proof.
   The dedicated build workflow retains the R11 heavy evidence lane and
   emits a clearly non-authorized candidate on success.

## Test and evidence entrypoints

- Pure C host: `firmware/t832/r12/r12_aux_trace.c`,
  `r12_aux_boot.c`, `test_r12_aux_trace.c` (GCC/UBSan GitHub Action).
- Strict parser: `t832_incident.py` + `r12/r12_decode.py`; 10
  adversarial Python tests including exact T832D2 byte layouts.
- Exact source: `r12_integrate.py` run after `r6/apply_r6.py --series R11`.
- Real source/CCFG/NV gates: `.github/workflows/t832-r12-target-build.yml`
  and `r12/r12_package.py`, first seeded with all the R11 lab proof.
- Source-ownership negative gate:
  `.github/workflows/t832-r12-aux-a0.yml`,
  `r12/r12_source_audit.py`. Its correct outcome remains **hardware
  ownership NOT proven**, even if CI reports green.
- Incident/private raw evidence stays in local protected recovery directory;
  publish only hashes and numeric, key-free event metadata.

**Verdict:** TARGET CODE REVIEWED; hardware release **BLOCKED** pending
independent AUX ownership/power/reset survival and network-preserving live A0
acceptance. Build success cannot override this status. No radio mutation was
performed during this review.

## Compiler-bound symbol hardening (additional review)

An exact-anchor source patch dry run initially verified code placement without
compiling the generated R11 header. An independent identifier check exposed
**three incorrect phase identifiers** in the R12 `r11_startup.h` bridge:
`T832_R11_PHASE_ENTRY/EXIT/CONFIRM` were not R11's actual
`T832R11_PHASE_ENTRY/EXIT/CONFIRM`. The bridge was corrected before any
device build was accepted. The new `test_r12_integrate.py` reads the real,
pinned R11 header and asserts all bridge identifiers exist among R11 macros;
it also tests rejection of double patching and changed anchors.

This confirms why **source-injection PASS is not compile PASS**.
The native CCS build still has to verify linkage and correct device behavior.
