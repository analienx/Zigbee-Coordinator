# SLZB-06P7 — M1 falsification-first ledger (2026-10-13)

**Base:** `d9fa8fde` (PR #61 head, PR #62 merged). **Qualification:** offline source/hosted-CI only; FLASH/ERASE/RESET/MIGRATION NOT AUTHORIZED. No `p7_implemented`/`p7_tested` flag is flipped by this document — flags in `firmware/slzb-06p7/ti832/phase0/feature-parity.json` stay `false` unless source **and** hosted-CI evidence at an exact SHA warrant it, which this slice does not claim for any G0 item.

## Evidence classes

- **S** = source inspected in this repo at the base SHA (pointer given).
- **H** = hosted-CI evidence exists (workflow/run at exact SHA).
- **R** = runtime/on-device evidence. **None exists for P7; every R cell is FAIL (absent).**
- Verdicts: PASS = claim proven at that class; PARTIAL = source only; FAIL = falsified or absent.

## G0 — 36 items (F01–F17, D01–D19)

All 36: `source_audited=true`, `p7_implemented=false`, `p7_tested=false` (`feature-parity.json` features array). Source class **PARTIAL** for every row: the P10 reference source was audited, no P7 implementation exists. Runtime class **FAIL (absent)** for every row. Pointers: F01–F17 and D01–D19 entries in `feature-parity.json`; explanatory audit in `firmware/slzb-06p7/ti832/phase0/README.md`; validator `validate_inventory.py --selftest` (11 negative mutations) is the only hosted gate (`.github/workflows/slzb-06p7-phase0.yml`). Per-item falsifiers remain the `acceptance` strings in the JSON; none may be marked implemented from P10 evidence (e.g. F13's P10 102-byte SYS `0xF0` v2 ABI is explicitly not a proven P7 ABI — see G5 spec, collision UNKNOWN).

## G2 — vanilla CCS baseline

Source **PARTIAL**: `firmware/slzb-06p7/ti832/g2/verify_vanilla.py`, `validate_elf_hex.py` with selftests wired in `.github/workflows/slzb-06p7-g2-vanilla-ccs.yml` (native CCS 12.8 job gated by `g3/ci_delta_gate.py`). Runtime **FAIL (absent)**: LaunchPad-target build evidence, even when green, is not SMLIGHT CC2652P7 board evidence (H1–H7 blocked).

## G3 — NV5

Source **PASS (host model)**: pinned TI `nvocmp.c`+`crc.c` compiled unmodified at `NVPAGES=5` (`tests/p7-nv5-host/`, `.github/workflows/slzb-06p7-g3-nv5-host.yml`), geometry `0xA4000/0xA000`, CCFG sector unmoved (`g3/nv5_layout.py:check_safety`). Host stress/fault verdicts are POSIX-simulation only: `simulator_hardware_accurate=false`, real power-cut and security-counter qualification **FAIL (absent)**. Runtime **FAIL**. The ten PR #62 falsification repairs are recorded in `docs/SLZB_06P7_G4_CAP192_SLICE1_2026-10-12.md`.

## G4 — CAP192 / PR #62

Source **PASS (compile-time only)**: `g4/cap192_capacity.py` fail-closed single-anchor overlay (TC 192 / NWK 96 / RTG 128 / RREQ 16); hosted CCS audit requires the generated `ti_zstack_config.h` macros. Runtime occupancy, heap headroom, 192-key NV persistence, route reliability: **FAIL (absent)**, `runtime_qualified=false` in the candidate manifest.

## G5 — crash diagnostics (this slice)

Source: bounded in-RAM recorder + decoder + negative classifier (`firmware/slzb-06p7/ti832/g5/`), host tests in `tests/p7-crashdiag-host/`. MT endpoint: candidate `0xF0`, collision **UNKNOWN**, endpoint **disabled**. Runtime: **FAIL (absent)** — no CCS wiring, no board, no retained-RAM-across-reset claim. UART-accepted ≠ host-received and 40 s host timeout ≠ crash are encoded as classifier rules, not prose.

## Blocked gates (unchanged)

H1–H7 physical evidence, NV migration/security-counter recovery, torn-erase geometry beyond the prefix model, and any flash/erase/reset action.
