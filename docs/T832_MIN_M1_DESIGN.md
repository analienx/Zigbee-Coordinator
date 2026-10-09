# T832-MIN v4 M1 Design — NOT_PRODUCTION_QUALIFIED

Status: M1 candidate definition. Offline only. No flash, no hardware access, no
HA/Z2M changes, no secrets. All build/test evidence comes from GitHub-hosted
Actions at the exact candidate SHA (project lane: `github_actions`).

## 1. Goal

One minimal T832-MIN firmware candidate for the SMLIGHT SLZB-MR4U main Zigbee
TI CC2674P10 radio (Radio 2). The EFR32MG26 (Radio 1) MUST NOT be touched.
M1 defines the candidate; M2 gates it with hosted-only T1–T5 checks. Stop at
OFFLINE_BUILD_READY or BLOCKED. Production qualification is explicitly out of
scope.

## 2. Pinned inputs (`firmware/t832/min/upstream.lock.json`)

- TI SDK 8.32.00.07 @ `6499c3f53fc5fb5806213be695450a7b43fbaf3d`.
- P10 ZNP example @ `87ff5b638b632050228a7504f35cf3b95581c278`.
- Toolchain: XDCTools `3.62.01.15` (prior pipeline used `.16` — deviation
  recorded), CCS `12.8`, TI-Clang `3.2.2`, SysConfig `1.21.1`, TI-RTOS7 M33F.
- Herdsman exact-pin attempt: `zigbee-herdsman 10.9.1`, status
  `ATTEMPTED_UNVERIFIED`. Hosted CI T1 resolves the exact published version
  via npm metadata; mismatch fails the gate. The historical "10.9.1" string
  may name herdsman rather than Z2M — this file does not resolve that
  ambiguity, the gate does.

## 3. Minimal patch classes (one image)

1. **Board static correctness** (`board/mr4u_board_contract.json`): only
   `target_device=CC2674P10` and `uart_transport=115200 USB CDC` are PROVEN
   (isolated-probe evidence, M0 checkpoint). ROM-BSL, HF XOSC, VDDR/RF,
   CCFG delta, PA variant, and the full pin map are HARDWARE_BLOCKED. Unknown
   pins are never filled from Ebyte 20 dBm data or faulty crystal deltas.
2. **Host ABI minimum** (`host_contract.cjs`): ZNP version behavior + MT SYS,
   ZDO, AF, NV/security dispatch entries. MULTICAST_ENABLED stays FALSE per
   Koenkk docs; the Koenkk patch is not imported. `product=0` is handled
   explicitly, never counterfeited.
3. **NV integrity** (`nv_lab.py`, `verify_compiler.py`): genuine
   compiler/linker/SysConfig/backend index0 agreement at base `0xFD800`, no
   app/NVS/CCFG overlap, factory identity + bootloader preserved, no
   destructive NV auto-format/recovery. Known seed conflict (CC2674R10 text,
   compiler-5 vs linker-2 pages) is a TOOLCHAIN-labeled finding, not a silent
   fix. Vendor 15-page `0xF8800/0x7800` geometry is deferred (GEOM15): physical
   extent alone proves nothing.
4. **Groupcast/source APS**: source-correct only where proven; no 13-variant
   family is included.
5. **Provenance** (`patch_min.py`, `diff_contract.py`): deterministic patcher
   from pristine pinned TI source in throwaway hosted staging. Exact anchors
   (each must occur exactly once) or fail closed. NO R10 imports, NO
   `apply_r6.base` call — enforced by the contract test and CI T2. Full diff
   allowlist (3 source files + generated manifest).

## 4. Tooling

| File | Role |
|---|---|
| `patch_min.py` | Deterministic patcher + R10-absence scanner + `--selftest` |
| `diff_contract.py` | Diff allowlist checker |
| `verify_compiler.py` | Toolchain pins + index0 agreement + no-overlap (static) |
| `host_contract.cjs` | MT dispatch table + ABI record + `selftest()` |
| `nv_lab.py` | NV lab: index0, no-overlap, preservation rules |
| `pack.py` | Deterministic pack-manifest assembly (sorted + digested) |

## 5. Hosted-only gates (`.github/workflows/t832-min-ci.yml`)

- T1 Pins & provenance: lock-file pins, toolchain match, Herdsman npm resolve
  attempt, secrets scan.
- T2 Patch determinism & R10-absence: `--selftest` (double-run equality +
  fail-closed anchor check), `--check-r10-absence`, allowlist dump.
- T3 Board contract: PROVEN vs HARDWARE_BLOCKED validation.
- T4 NV + MT: NV lab self-check, compiler verifier, MT dispatch presence via
  node.
- T5 Host contract + pack + unit test: node selftest, pack check, full
  `tests.test_t832_min_contract` run.

## 6. Non-goals / blockers

NOT_PRODUCTION_QUALIFIED. Flash/erase/reset, coordinator backup/restore, key
export, live serial probe, join/commissioning, HA API/SSH, Z2M restart, second
lab PAN, production migration/merge, forced recovery — all forbidden in M0–M2.
