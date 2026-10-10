# T832-MIN v4 M1 Design — NOT_PRODUCTION_QUALIFIED

Status: M1 candidate definition. Offline only. No flash, no hardware access, no
HA/Z2M changes, no secrets. All build/test evidence comes from GitHub-hosted
Actions at the exact candidate SHA (project lane: `github_actions`).

## 1. Goal

One minimal T832-MIN firmware candidate for the SMLIGHT SLZB-MR4U main Zigbee
TI CC2674P10 radio (Radio 2). The EFR32MG26 (Radio 1) MUST NOT be touched.
M1 contains older planning/mock contracts. The separate build_min_real.py applies exact genuine TI source deltas and t832-min-real-build.yml compiles/links a real firmware image; harden_real.py verifies actual ABI and linked layout. Green mock/static T1-T5 checks are never sufficient by themselves. Stop at
OFFLINE_BUILD_READY or BLOCKED. Production qualification is explicitly out of
scope.

## 2. Pinned inputs (`firmware/t832/min/upstream.lock.json`)

- TI SDK 8.32.00.07 @ `6499c3f53fc5fb5806213be695450a7b43fbaf3d`.
- P10 ZNP example @ `87ff5b638b632050228a7504f35cf3b95581c278`.
- Toolchain: XDCTools `3.62.01.16` (actual CCS hosted toolchain, linked-build proof; earlier planning `.15` corrected), CCS `12.8`, TI-Clang `3.2.2`, SysConfig `1.21.1`, TI-RTOS7 M33F.
- Herdsman exact pin: `zigbee-herdsman 10.9.1`, status `GATED_EXACT`.
  Hosted CI T1 gates exact (`npm view zigbee-herdsman@10.9.1 version` must
  equal lock `10.9.1`, fail closed on mismatch or resolve failure).

## 3. Minimal patch classes (one image)

1. **Board static correctness** (`board/mr4u_board_contract.json`): `target_device=CC2674P10` is hardware-documented, but the current DATA UART
   transport, pin map and RF/clock/CCFG details are NOT independently proven by
   this MIN session. Earlier M0's isolated-probe claim lacked a traceable receipt. ROM-BSL, HF XOSC, VDDR/RF,
   CCFG delta, PA variant, and the full pin map are HARDWARE_BLOCKED. Unknown
   pins are never filled from Ebyte 20 dBm data or faulty crystal deltas.
2. **Host ABI minimum** (`host_contract.cjs`): ZNP version behavior + MT SYS,
   ZDO, AF, NV/security dispatch entries. MULTICAST_ENABLED stays FALSE per
   Koenkk docs; the Koenkk patch is not imported. `product=1` is emitted in the actual compiled firmware with a real 32-bit little-endian `revision`; pinned Herdsman 10.9.1 requires 9-byte SYS_VERSION. The earlier 5-byte candidate was incompatible and is superseded.
3. **NV integrity** (`nv_lab.py`, `verify_compiler.py`): genuine
   compiler/linker/SysConfig/backend index0 agreement at base `0xFD800`, no
   app/NVS/CCFG overlap, factory identity + bootloader preserved, no
   destructive NV auto-format/recovery. Known seed conflict (CC2674R10 text,
   compiler-5 vs seed-linker-2 pages) is fixed in real source to five pages and must be verified in the actual map. Vendor 15-page `0xF8800/0x7800` geometry is deferred (GEOM15): physical
   extent alone proves nothing.
4. **Groupcast/source APS**: source-correct only where proven; no 13-variant
   family is included.
5. **Provenance** (`patch_min.py`, `diff_contract.py`): deterministic patcher
   from pristine pinned TI source in throwaway hosted staging. Anchors are
   synthetic interface-definition placeholders defined by M1, NOT present in TI source and NOT an actual firmware patch. The separate build_min_real.py uses anchored actual pinned TI source — each placeholder must occur exactly once in the staged
   target or the patcher fails closed. TI-side citation of each placeholder
   against TI SDK `6499c3f53fc5fb5806213be695450a7b43fbaf3d` and P10 ZNP
   example `87ff5b638b632050228a7504f35cf3b95581c278` is pending TI-side
   confirmation. NO R10 imports, NO `apply_r6.base` call — enforced by the
   contract test and CI T2. Full diff allowlist (3 source files + generated
   manifest, every entry requires a non-empty reason).

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
