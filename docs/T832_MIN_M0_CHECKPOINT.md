# T832-MIN v4 M0 — Source/Owner Baseline Checkpoint

Status: M0 COMPLETE. Date: 2026-10-09. Goal: T832-MIN v4 M0–M2, OFFLINE only.

## 1. Exact refs (verified this session)

- Repo: https://github.com/analienx/Zigbee-Coordinator (PUBLIC).
- Worktree (sole-writer): `C:\Workspace\worktrees\zigbee-t832-min-v4-m0m2`.
- Branch: `codex/t832-min-v4-m0m2`, HEAD `a48fa9deda36a9fc44624fcd142d5fa1533a449a`, clean (`git status --short` empty).
- Base matches brief base SHA. Remote `origin` = Zigbee-Coordinator GitHub.
- Separation confirmed: R11 `codex/t832-r11-diag` @ `ec02c6b`; R10 `codex/t832-r10-preserve-startup-nv` @ `904ef79`; counter-seal dirty `firmware/t832/r7/t832_hw_qual.py` left untouched.
- No `firmware/` tree in MIN worktree (clean baseline, confirmed). No secret material added.
- Brief hash verified: `5D86F4532722B32C03EC23935EF84FD59D93E6886CD2C5D469C91C2BDF489C73`.
- Canonical authority: issue #48 v4 cut comment `6078452867` (one T832-MIN target, de-scoped v3 matrix). Appendices A/B as reference library only.

## 2. Pinned upstream seed / toolchain (to be locked by M1 CI)

- TI SDK 8.32.00.07 @ `6499c3f53fc5fb5806213be695450a7b43fbaf3d`.
- P10 ZNP example @ `87ff5b638b632050228a7504f35cf3b95581c278`.
- Toolchain per TI notes + Appendix B: XDCTools `3.62.01.15` (prior pipeline used `.16` — document deviation), CCS `12.8` + TI Clang `3.2.2`, SysConfig `1.21.1`, TI-RTOS7 M33F.
- Herdsman/Z2M: NOT pinned yet. Historical snapshot "10.9.1" may mean herdsman, not Z2M — M1 must pin exact package/version from source for host-protocol tests.
- Target: SMLIGHT SLZB-MR4U main Zigbee TI CC2674P10. EFR32MG26 MUST NOT be touched.

## 3. Minimal allowed firmware patch classes (M1 only, one image)

1. Board static correctness: CC2674P10 target/ROM-BSL/clock/HF XOSC/VDDR/UART/RF. Unknown real pins → `HARDWARE_BLOCKED`.
2. Host ABI minimum: modern Z2M/Herdsman ZNP version behavior + necessary MT SYS, ZDO, AF, NV/security semantics. No counterfeit of unsupported features.
3. NV integrity: genuine compiler/linker/SysConfig/backend index0 agreement, no app/NVS/CCFG overlap, preserve factory identity + bootloader, no destructive NV auto-format/recovery.
4. Groupcast/source APS: source-correct only where proven; no 13-variant family.
5. Provenance: deterministic patcher from pristine pinned TI source in throwaway hosted staging, never `apply_r6.base()`; full diff allowlist + negative R10-absence test.

## 4. Upstream / host / board unknowns (M1 must mark PROVEN vs UNKNOWN)

- Real MR4U P10 pins, HF XOSC/CCFG deltas, PA/RF variant; do not copy Ebyte 20 dBm or faulty crystal delta.
- TI seed `CC2674R10` device-id text + compiler-5 vs linker-2 NV page mismatch → needs TOOLCHAIN-labeled reconciliation.
- Vendor 20240716 15-page `0xF8800/0x7800` vs TI 5-page `0xFD800/0x2800`: physical extent alone proves nothing (GEOM15 deferred, no compat claim).
- TI `product=0` vs Herdsman concurrent-request/feature expectations; MULTICAST_ENABLED FALSE per Koenkk docs (do not blindly import Koenkk patch).
- USB if02 vs Ethernet mode0 transport conflict; DATA/MANAGEMENT/UPLOADER/POWER only from prior receipts, no live host touch.
- 103-key current / 192-slot future capacity bounds; production vendor20240716 geometry NOT schema-proven.

## 5. Existing CI reuse

- MIN worktree has exactly one workflow: `.github/workflows/test-p10-r2-reset.yml` (PR/push `feat/mr4u-p10-r2-reset-helper`; `py_compile` + `python -m unittest -v tests.test_p10_radio_reset`). No TI compiler pipeline yet.
- R10 reference (read-only, in `zigbee-t832-minimal-debug`): `firmware/t832/r6/apply_r6.py`, `audit_source.py`, `package_r6.py`, `nv_contract.py`, `nvocmp` lab pieces. Reuse hosted-compiler/archive-assembly + static-audit *techniques* only.
- `.supervisor/project.yaml` mandates `github_actions` build lane, exact candidate SHA; host/usb/ssh_ha are management paths, not local verification evidence.

## 6. Future hardware blockers (M3/M4, separately authorized)

Flash/erase/reset, coordinator backup/restore, key export, live serial probe, join/commissioning, HA API/SSH, Z2M restart, second lab PAN, production migration/merge, forced recovery — all FORBIDDEN in M0–M2. `flash_authorized=false`, production untouched.

Next: M1 one T832-MIN implementation + M2 T1–T5 hosted gates, sole-writer coder, then 3 blind reviewers + challenger at sealed SHA. Stop at OFFLINE_BUILD_READY or BLOCKED.
