# T832 R8 completion report (A12)

Sealed SHA: `cf08937888935970e680b11b3a89c5a037b15669`
Branch: `codex/t832-r8-powercut-recovery` (base `3d8129daa97522ee53514e3872ad9f0b73710055`)
Hosted run: `37510690509` (T832 R7 vendor-layout NV regression) — nv-lab,
R7 BASE, R7 DIAG all green at the sealed SHA.
Artifacts: `t832-r7-nv-evidence`, `t832-r7-BASE-vendor-20240716`,
`t832-r7-DIAG-vendor-20240716`.
Fix: `t832-r8-nv-recovery-01`, patched nvocmp sha256
`ac3b00c8994dd20a176d30e018b38f7704a0676233669220d4cfec3da97453b6`
over pristine `d37c7f314696c8669413cfb098900e41ffd2a4d48704481e5dd8c9a8c012d6d6`
(TI SDK pin `6499c3f53fc5fb5806213be695450a7b43fbaf3d`).
Lab report sha256
`d5f07eba11c18c2a8cdf2d384b48ed99a1cb7f9c8f2a38db7a09ea3863d0b7f9c8`,
`all_power_cut_recovery_passed: true`.

## A1 — root cause of the ten R7 failures

See `docs/T832_R8_M1_FORENSIC.md`. Four cuts failed the post-cut
append reserve only, five rejected init/flash-programming, one combined.
Source causes from exact vendor source: resume replayed a stale
`tailPage` (zeroed by the fresh-handle memset) so copied items were
programmed NOR-illegally, and completion was trusted from headers that
are also written on rejected copies over reused destinations, hiding
live originals behind a wrong end cursor.

## A2 — fix without erase/reformat or reduced reserve

`firmware/t832/r6/nv_recovery_fix.py` (5 edits, idempotent,
fingerprint-gated): P1 marks the true copy destination instead of the
stale tail page; P2 refreshes RAM offsets to the true data end via
`NVOCMP_findOffset` then inactivates only destination copies that still
have a live original elsewhere (caller re-compacts); P3 removes the
unconditional resume-time compact so reopen is zero-mutation. No erase,
no reformat, `MINIMUM_FREE_BYTES=2048` unchanged, reserve pages unchanged.

## A3 — every compaction cut tested and green

201/201 physical compaction operations cut, per lane (BASE + DIAG).
Every cut proves saved population + anchor integrity, init success,
>=2048 free bytes, and a legal neutral create/update/delete cycle after
reopen. `power_cut_points_verified == power_cut_points_write_proof ==
201`, `unresolved_recovery_negative_controls == []`, both lanes.

## A4 — mutation cuts exhaustive and green

8/8 mutation-operation cuts verified per lane.

## A5 — BASE/DIAG parity

Identical cut verdicts, identical anchor-free values per cut, observer
API contract checked on DIAG; instrumentation does not alter recovery.

## A6 — read-only zero mutation

`readonly_reopen_unchanged: true` with matching pre/post sha256, both lanes.

## A7 — historical negatives stay negative

Five-page-400 control still rejects (`tiny_update_status=5`);
PR40 full-capacity deployment still rejected; preserved five-page-112
characterization retained as evidence, not a gate.

## A8 — runtime geometry and no-reformat

Sealed provenance per variant: `vendor-layout-proof.json` matches the
pinned vendor reference (0xF8800/0x7800, runtime page clamp 15, sector
0x800); `effective-macros.txt` pins `NVOCMP_NVPAGES 15`,
`NVOCMP_NVS_INDEX 0` with no `NVOCMP_RECOVER_FROM_COMPACT_FAILURE`
(hosted `check_macros` + packager gate raise on its presence).
Map, generated NVS config, and linked-map checks all green.

## A9 — sealed packages

| variant | SYS revision | slzb.bin sha256 (prefix) | flash_authorized |
|---------|--------------|--------------------------|------------------|
| BASE | 8320021 | 49884585dc5744d2 | false |
| DIAG | 8320022 | 567fe954712d5e62 | false |

BIN/HEX/OUT/map/generated/provenance sealed with `SHA256SUMS`
(verified 23/23 files per variant). BASE bytes are reproducible across
SHAs; DIAG differs only by its embedded build-ID. `hardware_validated`
is false everywhere: no household deployability is claimed.

## A10 — hardware qualification tooling only

`firmware/t832/r7/t832_hw_qual.py` (verify/plan, fail-closed exits,
one-shot seal, hash-only identity, allowlisted SLZB-06P10/CC2674P10),
`test_t832_hw_qual.py` (12 hosted unit tests, green in this run),
`docs/T832_R8_HW_QUAL_RUNBOOK.md`. No hardware action performed.

## A11 — hardware-only gates

`docs/T832_R8_HARDWARE_GATES.md` (H1-H8). Household path requires H1-H7
on sacrificial hardware first. Stop boundary respected: no live flash,
no restore, no HA mutation, no MG26 touch, no NVM erase.
