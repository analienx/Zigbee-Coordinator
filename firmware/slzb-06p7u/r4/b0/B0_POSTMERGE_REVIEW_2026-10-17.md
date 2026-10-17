# R4-B0 post-merge code review — 17 October 2026

**Scope:** source/CI review only. Reviewed target: PR #91 squash
`512e620f1901bf83c6453410d7e411126b7853a3` and PR #102
post-merge changes. No author has exercised R4 firmware on physical
SLZB-06P7U as a consequence of this report. This is an **author-side
follow-up review**, not an independent Wonder, security-specialist or
hardware reviewer sign-off.

## Verified evidence, not an inferred PASS

- Exact B0 PR #91 source SHA:
  `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`.
- Hosted native TI toolchain/SDK/CCS audit passed:
  [38923787459](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38923787459).
  Actual ELF/XML/HEX/BIN and generated ti_drivers_config were present.
- UART0 RX DIO12, TX DIO13, 115200, HWFC off, generated CC2652P7
  pinmux constraints, and 88-byte CCFG matching historical 20240710
  vendor digest were proved by the native CI. These do **not** prove
  RF hardware behavior nor current-stock 20260310/20260311 equivalence.
- `main` did **not** contain B0 on 17 October. PR #91 landed in draft
  PR #89 head `review/p7u-r4-issue87-independent-fixes`, which
  depends on draft R4-00 PR #86. GitHub branch names and PR base are
  authoritative; an API merge success alone does not imply `main`.

## Review findings and disposition

| Severity | Finding | Evidence / remediation | Status |
| --- | --- | --- | --- |
| P1 — integration | PR #91 recorded as merged to `main` despite base being the PR #89 review branch. | Corrected issue #90 title/top-status, explicitly documented #86 → #89 → #91 stack and no premature deployment. | **Corrected record; main integration still OPEN** |
| P1 — NV safety | ELF-derived `tiarmobjcopy -O binary` spans `0x00000..0xAFFFF` including synthetic fill in 16KiB reserved `FLASH_NV 0xAA000..0xADFFF`. A contiguous raw-BIN writer can erase NV, network identity and security counters. HEX contains no programmed NV data, but that is insufficient to qualify a programmer. | PR #102 `b0_flash_boundary.py` refuses HEX NV writes, verifies full BIN and matching HEX payload, and emits a SHA-bound **DO_NOT_FLASH** receipt with all approval flags false. Regression tests cover multiple hostile mutations and missing/invalid manifest fields. | **Source mitigation in draft PR #102; not production-qualified** |
| P2 — evidence | Native build source checks are not physical qualifications; an offline receipt cannot prove toolchain provenance or boot. | Receipt explicitly says `NV_SPAN_CHECK_ONLY_NOT_SOURCE_OR_HARDWARE_ATTESTATION`; independent native provenance remains in separate CI logs/ELF audit. Failed re-runs overwrite stale receipts with a new `FAILED_CLOSED` denial. | **Addressed in PR #102** |
| P2 — docs | B0 README had stale “native build still pending” language and omitted `examples/rtos/` in a CCS path. | Restored exact upstream projectspec location and reconciled native result; documented raw-BIN hazard prominently. | **Addressed in PR #102** |

## Verification matrix

PR #102 has source negative tests against (1) HEX programming NV,
(2) changing a programmed application byte even after re-hashing a
tampered BIN, (3) HEX addresses outside the 704 KiB flash, (4) truncated
BIN with re-hashed manifest, (5) uniformity of NV filler, (6) digest
tampering, (7) manifest path traversal, (8) a prior successful receipt
remaining after a failed check and (9) false source/physical attestation.
The **exact-HEAD hosted results of PR #102 must be checked separately**
before any review decision; do not recycle previous run #38923787459
as proof of the post-merge script.

## Physical / firmware acceptance still OPEN — no shortcuts

1. Prove an address-aware, sector/erase-protected write method on
   **isolated expendable** P7U, with explicit no-NV-write proof and a
   compatible, rehearsed stock rollback; full BIN writes forbidden.
2. Independent physical boot with exactly one UART owner, 3 cold-boot
   sequences, SYS_PING/SYS_VERSION, reset reason and reproducible
   minimal traffic with no network formation side effects.
3. Read-only comparison with **current-stock** 20260310/20260311
   CCFG, RF/PA/clock and NV partition design. Historical 20240710
   CCFG equality is insufficient.
4. Separate security migration authority: coordinator IEEE uniqueness,
   keys, TCLK table and monotonic outgoing counters; no physical
   restore, format, merge or migration before verified proofs.
5. Independent reviewers for source security/build, NPI/ABI and
   hardware; dense-mesh soak only after dedicated approval.

**Result:** B0 native source/build gate passed; PR #91 merged to R4
review stack; release, current-stock parity, physical, main-integration
and PR #102 acceptance remain open. Nothing here authorizes access to
live HA/Z2M/EMQX, Zigbee radio, USB/BSL, MQTT, flash or OTA.
