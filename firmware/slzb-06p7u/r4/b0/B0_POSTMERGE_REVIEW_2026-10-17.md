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
| P1 — CI artifact publication | Original workflow uploaded **full BIN/ELF/HEX even when native audit failed** (`if: always()`), making unvalidated firmware downloadable from a red run. | PR #102 now uploads full firmware files on **success only**, after the linked image and NV boundary both pass. Failure jobs upload only allowlisted logs/receipts under `FAILED_DIAGNOSTICS_NO_FIRMWARE`. Static CI tests enforce order and allowlist. | **Source fix in PR #102; latest exact-head CI must be checked** |
| P2 — evidence | Native build source checks are not physical qualifications; an offline receipt cannot prove toolchain provenance or boot. | Receipt explicitly says `NV_SPAN_CHECK_ONLY_NOT_SOURCE_OR_HARDWARE_ATTESTATION`; independent native provenance remains in separate CI logs/ELF audit. Failed re-runs overwrite stale receipts with a new `FAILED_CLOSED` denial. | **Addressed in PR #102** |
| P2 — docs | B0 README had stale “native build still pending” language and omitted `examples/rtos/` in a CCS path. | Restored exact upstream projectspec location and reconciled native result; documented raw-BIN hazard prominently. | **Addressed in PR #102** |

### Additional independent pass — conservative historical NV5 boundary

The first PR #102 safety guard correctly denied erasing the TI donor's
`FLASH_NV = 0xAA000..0xADFFF` 16 KiB NV2 extent. However, the
separately documented older R2 source used a **candidate** NV5 area
`0xA4000..0xADFFF` (40 KiB). A valid manifest+HEX with data in
`0xA4000..0xA9FFF` could previously receive the same non-flashable
receipt even though the historical partition would be overwritten by an
address-aware programmer. This is a **source-safety review gap**, not
evidence that current vendor stock actually uses NV5.

The fail-closed boundary now conservatively rejects HEX programming
anywhere in `0xA4000..0xADFFF` and requires consistent erased filler
in the whole 40 KiB flat-BIN span. Its receipt distinguishes the
16 KiB TI donor `FLASH_NV` from the **unverified** historical NV5
candidate and continues to set all flash/release/migration approvals
to `false`. Added negative tests modify HEX and BIN in the previously
unguarded `0xA4000..0xA9FFF` band with independently refreshed SHA
digests. This does not replace proof of the actual installed-stock
storage map; it is a conservative denial gate.

### Additional P1 — parallel red gate still allowed native artifact publication

A separate review of the GitHub Actions job graph found that the native
firmware job originally ran **in parallel** with `r4-b0-overlay` and
`r4-b0-upstream-inventory`. The uploader's `if: success()` only
tested success of **its own job**. Therefore a broken hostile source
test or failed TI upstream donor validation could coexist with a green
native job and a downloadable firmware artifact on an overall red run.
This invalidated the stronger claim that *all* source/provenance gates
must pass before images are published.

The native job now explicitly declares
`needs: [r4-b0-overlay, r4-b0-upstream-inventory]`, so it does
not start (or publish candidate files) until both independent gates
succeed. A static regression test rejects removal of this dependency.
This is source-workflow control, not a tested production deployment
interlock. The native job still labels every artifact NOT_FLASH_QUALIFIED.

### Manifest failure and GitHub provenance hardening

The NV safety tool previously assumed the root `manifest.json` was
always a mapping. A top-level JSON list could throw outside its
fail-closed exception handler, leaving a stale on-disk receipt from
an earlier invocation. It now checks a 128 KiB manifest size cap and
JSON root type before accessing keys, and emits a fresh
`FAILED_CLOSED` receipt for malformed inputs. Hostile tests exercise
malformed null/list/scalar and oversized manifests.

On pull-request runs, the workflow builds the explicit
`pull_request.head.sha` while `github.sha` can identify GitHub's
synthetic PR merge commit. Artifact names now use the **actually
checked-out** `github.event.pull_request.head.sha || github.sha`,
with source checks that reject a misleading label.

## Verification matrix

PR #102 has source negative tests against (1) HEX programming NV,
(2) changing a programmed application byte even after re-hashing a
tampered BIN, (3) HEX addresses outside the 704 KiB flash, (4) truncated
BIN with re-hashed manifest, (5) uniformity of NV filler, (6) digest
tampering, (7) manifest path traversal, (8) a prior successful receipt
remaining after a failed check and (9) false source/physical attestation.
The **exact-HEAD hosted results of PR #102 (including failure-artifact publication guards) must be checked separately**
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
