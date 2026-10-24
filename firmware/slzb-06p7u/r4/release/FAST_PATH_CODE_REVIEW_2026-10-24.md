# P7U R4 fast-path — code and critical-logic review

This is a source-review artifact, not a release or flash authorization. It covers PR #152 (known-installed R4 updates only), preserving the original conservative recovery lane.

## Review 1 — findings and corrections

| Severity | Finding | Correction |
|---|---|---|
| P0 | An installed, fully verified flash could be considered a known R4 even if it never booted. The first R4 hardware candidate suffered exactly this kind of failure. | Added independently pinned previous-install runtime receipt, source-bound native B1 completion-frame verification, state 9, one original owner, error-free observation and fresh nonretained device traffic. Without it, known-R4 optimization is rejected. |
| P0 | The prepared SDK manifest previously trusted a digest repeated by the same runtime configuration. | Only SDK identities explicitly approved in reviewed repository trust file are accepted. The trust list is currently empty, correctly blocking falsely qualified builds. |
| P0 | Hardware execution previously accepted user-supplied arbitrary SSH commands and a writable local success JSON. | Removed this unsound route. Execute now fails closed before any build or radio action until independently audited HA operator/recovery evidence exists. |
| P1 | Expensive all-88 CRC loops repeated around each flash sector and boot commit. | Narrowed routine checks to each target before erase, protected region at phase boundaries and a full CRC checkpoint before boot change. Retained final **full 88-sector byte/SHA** and per-written-sector byte-readback. |
| P1 | Native package source validation did not match the real TI `manifest.json` and `r4-final-ti-source-manifest.json` schemas. | Changed to exact real source schema and verified `firmware_source_sha`. Atomic non-authorizing packager now binds real compiled APP/ELF/source/handoff. |
| P1 | Build/staging budget declared 60/5 seconds but command timeouts allowed longer. | Enforced the actual stage deadlines with hard HOLD if exceeded, before production outage. |
| P1 | CLI argument inspection could index past the last token; package output was not bound to the requested destination. | Explicit single-value flags and exact output-directory comparison. |
| P2 | Duplicate current APP builds and two same-link protected reads inflated the routine upgrade. | One clean source-specific build, one live CRC-verified protected-region read; conservative duplicate modes retained separately. |

## Security and hardware preservation

- Same physical silicon and original Z2M owner must be identified and quiesced before ROM access.
- No bank/chip erase, no writing NV/CCFG, no guessed counter bump, no re-pairing or automatic reset/retry.
- An ephemeral same-session witness is consumed once; live CRC prevents stale-target and protected-sector drift.
- Durable pre-erase journal, immediate readback of written sectors and the boot-vector final-write rule remain mandatory.
- Final 88-sector ROM byte/SHA comparison and explicit ROM status fence are never bypassed to meet a time budget.
- The previous **working** R4 image and a verified rollback route are separate preconditions, not inferred from a previous write success.

## Verified vs outstanding

Verified off hardware: source import/compilation, native ARM64 TI reader GH build, private Win64/ARM64 reader parity on two earlier captures, the controller/sector-writer and negative source tests. The sole production unit remains on stock firmware.

Still **NOT qualified**:
1. Actual prepared, license-reviewed, immutable TI toolchain/SDK library layer: no identity has been approved in the repo's trust file.
2. Real single-new-source CCS build from that prepared layer and atomic handoff packaging measured within 60 + 5 seconds.
3. Independent HA-local *mutating* operator with full live-owner backup, BSL entry, journal, source/ROM security, post-boot original Z2M state-9/device traffic and non-automatic recovery semantics.
4. One complete end-to-end timed hardware run. The 290-second target is not yet measured or guaranteed, and must not be obtained by skipping required checks.

## Promotion decision

**HOLD / draft PR.** Green source CI is necessary but insufficient. This is not a valid known-R4 fast-upgrade target while the sole production P7U is on stock; its first R4 hardware acceptance previously failed. First restore a qualified, working R4 baseline through the separately guarded procedure, not by bypassing the known-R4 preconditions.
