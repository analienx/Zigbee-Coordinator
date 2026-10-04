# T832-DIAG-R0 R2 checkpoint

- Goal: goal-01a1060a-668f-73c3-ab72-69f314fcb68c (R2: fix S01–S16)
- Evidence-run HEAD: `fb7b641` (branch `codex/t832-diag-r0`, pushed; seal
  commit is docs-only over it — `git diff fb7b641 <seal-sha> --stat` shows
  only `docs/*.md`)
- Branch: `codex/t832-diag-r0`; PR #38 draft, base `exp/mr4u-p10-ti832-kctrl-r0`
- Brief: `2fc44fab-...` SHA256 verified `776d613c…4972`, read fully
- Issue 73: open (re-check at seal)
- Prior review inputs: `C:\Workspace\scratch\t832-review-20261003\`
  (pinned SDK sources), `C:\Workspace\scratch\t832-review-20261004\artifacts`
- Base CI: run 37147303827 fully green at `aca72e8`

## Push log (all on codex/t832-diag-r0)

- `374d011` M1 fix — run 37190162983 fully green (4/4 jobs). A01–A04 sealed.
- `30c95b2` M2 (S05–S07) — run 37190830381 failed: 6 harness CHECKs
  (test-side wrong AF key ep + poll-gap decode skew).
- `a603830` M3 (S08/S09/S13 + retention audit) — new CollectorExactnessTests.
- `783fa24` M2-test fix (true SrcEp keys, gap-skew comment) —
  run 37191513286: 1 harness + 2 python failures left.
- `2b1e913` fixes (AF age 32 with UART model; python cap/JSON checks).
  Run 37191856793 cancelled by next push at 6m48s (no failures logged).
- `3346979` M4 (S10–S12: trigger evaluator, ZDO proof, single-RTS latch,
  barrier YAML wiring). Run 37192214462 cancelled by next push (no log).
- `f9591b8` M4b (S14/S15/S16: latch schema gate, bundle inventory, binding
  roles, build identity). Run 37192453412 failed: 1 python test.
- `e7f4a52` docs (A08–A16 mapping). Run 37192492312 failed: same 1 test.
- `41d63db` fix (schema-1 revision fallback). Run 37192563362 cancelled
  by next push (d31253c); no failure diagnosis — superseded, not failed.
- `d31253c` tests (three-poll partial, rotation-with-partial pins).
  Run 37192656756 cancelled by next push; fast lane + interop green.
- `fb7b641` fix (NaN proof clock labeled `missing`). Run 37192825360 FULLY
  GREEN at fb7b641 (4/4 jobs success, 7m35s) — the seal evidence run.
- R2 seal (this checkpoint + ACCEPTANCE-R2 exact-SHA mapping + PR draft,
  docs-only over fb7b641). No code changes after fb7b641.

## Diagnosed root causes (test-side, impl correct)

- AF correlation keys are (SrcEp, TransID) = payload bytes 3/6; the M2 test
  drove identity via DstEp (req[5]). Fixed to req[6].
- Export-gap poll metric conflated decode poll with export time for the
  pre-loop baseline frame. First loop export now skipped in metric.
- AF survivor age is 32, not 30: harness 2 ms UART TX model lands between
  B's insert and the observation. Comment records the arithmetic.
- V1 frames name hdr[6] firmware_revision; comparison falls back to it.

## A01–A16 states

- A01–A16: ALL GREEN at fb7b641 (run 37192825360, 4/4 jobs success).
  A01–A04 additionally green at M1 374d011 (run 37190162983).
- Omission audit (2026-10-04): all 10 C-harness fixtures
  (`test_tx_refused_stages`, `test_npi_paths`, `test_fifo_overflow_converges`,
  `test_mismatch_retire`, `test_write_reject`, `test_staged_retire_identity`,
  `test_sreq_generations`, `test_fair_schedule_15min`,
  `test_early_nv_preserved`, `test_af_correlation`) exist literally in
  `firmware/t832/host_harness/t832_diag_host_test.c`; `TriggerEvaluatorTests`,
  `ZdoProofTests`, `StabilityCloseOnceTests`, `RtsSingletonTests`,
  `CollectorExactnessTests`, `ContinuityTests` in `test_diag.py`;
  `BarrierStructureTests` + `BarrierChainTests` in `test_barrier.py`.
- Ledger: docs/T832_DIAG_R0_ACCEPTANCE_R2.md.

## Open questions (from brief)

- Q1 transport-mode reset semantics: retained hypotheses, no experiments.
- Q2 safe task/stack/fault observations from public TI interfaces: kept to
  existing public-interface hooks; no fault-handler rewrite.
- Q3 passive ZDO/traffic freshness: answered by construction — ZDO proof is
  the barrier's own permit_join transaction match (recorded, fresh,
  transaction-bound), never a periodic radio workload.

## Next action — SEALED, review pending

- M5 seal committed: ACCEPTANCE-R2 maps A01–A16 to run 37192825360 at
  fb7b641 (4/4 green) with matched images + raw evidence; PR draft prepared
  in docs/T832_DIAG_R0_PR_R2.md (NOT posted: no live actions).
- Independent acceptance review PENDING; no merge, no flash, no live runs.
- Authority limits: hosted-only execution; no local builds/tests; no live/merge.

## 2026-10-04T11:39Z addendum — runner environment

- Run 37191856793 (SHA 2b1e913, cancelled by next push at 6m48s) shows
  "Build and verify T832-DIAG-R0: completed success" — the full firmware
  job (python suites incl. new M3 tests, C harness, TI build, images)
  passed at 2b1e913. Only the control job was still running at cancel.
- Runs 37192656756 (d31253c) and 37192825360 (fb7b641): fast lane +
  interop green (all python/barrier/harness tests pass at final code),
  control-job validation step green; firmware/control jobs then hang in
  "Install CCS 12.8.0 SimpleLink toolchain" with no update for ~2 h.
  Same workflow completed the same step in the M1 cycle (7m25s total).
  Diagnosis: hosted-runner/toolchain-download stall, not a code failure —
  every step that can execute passes.
- Seal still requires a fully green run on the final SHA; keep monitoring.
  Do NOT push code changes unless the final run reports a test failure —
  any push restarts the 4-job cycle and voids in-flight evidence.
- Provenance bound (verified by diff, 2026-10-04T11:40Z): C implementation
  (.inc/.h) byte-identical between 2b1e913 (firmware job success) and
  fb7b641; control sources (coordinators/) identical between 374d011 (M1
  green) and fb7b641. All post-2b1e913 deltas are Python+YAML+docs+tests,
  already green in fast-lane/interop/validate steps at d31253c and fb7b641.
  The hanging TI-toolchain steps therefore rebuild proven inputs; the
  missing piece is the ceremonial full-green run on the final SHA, not
  unvalidated code.

## 2026-10-04 closing addendum — seal run complete

- The "hung" reading above was stale polling: run 37192825360 COMPLETED
  success (total 7m35s, headSha fb7b64182d0950e0010afc8e40114bb4fc4c0810).
  All 4 jobs success: fast lane 111408470109 (C HARNESS PASS; 73 + 22
  python tests OK), firmware 111408470176 (policy contract PASS; 73 + 22
  OK; C HARNESS PASS; T832_BUILD_ID 0xfb7b6418; capacity contract PASS),
  interop 111408470195 (10 records round-tripped, negatives rejected),
  control 111408470198.
- Image hashes recomputed locally from downloaded run artifacts and equal
  to bundle SHA256SUMS (DIAG HEX 2b0b5d43…92e6 / OUT e1987657…39f2af;
  CTRL HEX bf2a178b…54a5 / OUT f4eed7bf…c0d). Manifests bind
  repository_commit fb7b641; flash_authorized: false.
- No code changes after fb7b641; seal commit is docs-only. Independent
  acceptance review pending; session preserved with goal active until
  handoff.
