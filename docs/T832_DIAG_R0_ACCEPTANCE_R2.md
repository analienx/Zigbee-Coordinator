# T832-DIAG-R0 ACCEPTANCE-R2

Completion oracle for R2 (S01–S16). Every row begins **pending**; state changes
only with linked hosted evidence at the sealed final SHA. Final owner
acceptance is a later independent Codex review, not Muse's internal completion.

Reviewed base: `aca72e8` (run 37147303827, all green). R1 docs overstated
R04/R05/R08/R09/R12/R14/R15/R16; S01–S16 below are the binding defects.

## A01 / S01 — actual RX/TX allocation hooks, truthful capability coverage

- Required: RX refusal (`NPITask_sendBufToStack`) classified as RX with no
  TX-pending mutation; real TX refusals (`NPIFrame_frameMsg` NULL,
  queue-record malloc NULL, unsupported type) hooked in both `NPITask_sendToHost`
  and `NPITask_processStackMsg`, reconciling only the owned queued entry.
  `global_allocation_failure_sites` capability audited/narrowed.
- Sources: `firmware/t832/t832_diag_impl.inc` (txPush/txRelease/dequeue/
  uartTxFinished/uartWriteRejected/npiAllocFailed/npiTxRefused),
  `firmware/t832/apply_diag.py` (send_to_host_refuse, stack_msg_refuse,
  stack_msg_unsupported, rx_msg_alloc_fail, site-1→2 reclassification),
  `firmware/t832/t832_diag.h` (npiTxRefused stages), `diag_manifest.json`
  (`npi_path_refusal_hooks`)
- Fixtures: `test_tx_refused_stages` (all 6 TX stages + unowned),
  `test_npi_paths` (RX site-2 neutrality, TX site-1 orphan) — host harness on
  the real `.inc` with controlled allocator/transport stubs
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; see Sealed final evidence). M1 history: run 37190162983 at 374d011 (4/4 success).
- Raw evidence: hosted run logs + artifacts at run 37192825360 (jobs 111408470109/176/195/198)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending
- Hardware-only: real allocator exhaustion on target (harness injects refusals
  through identical hook call order).

## A02 / S02 — bounded overflow, no ghost pending

- Required: >8 mixed/identical frames through the real queue/wire path with
  reject/drop cases; after drain, telemetry resumes or reports a defined bounded
  uncertainty; no ghost counts; no transmission during truly busy transport;
  write-rejection and mismatch reconciliation exercised.
- Sources: same `.inc` ownership core as A01 (drop-newest FIFO, deeper-match
  retire-as-uncertain, untracked completions, write-reject release)
- Fixtures: `test_fifo_overflow_converges` (9 frames, duplicates, resume),
  `test_mismatch_retire` (deeper match + unknown), `test_write_reject`
  (rejection vs completion, stray finish)
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; see Sealed final evidence). M1 history: run 37190162983 at 374d011 (4/4 success).
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A03 / S03 — atomic ownership/staging, identity-aware retirement

- Required: deterministic task/ISR interleavings (completion during enqueue;
  producer during stage/build/retire; coalesce and wrap under staged export);
  counts, identities, exported repetitions and explicit loss accounting verified;
  bounded critical-section work proven (CS depth/cost evidence).
- Sources: same `.inc` (per-function CS on tx/push/pending/dequeue/finish/
  reject/AF table; identity-aware `popPeeked(sel, seq)`)
- Fixtures: `test_staged_retire_identity` (overwrite-then-retire reports loss,
  newest intact, positive control retires); CS depth bound (<=4) in M1 tests
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; see Sealed final evidence). M1 history: run 37190162983 at 374d011 (4/4 success).
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A04 / S04 — SREQ generations, no stale SRSP clear

- Required: queued reply completing after a newer SREQ dispatch and before its
  reply leaves suppression set until the matching terminal event; same-command
  repetitions and dropped/error responses through patched MT/NPI call sites.
- Sources: same `.inc` (`sync_gen`/`sync_seq`, SRSP gen stamping, gen-gated
  clear, stale-completion event, error-SRSP terminal)
- Fixtures: `test_sreq_generations` (overtake, repetition, error SRSP)
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; see Sealed final evidence). M1 history: run 37190162983 at 374d011 (4/4 success).
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A05 / S05 — fair exports, true deltas, genuine progress ages

- Required: >=15-minute one-second poll fixture with sticky fault, pressure,
  busy intervals and MT refusal; nonzero schedule deltas; all 13 resource
  selectors within documented bounded max age; retained overdue work;
  first-fault repeat availability; bounded ring draining; exact wire budgets
  (1 frame / >=5 s, <=240 B payload, <=4 records); observed emitted bytes.
- Sources: `.inc` exportPoll (accept-gated baselines, resources-first, health
  rotation, TXQ backpressure), orig-kind flags, zstack-valid unknown ages
- Fixtures: `test_fair_schedule_15min` (900 one-second polls; selector revisit
  bound 100 exports; min frame gap 5 s; payload <=234 B; <=4 records/frame)
- Fixes since M2: gap metric skips decode-skewed baseline export (throttle
  itself guarantees the 5 s delta); impl cadence unchanged
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; firmware job C-harness HARNESS RESULT: PASS incl. `test_fair_schedule_15min`; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A06 / S06 — early NV records survive MT init

- Required: main-order fixture runs actual NV init/failure/recovery hooks before
  actual MT init, then exports; each early event and first-fault identity
  survives with truthful timing; linked main reset-capture proof retained.
- Sources: `.inc` ensureEarly/init-absorb/TIMING_APPROX; linked main reset
  capture unchanged (prior CI gate)
- Fixtures: `test_early_nv_preserved` (pre-init NV init/start/fault, then
  init, export; TIMING_APPROX count; FIRST_FAULT orig kind)
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; firmware job C-harness HARNESS RESULT: PASS incl. `test_early_nv_preserved`; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A07 / S07 — accurate bounded AF correlation

- Required: actual AF request/SRSP/confirm paths for duplicate keys,
  oldest-first removal, nonzero confirm status, rejected/dropped SRSP, AREQ and
  timestamp wrap; exported state and raw statuses inspected.
- Sources: `.inc` afInsert (supersede, wrap-safe evict, origin counters),
  afRemove (oldest recompute), afConfirm (failed confirm is a reject)
- Fixtures: `test_af_correlation` (dup, nonzero confirm, AREQ, recompute age,
  tick-wrap eviction of largest age)
- Fixes since M2: harness drives identity via true SrcEp (req[6], payload
  byte 3) not DstEp; survivor age 32 (30 advances + 2 ms UART model);
  impl wire layout unchanged
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; firmware job C-harness HARNESS RESULT: PASS incl. `test_af_correlation`; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A08 / S08 — bounded collection, no lost unread data

- Required: repeated small-budget polls recover every complete line exactly
  once; huge lines/backlogs/lock contention within explicit memory/time
  allowance; delayed/blocked capture exits within positive deadline + tolerance,
  never authorizes reset, leaves resumable state. Hosted subprocess tests.
- Sources: `t832_incident.py` (budget rewind in _collect_locked, bounded
  LockFile with LockError timeout, MAX_TEXT_MATCHES_PER_LINE)
- Fixtures: budget-rewind-recovers, lock-timeout-fails-loudly,
  collect-budget-marks-partial, barrier chain tests (real CLI subprocesses)
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; python suites 73 + 22 tests OK in fast-lane and firmware jobs; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A09 / S09 — exact partial-line bytes across polls

- Required: three polls before newline, multiple partials, split UTF-8, rotation
  with partial; byte-for-byte raw line, correct offsets, one host event/record,
  no spurious decode errors through both decoder representations.
- Sources: `t832_incident.py` (byte-exact read_increment re-read, bounded
  oversized-line drain with notes, no cursor prepend)
- Fixtures: split-utf8-byte-exact, oversized-skipped-with-note,
  partial-line-buffered-durably, rotation-and-truncation-reset
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; python suites 73 + 22 tests OK in fast-lane and firmware jobs, incl. three-poll/rotation-with-partial pins; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A10 / S10 — production-faithful triggers, no healthy reset

- Required: actual candidate YAML trigger evaluator driven with healthy removal,
  ordinary permit_join success, unrelated error, malformed payload, qualifying
  SRSP timeout; only qualifying outage/timeout events reach reset authorization;
  pinned production source SHA recorded.
- Sources: `t832_incident.py` (load_trigger_defs/evaluate_trigger/
  evaluate_radio_timeout, capture verdict, authorize_reset gate),
  `deploy/t832_capture_barrier.yaml` + `t832_shell_commands.yaml` (evidence flags)
- Fixtures: TriggerEvaluatorTests, chain healthy/malformed/wrong-topic/
  unknown-trigger refuses, qualifying-timeout authorizes with source SHA pin
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; TriggerEvaluatorTests in 73-test suite OK, barrier chain tests in 22-test suite OK; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A11 / S11 — stabilization can close, honestly

- Required: actual candidate automation timer advanced through a healthy
  >=600 s window closes exactly once; gaps, stale sensors, absent real ZDO/
  traffic evidence, transient outages and host reboot cannot close;
  outage-derived Boolean alone never becomes ZDO proof.
- Sources: `t832_incident.py` (record_zdo_proof/zdo_proof_state, proof-gated
  recovery_result, mono-anchored freshness), barrier YAML proof step +
  transaction binding, StabilityTests/close-once
- Fixtures: ZdoProofTests (missing/stale/mismatch/empty), chain
  zdo-claim-without-proof fails, StabilityCloseOnceTests
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; ZdoProofTests + StabilityCloseOnceTests in 73-test suite OK; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A12 / S12 — correlated waits, persisted failures

- Required: actual YAML/script execution with already-online bridge, fast
  response, unrelated/stale response first, no response, failed stop/reset/start,
  tool/API failures; one RTS maximum; failure persisted; serial ownership
  prerequisite; only matching fresh success reaches stabilization.
- Sources: `t832_incident.py` (record_rts_used singleton), barrier YAML
  RTS-gate + proof-gated recovery, chain shims (supervisor/RTS)
- Fixtures: success chain (slow-stop order, single rts-invoked, RTS retry
  refused), RtsSingletonTests, supervisor-failure halts, transaction-gate
  structure tests
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; RtsSingletonTests in 73-test suite OK, success-chain BarrierChainTests in 22-test suite OK; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A13 / S13 — frame-level continuity, honest replay/BOOT handling

- Required: real batched C bytes through herdsman and both decoders; first BOOT
  not first record; delayed BOOT; sequence wrap; copied rotated logs; replay
  with lower uptime; actual reboot. Same-frame records share association;
  replay/delay never selects a false current boot.
- Sources: `t832_incident.py` (frame-aware Continuity.annotate, boot_in_frame),
  `t832_diag_decode.py` (same per-frame rule)
- Fixtures: CollectorExactnessTests (multirecord BOOT one-boot, clean-continuation
  no-double-boot, clean-wrap gap-zero), ContinuityTests (wrap/replay/duplicate/boot)
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; CollectorExactnessTests + ContinuityTests in 73-test suite OK; interop job: 10 records round-tripped, negatives rejected; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A14 / S14 — invalid latch/hash schemas fail closed

- Required: valid-JSON wrong types, missing fields, unknown schema/status,
  inconsistent reset-used/state, empty/incomplete hash inventory and missing
  required payloads cannot grant reset or fresh incident; normal closed/cleared
  lifecycle still works; concurrent invocations serialized.
- Sources: `t832_incident.py` (LATCH_SCHEMA gate in update_latch,
  verify_bundle empty/manifest-inventory gates)
- Fixtures: empty-hash-inventory / uninventoried-manifest / unknown-schema
  blocks, plus existing corrupt-latch/tampered-bundle/missing-bundle/concurrent
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; latch/hash-gate tests in 73-test suite OK; firmware policy contract PASS; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A15 / S15 — bounded private store, unknown-time supplement

- Required: repeated rotations/bundles under small total byte allowance stay
  bounded; active bundle intact; failures cannot silently delete the only active
  evidence; unknown/naive timestamps preserve bounded raw rows separately with
  honest time provenance.
- Sources: `t832_incident.py` (rotate returns audited retention notes,
  latched-bundle exemption, host-events cap)
- Fixtures: repeated-collects-bounded-and-audited, latched-bundle-survives,
  retention-deletions-audited, existing rotation/unknown-time tests
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; retention/rotation tests in 73-test suite OK; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## A16 / S16 — observed vs declared build identity

- Required: matching bundle binds; wrong variant, stale manifest, mismatched
  file hash, candidate-only role and observed different build fail binding or
  yield explicit mismatch/unavailable; boot/incident identity truthful across
  firmware changes.
- Sources: `t832_incident.py` (bound_firmware re-hash, deployed-only roles,
  firmware-build-mismatch notes, bind --build-id)
- Fixtures: bind-gates-capture, candidate-role-never-gates, swapped-artifact,
  observed-build-mismatch-noted, matching-build-silent
- Final SHA / run / jobs / results: run 37192825360 at fb7b641 (4/4 success; bind-gate tests in 73-test suite OK; build manifest binds repository_commit fb7b641; see Sealed final evidence)
- Implemented / tested / independently verified: yes / yes-hosted / no — independent acceptance review pending.

## Sealed final evidence — run 37192825360 (2026-10-04, 7m35s)

- Code SHA: `fb7b64182d0950e0010afc8e40114bb4fc4c0810` (branch
  `codex/t832-diag-r0`; this seal commit is docs-only over it — verify with
  `git diff fb7b641 <seal-sha> --stat`, expected: only `docs/*.md`).
- Run: https://github.com/analienx/Zigbee-Coordinator/actions/runs/37192825360
  (status completed, conclusion success; headSha == code SHA above).
- Jobs (all success):
  - Host regressions for ACCEPTANCE-R2 (fast lane) — job 111408470109:
    C recorder regressions on the real implementation HARNESS RESULT: PASS;
    Python suites `Ran 73 tests … OK` + `Ran 22 tests … OK`.
  - Build and verify T832-DIAG-R0 — job 111408470176: policy contract PASS;
    `Ran 73 tests` + `Ran 22 tests` (both pass, job success);
    C harness HARNESS RESULT: PASS; compiled `T832_BUILD_ID 0xfb7b6418`;
    capacity/NVS/stack/RAM contract PASS; `flash_authorized: false`.
  - Herdsman interop (C bytes to pinned parser to decoders) — job
    111408470195: HARNESS RESULT: PASS; `INTEROP PASS: 10 records
    round-tripped, negatives rejected`.
  - Build matched T832-KCTRL-R0 control — job 111408470198: success.
- Diagnostic image (`mr4u-p10-t832-diag-r0` artifact, bound to
  `repository_commit fb7b641…` in `T832-BUILD-MANIFEST.json`):
  - `T832-DIAG-R0.hex` 549646 bytes —
    `2b0b5d430668505ce982b4fe41a188e261365a71d2afe3c4bb7ff2c56f6a92e6`
  - `T832-DIAG-R0.out` 2593608 bytes —
    `e19876578c24e8957a4638a27ddeb01ccff449684e04c8ad316a85232839f2af`
  - Hashes recomputed locally from the downloaded run artifacts and equal to
    the bundle `SHA256SUMS`.
- Control image (`mr4u-p10-t832-control-r0` artifact, manifest binds
  `repository_commit fb7b641…`, `flash_authorized: false`):
  - `T832-CONTROL-R0.hex` —
    `bf2a178b04276a9af0dfe75ca2a6ddb324d3da9d636491c829d5d4a0b11d54a5`
  - `T832-CONTROL-R0.out` —
    `f4eed7bfea6aca2016d8f605a68fbb721aaf21a6f71885242e03089a11d7fc0d`
  - Hashes recomputed locally from the downloaded run artifacts and equal to
    the bundle `SHA256SUMS`.
- Provenance/maps/symbols: inside the same two artifacts (`provenance/`,
  `generated/`, `linked/` — compiled-contract, patch evidence, manifests,
  schemas, disasm, `.map`, linkInfo XML, `SHA256SUMS` self-check `OK`).
- A01–A16 map: every row above cites this run at this code SHA; per-row
  fixture names were audited to exist literally (10 C-harness cases in
  `firmware/t832/host_harness/t832_diag_host_test.c`; `TriggerEvaluatorTests`,
  `ZdoProofTests`, `StabilityCloseOnceTests`, `RtsSingletonTests`,
  `CollectorExactnessTests`, `ContinuityTests` in `firmware/t832/test_diag.py`;
  `BarrierStructureTests` + `BarrierChainTests` in
  `firmware/t832/test_barrier.py`).
- Not covered by hosted evidence (honest scope): real-HW allocator
  exhaustion/timing, 72 h soak, fault injection; production board/CCFG/
  recovery/backup flash gates remain separate (`flash_authorized: false`).
- Independent acceptance review: PENDING (not Muse's internal completion).
