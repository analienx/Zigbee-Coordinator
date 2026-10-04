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
- Final SHA / run / jobs / results: pending (M1 push awaited)
- Raw evidence: pending
- Implemented / tested / independently verified: yes / pending-hosted / no
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
- Final SHA / run / jobs / results: pending (M1 push awaited)
- Implemented / tested / independently verified: yes / pending-hosted / no.

## A03 / S03 — atomic ownership/staging, identity-aware retirement

- Required: deterministic task/ISR interleavings (completion during enqueue;
  producer during stage/build/retire; coalesce and wrap under staged export);
  counts, identities, exported repetitions and explicit loss accounting verified;
  bounded critical-section work proven (CS depth/cost evidence).
- Sources: same `.inc` (per-function CS on tx/push/pending/dequeue/finish/
  reject/AF table; identity-aware `popPeeked(sel, seq)`)
- Fixtures: `test_staged_retire_identity` (overwrite-then-retire reports loss,
  newest intact, positive control retires); CS depth bound (<=4) in M1 tests
- Final SHA / run / jobs / results: pending (M1 push awaited)
- Implemented / tested / independently verified: yes / pending-hosted / no.

## A04 / S04 — SREQ generations, no stale SRSP clear

- Required: queued reply completing after a newer SREQ dispatch and before its
  reply leaves suppression set until the matching terminal event; same-command
  repetitions and dropped/error responses through patched MT/NPI call sites.
- Sources: same `.inc` (`sync_gen`/`sync_seq`, SRSP gen stamping, gen-gated
  clear, stale-completion event, error-SRSP terminal)
- Fixtures: `test_sreq_generations` (overtake, repetition, error SRSP)
- Final SHA / run / jobs / results: pending (M1 push awaited)
- Implemented / tested / independently verified: yes / pending-hosted / no.

## A05 / S05 — fair exports, true deltas, genuine progress ages

- Required: >=15-minute one-second poll fixture with sticky fault, pressure,
  busy intervals and MT refusal; nonzero schedule deltas; all 13 resource
  selectors within documented bounded max age; retained overdue work;
  first-fault repeat availability; bounded ring draining; exact wire budgets
  (1 frame / >=5 s, <=240 B payload, <=4 records); observed emitted bytes.
- Sources / fixtures / evidence: pending.

## A06 / S06 — early NV records survive MT init

- Required: main-order fixture runs actual NV init/failure/recovery hooks before
  actual MT init, then exports; each early event and first-fault identity
  survives with truthful timing; linked main reset-capture proof retained.
- Sources / fixtures / evidence: pending.

## A07 / S07 — accurate bounded AF correlation

- Required: actual AF request/SRSP/confirm paths for duplicate keys,
  oldest-first removal, nonzero confirm status, rejected/dropped SRSP, AREQ and
  timestamp wrap; exported state and raw statuses inspected.
- Sources / fixtures / evidence: pending.

## A08 / S08 — bounded collection, no lost unread data

- Required: repeated small-budget polls recover every complete line exactly
  once; huge lines/backlogs/lock contention within explicit memory/time
  allowance; delayed/blocked capture exits within positive deadline + tolerance,
  never authorizes reset, leaves resumable state. Hosted subprocess tests.
- Sources / fixtures / evidence: pending.

## A09 / S09 — exact partial-line bytes across polls

- Required: three polls before newline, multiple partials, split UTF-8, rotation
  with partial; byte-for-byte raw line, correct offsets, one host event/record,
  no spurious decode errors through both decoder representations.
- Sources / fixtures / evidence: pending.

## A10 / S10 — production-faithful triggers, no healthy reset

- Required: actual candidate YAML trigger evaluator driven with healthy removal,
  ordinary permit_join success, unrelated error, malformed payload, qualifying
  SRSP timeout; only qualifying outage/timeout events reach reset authorization;
  pinned production source SHA recorded.
- Sources / fixtures / evidence: pending.

## A11 / S11 — stabilization can close, honestly

- Required: actual candidate automation timer advanced through a healthy
  >=600 s window closes exactly once; gaps, stale sensors, absent real ZDO/
  traffic evidence, transient outages and host reboot cannot close;
  outage-derived Boolean alone never becomes ZDO proof.
- Sources / fixtures / evidence: pending.

## A12 / S12 — correlated waits, persisted failures

- Required: actual YAML/script execution with already-online bridge, fast
  response, unrelated/stale response first, no response, failed stop/reset/start,
  tool/API failures; one RTS maximum; failure persisted; serial ownership
  prerequisite; only matching fresh success reaches stabilization.
- Sources / fixtures / evidence: pending.

## A13 / S13 — frame-level continuity, honest replay/BOOT handling

- Required: real batched C bytes through herdsman and both decoders; first BOOT
  not first record; delayed BOOT; sequence wrap; copied rotated logs; replay
  with lower uptime; actual reboot. Same-frame records share association;
  replay/delay never selects a false current boot.
- Sources / fixtures / evidence: pending.

## A14 / S14 — invalid latch/hash schemas fail closed

- Required: valid-JSON wrong types, missing fields, unknown schema/status,
  inconsistent reset-used/state, empty/incomplete hash inventory and missing
  required payloads cannot grant reset or fresh incident; normal closed/cleared
  lifecycle still works; concurrent invocations serialized.
- Sources / fixtures / evidence: pending.

## A15 / S15 — bounded private store, unknown-time supplement

- Required: repeated rotations/bundles under small total byte allowance stay
  bounded; active bundle intact; failures cannot silently delete the only active
  evidence; unknown/naive timestamps preserve bounded raw rows separately with
  honest time provenance.
- Sources / fixtures / evidence: pending.

## A16 / S16 — observed vs declared build identity

- Required: matching bundle binds; wrong variant, stale manifest, mismatched
  file hash, candidate-only role and observed different build fail binding or
  yield explicit mismatch/unavailable; boot/incident identity truthful across
  firmware changes.
- Sources / fixtures / evidence: pending.

## Sealed final evidence (pending)

- Final SHA: pending
- Diagnostic image (HEX/OUT hashes): pending
- Control image (HEX/OUT hashes): pending
- Runs/jobs: pending
- Provenance/manifests/symbols/maps: pending (CI artifacts)
