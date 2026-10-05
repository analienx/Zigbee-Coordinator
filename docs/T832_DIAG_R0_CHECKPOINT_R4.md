# T832-DIAG-R0 R4 checkpoint

- Goal: R4 F01–F12 on retained candidate PR38 (draft, base
  exp/mr4u-p10-ti832-kctrl-r0). Starting SHA 8d59a798, worktree clean.
- Brief: `2d2b3453-…` SHA256 verified
  `697438be918cb5e988d95487eeb827b2b34730ba6aa0173af5cc0759576369e0`,
  read fully.
- Native goal: `goal-01a10aae-fb82-74e3-b031-6fab5e1322f1` active, 5%.
- R3 preserved: run 37237963282 green 5/5 at 8d59a798. No R0–R3 relaunch.
- Issue 73: open, latest comment 2026-10-03T10:01:37Z (unchanged, 27 comments).
- Authority: hosted-only builds/tests; local inspection/edit allowed; no
  local repo tests, no flash/live/merge/deploy.
- Ownership: work_list empty, no active writers observed, checkout clean,
  HEAD 8d59a798 matches reviewed, base 47a1a032 matches, PR38 open draft.
  Predecessor R3 goal state not directly queryable from this session;
  transfer assumed per brief after clean recheck; conflict check done.

## M1: Re-anchor and production oracles (in progress)

Exit: adverse fixtures demonstrably distinguish reviewed source defects
from infra failures, through actual external paths.

### F01 (P1) refusal accounting — CONFIRMED in source
- Source: `firmware/t832/t832_diag_impl.inc:922-952`
  `T832Diag_txRefusedUncertain` decrements normal_pending on any
  header/length match; `1496` FIFO-full blocks export forever on stale
  descriptors. Harness `host_harness/t832_diag_host_test.c:1015-1040`
  expects wrong decrement + completes refused B.
- Required oracle: actual patched SDK entry bodies, A owned/B unowned
  identical headers, owned downstream refusal, all six sites, overflow,
  eight owned AREQs refused then quiet polls.
- Status: source inspected; adverse harness fixture pending.

### F09 (P2) AF oldest-age — CONFIRMED in source
- Source: `t832_diag_impl.inc:470-495`: eviction path recomputes
  af_oldest_ms only if outstanding was zero; 8→7→8 leaves evicted stamp.
- Status: source inspected; adverse fixture pending.

### F10 (P2) saturated coalescing — CONFIRMED in source
- Source: `t832_diag_impl.inc:244-246` record updates last_ms after
  saturation; `1223-1225` popPeeked ignores last_ms/revision.
- Status: source inspected; adverse fixture pending.

### F02–F08, F11–F12 — source inspection queued
- F02 YAML222-238 publish-before-wait; F03 minutes:/5 phase vs 600s/120s;
  F04 close2460-2473 ignores false traffic/zdo; F05 stop/start exceptions;
  F06 capture1761-1773 truthiness + 1522 default; F07 scanner778-854 caps;
  F08 recent_rows1407-1459 earliest-preserved; F11 bind arbitrary build_id +
  1075-1104 mismatch hash; F12 runbook/matrix/cost/PR staleness.
- Status: pending detailed inspection.

## M2 firmware fixes (implemented, hosted verification pending)

- F01: refusal ownership correlated at patched call site. Unowned stages
  (1,2,4,5,6 + MT-response alloc failure) retire nothing
  (`T832Diag_txRefusedUnowned`); stage-3 owned refusal retires exactly the
  generation stashed by the preceding QueuedOther push
  (`T832Diag_npiTxRefusedOwned` + `last_other_gen`, init sentinel).
  Header-match release deleted. Patch site, header, validator updated;
  harness mirror reproduces stage-3 push-before-default order.
- F09: AF eviction/insertion recomputes `af_oldest_ms` via rescan inside
  the atomic section (covers insert, eviction, wrap).
- F10: staged retirement identity gains `last_ms` (exportPoll snapshots,
  both popPeeked branches); saturated coalescing re-stages newer timing.
  Wire format unchanged. Harness decoder now parses first/last_ms.
- New adverse fixtures (fail on 8d59a798, pass fixed): per-stage refusal
  oracle, identical-headers oracle without fabricated completions,
  8×owned-refused drain + export recovery, overflow survivor preservation,
  AF evict age (incl. wrap) with liveAfState assertions, saturated last_ms
  preservation with emitted-bytes decoder assertions.
- Changed: firmware/t832/t832_diag_impl.inc, t832_diag.h, apply_diag.py,
  validate_diag.py, host_harness/t832_diag_host_test.c.

## M3: host capture and durable recovery (implemented, hosted verification pending)

- F02: incident catcher pre-armed (subscribed from HA start), single
  publish, read-only `zdo-proof-state` probe sharing the verdict check
  (`query_zdo_proof`, `t832_zdo_proof_state`). No double publish, no
  fabricated completions. Tests: `R4F02CatcherTests`.
- F03: grace one /5 period (300 s, `STABILITY_OBS_GRACE_S`), midpoint
  belongs to both halves, gap budget 360 s still catches a missed tick.
  Tests: `R4F03PhaseTests` (first-tick offsets incl. 0/1/120/121/130/
  299/300) + phase matrix.
- F04: every observation must hold bridge+traffic+continuity
  (all-must-hold); passive state triggers record inter-tick outages.
  Tests: trigger evaluator + stability close/fail paths.
- F05: every fallible service `continue_on_error` with fail-closed gate;
  terminal persist failures raise `recovery-result-unpersisted`; consumed
  permit retained, no later reset/control action. Tests:
  `R4F05TerminalTests` incl. unpersisted-terminal honesty.
- F06: file absence is the ONLY initial state (`latch_present False`);
  every present value — falsy JSON included — validates before any
  collection/bundle/permit change, bytes preserved; explicit boolean
  permit required; audited manual repair explicit, never automatic;
  cleared latch carries explicit unused boolean permit. Tests:
  `R4F06LatchTests` (falsy rejection + `incident-latch-` discriminator,
  `reset-used-missing`, nonforce-falsy, force-audit).
- F07: verify-after-open (fstat identity vs path stat, rescan-from-zero on
  replace) + shared `_deadline_exceeded` single time source +
  deadline-commit (prefix commits with `collect-deadline-exceeded` note,
  next poll resumes exactly once; no TimeoutError loss). unreadable paths
  return explicit notes. Tests: deadline-commit-and-resume, helper
  single-source.
- F08: newest chronological pre-hang tail — oldest-first stream into a
  bounded maxlen ring (sheds oldest above cap with `window-rows-capped`
  note), stable ascending SOURCE-time sort; `diag[-1]` selects the actual
  latest diagnostic state. Tests: above-cap newest-fault preservation
  (single-file), midnight multi-file source-time order.
- F11: manifest-derived wire-ID uint32 range gate, caps recorded in the
  mismatch note, authorize-time observed-vs-bound verdict after
  hash/inventory. Tests: `R4F11AuthorizeCliTests` + mismatch/build
  binding tests.
- Changed: `firmware/t832/t832_incident.py`,
  `deploy/t832_capture_barrier.yaml` (3-automation catcher wiring),
  `deploy/t832_shell_commands.yaml` (`zdo-proof-state`),
  `firmware/t832/test_diag.py`, `test_automation.py`, `test_barrier.py`,
  `test_stability.py`.

## M4: seal and honest handoff (in progress)

- F12 docs: runbook capture pins qualifying trigger IDs + `--triggers`
  defs SHA + binding roles; close rules state 600 s window / 360 s gap /
  all-must-hold / midpoint-in-both / 300 s out-of-window grace /
  falsy-latch validation / explicit-permit cleared state /
  `zdo-proof-state` probe; window section states newest-tail +
  `window-rows-capped` + source-time latest state. Matrix R4 rows added
  (F01 ownership, F09 rescan, F10 `last_ms`, F07/F08, F02–F06/F11).
  Cost doc queue-hook corrected (full FIFO refuses, oldest never
  evicted; call-site refusal ownership).
- F12 neg control: `t832_neg_r3.c` gains `r4-f01` (unowned refusal
  retires nothing) and `r4-f09` (evict recomputes oldest survivor)
  probes with per-probe `NEG-PROBE`/`NEG-FAIL` identification; job
  requires every probe ran + `NEG-RESULT` + ≥1 intended `NEG-FAIL` per
  R4 probe (nonzero exit alone no longer suffices). New host neg steps:
  4 named R4 tests must FAIL on the HEAD-module overlay (identified
  `FAIL:` lines); F07 TimeoutError-loss probe script on HEAD.
  Excluded from host neg: automation/YAML tests (defect+fixture both
  uncommitted — no pre-R4 pairing) and force-clear (KeyError-shaped on
  old code, not an assertion); F10 shares the B02 assertion shape
  (coalesced occurrence must survive) — see probe header.
- Reviewers: 3 independent read-only reviewers spawned (firmware,
  host, docs/neg-job).
  - Docs/neg-job: PARTIAL (docs PASS with nits; neg-job FAIL-blocking).
    Repaired: neg `git show HEAD:` pinned to `8d59a79891be...` (+comments/
    echoes); rotation arithmetic corrected to 2 selectors/export, ~7 min
    full rotation (cost doc + matrix); runbook probe boot wording fixed
    (continuity enforced at close, not in probe); stale headers comment
    corrected. Reviewer verified all 4 host-neg test IDs exist and
    genuinely FAIL on the pre-R4 module, C symbols against the R2 tree,
    and all doc numbers against source.
  - Firmware (F01/F09/F10): PASS (advisory). Post-report repairs:
    stash-consume added to the Owned DIAG-frame branch (latent leak
    hardened, unreachable today); validator pins added (QueuedOther <
    RefusedOwned order, 5-arg popPeeked identity, afOldestLocked
    presence); F09 wrap-half test now genuinely crosses 2^32
    (0xFFFFFFE0 start, victim 0xFFFFFFF0, survivor 0x00000000).
    Accepted limits noted: liveAfState unlocked read (benign),
    DIAG_LOSS 3u staged==live==0xFFFF indistinguishability, F10 neg via
    B02 lineage, patch-order anchors in CI not worktree-verifiable.
  - Host (F02–F08/F11): FAIL-driven repairs in progress —
    1. F06 force-repair regression (`state-corrupt` re-raised under
       `--force`, broke pre-existing `test_force_clear_audits_and_unbricks`
       + new corrupt-latch test): REPAIRED (force now audits +
       resets, matching reviewed behavior + brief's audited-repair rule).
    2. F02 harness root cause (`run_body` fed dict conditions raw into
       string-only `eval_condition`, 15 automation failures): REPAIRED
       (new `eval_any_condition` unwrap, same shapes as choose/repeat).
    3. New-test assertion bugs (`assertNotIn("zdo_proof")` unsatisfiable —
       failed latches carry the check detail): REPAIRED (assert
       unverified + `"missing"` detail).
    4. Stale `test_zdo_proof_uses_incident_transaction` (late-probe
       branch): REPAIRED (assert wait-branch observed transaction +
       late-branch incident transaction separately).
    5. F05 catcher gate (`t832_catch_proof` tolerated, unconsumed):
       REPAIRED in product (consume gated on proof rc==0; error leaves
       expectation armed for duplicates; all terminal branches clear).
    6. Minors folded: F08 traversal-skew wording (docstring + runbook),
       pre-R4 cleared-latch migration note (runbook); falsy-capture test
       added to host neg list (5 neg tests). Known gaps kept explicit:
       verify-after-open path untested, `b"deadline"` sentinel note-only
       collision, authorize-time scan bounded by bundle caps, F10 neg via
       B02 lineage, automation/YAML tests excluded from host neg (no
       pre-R4 pairing).
- Seal/CI/PR pending: exact-final-SHA hosted 5-job green, artifacts
  (images/symbols/hashes/maps/schema/host tools/provenance), full PR38
  description update, Codex handoff with `flash_authorized=false`,
  no merge.
- CI#1 run 37277551741 on dd9ea8d: negative-control SUCCESS (B01/B02 +
  R4-F01/R4-F09 intended failures reproduced); firmware/interop/
  host-regressions/control FAILED pre-repair-verdict:
  (a) harness use-before-definition (`sdk_sendToHost_mirror`) broke all
  gcc builds; (b) 4× `test_mesh_outage_runs_to_stabilizing` — nested
  catcher run clobbered the outer `bus_mark`, outer scan skipped arrived
  messages, mid-run suppression lost (runs still completed);
  (c) 2× stop-phase terminal tests wrongly expected RTS==1 although stop
  precedes the reset helper (fail-closed is rts==0, permit retained);
  (d) `late-tick-closes` leg built a 450 s gap (>360 budget) instead of
  a phase shift — correctly failed as coverage gap.
  Repair round 2 (uncommitted when CI#1 ran): forward declaration,
  `bus_mark` save/restore in `deliver_catchers`, rts==0 fail-closed
  assertions, phase-shifted late leg (150/450/750, gaps 300, close 750
  inside grace — consistent with the R4F03 phase matrix).
- CI#2 run 37280268910 on a584006: negative-control SUCCESS again;
  firmware/interop/host/control FAILED with 6 harness CHECKs, all one
  chain: (i) stale R3 B01 assertion (`pending==0` after unowned
  alloc-failure; R4 keeps the unit); (ii) REAL bug: descriptor
  generation 8 collides with the `T832_DIAG_TXQ_DEPTH` stash sentinel,
  so every 8th push after a reset (and each queue_gen wrap onto 8)
  made the owned refusal skip — txq/pending stuck, export's
  nonzero-pending early-return stalled, downstream emit/drain/mismatch
  checks cascaded. Repair round 3: generation 8 is never assigned
  (skip in txPushLocked); B01 test updated to R4 semantics. The k=7
  loop iteration in `test_f01_owned_refusals_drain_and_export` is the
  pinned regression for the collision.

## CI#3 evidence (exact SHA 15eb803bc208de3a70e539e930daac827a10902a)

Run 37282777884: 5/5 SUCCESS (firmware, control, interop,
host-regressions, negative-control). Artifacts
`mr4u-p10-t832-diag-r0` (33 files) + `mr4u-p10-t832-control-r0`
(16 files): images, maps, generated sources, provenance, SHA256SUMS —
all 49 files hash-verified against the hosted SHA256SUMS; manifests pin
repository_commit 15eb803 with flash_authorized false. PR38 description
rewritten with final SHA, run id, repair history, reviewers, limits.

## Next action

Record the final exact-SHA green run above; commit this ledger; push;
watch hosted CI#4 to green on the new final SHA; reconcile artifacts;
hand off for Codex acceptance with flash_authorized=false. No live
actions, no merge.
