# T832 R11-DIAG checkpoint (parent-owned, bounded)

Goal: R11-DIAG from pinned PR46 (operation/site-aware NV first fault, bounded
restored-startup milestones, backward decoder, honest reset-retention limits,
exact-SHA hosted NV/BASE/DIAG CI, 3 blind reviews + challenger).
Oracle: A0-A9 ledger, draft PR, immutable hashes, four PASS or BLOCKED/PARTIAL.
Hardware: PENDING always. NO flash/merge/live radio/HA/Z2M/network changes.

## M0a freeze (2026-10-08, parent)

- Base: PR46 `codex/t832-r10-preserve-startup-nv` @
  `904ef7911b21bd3cd4534354f3285f9b21d9ed3d` (OPEN, rechecked via gh; matches brief).
- R11 branch: `codex/t832-r11-diag` from 904ef79 (clean, sole writer: this session).
- R11 worktree: `C:\Workspace\worktrees\zigbee-t832-r11-diag` (sole-write slice).
- SDK (from t832-diag-build.yml; coder to freeze exact archive/toolchain SHA):
  sdk @ `6499c3f53fc5fb5806213be695450a7b43fbaf3d`,
  sdk833 @ `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`, CCS 12.8.0 SimpleLink.
- Out of scope: `codex/t832-r10-counter-seal` +2 commits (6c20a4b, d756f42)
  are NOT in PR46; R11 stays clean from PR46 head.
- Protected (never modify): minimal-debug worktree, R8 .tmp, production/private
  recovery checkout, R10 branch, remote protection; no force-push.
- Lane: PUBLIC EDIT-ONLY. Local edit/inspect only. All build/test/lint/verify
  evidence from GitHub-hosted Actions at exact candidate SHA. No local runs.

## A0-A9 (all PENDING unless noted)

- A0: M0a done (freeze + isolated ownership); SDK/toolchain SHA freeze -> coder M0.
- A1-A4: pending M0 investigation record (M0.md) + M1-M3 implementation.
- A5-A9: pending.

## Next action

- Workflow M0: investigation-only coder writes `firmware/t832/r6/M0.md`
  (no source changes), then 3 blind lanes + challenger review the record.
- Review before M1; stop if hooks unsafe. Then M1-M4 workflow, hosted CI, M6 PR.

## Isolation incident 2026-10-08 (parent read-only audit, supervisor-ordered)

- Supervisor flagged counter-seal worktree dirty:
  `firmware/t832/r7/t832_hw_qual.py` (+2/-1, adds `"identity"` to the
  vendor-rollback ordering tuple in `check_phase`), mtime 2026-10-08T20:34:18Z.
- PROVENANCE: this session's M0 workflow child #1 (coder). Root cause is a
  parent args-encoding error: Workflow `args` was passed as a JSON-encoded
  string, the script saw a string and fell back to defaults ("Implement the
  assigned task" / "current workspace"). The child therefore worked in its
  file-tool root (counter-seal R10 tree), fixed HEAD's red-first test, and
  RAN LOCAL TESTS (reported 27/27 + 65/65) -- a PUBLIC EDIT-ONLY violation;
  those results are non-authoritative and the whole run's verdict is VOID.
- Action: did NOT alter/restore/delete/commit the file per supervisor order;
  stopped the void workflow run. No commits made anywhere by this session
  (counter-seal HEAD still d756f42, R11 HEAD still 904ef79).
- R11 sole-writer ownership: ESTABLISHED (R11 tree holds only this
  checkpoint, untracked). M0 relaunched with args-as-object plus a
  brief-receipt fail-closed (child must quote the R11 slice path first or
  STOP / reviewers return PARTIAL P0 no-brief).
- Retry note: the args-as-object relaunch showed the same transport note
  (script sees a string); stopped before its coder wrote anything (trees
  verified unchanged). Relaunched self-contained: M0 task/repo/acceptance
  hardcoded in-script, JSON.parse-tolerant args, script-level guard aborts
  the writer if the brief sentinel is absent.

## New brief F1-F4 reconciliation 2026-10-09 (parent)

- New goal brief f0c0ef04 (sha256 dc1df950..., verified) orders concrete
  F1-F4 implementation from 904ef791. M0 research HEAD a9b5e7a9 accepted as
  base; supervisor orders: don't restart M0.
- M0 commit verified: a9b5e7a9, single file firmware/t832/r6/M0.md
  (731 lines), proof-of-receipt present, read-only, no code change.
  Formal M0 review verdicts UNRECOVERED (runtime restart; child replay
  unavailable on Windows; workflow resume blocked on UNC scriptPath).
  Recorded honestly; final R1 gate re-verifies M0-derived claims.
- Counter-seal tree still holds only the known supervisor-flagged dirty
  file (untouched per order; accidental local results VOID). R11 sole-write
  slice clean (only this checkpoint, untracked).
- CI: no in-progress jobs (latest: R7 regression on other branches).
  Revisions 8320051/8320052 unused in tree: available for BASE/DIAG.
- Next: sole-writer F1-F4 workflow (self-contained script), hosted exact-SHA
  CI, draft PR against codex/t832-r10-preserve-startup-nv (NOT main).

## F1-F4 review verdict FAIL 2026-10-09 (parent ledger)

- Workflow completed review-blocked. Verdicts: coder BLOCKED/red-CI;
  semantics FAIL; evidence PARTIAL; regression FAIL; challenger FAIL.
  Zero PASS. Offline-candidate claim BLOCKED per contract.
- Pushed code SHA f1bf490 (PR47 head, draft, base PR46 branch, no merge):
  3/3 hosted R11 runs failure; latest 37903710768 nv-lab FAILED in ~36s
  (verify_startup_guard export9: 212 failures of 704 cases/384 runs +
  GateError); firmware/matrix skipped. Local d4ec6c4 docs-only, unpushed.
- P0 (all agree): acceptance unproven. Guard pins pre-R11 contract
  (a7==(0,init_status), a9 latch, single FAULT ev29, TOPOLOGY/COUNTERS)
  while R11 emits First16B/Current12B, a7 fault_id, gated FAULT.
  Stale-vs-genuine per-case split UNRESOLVED. Green only: r7 vendor 4/4,
  trial 34/34, r6 74/74 (synthetic R11 decoder units), trace 7.
- P1: explicit-COMPACT stale api (WRITE latched for 0x10); patch-placement
  unexercised (harness drives capture() directly, bypasses ternary+anchors);
  fairness starvation on legacy-idle; dual-snapshot runtime race;
  startup valid-clobber (NLME bits never survive; harness shape never
  emitted); hash-zero suppression. P2/P3: decoder a-field leniency
  (bit11-only, 0x1400/0x17F0 accepted); COMPACT BADPARAM over-broad;
  MT-refusal side-effect order; size-label 233/234/240 conflation;
  unproven 60s-repeat/gates/5s/CREATE-27/wrap-sat; boot-zero STARTUP_V1.
- Push budget M5 3/3 spent. Repair authorized max +3 pushes (cumulative 6),
  changed inputs per two-identical-signature rule, then re-review.
- Next: sole-writer repair workflow (self-contained), recategorize 212
  guard cases first, fix P0/P1, hosted green incl BASE/DIAG + real-parser
  chain, update PR47, R1 re-review at final SHA.

## Repair round 1 verdict FAIL 2026-10-09 (parent ledger)

- Verdicts: 3x FAIL + challenger FAIL, zero PASS, no malformed reports.
  Push budget 6/6 spent. Local 525fef7 unpushed (docs-only BLOCKED record,
  zero hosted evidence); PR47 head still 72e7fd0.
- STEP A: 212/212 stale-oracle direction agreed; strength PARTIAL
  (single-source: no reviewer independently inspected report.json rows).
  Green closers: 0/384 + nv-lab SUCCESS at 72e7fd0.
- Firmware matrix at 72e7fd0 BLOCKED (unanimous P0): BASE FileNotFoundError
  (audit not variant-aware: BASE never installs DIAG-only r11_startup.h);
  DIAG IsADirectoryError (exact BDB source file unnamed, dir passed to
  read_text). Fixes agreed sterile/two-line but unpushed. E1/B1 not run.
- STEP B code fixes NOT IMPLEMENTED (checkpoint admits): valid-lifetime
  assign, single snapshot, fairness liveness, MT-refusal order, boot-zero
  guard, decoder strictness, BADPARAM scope, size labels, hosted
  60s/5s/CREATE-27/wrap-sat/gate/anchor proofs, hw-qual re-audit.
- Challenger-NEW P0: guard-green does not transfer to device (pinned
  (0,1,1,1) needs generation==fault_id==1, true only in single-capture TU;
  real boot latches fault_id>=4, cold-boot auto-compact latches
  api=UNKNOWN/item=0/sub=0) + wrap aliasing + TU-vs-ring census gap.
- Owner decision: NOT at impasse (fixes precisely diagnosed, push/CI path
  works, goal requires hosted green + PR). Grant repair round 2: max +3
  pushes (cumulative 9), changed inputs per two-signature rule, tight scope:
  (i) variant-aware audit + exact BDB file vs pinned SDK, (ii) STEP B +
  challenger P0 re-triaged vs green firmware baseline, (iii) seal/CI-green
  at exact SHA, update PR47, R1 re-review. STOP and report if still red.

## Repair round 2 verdict FAIL 2026-10-09 (parent ledger)

- Verdicts: 3x FAIL + challenger FAIL, zero PASS, well-formed. Push budget
  9/9 spent. HEAD 3fac4ce pushed = PR47 head; tree clean.
- Green at 3fac4ce: nv-lab SUCCESS + BASE8320051 SUCCESS (CCS+package).
  DIAG8320052 FAILURE is one deterministic line: DIAG allowlist permits
  only mt/r11_startup.h copy while patch_startup copies the header into
  4 dirs (mt/startup/zdo/bdb); r11_audit.py equally blind. Fix diagnosed,
  unpushed. Downstream DIAG steps (run_r11_host/CCS/E1/B1 bundle) skipped:
  zero evidence at final SHA. Push-3 C-test corrections hosted-unproven
  (sequencing disputed, either way unproven at final SHA).
- STEP B code fixes inspection-pass, hosted-proof missing. Challenger P0
  (device transfer: fault_id>=4 bound, UNKNOWN/0/0 latch, wrap alias,
  ring census) unaddressed; challenger NEW P1s: explicit-compact stale
  inheritance (install_ctx=0), E1 oracle unsatisfiable for cold-boot
  (needs dual-sequence oracle). Fairness breakthrough partially disputed.
- Owner decision: converging (guard -> nv-lab+BASE -> one DIAG line +
  proofs), not impasse. Grant FINAL repair round 3: max +3 pushes
  (cumulative 12), changed inputs per two-signature rule: (1) allowlist
  line + dead runtime + fairness breakthrough + 2 challenger P1s,
  (2) real-boot-equivalent + hosted end-to-end proofs, (3) push/CI-green/
  PR47/re-review. If still red: STOP, report BLOCKED, no further pushes.
## F1-F4+M5 implementation 2026-10-09 (sole writer)

- Base: M0 a9b5e7a9 on PR46 head 904ef79; branch codex/t832-r11-diag; R11 slice only.
- F1: compact classified by NVOCMP_COMPACT_FAILURE (0x10); SRCDONE/DSTDONE/BOTHDOE benign;
  raw domain/status preserved; EXIST/NOTFOUND and explicit-compact no-work BADPARAM benign only;
  historical a8 marked ambiguous in schema/decoder/docs.
- F2: NV POD carries First16B (fault_id/item/sub/api/sys/site/status/phase-domain/known)
  plus Current12B generation context; 116 B at 15 pages, 124 B at 18 pages, cap 128 B;
  first meaningful failure immutable; auto-compaction inherits caller; prelock exits unavailable.
- F3: 8-site startup POD (main initNV, BDB restored, ReadNetworkRestoreState,
  RestoreNetworkState/NLME, SecInit, NetworkInit, formation confirm, NetworkStartEvt)
  with entry/exit masks, generation, validity; observer-only TI patches, no logic changes.
- F4: atomic 4-record frames 51 NV_FIRST_V1 / 52 STARTUP_V1 / 53 RUNTIME_V1, cap bit30,
  bit31 clear; 30 s runtime cadence; 60 s repeats; fairness reserves legacy after two
  extended frames; strict decoder rejects torn/duplicate/missing/mixed groups.
- M5: series R11 BASE8320051/DIAG8320052; diag RAM assert <=4096 B; SRAM floor 8192 B;
  FLASH_NV exact 0x7800 at 0xF8800; real C exporter to pinned herdsman 10.9.1 to decoder;
  red-before-green negative control fails on original source (hosted).
- Evidence: hosted exact-SHA CI on push (nv-lab + firmware BASE/DIAG matrix), draft PR
  base codex/t832-r10-preserve-startup-nv, no merge. Hardware: always PENDING.

## Hosted CI BLOCKED 2026-10-09 (sole writer, push budget exhausted 3/3)
- Final SHA: f1bf490, PR47 draft OPEN, base r10-preserve-startup-nv, no merge.
- Green at final SHA: r7 vendor-contract (4), r7 trial-bundle (34), r6 suite (74).
- Red: verify_startup_guard, 212 failures. Cause: its probe uses the real R11 capture
  and export files, but its export9 checks still encode the old first-failure contract.
- Fix direction, not applied, budget spent: teach the guard the R11 a7 and FAULT
  semantics; keep all preservation checks byte-exact. Case list is a named gap.
- Pre-existing out of scope: r7 hw-qual counter-seal regression on untouched files.
- Not yet run, blocked behind the guard: nv-lab vendor run, red-first, regressions,
  sizeof proof, BASE and DIAG firmware matrix, herdsman chain. HW always PENDING.

## R11 REPAIR STEP A 2026-10-09 (sole writer)

- Brief receipt: R11 slice `C:/Workspace/worktrees/zigbee-t832-r11-diag`,
  branch `codex/t832-r11-diag`, base local d4ec6c4 (docs-only over pushed
  f1bf490 = PR47 head). File-tool root
  (`C:/Workspace/worktrees/zigbee-t832-counter-seal`) NOT modified; no
  contact with counter-seal/minimal-debug/R8/private checkouts. Lane:
  PUBLIC EDIT-ONLY (reads/edits/gh inspection only; no local run of repo
  code; CI only via push).
- Hosted inputs, read-only (`gh run view --log-failed`, `gh api .../artifacts`):
  run 37903710768 (push, SHA f1bf490f03fe34fb5f6bda86cb2fc36bfd85b453,
  conclusion failure, ~36 s): nv-lab fails at verify_startup_guard with
  `{ok:false, rejection_cases:704, sanitizer_sweeps:352, admit_runs:64,
  cost_runs:44, export9_runs:384, failures:212}` + GateError
  (`startup preservation gate failed; see report failures`); all downstream
  steps skipped (firmware/matrix never ran); artifact upload
  t832-r11-nv-evidence FAILED (`No files were found ... nv-evidence`) so the
  run carries ZERO artifacts and the per-case report.json is unrecoverable
  hosted-side. Runs 37902746074 and 37902316273 (same branch) also failure
  with ZERO artifacts.
- Structural fact (from the failed log): export9_done (384) ==
  export9_expected (384): EVERY reject/admit case reached the export9 probe,
  so all pre-export9 checks PASSED on every lane x case: reject/adverse image
  immutability, zero physical ops, init/re-init stability, TI sanity bit,
  oracle tag agreement, latch-tuple equality vs oracle_latch, a9-oracle path.
  The 212 failures are therefore confined to export9 projection checks.
- R11 encoding delta, proven by source diff 904ef79..15db7cb (no execution):
  `r6_nv_export.inc` a7 changed from `(init_action, first_failure)` to
  `(init_action, fault_id & 0xFFFF)`; FAULT ev29 changed from
  `(8, first_failure, first_failure_requested)` to
  `(8, first.status, first.requested)` gated on `fault_id != 0`; a8, a9,
  TOPOLOGY, SPACE, COUNTERS emission lines are byte-identical pre/post R11,
  and `T832R6NvSnapshot` keeps `rej_*`/handle fields used by them.
- Guard-TU capture topology, proven by source (no execution):
  `nv_recovery_fix.py` (the only patch applied to the guard TU's nvocmp.c)
  contains ZERO `T832R6Nv_capture`/`captureCtx`/probe references; the single
  capture in the TU is the probe's manual stage-8
  `T832R6Nv_capture(8u, 0u, NVOCMP_failW)` in `startup_guard_probe.c`
  `export9`. Hence in each export9 process: no init captures fire,
  `current.generation` 0->1, `fault_id==1`, `init_action==0` (no stage-7),
  `first.status=(uint8)failW`, `first.requested=0`, with failW==init_status
  by the re-init-stability check that already passed. So R11 emits
  a7==(0,1) while the guard pins a7==(0,init_status): failure iff
  init_status != 1 (NVINTF_FAILURE==1). FAULT emits (8,init_status,0),
  matching the pinned bytes. a8/a9/TOPOLOGY/SPACE/COUNTERS emit pinned bytes.
- Check-level categorization (stale-oracle vs preservation-identical):
  STALE (pins pre-R11 projection, preservation bytes provably identical):
  `export9 a7 not NORMAL_INIT/first-failure` only. PRESERVATION-IDENTICAL
  (emission + snapshot fields unchanged by R11, expectations independently
  sourced): `production export rejected by trial checker` (structural
  range/u16/order rules; R11 bytes satisfy them exactly as base bytes did --
  provisional, confirm from per-case errors), `export9 verb mutated image`,
  `export9 wrote`, `export9 init disagrees with reject init`,
  `export9 record census wrong`, `export9 stage record wrong` (a8),
  `export9 a9 mispacks the latch`, `export9 FAULT record wrong`,
  `export9 TOPOLOGY/COUNTERS bytes wrong`, `export9 SPACE shape wrong`, and
  all admit-path export9 checks (admit a7 bytes are (0,0) both pre/post R11).
- Count fit: 212 = 4 lanes x 53: predicts 53 reject cases/lane fail at the a7
  check (init_status != 1) while 35 reject cases/lane (init_status == 1) and
  all 8 admit cases/lane pass. CONFIRMATION PENDING from per-case report:
  every one of the 212 `failures[].error` strings must carry the prefix
  `export9 a7 not NORMAL_INIT/first-failure`; any other prefix (mutated
  image, wrote, unstable, latch mismatch, FAULT, TOPOLOGY, COUNTERS, trial
  checker) is GENUINE breakage and re-scopes the fix.
- Caveat: each per-case entry records only its FIRST failing check, so for
  failing cases the checks after a7 (a9/FAULT/TOPOLOGY/SPACE/COUNTERS) are
  UNEVALUATED. Full evaluation of every check on every case requires the
  guard fix + a green run; a green run is therefore the categorization
  closer, not just the fix proof.
- Self-contradiction resolution (guard-fix doctrine for the next push; NOT
  yet implemented): the guard keeps every preservation check byte-exact and
  keeps rejecting the OLD encoding where bytes differ; it accepts the R11
  a7/FAULT encoding ONLY via (i) cross-channel exactness against POD fields
  printed by the same export9 process (new `first_fault` JSON: fault_id,
  status, requested, generation), plus (ii) independently sourced anchors:
  a7.b==0 (no stage-7 in this TU), fault_id==1 (exactly one store: zero init
  captures + one manual capture, proven by POD generation==1), a7.c==1,
  first.status==reject-verb init_status, first.requested==0, FAULT
  presence iff fault_id != 0 with (8,init_status,0). No `or`-branch may
  accept stale bytes; any double-latch/overwrite (generation != 1) fails
  closed and forces re-derivation. Admit path additionally pins a7==(0,0).
- Named gaps: G1 per-case 212 rows (report.json never uploaded; recovery:
  forensic always-upload in THIS push, then hosted read); G2 post-a7 checks
  unevaluated on failing cases (recovery: green run); G3 trial-checker
  per-case verdict (from report error prefixes).
- Assumptions: probe verbs deterministic per image across processes (lanes
  symmetric: 212 divisible by 4); failW==init_status at manual capture;
  NVINTF statuses fit uint8 (no first.status truncation); guard green at
  base 904ef79 (script identical base->R11; exporter delta proven by diff).
- Push log: this push (#4 cumulative, budget 3+3 max 6) = STEP A record
  (this section) + forensic always-upload (nv-lab `t832-r11-nv-evidence`
  now also uploads `nv-evidence-startup-guard`, `nv-evidence-corrupt-copy`,
  `nv-evidence-write-gate`, `vendor-nvs-audit.json`). Zero behavior change
  to code under test; expected signature identical (guard 212 + GateError)
  WITH the per-case artifact attached. 2 pushes remain for fixes + seal.
- STEP B survey (all NOT IMPLEMENTED; file pointers for the fix push):
  stale-API install order + valid-lifetime OR-accumulation + single snapshot
  (`nv_r6_probe.inc` T832R6Nv_store); fairness liveness + MT-refusal
  side-effects + boot-zero guard (`r11_ext_export.inc` tryExport/sendGroup);
  decoder strictness 51/52/53 (`r6_observer.py` decoder + `t832_incident.py`
  EVENT_NAMES); patch-anchor ternary (`r6_observer.py` apply_observer,
  anchors nvocmp/zd_app/bdb/main); COMPACT BADPARAM scope (pinned TI source
  nvocmp.c:1242/:1247 vs blanket exemption); size labels 233/234/240
  (`r11_ext_export.inc` header comment + docs); hosted proofs
  (60s-repeat/downstream-loss, gate conjunction, 5s boundary, CREATE-27,
  wrap/saturation); r7 hw-qual red re-audit (pre-existing at base SHA).
  M5 seal/push/CI + PR47 update pending final SHA.

## R11 REPAIR STEP A close-out 2026-10-09 (sole writer, run 37913043735 @ 4d9202a)

- Push #4 produced the identical failure signature WITH the per-case artifact
  (forensic always-upload works): guard `{export9_runs:384, failures:212}` +
  GateError; `nv-evidence-startup-guard/report.json` recovered hosted-side
  (write-gate dir absent as expected: it runs after the guard).
- Per-case table, all 212 rows inspected: error-prefix histogram 212/212
  `export9 a7 not NORMAL_INIT/first-failure`; lane split 53x4; 53 distinct
  cases each failing 4/4 lanes (deterministic, symmetric); 0 admit-case
  failures (corpus 88 reject + 8 admit).
- Byte proof from the error-embedded export JSON of every failing row:
  ev49 a7==(0,1) vs pinned (0,init_status); init_status==12 (BADVERSION) in
  all 212 rows; the same exports contain a8==(0,12), TOPOLOGY row0
  (0,15,0), SPACE summary (65535,0,0), COUNTERS row2 (2,0,0), single FAULT
  (8,12,0), exactly one a9. Passing reject rows (140 = 35x4) all carry
  init_status==1, where R11 fault_id==1 coincides with the old pin.
- Verdict: 212/212 STALE-ORACLE. The guard pins pre-R11
  `first_failure=status`; R11 emits `fault_id=generation`, which is 1 in
  this single-store TU (zero init captures + one manual stage-8 capture,
  proven by source). GENUINE R11 preservation breakage: 0 rows.
  Pre-export9 preservation checks passed 384/384 (image SHA, zero physical
  ops, init/re-init stability, TI sanity bit, oracle tags, latch tuples);
  trial-checker check passed 384/384, so NO checker change is needed.
- a9 on failing rows: gate-unevaluated (post-a7) but correctness follows
  from the PASSED latch-tuple check on the same run (rej_* == oracle latch)
  plus the byte-identical a9 packing line pre/post R11. Remaining
  gate-evaluation of #8-#12 on those rows closes with the green run.
- Push #5 result (run 37915257052 @ c30ef6c): GUARD GREEN --
  `verify_startup_guard` prints `{ok:true, rejection_cases:704,
  sanitizer_sweeps:352, admit_runs:64, cost_runs:44, export9_runs:384,
  failures:0}`. The R11 a7 doctrine is proven hosted-side: all 384 export9
  runs pass, including gate-evaluation of a9/FAULT/TOPOLOGY/SPACE/COUNTERS
  on the 53 BADVERSION cases (G2 closed by green, not by argument).
  `verify_corrupt_duplicate` and `verify_write_gate` also passed (step
  reached `run_nv_lab`). New sterile failure, different signature:
  `run_nv_lab.py --out nv-evidence` dies with FileExistsError because the
  workflow step pre-creates `nv-evidence` via `mkdir -p` while the script
  requires `exist_ok=False`. Latent R11-workflow bug (run_nv_lab never ran
  on this branch: the guard always failed first). Fix in THIS push (#6,
  last of budget): delete the pre-create line; `run_nv_lab.py` owns the dir.
- Fix in THIS push (#5, two commits): probe export9 prints the first-fault
  POD (`generation`, `fault_id`, `first_status`, `first_requested`);
  verifier replaces the stale a7 check with the R11-pinned triple from the
  STEP A doctrine (a7.b==0; generation==fault_id==1; a7.c==1 with
  first_status==reject-verb init_status and first_requested==0); admit path
  additionally pins a7==(0,0) with fault_id==0. FAULT/a8/a9/TOPOLOGY/SPACE/
  COUNTERS/trial checks UNCHANGED (bytes already match). Zero firmware
  behavior change. Shipped as c30ef6c (run 37915257052: guard green, 0 failures).
  THIS push (#6, last of budget): mkdir-collision fix only, to reveal the true
  downstream state (run_nv_lab vendor profile, red-first, regressions, sizeof,
  firmware BASE/DIAG matrix, parser chain -- none has ever run on R11). STEP B
  P1 code fixes + M5 seal/PR47 are scoped from that signal; see survey below.

## R11 REPAIR Push-6 result + BLOCKED 2026-10-09 (sole writer, budget 6/6 spent)

- Run 37915793186 @ 72e7fd0 (final budget push): **nv-lab job SUCCESS** --
  full lane green for the first time on R11: verify_startup_guard
  `{ok:true, failures:0}` over 384 export9 runs, verify_corrupt_duplicate,
  verify_write_gate, run_nv_lab vendor-20240716, F1 red-first, collector/
  recorder regressions, R11 sizeof proof. The mkdir fix worked; no
  identical-signature retry was needed at any step (every push changed the
  signature or the attached diagnosis).
- Firmware matrix ran for the first time and BOTH variants FAILED on two
  distinct sterile defects in never-executed R11 Python (hosted proof;
  quoted `gh run view 37915793186 --log-failed`):
  - BASE: `FileNotFoundError: sdk/source/ti/zstack/mt/r11_startup.h` via
    `apply_r6.py:70 apply -> audit_source.py:63/56 -> r11_audit.py:17
    audit_r11 -> read_text`. BASE never installs that header (the copy into
    mt/ lives in DIAG-only `apply_observer`), yet the audit demands it
    unconditionally. Fix direction (NEXT budget): variant-aware
    `r11_audit.py` -- BASE asserts header absence + zero startup hooks;
    DIAG asserts presence. Read `r11_audit.py` + `audit_source.py` fully
    before editing.
  - DIAG: `IsADirectoryError: .../stack/bdb` via `apply_r6.py:70 apply ->
    r6_observer.py:215 apply_observer -> :97 patch_startup ->
    apply_diag.py:55 replace -> read_text`. `patch_startup` passes the
    `bdb` DIRECTORY (r6_observer.py:83) to all three site-2 `ex.replace`
    calls (:97, :98-103, :104-109) instead of a source file. Fix direction:
    name the exact BDB source file carrying `#include "bdb.h"` plus the
    `ZDOInitDevice(0)==RESTORED` / `bdb_setNodeIsOnANetwork(FALSE)` anchors
    (candidate `bdb.c` -- MUST verify hosted against the pinned SDK tree
    before editing; add a listing step or read the tree in the fix push).
- Green hosted evidence banked this turn: trace_nv_caller on BASE+DIAG
  (patch-anchor prerequisites hold on pristine SDK); entire nv-lab lane.
- Ledger map at final pushed SHA 72e7fd0: F1 red-first PASS (hosted);
  F2 sizeof+immutable PASS (hosted); F3 boundaries PASS (guard 0/384);
  F4 frames/decoder PASS at unit level (r6 74/74 + guard green), end-to-end
  cadence proofs PENDING; B1 budgets/artifacts BLOCKED (firmware red);
  E1 real-parser chain NOT RUN (blocked behind firmware); PR47 draft OPEN at
  72e7fd0, base `codex/t832-r10-preserve-startup-nv`, no merge; R1 four
  explicit PASS NOT claimed (reviewers' gate); H1 hardware PENDING always.
- STOP state per brief (no pushes remain): this diagnosis is committed
  LOCALLY ONLY (unpushed, PR47 head stays 72e7fd0). Next session with fresh
  budget: apply the two firmware fixes above, push, and resume M5
  (BASE/DIAG artifacts, E1 chain, PR47 seal, R1 re-review). STEP B P1 code
  items from the survey (install order, valid lifetime, snapshot atomicity,
  fairness, decoder strictness, BADPARAM scope, size labels, 60s/5s/CREATE-27/
  wrap-sat proofs, hw-qual re-audit) remain NOT IMPLEMENTED at 72e7fd0 and were
  scoped for repair round 2 below.
## R11 REPAIR ROUND 2 progress 2026-10-09 (sole writer, PUBLIC EDIT-ONLY)

- Brief receipt: R11 slice `C:/Workspace/worktrees/zigbee-t832-r11-diag`,
  branch `codex/t832-r11-diag`, base local 525fef7 (docs-only BLOCKED record
  over pushed 72e7fd0 = PR47 head). File-tool root untouched; no contact
  with counter-seal/minimal-debug/R8/private checkouts. No local run of repo
  code; CI only via push.
- Scope (i) IMPLEMENTED this turn: variant-aware `r11_audit.py` (BASE asserts
  absence + zero startup hooks, DIAG asserts presence); exact BDB source file
  `bdb.c` in `r6_observer.py` (never a directory); hosted BDB anchor proof
  step in `t832-r11-diag.yml` pinned to SDK 6499c3f53fc5fb5806213be695450a7b43fbaf3d.
- Scope (ii) PARTIAL this turn: valid-lifetime OR-accumulate + confirm OR in
  `r11_startup.h` (NLME survives full boot; `r11_host_test.c` F3 expectation
  updated to 0x1F); boot-zero guard in `T832R11_buildStartup`; MT-refusal
  side-effects past `build_failed` in `T832R11_sendGroup`; fairness liveness
  bypass for overdue runtime/60s repeat; single committed runtime snapshot
  (`T832R11_buildRuntimeSnap` + commit-on-acceptance); decoder strictness in
  `t832_incident.py` (exact 51/52, uniform 53, rejects 0x1400/0x17F0-style)
  with new `test_r11_frames.py` cases; narrowed COMPACT BADPARAM comment
  citing nvocmp.c:1242/:1247; size labels 233-char vs 234B vs 240B in
  `r11_ext_export.inc` + `verify_r11_chain.py`.
- Scope (ii)+(iii) GAPS (not implemented, no hosted proof): 60s-repeat and
  downstream-loss end-to-end proofs beyond the existing MT-refusal scenario;
  gate-conjunction and 5s-boundary proofs; CREATE-27 path; wrap/saturation
  beyond existing delta/age unit checks; end-to-end patch-anchor assertions
  through the real patch_nv ternary and real nvocmp/zd_app/bdb/main anchors;
  r7 hw-qual re-audit at base SHA with log evidence; challenger P0 bounds
  (real-boot fault_id>=4, cold-boot auto-compact UNKNOWN/0/0, wrap aliasing,
  TU-lossless-96 vs bounded-ring census, F3 device transfer on a
  real-boot-equivalent sequence).
- Push 1/3 (ec02c6b) hosted result (run 37922851165): nv-lab SUCCESS
  (guard green + new strict-decoder unit tests pass); sterile (i) bugs GONE --
  BASE audit passed to CCS build, DIAG apply passed to host test. Two new
  next-layer sterile defects diagnosed from hosted logs (different
  signatures, no identical-signature retry): DIAG `run_r11_host` gcc
  `conflicting types for wire_complete_diag` (pre-existing duplicate static:
  host harness defines `wire_complete_diag(uint32_t)` and `r11_host_test.c`
  defined `wire_complete_diag(void)` in the same TU; never compiled before
  because apply always failed first); BASE package `FileNotFoundError:
  nv-lab-evidence/nv-lab-report.json` (pre-existing workflow path bug: the
  downloaded artifact nests `nv-evidence/` one level deeper than the
  `--lab`/`--vendor-audit` args assumed; never reached before because audit
  always failed first). Fixes in THIS turn (push 2/3): rename R11 helper to
  `r11_wire_complete_diag` + 3 call sites; point `--lab` and
  `--vendor-audit` at `nv-lab-evidence/nv-evidence/`.
- Push 2/3 (0f40bfd) hosted result (run 37925205922): nv-lab SUCCESS, BASE
  SUCCESS (BASE8320051 lane green incl CCS build + package), DIAG red on two
  hosted test-expectation defects in `r11_host_test.c` (never executed before:
  apply always failed first): (a) `delta16(21,0xFFFFFFF0)` expects 33, C
  proves 37 (21-(-16)); (b) fairness-reserve CHECK expects tryExport==0 on
  streak 2 with runtime 100000 vs last 0 (overdue) -- the new liveness bypass
  correctly returns 1. Fixes in THIS turn (push 3/3, last of budget): expect
  37; seed NV/startup/runtime-ms to `now` for the reserve CHECK (==0) and
  reset `last_runtime_ms` to 0 for a liveness CHECK (==1).
- Seal/push/CI: PENDING. This checkpoint + code fixes are local-only until
  pushed (budget 3 pushes, cumulative 9). Next: commit, push without force,
  watch exact-SHA hosted CI (nv-lab + BASE8320051/DIAG8320052 + real-parser
  chain), update draft PR47, R1 re-review. If CI red, diagnose and retry
  within budget; after two identical signatures change inputs; then STOP and
  report BLOCKED with logs.

## Codex takeover, 2026-10-09

User requested that Muse stop and Codex finish the candidate. Retained TUI PID
18016 was stopped after exact process identity inspection; its active 82% native
goal is historical, not a completion proof. Existing checkpoint work is preserved.

Final source review found and fixed: unclassified startup headers; startup POD
concurrency/current-field validity; explicit COMPACT/INIT context contamination;
allocation-refusal attempt pacing; production group decoding; changing-startup
starvation; legacy NV_RESULT status compatibility; R11 raw manifest admission;
and missing downloadable parser evidence/runbook. Added hosted actual exporter,
production CLI and manifest-bound raw decoder regressions. No public builds or
tests were run locally. No live flash/reset/HA/MQTT/NV actions in this takeover.

Hosted exact-SHA full validation is required for the final candidate. Prior
34c296e nv-lab is green but its build cannot qualify a later SHA. Source reviews
are limited to reviewed code; hardware validation and four offline full PASSes
are not yet claimed. Hardware reset behavior, bridge-loss/soak and task cost
remain pending. Old Muse retry budgets and pending next-step text above describe
its historical stop, not Codex's current implementation authority.
