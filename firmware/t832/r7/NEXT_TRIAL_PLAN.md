# Next-trial evidence plan (Q4)

Plan version: 1.0.0. Bundle schema: trial-bundle/1.0 (see
check_trial_bundle.py). Candidate SHA: TBD (set at seal; must equal the
sealed PR46 HEAD; the bundle manifest pins it per capture).

## 1. Goal and non-goals

Goal: capture physical evidence that distinguishes, for the sealed R10
candidate on real hardware, (a) uploader erasure from startup cleanup,
(b) the exact NV program/erase ranges of the trial, and (c) the
first-boot init outcome including the Q3 rejection latch.

Non-goals: this plan authorizes no live operation by itself. It is a
procedure plus an offline checker for a FUTURE separately-authorized
trial. Until that trial runs green, the candidate disposition stays
OFFLINE_QUALIFIED: qualified by hosted CI on synthetic data only, not
hardware-qualified.

## 2. Capability prerequisites (gates)

Each prerequisite is PROVEN (evidence cited) or an EXTERNAL GATE (must
be satisfied before the trial; the trial must not proceed on an
assumption).

- G1 app-held programming/readback with a preboot boundary: the
  operator must program the candidate and read back full physical NV
  while the application is held out of boot (no auto-boot between
  program and post-program readback). EXTERNAL GATE. The old private
  p10_debug_flash.py does NOT supply this: it is intentionally
  hard-pinned to PR45 and the management API auto-boots. Do not
  mechanically repin it. Safe alternative if G1 cannot be proven from
  tool source/protocol: JTAG/SWD halt-and-readback with a documented
  halt that precedes any application boot, or defer the trial.
- G2 complete pretrial physical NV image: a full 15-page (30,720-byte)
  readback taken under the G1 boundary before programming. EXTERNAL
  GATE when missing: without it, full commissioned-NV replay stays
  pending. A native NIB JSON export or a logical backup is NOT a
  physical NV image and cannot substitute.
- G3 uploader erase/program range evidence: the exact flash ranges the
  uploader erases and programs, from uploader logs plus the
  pre/post-program diff. EXTERNAL GATE when missing.
- G4 first-boot DIAG capture: a host log of the first boot over
  SYS/DEBUG from release-of-hold, decoded with the packaged codec from
  the sealed build. PROVEN PATH (PR45 precedent: a DIAG build answered
  SYS/DEBUG post-boot); the capture window and record list below make
  it checkable.

## 3. Runbook

1. Satisfy G1-G4. Record tool names, versions, and operator in the
   manifest meta. The candidate hex must hash-match the sealed bundle.
2. PRE: under the G1 boundary, read back full physical NV (30,720
   bytes) to pre-nv.bin. Hash it (sha256) immediately.
3. PROGRAM: program the candidate hex while held. Record the
   uploader-declared erase/program ranges in the manifest.
4. POST-PROGRAM: still under the G1 boundary (no boot), read back
   full physical NV to post-program-nv.bin. Hash it.
5. RELEASE: release the hold, starting the first-boot capture window
   (minimum 120 seconds of SYS/DEBUG logging from release).
6. FIRST BOOT: capture to first-boot raw log; decode with the packaged
   t832_incident codec from the sealed build into records.json.
   Required records: BOOT, NV_RESULT a7 (init action + first failure),
   NV_RESULT a9 (rejection latch). Any reset during the window
   invalidates the window: re-hold, re-capture, and record the reset.
7. POST-BOOT: read back full physical NV to post-boot-nv.bin. Hash it.
8. CHECK: run `python3 check_trial_bundle.py --bundle <dir>` from the
   sealed SHA. Exit 0 is required; any failure fails the trial.
9. ARCHIVE: the bundle directory (manifest + 4 blobs) is the trial
   artifact. Never edit blobs after hashing; re-run from step 2 on
   any procedural fault.

## 4. Bundle manifest

manifest.json carries schema, plan_version, candidate_sha, operator
and tool meta, files {role: {file, sha256, size}} for roles pre_nv,
post_program_nv, post_boot_nv, records, and ranges
{expected_changed_pages: [...]} derived from the G3 uploader ranges
plus the pages first-boot NV traffic is allowed to touch. The checker
fails on any integrity violation, any program-diff page outside the
claimed set, any missing required record, and any undecodable a7/a9.

## 5. Pass/fail criteria

- PASS: checker exit 0, a7 decodes to the expected init action for
  the pretrial topology, and the a9 latch is consistent with the
  observed boot (zeros on admit; exact site on reject, matched
  against the REJ table of the sealed SHA).
- DISTINGUISHING RULE (PR45 lesson): a post-boot NV image without a
  native NIB, by itself, does NOT distinguish uploader erasure from
  startup cleanup. The verdict comes from the pre/post-program diff
  (uploader effect, no boot in between) crossed with the first-boot
  records (startup effect). Any claim that skips either side fails.
- FAIL: checker exit nonzero, any reset inside the capture window,
  any boot between steps 2 and 4, or a candidate-hex hash mismatch.

## 6. Explicit limits (carried, not closed)

- The Linux backend's power cuts land on whole-operation boundaries.
- Handcrafted NOR-valid header negatives do not establish exhaustive
  torn-write behavior. Whether a random power-cut tear can forge a
  recognized walk window is UNPROVEN (see the guard source note); do
  not claim it.
- The reject-case MT-answers path rests on the traced fact that both
  production initNV callers ignore the return status; no later boot
  assert on NV readiness has been traced. The trial's own BOOT + a9
  records are the first direct evidence for the reject case.
- A RAM latch does not survive reset/ROM; a9 is first-boot evidence
  only. No raw NV records, keys, or private payloads enter public
  telemetry or artifacts; captures stay in the private trial bundle.

## 7. Disposition mapping

- OFFLINE_QUALIFIED (current): all hosted gates green on synthetic
  data; Q2/Q3 closed; this plan + checker reviewed and versioned.
- HARDWARE-QUALIFIED (future): this plan executed with checker exit 0
  on a complete pretrial physical image, pre/post diffs inside
  claimed ranges, and first-boot records consistent with the
  pretrial topology. Partial evidence (e.g. missing G2) keeps
  OFFLINE_QUALIFIED with the gap named.
