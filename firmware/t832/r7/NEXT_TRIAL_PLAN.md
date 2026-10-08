# Next-trial evidence plan (Q4)

Plan version: 1.0.0. Bundle schema: trial-bundle/1.0 (see
check_trial_bundle.py). Candidate SHA: recorded in the PR46/issue73 seal
checkpoint (must equal the sealed PR46 HEAD); the bundle manifest pins
it per capture (40 hex, TBD fails).

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
  mechanically repin it. A bare management success event and
  eraseNVM=0 are insufficient: neither proves the preboot boundary.
  Safe alternative if G1 cannot be proven from tool source/protocol:
  JTAG/SWD halt-and-readback with a documented halt that precedes any
  application boot, or defer the trial.
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
8. COMPARE: compare the pretrial commissioned network state against
   post-boot (pre-nv vs post-boot bytes under the G2 image; NIB
   presence/identity per the §5 distinguishing rule) and record
   network_state {preserved, note} in the manifest. Without a
   complete pretrial image (G2 external) the comparison is
   inconclusive: record preserved false with the G2 reason; the
   trial fails as inconclusive, not as demonstrated loss.
9. CHECK: run `python3 check_trial_bundle.py --bundle <dir>` from the
   sealed SHA. Exit 0 is required; any failure fails the trial.
10. ARCHIVE: the bundle directory (manifest + 4 blobs) is the trial
   artifact. Never edit blobs after hashing; re-run from step 2 on
   any procedural fault.

## 4. Bundle manifest

manifest.json carries schema, plan_version, candidate_sha (40 hex;
TBD fails), meta {operator, tools, hex_sha256, capture_window_s >= 120},
files {role: {file, sha256, size}} for roles pre_nv,
post_program_nv, post_boot_nv, records, ranges
{expected_changed_pages: [...]} derived from the G3 uploader ranges,
and network_state {preserved: bool, note: non-empty string} from
runbook step 8.
expected_changed_pages covers the PROGRAM diff (pre to post-program)
only. The boot diff (post-program to post-boot) is reported for
operator review and is gated only when the manifest additionally
claims ranges.boot_allowed_pages. The checker fails on any integrity
violation (including file paths escaping the bundle), any program-diff
page outside the claimed set, any missing required record, any
undecodable a7/a9 record (all of them, not just the first), any
record disorder (multiple BOOTs i.e. a reset in the window, BOOT not
first, an a9 without a preceding a7, a trailing a7 without its a9),
any malformed record entry, a missing network_state verdict, and
preserved false (loss or inconclusive: the note says which).

## 5. Pass/fail criteria

- PASS: checker exit 0, a7 decodes to the expected init action for
  the pretrial topology, the a9 latch is consistent with the
  observed boot (zeros on admit; exact site on reject, matched
  against the REJ table of the sealed SHA), and network_state
  records preserved true with the comparison note.
- DISTINGUISHING RULE (PR45 lesson): a post-boot NV image without a
  native NIB, by itself, does NOT distinguish uploader erasure from
  startup cleanup. The verdict comes from the pre/post-program diff
  (uploader effect, no boot in between) crossed with the first-boot
  records (startup effect). Any claim that skips either side fails.
- FAIL: checker exit nonzero, network_state.preserved false, any
  reset inside the capture window, any boot between steps 2 and 4,
  or a candidate-hex hash mismatch. The checker enforces the
  records side of the no-reset rule (a second BOOT fails); the
  image side rests on the G1 boundary plus immediate hashing.

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
- Retrieve first-boot records promptly: NV_RESULT is routine-ring
  (overwrite) on device, so heavy post-burst traffic can bury a9.
  Burial is detectable, not silent (routine overwrite counters plus
  the decoder's missing-diagnostic failure), and the checker's
  a7-pairing rule fails a burst whose a9 was lost.

## 7. Disposition mapping

- OFFLINE_QUALIFIED (current): all hosted gates green on synthetic
  data; Q2/Q3 closed; this plan + checker reviewed and versioned.
- HARDWARE-QUALIFIED (future): this plan executed with checker exit 0
  on a complete pretrial physical image, pre/post diffs inside
  claimed ranges, and first-boot records consistent with the
  pretrial topology. Partial evidence (e.g. missing G2) keeps
  OFFLINE_QUALIFIED with the gap named.
- HARDWARE_PENDING: the Q5 token for the same future state: the
  trial above has not run yet.
