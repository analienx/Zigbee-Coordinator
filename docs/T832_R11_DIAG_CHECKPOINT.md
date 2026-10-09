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
