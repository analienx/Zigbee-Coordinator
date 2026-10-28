# R4 TC-zero compatibility REV1 — new source candidate (not flash authorization)

Date: 2026-10-24. Branch: `codex/p7u-tc-compat-20261024`. Base: `dae80a1a7f5fc4a2d2852a55f8d78c40b2eeac69`.

## Why this is a separate candidate

The frozen radio source `323949a95c9a07901c4ffc3d026fca414982c148`
cannot restore this board's stock persisted `ZCD_NV_TRUSTCENTER_ADDR=0000000000000000`:
its B1 early check and independent native Python preflight both reject the
zero value. Never amend the candidate manifest in place. A compiled image
bearing this change must carry its own **new Git source SHA** and independent
native build/provenance/handoff receipts.

## Actual TI execution order

Pinned SimpleLink SDK `3615ad5d3f4f271258d18a2f5ce1785064ff9a58`:

1. `zd_sec_mgr.c`, `ZDSecMgrEntryInit(restored)` calls
   `ZDSecMgrRestoreFromNV`, which reads the *persisted* TC into
   `zgApsTrustCenterAddr`.
2. `zd_sec_mgr.c`, `ZDSecMgrInit` subsequently calls
   `APSME_SetRequest(apsTrustCenterAddress,0,NLME_GetExtAddr())`
   for the coordinator. That sets the *runtime APS AIB* Trust Center identity.
3. Existing B1 early security preflight runs before the above, so it must
   recognize the valid *persisted* zero representation instead of rejecting it.
   A foreign nonzero TC remains rejected.

The semantic exception applies only with all these invariants: formed
coordinator NIB, local valid nonzero/non-FF IEEE, correct active network key,
NWK and TCLK counter floors, address/key tables and existing B1 HOLD behavior.
The validator never writes a byte or supplies a replacement TC address.

## Modified source contracts

- `b1/tools/patch_security.py`: strictly local EUI64 verification, persisted
  TC zero/self-only check; no normal joining or NV restore rewrite.
- `qualification/stock20260311_security_preflight.py`: matching **offline**
  semantic recognition; all other formed-network/counter/peer validation stays.
- `b1/tools/make_security_harness.py`: genuine patched TI C body, zero-TC
  positive and foreign/missing/invalid-local-EUI negative synthetic scenarios.
- `tests/test_p7u_stock20260311_security_preflight.py`: native ABI synthetic
  preflight zero-TC positive, nonzero foreign and invalid coordinator negative.

## Qualification gates still required

- Hosted `r4-b1-admission-source` patched actual TI native GCC/ASAN/UBSAN
  harness must PASS; ensure new and existing negative C cases run.
- Both hosted TI Clang independent native radio builds and reproducibility
  receipts must PASS at **the new source SHA**, not at 323949a.
- Compose and audit exact APP-only image + matching AC000 handoff. Never
  reuse an older candidate manifest/handoff binary under a new label.
- Independent owner-security comparator currently retains an incompatible
  zero-TC equality assumption; it must be reviewed and fixed before any
  qualifying deployment PASS. The 107-historical/106-current difference must
  not cause any unreviewed NV/peer migration.
- The USB ROM and single-owner operator must pass strict source/package
  provenance, fresh live capture, bounded journal, protected-region guards,
  exact sector byte readback, startup state9, and service handoff.

## Explicit exclusions

No erase or writes at 0xA0000..0xABFFF or 0xAE000..0xAFFFF.
No stale NV restore, owner database substitution, frame-counter reset,
re-pairing, automatic reflashing or reboot-on-failure. Physical flash remains
not authorized until the candidate and owner transaction are complete.
