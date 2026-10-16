# R4 B4 acceptance receipt — PR #100, issue #98

**Status as of 2026-10-16:** **B4_SOURCE_READY = BLOCKED**; HOST_SOURCE_READY = BLOCKED; NATIVE_LINKED = **NOT VERIFIED**; HOST_INSTALLED = **FALSE**; COMBINED_INTEGRATION = **PENDING**; PHYSICAL_VERIFIED = **FALSE**; independent reviewer PASS = **NOT AVAILABLE**.

This is an *implementation/coverage ledger*, **not a green CI report**. GitHub Actions were queued when last checked; no success conclusion must be inferred. Tests marked "staged" exist in the branch but have no verified hosted PASS. CI IDs/review signatures must be filled from actual completed runs. No hardware actions took place.

| Annex | State of evidence / blocker |
|---|---|
| D01 | SOURCE_ONLY: stock SYS entry-path anchored, no behavioral baseline yet |
| D02 | UNIT_SOURCE_MUTANTS_PRESENT; GHA unverified |
| D03 | PYTHON_ORACLE_PRESENT; native v2 reference only |
| D04 | PYTHON_ORACLE_PRESENT; experimental native partial |
| D05 | UNIT_PRESENT; native unknown minor not representable |
| D06 | UNIT_PRESENT; no true hardware stream |
| D07 | ALLOWLIST_TEST_PRESENT; no installed recorder |
| D08 | REFERENCE_TEST_PRESENT; source-qualified wrap proof missing |
| D09 | BLOCKED unqualified radio epoch |
| D10 | BLOCKED trusted boot source absent |
| D11 | UNIT_REFERENCE only; native cannot qualify epoch |
| D12 | BLOCKED TX_FINISHED counter absent |
| D13 | BLOCKED verified UART distinction absent |
| D14 | BLOCKED AF_CONFIRM vs SRSP lifecycle host hook missing |
| D15 | BLOCKED B2 route metric not integrated |
| D16 | PARTIAL offline independent timeout categories only |
| D17 | PARTIAL bounded parser/recorder; native load fairness unverified |
| D18 | SOURCE_NODE_TEST staged skip/coalesce; no actual OTA backpressure proof |
| D19 | PARTIAL SIGTERM host category, not live process |
| D20 | PARTIAL USB detach replay; no actual USB source |
| D21 | PARTIAL last-good preserved; no installed host hook |
| D22 | NODE_TEST staged timeout/cooldown; no actual waiter leak proof |
| D23 | NODE_SOURCE existing owner only; second-client hostile test missing |
| D24 | SOURCE_PROVEN ZStackAdapter.znp private; unsupported extension |
| D25 | PYTHON_UNIT recovery interruption proof staged |
| D26 | PYTHON_UNIT IO/fsync failure proof staged |
| D27 | PYTHON_UNIT bounded events proof staged |
| D28 | PYTHON_UNIT out-of-order rejection staged |
| D29 | PYTHON_UNIT duplicate waiter rejection staged |
| D30 | PYTHON_UNIT allowlist denial staged |
| D31 | OFFLINE_REPLAY staged with actual historical counts |
| D32 | OFFLINE_REPLAY staged synthetic starvation |
| D33 | OFFLINE_REPLAY staged unknown prior radio epoch |
| D34 | OFFLINE_REPLAY staged USB alternate root |
| D35 | BLOCKED B1 real HOLD source integration |
| D36 | SOURCE_ONLY all unavailable counters remain UNKNOWN |

## Five independent challenger scenarios (proposed, NOT reviewer-executed)

1. **Source collision alias:** TI defines decimal `240` instead of hex `0xF0`. The source verifier and mutant must detect the collision, not pass because of hex-only parsing. Countermeasure: revised lexical parser in `b4_verify_source.py`.
2. **Buffalo truncation:** `readBuffer(132)` on a 131-byte buffer silently returns a 131-byte slice. Countermeasure: source overlay exact-length check before read; actual pinned compiled Node negative test staged.
3. **Post-rename fsync crash:** `os.replace()` succeeds but directory fsync fails. Last-good target may have changed; never promise restoration of original after rename; report failure and require production I/O isolation.
4. **Host clock discontinuity:** `Date.now` jumps backward causing over-poll; use monotonic `performance.now()` 30s cooldown and no retries. Radio epoch remains independent.
5. **SERIAL owner leak through external cast:** plugin casts private `ZStackAdapter.znp` or constructs a second `Znp`. No external API permitted; native host overlay only on existing adapter. **Hard second-owner rejection test is still MISSING**—staged source test is not enough.

## P0/P1 blockers — do not waive

- Native CCS full-link output, actual registered F0 packet on real source, pinned SHA binary/map/CCFG, two reproducible builds, SRAM/stack delta and source-linked/RTOS callback/queue fairness tests are unverified.
- Host compiled TypeScript and actual owner/waiter lifecycle tests queued, no Z2M2.14.0 installation audit, no live Z2M or extension. No injected capture in real AF/ZDO/SYS waiter paths.
- Native radio boot identity is unknown, no minor/build digest/reset cause in v3, missing UART FINISHED and AF_CONFIRM routing state, no causal conclusions.
- B1/B2/B3 sealed combined integration missing; safety and regression cannot be guaranteed.
- Independent four-lane reviews, blind-spot reviewer with reproduced novel mutations, P0/P1 re-reviews and R4-07 physical qualification not obtained.

**STOP / NOT READY.** PR remains draft and unmerged. Once actual Actions terminate, record exact head SHA, run+job IDs, two ELF manifest hashes, relevant counter validity, linked map/memory budget and proven independent reviewer verdicts before changing any status.
