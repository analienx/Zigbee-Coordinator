# R4 GLOBAL REVIEW II — independent GitHub-only code and safety audit

Date: 2026-10-17 (Europe/Prague). Reviewer: ChatGPT GPT-6 (NOT Muse Wonder; no claim of a Muse review). Issue: https://github.com/analienx/Zigbee-Coordinator/issues/85. This is a source/CI audit, not a hardware qualification, code change, or approval.

## Scope and method

Independently read GitHub PR metadata, native code/patch generators, security/host source, approval gates, author documentation, and GitHub-hosted Actions job status/log excerpts. Compared eight active candidate streams at fixed HEAD, plus the competing F1 branch, and checked critical compiler failures from raw native job logs. Historical Muse findings were used as leads to *challenge*, not proof. Four review lenses: (I) provenance/ELF/native/flash, (II) boot/NV/security, (III) routing/RAM/counter state, (IV) NPI/host/diagnostics; and a cross-phase blind-spot challenge of interacting safeguards. No independent new test builds were performed; native build claims below refer solely to GH Actions at their named SHAs. No Zephyrus, self-hosted runner, hardware, secrets, serial, Home Assistant, MQTT, Zigbee2MQTT, RF, backup, restoration, or production operation. No implementation files, tags, worktrees, or author branches were changed.

### Reviewed exact heads

| Scope | PR | Reviewed SHA | Observed hosted status / scope |
|---|---|---|---|
| R4-00 | #86 | 38dbd279cd7112579726a38862ec3048b44ab5b3 | source CI green; vendor ancestry unknown |
| R4-01a + B0 | #89 (contains #91 and #102 merged on its branch, NOT main) | dc74b44019853f8b6cadf75c4e6e940fc715c906 | hosted native B0 green (39011888813), unqualified image |
| B1 | #94 atop #93 | a514c194ea0d94b5d38b28c7b07ca5caba9aeffd | hosted B1 native/test 39006604255 green; not integrated |
| B2 | #96 | 0b06ef8b2fd4fc3008c228208e7a16e1c86d8492 | capacity native 39010370810 green; routing logic opaque |
| B3 | #99 | 9b72e4fee2cb8adca89c4afed72dfa7db90d5163 | two native suites 39011537997 and 39011538069 FAILED |
| B4 v3 | #100 | 981ce098658a40aa3145916a2f08a155aaa0367e | seven hosted workflows including native dual-link green |
| B4 v4 alternative (REJECT) | #104 | b0559920af1321edf0f3f661abfdd7f8ac14504f | native 39020665837 FAILED; SYS F1 conflict |
| B4 v4 preferred F2 candidate | #105 | b09c6c1c2bb55ff7d46dd85ea15622e7f3a21e6a | all seven exact-head workflows now COMPLETED SUCCESS; native B0 39024103773 and dual 39024103860 passed on recheck |

Author descriptions/packet referring to older #105 heads 26b0fbe3 or 4019a7da are NOT exact-head green evidence for b09c6c1c.

## Phase acceptance matrix

| Phase | Review verdict | Decisive evidence / missing gate |
|---|---|---|
| R4-00 | PARTIAL | Immutable TI examples-to-SDK gitlink and Koenkk paths checked by in-PR hosted attester; still no independent protected trust root; exact stock 20260310 source remains UNKNOWN; toolchain download digests UNKNOWN |
| R4-01a / B0 | PARTIAL | genuine pinned TI compiler/native-link gates and flash denial documented; real P7U RF/clock/20260310 NV parity and SYS_PING not proven; #89 is draft not main |
| B1 | PARTIAL, security gate OPEN | actual-source NV/SYS F1/hold hooks compiled in hosted CI; queued/ROM RF and healthy restored-network integration unmeasured; B3 semantics not combined |
| B2 | FAIL for requested full B2 scope; PARTIAL capacity-only | linked source-route 192, neighbor 64, NWK route 128; TC 192 / child 96 not yet delivered, MTO default disabled; proprietary TI RTG body unavailable; T05–T28 largely blocked |
| B3 | FAIL | compiler type conflict in genuine NV2 and NV3/NV5 CCS builds; counter reservation lacks enforced readback/RF admission; old-stock NV decision unknown |
| B4 v3 | PARTIAL | real TI dual-link and disposable herdsman tests green, but no real UART/OTA/hardware demonstration or composite |
| B4 v4 F2 (#105) | PARTIAL, standalone native GREEN | collision-safe SYS F2 exists in source; newest native jobs passed at exact SHA; B1 HOLD still blocks F2 until combined change, boot TRNG is unmeasured |
| B4 v4 F1 (#104) | FAIL / REJECT | SYS F1 directly conflicts with B1 status; native ELF audit failed at exact HEAD |
| B5 optional | DEFER | no proven transport-scheduler performance deficit; avoid resurrecting G7 latch |
| Composite B0+B1+B2+B3+B4 | FAIL / ABSENT | no common reviewed image SHA, no integrated ELF/HEX/linker/MTO/HOLD evidence |
| R4-07 hardware and migration | NOT QUALIFIED | no isolated-device readback, safe sector writer, rollback, counters, 100+ device soak, or authorized physical test |

No individual green branch equates to an accepted production coordinator.

## Findings (code-backed, highest priority first)

### R4-II-01 [P0 — build hard stop] B3 native candidate does not compile
- SHA: #99 9b72e4fe. Exact genuine hosted run 39011537997 / job 117334914239 fails in TI compiler on zd_sec_mgr.c:280: *conflicting types for ZDSecMgrGenerateKeyFromSeed*, where the overlay changes its return type to ZStatus_t but a void declaration remains. NV3/NV5 native run 39011538069 also failed.
- Source: https://github.com/analienx/Zigbee-Coordinator/blob/9b72e4fee2cb8adca89c4afed72dfa7db90d5163/firmware/slzb-06p7u/r4/b3/tools/b3_source_overlay.py ; log https://github.com/analienx/Zigbee-Coordinator/actions/runs/39011537997 .
- Correction: consistently update **all** declarations, prototypes, definitions, and callers in the pinned SDK; add a compile-time signature assertion and negative old-prototype mutant. Rebuild NV2, NV3, NV5 at a NEW exact SHA with TWO hosted native replicas. Until then no B3 firmware artifact exists.

### R4-II-02 [P0 — security release gate] B3 persistent frame-counter floor is not a proven durable transaction
- SHA #99: b3_source_overlay.py, ZDApp_RestoreNwkSecMaterial replacement: after one successful osal_nv_write_ex the code assigns nwkFrameCounter, FrameCounterUpdated and resets nwkFrameCounterChanges, without a readback/strict compare of persisted row. Other APS/TCLK pending writes clear on backend SUCCESS alone. B1 patch_security.py independently implements checked write/readback, but neither patch composition nor every secure-TX boundary is established.
- Counterexample: flash backend reports SUCCESS yet recorded bytes differ (or a power-cut alters the checkpoint), RAM becomes authoritative for further secured transmissions; on reboot old persisted floor may be reused. This is a failure model to TEST, not a claimed observed event.
- Correction: native per-key floor reservation with read-after-write comparison and explicit hold on mismatch, ensure reserve-before-*all* protected TX, and host fault injection for silent short/corrupt writes, partial compaction, read failure, restart, exhaustion and near-wrap. Never generate keys or silently reform a restored network.

### R4-II-03 [P0 — unsafe deployment if bypassed] address-flat BIN includes protected NV
- SHA #89: b0_flash_boundary.py independently verifies that tiarmobjcopy -O binary is 0xB0000 (704 KiB) and contains padding across candidate NV 0xA4000..0xADFFF, whereas the HEX has no writes in that union. A naive whole-BIN flasher can destroy network keys, high-water counters and identity. Current denial certificate is a GOOD safeguard, not flash permission.
- Source: https://github.com/analienx/Zigbee-Coordinator/blob/dc74b44019853f8b6cadf75c4e6e940fc715c906/firmware/slzb-06p7u/r4/b0/tools/b0_flash_boundary.py .
- Correction: retain DO_NOT_FLASH checks; future writer must erase PROGRAM SECTORS only after same-device image-range, sector-granularity, NV/CCFG, historical NV5, backup and readback proof. A safe HEX payload alone does not prove erase boundaries.

### R4-II-04 [P0 for integration] B4 alternative #104 appropriates B1 SYS F1 and fails native link
- #94 B1 b1_management.h/management.c reserves F1 B1Q1/B1S1 (8-byte query/24-byte status). #104 v4 also uses F1 for a different 160-byte diagnostic response, so composing them violates command ownership and HOLD admission. Exact CI 39020665837 fails with missing B4_V4InitializeBootOnce in ELF. #104 must NOT be merged/promoted.
- Prefer #105 SYS F2 version after its exact-head native acceptance and security review. Keep B1 F1, v3 F0 distinct.

### R4-II-05 [P1 — release invariant] No tested cross-phase composition exists
- The reviewed streams branch from different B0 histories and patch overlapping TI zglobals/zd_app/zd_sec_mgr/NVOCMP/NPI/MT. In particular B1 security and B3 security own overlapping original SDK function bodies; successful sibling CI is not merge/composition or runtime proof.
- B4 F2 cross-phase gate at #105 explicitly sets b1_hold_allows_b4_v4_f2=false and b1_b4_combined_source_ready=false (positive honesty), so the diagnostic method is unavailable in B1 HOLD, the situation it might eventually need to diagnose.
- Correction: create a new isolated *composite* candidate with deterministic patch ownership (B0 → B1 → B3 security transaction reconciliation → B2 table/runtime guards → B4 v3 → F2) and no automatic cherry-pick. Pin combined source SHA, two hosted native builds, fresh RAM/linker/NV audit, tested F0/F1/F2 dispatch in healthy and each HOLD, real queue-boundary source tests, all relevant negatives, and independent source re-review. No merge/deploy until P0/P1 close.

### R4-II-06 [P1 — performance acceptance] B2 effective MTO is NOT enabled by larger tables
- #96 source MTO_EFFECTIVE_STATE.md and TEST_MATRIX.md show default CONCENTRATOR_ENABLE=false, ROUTE_CACHE=false, DISCOVERY_TIME=0 with persisted NV override unknown; 1000-ms linked RTG throttle only proves constant presence. +3,488 B static SRAM and 192/64/128 allocations do not prove a dense network can discover/evict/recover routes.
- Actual proprietary libZStack_nwk_all.a RTG internals are unavailable; T05–T28 mostly blocked. Do NOT fabricate a C implementation or assert routing is resolved by capacity. Resolve #101 through a lawful instrumentable seam or explicitly narrow B2 acceptance to *capacity only*, with separate disposable physical RF qualification.

### R4-II-07 [P1 — security HOLD integration] B1 and B3 failure states are not a single RF-denial guarantee
- B1 b1_management.c includes sticky HOLD and an MT command filter plus a new-ZMac-submission gate, but the B1 documentation explicitly exempts already executing operations; queued/in-flight and ROM paths are NOT_MEASURED. B3 admits its void-ABI and key/counter failure handling does not yet wire all failures into B1 HOLD_SECURITY.
- Test denial at enqueue, dequeue, MAC handoff, late callback and power-cut/reboot with zero new secured sends after an asserted hold. Explicitly describe irreducible in-flight radio limits rather than claiming physical zero-RF.

### R4-II-08 [P2 — source-evidence freshness] #105's current head required an exact-SHA recheck
- Exact #105 head b09c6c1c, not packet 26b0fbe3 or previous reviewer 4019a7da. At first observation runs 39024103860 (native dual) and 39024103773 (B0 native) were IN_PROGRESS. On a later same-session GitHub recheck **BOTH COMPLETED SUCCESS for b09c6c1c**, and all seven exact-HEAD checks were green. Prior run 39020297149 remains stale/irrelevant to the newer head. This clears the standalone native CI gate only, not B1/B4 integration or physical TRNG proof.
- Persist the successful 39024103773/39024103860 exact-head receipts and SHA-bound manifests, inspect compiled TRNG linkage/stack evidence, and rerun after any HEAD change. Native success is not evidence of real TRNG operation or the combined firmware.

### R4-II-09 [P2 — boot/entropy/stack] #105 F2 boot token remains a source-only identity heuristic
- Native overlay b4_v4_native_patch.py uses one 8-byte TI TRNG sample from existing NPI task and a computed 100 ms Clock_tickPeriod timeout. Timeout/error now cancels queued job before close, avoiding the identified dangling-semaphore/stack-buffer risk. This is a meaningful *source fix*, but the ELF audit lists four v4 symbols; it does **not** alone prove generated TRNG instance, task stack headroom, radio liveness, true entropy quality or bounded hardware startup.
- Build a disposable-board trace showing TRNG_open/get/cancel/close sequencing, NPI starts after entropy failure, actual reset-source semantics, SRSP stability and hardware boot-token changes; never call the token authentication or an immutable image digest.

### R4-II-10 [P2 — diagnostics/HOLD] F2 is collision-free but NOT available during B1 hold
- In #105 b4_v4_cross_phase_gate.py source inspection returns b1_hold_allows_b4_v4_f2=false, since #94 accepts only SYS PING, VERSION and B1 F1 under HOLD. This is not a B1 bypass; it is an observability limit. Either document B1 F1 as the sole diagnostic available in HOLD or compose a separately reviewed read-only F2 exception with proof of no RF/NV/write side effects and correct one-owner queue semantics. Do not authorize a blanket SYS exception.

### R4-II-11 [P2 — provenance] some labels and trust roots are weaker than the evidence implies
- #86 SOURCE_PROVENANCE.json has 8.33 source pins (properly distinct from vendor catalog label 8.32); the *unknowns* still claim fitted board revision unverified while historical #80 records R1.73. Correct that narrow metadata. Exact 20260310 source ancestry, RF/PA, active NV and CCS/compiler download SHA256 remain UNKNOWN. Attester's EXPECT_* values live in the PR being tested, not an externally protected approval policy; green self-attestation is not a secure independent trust root.
- Keep generated ELF/CCFG and vendor comparisons independent; require external protected policy/attested builder identity before any trusted release.

### R4-II-12 [P2 — diagnostic privacy/debuggability tradeoff] v4 host logging changes deserve explicit operator review
- #105 host/r4-b4/b4_v4_herdsman_overlay.py redacts all raw UNPI parser/writer payload debug lines to prevent diagnostic nonce/token leakage; normal ZNP command debug remains. This reduces future packet-level trace visibility for any command, not only SYS F2. That may complicate forensic diagnosis during OTA/routing incidents. Review a safe opt-in, per-command metadata/redaction policy and test it against trace consumers; do not restore raw keys or raw NV logging.

## Independent blind-spot challenge: false confidence scenarios

1. **Green native, wrong firmware board:** CCS builds for TI LP_CC1352P7_4 but fitted CC2652P7 has unverified exact R4 RF/clock/PA/20260310 CCFG and stock NV mapping. Native green != physical SYS_PING or RF.
2. **Green B1, broken B3:** independent B1 verified writes do not compose automatically with a B3 void-ABI security writer; no default proof that RF holds before counter reuse.
3. **Good HEX, bad flasher:** HEX has no NV records yet a whole-image erase or BIN fill destroys keys; enforce a separate sector writer gate.
4. **Fresh diagnostic, old radio:** host process restarts and late SRSPs can create false continuity; F2 echoes nonce (correlation) but token is probabilistic, not authentication, and cannot authorize cross-reset counter deltas.
5. **Big tables, ineffective routes:** route cache size 192 is irrelevant if MTO disabled in persisted NV or opaque RTG eviction fails in a 60+ router mesh; no full B2 acceptance.
6. **Silent device refusal:** security HOLD could make SYS F1 responsive but Z2M startup/restore treat it as a fatal no-network radio; the integration must demonstrate operator-recoverable host semantics without erasing network identity.

## Closure sequence and falsifiable acceptance

**G0 — freeze provenance and branch heads.** Correct #86 fitted-board-status metadata, record toolchain limitations, protect CI trust root externally, rebaseline #89 against #86 without mistaken main-merge claims.

**G1 — fix B3 compiler P0 and durable security.** Compile genuine NV2/3/5 after consistent function declarations; readback/assert persisted floors, forced write-corruption and cold-reboot tests; no new/random keys or RF on HOLD.

**G2 — qualify #105 as alternative, reject #104.** Its 7 exact-head hosted checks are now GREEN, including genuine native B0/dual links. Preserve SHA-bound receipts, independently inspect TRNG symbol/config/stack and host guards; explicitly retain B1 F1 during HOLD. Do not treat this as physical approval. Review async host abort/OTA race and UART response behavior.

**G3 — B2 disposition.** Either lawful closed-stack seam with source-backed tests and RAM/heap+NV MTO effective evidence, or relabel capacity-only with T05–T28 still blocked. No invented completed mesh reliability tests.

**G4 — compose ONE immutable candidate.** Independent reviewer must inspect actual composed patch and two same-head hosted native builds, integrated F0/F1/F2, NV2/3/5 decision, HEAP/HOLD and error path, full negative and rollback-denial tests. Every changed HEAD invalidates stale green evidence.

**G5 — separate physical proposal only.** After new explicit authorization and whole-device backup, perform isolated same-model device SYS_PING, multiple cold starts, NV and security counter monotonicity, qualified sector programming/rollback, then staged router/sleepy/106-device long soak. NOT authorized by this review.

## Verdict

**GLOBAL FAIL for source-ready/production-ready acceptance. No release, no flash, no merger of implementation candidates, no automatic phase promotion.** Creditable partial deliveries: R4-00 provenance, B0 native source and image-denial audit, B1 fault-source mechanisms, B2 linked capacity, B4 v3 hosted native+host tests, and B4 v4 F2 design. Key executable gates missing or failed: B3 native signature, verified per-key durable high-water and RF HOLD integration, B2 opaque route behavior, #105 B1-HOLD F2 admission/real TRNG qualification, and single composite hosted build. Exact working P7U hardware and household Zigbee network remain untouched.
