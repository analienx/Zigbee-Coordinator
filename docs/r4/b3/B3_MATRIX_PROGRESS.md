# B3-04 — mandatory Annex M01–M36 status (no result inflation)

The issue #97 annex is the acceptance source. Only cases which actually exercise the specified function/failure qualify as PASS. Current `tests/test_r4_b3_migration.py` uses invented JSON/ZIP fixtures, and `tests/b3_host/osal_driver_test.c` executes the original pinned TI OSAL C with narrow patches and callback mocks. Neither is the required NVOCMP crash/reboot harness. Native TI CCS NV2/NV3/NV5 builds have passed, **but do not** prove real radio/NV retention.

| Annex | State | Current coverage / missing oracle |
|---|---|---|
| M01–M06 | OPEN | Native NV2/3/5 persisted item recovery, page data, correct empty vs error, capacity, malformed NVS geometry still need actual compiled fault harness. |
| M07 | PARTIAL | NVS_open NULL check patched; not yet executed in actual NVOCMP fault harness. |
| M08 | PARTIAL | Actual TI source read failure guard plus sticky fatal handling; physical NVS evidence still open. |
| M09 | PARTIAL | Actual TI OSAL C mocked write callback failures; NVS driver/compaction test OPEN. |
| M10–M16 | OPEN | NVS erase fail, malformed header, interrupted compaction, generations, tombstone, free-space/wear all OPEN. |
| M17 | PARTIAL | 106/128/160/192 mock identities tested; no actual serialized source row/native capacity proof. |
| M18–M19 | PARTIAL | Offline counter floor overflow checks; no actual security checkpoint or RF gate implementation. |
| M20 | PARTIAL | Offline per-key mock TX high-water; real APS/TCLK sender unknown. |
| M21–M22 | PARTIAL | Changed key mocked; true RX semantics/counter source paths unproven. |
| M23 | PARTIAL | Synthetic missing-key denial; no native NIB/key persistence proof. |
| M24–M25 | OPEN | TRNG failure and cross-item interrupted commit harness missing. |
| M26–M27 | PARTIAL | Strict synthetic root ZIP names, content SHA, CRC, duplicate, symlink, traversal, no extraction; real backup canonical selector not implemented. |
| M28–M30 | PARTIAL | Synthetic 3+3 mismatch, old counter maximum, changed-key conflicts. |
| M31–M32 | PARTIAL | Synthetic concurrent radio and network identity conflicts; physical isolation not tested. |
| M33 | PARTIAL | Synthetic NV2/NV5 profile mismatch denial; actual NV page reader/format proof missing. |
| M34 | PARTIAL | Untrusted synthetic metadata never grants authority; authenticated real backup evidence not supported. |
| M35 | OPEN | B1 HOLD_SECURITY with real queued RF and B2 routing interactions unimplemented. |
| M36 | PARTIAL | Synthetic consistency always returns three false mutation authorities. No restoration capability whatsoever. |

**No M01–M36 full result is asserted yet**; success in partial tests must not be converted to test PASS without actual source-compiled injection, flashed data digest, functional NVS op receipts and independent review. Native NV3/NV5 builds passed (not deployment-qualified); 1k/10k/100k wear, cold-power recovery and physical RF remain OPEN. Test run IDs and exact current SHA belong in #97 progress comment only after verified CI conclusion.

## 17 October actual source-C supplemental coverage (not full Annex acceptance)
M01/M03/M04: original TI 8.33 NVOCMP C host runs healthy NV2/NV3/NV5 seed/update/compaction, with persistent mock flash re-open across process restarts; native NV3/NV5 CCS builds subsequently passed in run 39002607845.
M08/M09: real TI NVOCMP source write/read status injections (bounded) now exercised; first red CI reproduced data-write rejection followed by invalid item header; narrow TI patch repaired it, as shown by NV2/3/5 passing [write run 39001593062](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39001593062) and [read run 39001618236](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39001618236).
M12: actual compaction healthy, but not all mutation-boundary cuts and repair states; still PARTIAL. M17: actual pinned TI APS/TCLK native types 24/20 bytes plus NVOCMP item header 7; no whole table native capacity guarantee. M18: source-extracted actual TI APS/TCLK saving routines retain pending after rejected writes; no B1 RF block or reserve-before-send. M25: no cross-item transactional generation. M01–M36 full case matrix and independent reviewer proof **remain OPEN**.
Real NVS hardware, preserved pre/post every step SHA, physical cold-brownout behavior, flash lifetime and radio security never claimed.

## Native CCS verification and independent code-review findings — 17 October

Verified GitHub Actions successful latest-head jobs: [NV3 and NV5](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002607845), [NV2](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002607852), [B0 native baseline](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002607854). These validate compiler/linker/audit paths, **not** hardware persistence, power-cut recovery, capacity or RF authorization.

Source review of `b3_source_overlay.py` identifies a security-critical unresolved contract: `NVOCMP_read` is a void-returning function, sets global `NVOCMP_failF` and wipes a bounded buffer, but several internal callers may continue using the output unless they explicitly inspect the sticky failure; the external `readItem` wrapper detects failure only after its inner call. Audit every internal caller, compaction and initialization before asserting that a read failure cannot promote partial state. Another hazard: the `NVOCMP_read` bounds check validates `pg` against `NVOCMP_NVPAGES` but does not independently validate that the runtime NVS handle and page layout are initialized before use. No claim of physical safety follows from passing mocked tests.

Security review: `ZDSecMgrGenerateRndKey` now returns a checked status, but its failure path zeroes the caller buffer and all call sites must be shown to suppress **subsequent** publication, fallback, and commissioning side effects. `ZDApp_SaveNwkKey` still ignores persistence status and clears `nwkFrameCounterChanges`; counter reservation-before-send and B1 RF hold remain P0. Treat the current build as experimental and not flashable.


## Final narrow regression results

The original NV2 interrupted-compaction failed at flash op 627 with missing NV rows after restart. B3 now latches **every** failed primitive write, including page-state/commit metadata. All real-source NVOCMP NV2/3/5 mock flash cases PASS: https://github.com/analienx/Zigbee-Coordinator/actions/runs/39010415494 . Later hardening adds failF-aware NVOCMP_checkItem and the read-after-rejected-write denial oracle to distinguish fatal I/O from NOTFOUND.

Real TI ZDApp_SaveNwkKey and ZDApp_RestoreNwkSecMaterial C bodies were extracted and passed rejection/overflow/order tests with negative mutant: https://github.com/analienx/Zigbee-Coordinator/actions/runs/39010726085 . These are source-hosted results, not physical RF or a complete Annex M01-M36 certification.
