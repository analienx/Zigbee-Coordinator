# B3-04 — mandatory Annex M01–M36 status (no result inflation)

The issue #97 annex is the acceptance source. Only cases which actually exercise the specified function/failure qualify as PASS. Current `tests/test_r4_b3_migration.py` uses invented JSON/ZIP fixtures, and `tests/b3_host/osal_driver_test.c` executes the original pinned TI OSAL C with narrow patches and callback mocks. Neither is the required NVOCMP crash/reboot harness. The native workflow, if green, compiles an NV2 image **but does not** prove real radio/NV retention.

| Annex | State | Current coverage / missing oracle |
|---|---|---|
| M01–M06 | OPEN | Native NV2/3/5 persisted item recovery, page data, correct empty vs error, capacity, malformed NVS geometry still need actual compiled fault harness. |
| M07 | PARTIAL | NVS_open NULL check patched; not yet executed in actual NVOCMP fault harness. |
| M08 | OPEN | Void `NVOCMP_read` ignored NVS status unresolved. |
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

**No M01–M36 full result is asserted yet**; success in partial tests must not be converted to test PASS without actual source-compiled injection, flashed data digest, functional NVS op receipts and independent review. Native NV3/NV5, 1k/10k/100k wear, cold-power recovery and physical RF remain OPEN. Test run IDs and exact current SHA belong in #97 progress comment only after verified CI conclusion.
