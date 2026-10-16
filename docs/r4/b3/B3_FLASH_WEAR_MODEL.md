# B3-00/04 — storage and wear model, evidence limits

TI SDK8.33 `NVOCMP_NVPAGES` allocates N pages (one compaction reserve and N−1 ACTIVE), each **8192 bytes**. The actual source stores 4 bytes page header + 3×4 bytes compact header = 16 bytes, and **7 compressed bytes per item header**. Thus one active sector upper bound before payload is **8176 bytes** and an individual new record requires exactly `data_length+7` bytes *under the source-documented byte-aligned NVOCMP record mode*. This does not include obsolete records, compaction duplicates, additional application-level journaling or future native layout changes.

| Candidate | Raw total | Nominal active bound before individual item headers | Reserved raw swap |
|---|---:|---:|---:|
| B0 NV2 | 16384 | 8176 | 8192 |
| Experimental NV3 | 24576 | 16352 | 8192 |
| Experimental NV5 | 40960 | 32704 | 8192 |

For live item lengths `L[i]` and one instance of each item, minimum append footprint is `SUM(L[i]+7)`. A necessary (not sufficient) fit condition is `SUM(L[i]+7) <= (N-1)*8176`. A safe compaction requires enough remaining destination space, retrievable valid originals, properly sequenced generation markers and bounded duplicate writes. No claim of safe capacity follows from the simple sum. For `u` updates to a counter item of length `c`, the unavoidable initial append traffic lower bound is `u*(c+7)`; compaction and status byte rewrites increase it, with erase counts depending on actual free-space/item churn. No synthetic lifetime estimate has hardware endurance meaning.

**Not yet executed:** actual measured `L[i]` for NWK/TC/APS/TCLK/BDB/binding/group/address items; page-stream simulation at 1k, 10k and 100k updates with P90/P99 free space, erase distribution, worst-case copy peak, interrupts at every write/erase, native NV3/NV5 compile and B2 effective RAM/TC choice. The source-only decision is therefore **NO_PROFILE_LOCKED**. Empty-page nominal bound must never be substituted for a production capacity recommendation.
