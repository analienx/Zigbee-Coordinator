# N01–N30 coverage ledger

This is a source-to-test map, **not a claim that all thirty acceptance cases
have passed**. `test-results.json` from a successful exact-head hosted source
job establishes HOSTED_SYNTHETIC results only for the named controls. Real
CCS images need separate HOSTED_NATIVE_LINKED seals. Physical claims remain
NOT_MEASURED. Each remaining requirement below keeps the full case open.

| ID | Actual-source control | Remaining acceptance scope |
|---|---|---|
| N01 | Admission all-FF; real NV API refuses unapproved blank | Reachable host path tested separately; no physical boot claim |
| N02 | Donor-generated rows; real NV2 init; NWK/APS/TCLK healthy restore; healthy MT | Whole-stack NETWORK_READY, normal AF/ZDO and physical restore open |
| N03 | Actual NV init bad sector/base/size; backend page/range faults | Device geometry additionally audited in native artifacts |
| N04 | Actual init NULL NVS handle; compiled bypass mutant must assert | Physical NVS failure not injected |
| N05 | Admission/read/init failures with poisoned buffers; actual backend | Whole controller failure not measured |
| N06 | Backend write failures, APS/TCLK/NWK write and readback faults | Physical persistence unknown |
| N07 | Actual erase nonzero status and voltage denial, no subsequent mutation | Hardware voltage/current and power failure unknown |
| N08 | Actual init priority/POSIX/sem variants; NPI queue/sem/register faults | Every native RTOS failure/interleaving not exhausted |
| N09 | Packed TI rows with header/CRC mutations, actual donor CRC | Vendor provenance cannot be inferred from a valid-looking slice |
| N10 | Pending/mixed compaction, destination payload, forbidden init repair | Every runtime compaction interruption remains open |
| N11 | Actual scan/header/length/read failures, bounded admission | Hardware timing not measured |
| N12 | Missing NWK/APS/TCLK/BDB/seed/TC restored rows; no replacements | Complete security variants require review |
| N13 | Real counter overflow, checkpoint faults, RAM rollback, readback mutants | Global/ROM counter paths and physical continuity open |
| N14 | Actual SYS PING/VERSION and NPI/MT HOLD routing | PRE_BOOT has no reply; physical UART receipt unknown |
| N15 | Actual main skips stack on NV fault; NPI task/register ordering | Full RTOS scheduling interleavings not measured |
| N16 | Actual MT filter rejects mutating AF/ZDO/SYS requests in HOLD | Already executing operations/direct stack callers require review |
| N17 | 1001 mixed synthetic frames, bounded allocations, original replies | Real queue saturation/late callbacks and UART timing open |
| N18 | Synthetic flash reopened; damaged image revalidated; sticky init | Physical reboot/power-cycle unknown |
| N19 | Explicit test factory define runs actual blank donor initialization | Production formation stays unauthorized; no live formation |
| N20 | Unknown/mixed immutable admission, strict NV2 read bounds | Valid-looking subset cannot prove old NV3/NV5 provenance |
| N21 | Actual UART open/read and NPI init boundary failures | Physical transport death and host timeout unknown |
| N22 | Actual ZMac data/no-data reject post-fault; bypass mutants fail | Queued/ROM RF not cancelled/proven |
| N23 | Actual FCS rejection; strict F1 magic/version/length/reserved query | Host decoder/all framing adversaries not exhausted |
| N24 | Failures at read/write/erase and init-repair boundaries | **OPEN:** exhaustive compaction-step and physical brownout proof |
| N25 | Key generation, index, seed/counter and restored inconsistencies | Full NIB/APS/TCLK generation/identity review remains |
| N26 | Sticky state; benign candidate/traffic cannot clear HOLD | Reboot must revalidate; no recovery API added |
| N27 | Authorized blank/configured-new use actual donor dispatch | Every optional singleton/library path not exhausted |
| N28 | Empty optional APS versus missing referenced APS/TCLK | Full table variants need independent review |
| N29 | 128 dummy rows and 1001 management events, bounded reads/allocations | **Not** an RF soak or native stack high-water measurement |
| N30 | Diagnostics has no NETWORK_READY capability; early faults hold | **OPEN:** complete positive readiness lifecycle/fresh-boot proof |

Every test uses synthetic bytes. No keys, raw NV, IEEE/PAN values, rosters or
packet payloads from a real household network enter logs or artifacts.
Active scenarios and generated-C hashes are in the hosted JSON, not inferred
from this table. Source-ready acceptance also requires significant independent
review findings to close at an exact commit.
