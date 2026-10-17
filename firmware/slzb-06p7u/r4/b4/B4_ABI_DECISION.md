# B4 ABI decision — issue #98

**Decision (updated 2026-10-17): experimental R4 v3 SYS F0 is genuinely native-linked on P7U but is NOT COMPLETE or DEPLOYMENT-AUTHORIZED.** Do not route live host traffic to an experimental source-only firmware handler until complete source-qualified ABI/counters, independent safety review and separate deployment authorization exist. Status: `B4_SOURCE_READY=BLOCKED`, `PHYSICAL_UNVERIFIED`, `HOST_NOT_INSTALLED`.

## Evidence (not extrapolation)

* `TexasInstruments/simplelink-lowpower-f2-sdk@3615ad5d3f4f271258d18a2f5ce1785064ff9a58` `source/ti/zstack/mt/mt.h:100-146` enumerates SYS IDs, none 0xF0; `mt_sys.c:246-398` dispatches real `MT_SysCommandProcessing`, no F0 case; unknowns return `MT_RPC_ERR_COMMAND_ID`.
* `Koenkk/zigbee-herdsman@0968f979d558874b17396c96b66382d4236bbdcd` `src/adapter/z-stack/znp/definition.ts:20-422` has no SYS command ID 240.
* `b4_verify_source.py` checks *both* pinned checkouts at exact HEAD and fails on a dictionary or dispatch collision, missing stock SYS paths, altered owner, or unverified source. Successful source check is **not** native handler or deployed host proof.

## Historical v2 (P10 donor, not R4)

MT SYS `0xF0` response payload exactly 102 bytes: version `0x02`, flags only bits 0–2, 25 little-endian uint32 values. No validity mask, boot identity, timestamp, monotonic sequence, or UNKNOWN sentinel. A numeric `0xffffffff` is a legal reading. No counter subtraction is permitted without separate trustworthy continuity (unavailable for v2).

## R4 proposed v3 (wire design, experimental source overlay only)

MT SYS `0xF0`, SRSP CMD0 0x61, CMD1 0xF0, and proposed fixed **132-byte** reply:

| Offset | Type | Field |
|---|---|---|
| 0 | 4 bytes | magic `R4D3` |
| 4 | u8 | major 3 |
| 5 | u8 | legacy flags bits 0–2 |
| 6 | u16 LE | payload length 132 |
| 8 | u32 LE | capabilities, bit 0 potential radio boot identity |
| 12 | u32 LE | validity bits 0–24 |
| 16 | u64 LE | radio_boot_id |
| 24 | u32 LE | uptime_ms |
| 28 | u32 LE | sample_seq |
| 32 | 25 × u32 LE | counters |

The existing contract contains no minor version, source digest, build ID or native reset reason. **Do not pretend those requirements are satisfied**: adding them needs a separately versioned ABI and revalidated MT-length/capability budget. Current `b4_protocol.py` rejects every unknown version, reserved bit, malformed body, FCS, command, length and unbounded input. It never sends a request.

Even if a wire response declares boot-identity capability, identity continuity remains **UNKNOWN** until a native, independently qualified generator and reset evidence exist. Matching process generations never qualify radio epochs. `radio_boot_id_verified` in the historical reference decoder means only the *wire capability assertion*, not independent trust; `trustworthy_radio_epoch()` requires `source_qualified=True`. The B4 branch never sets it true based on a frame.

## Failure and acceptance

No opaque F0 fallback to raw ZNP, no SYS_PING/SYS_VERSION changes, no direct UART owner, no NV/security/network information, no RF side effects. A dead NPI cannot answer diagnostics; rely on a last-good passive host snapshot only. The experimental native SYS F0 now has **five** source-backed NPI TX queue counters in `b4_native_patch.py`: SRSP depth/HWM, async depth/HWM and successful SRSP enqueue. In the stock P7U build where `NPI_SREQRSP` is disabled, the new source classifies framed CMD0 SRSP messages within the existing general NPI TX queue, allowing actual indices 0..4 (`0x1F`) without altering TI transport priority/watchdog and deliberately reports boot-epoch capability=0. An experimental opt-in herdsman adapter patch exists as source in `host/r4-b4/herdsman_overlay.py`. The five-counter patch has TWO genuine CCS links and byte-identical ELF/HEX/BIN proofs ([run 39012416673](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39012416673)); pinned herdsman source compiles and passes synthetic Node tests. Neither image nor host overlay has been deployed or demonstrated safe under real load. On timeout, F0 has no request nonce/transaction ID, so later diagnostic requests are quarantined within that existing ZNP session until a newly constructed owner exists; stock commands remain available. This is a diagnostic-only guard, not a transport fault latch. Complete HAL instrumentation, source-qualified boot epochs, B1/B2/B3 integration, production host event hooks, loaded-system fairness/stack measurements and full D01–D36 proof are **not yet completed**.

**Producer/consumer proof:** Pinned TI `npi_task.c` sends via two successful SRSP enqueue sites (`:679,:810`) and two async enqueue sites (`:687,:818`), then calls exactly one dequeue path per TX queue (`:892,:860`); each operates under existing `OsalPort_enterCS`. Native counters are **software queued-record gauges**, not UART FIFO occupancy, AF confirms, RF mesh or actual host receipt. Diagnostic self-observation can affect later SRSP counter samples. Counter deltas/boot continuation remain unqualified.

### Critical correction — earlier native image was ASYNC-only
The prior genuine CCS image (ELF `aca1b55c6e506c1c0f068d8d7a4d06ce40e63c51f99a1bcb7389ffde2f69ae28`) had `B4_SysReadOnlyDiagnostics` literally emit validity `0x0C` because stock P7U **does not compile NPI_SREQRSP**. Its sync SRAM globals were linked but NO sync producers were active. That earlier "five counters native-linked" statement referred to symbols only, not five functional gauges, and is superseded. An alternative trial enabling `-DNPI_SREQRSP` was NOT promoted: doing so would alter the stock NPI priority/watchdog. Instead the new source-only generator keeps TI options **unchanged** and tags the actual framed SRSP CMD0 (`MT_RPC_CMD_SRSP=0x60`) when it passes the existing general TX queue. This counts queued synchronous replies without changing scheduling. New exact-head CCS code emission and parity evidence are required before claiming the corrected image valid. Boot epoch and UART TX_FINISHED still UNKNOWN.
