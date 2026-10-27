# P7U R4: F2 v4.2 causal telemetry contract (exact 4cfe serving lineage)

**Status: SOURCE-ONLY / native qualification ongoing / never flashed or activated.**

F2 remains MT SYS 0xF2, **8-byte nonce request, 160-byte R4D4 reply**, boot token, reset metadata and 25 x u32 slots in identical positions to accepted F2 minor1. **Minor 2** is signaled only by response byte 157; byte 159 remains zero. No new UART owner, ZNP requests, unsafe timeouts, RF or NV/CCFG/counter operations. The originally qualified P7U runtime uses **minor1**, and cannot supply these values without an independent safe APP flash and matched new host.

Existing slots0..5 preserved: SRSP queue depth+HWM (only if NPI_SREQRSP), async depth+HWM, SRSP enqueues (NPI_SREQRSP only), UART2 TX_FINISHED notifications. Their validity semantics are **unchanged**. This feature **does not fabricate** the three unsupported SRSP queue slots seen as NULL with the real UART/MT design.

## New versioned slots (existing byte offsets 56–127)

| Index | Key | Source-backed event |
|---|---|---|
| 6 | allProduced | original MT synchronous reply function called |
| 7 | allEnqueued | successful OSAL producer-to-NPI ownership transfer |
| 8 | allAllocFailed | MT response-message allocation failed |
| 9 | allSendFailed | MT response OSAL msgSend failed, no ownership transfer |
| 10 | allNpiReceived | existing NPI dispatcher accepted response message |
| 11 | allFramedQueued | NPI async queue accepted framed response |
| 12 | allFramingFailed | native NPI frame creation/queue allocation failure |
| 13 | allTlSubmitted | original NPITL_writeTL returned complete length |
| 14 | allTlRejected | original NPITL_writeTL returned short/error |
| 15–23 | afRegProduced, afRegEnqueued, afRegAllocFailed, afRegSendFailed, afRegNpiReceived, afRegFramedQueued, afRegFramingFailed, afRegTlSubmitted, afRegTlRejected | Same nine existing **AF_REGISTER-only** counters from the physically accepted 4cfe F3 diagnostics |

**Slot24 remains reserved zero.** General counters include SYS F2 self-responses *after* snapshot, so they are not directly comparable to AF host counts one-for-one. AF_REGISTER-only metrics diagnose startup endpoint registration; **do not confuse them with steady-state AF DATA_REQUEST replies**.

Counters are saturating uint32 held in RAM and read under a single OSAL critical section in F2. Original producer/NPI behavior and failure policy are unchanged. All-stage coverage is conditional on the exact compiled CC2652P7 SDK source; native C and stack-overhead checks are release gates. No physical UART-TX proof from TL accepted. Host USB writer queued bytes are likewise **not physical-transmission evidence**.

## Strict ABI constraints

- v4.1 retains minor=1 with mask 0x2C or 0x3F and **all unused slots zero**.
- v4.2 uses minor=2 with mask **0x00FFFFEC** (default NPI async) or **0x00FFFFFF** (only with NPI_SREQRSP). Only slots6..23 newly valid.
- Common magic/caps/nonce echo/boot-token/seq/reset checks are unchanged; bad mask/minor combination, nonzero slot24, or late wrong nonce => **optional F2 session quarantined**, no UART reset.
- Per-host durable journal stores sanitized scalar counters and trusted timestamp, not boot token, nonce, EUI, PAN, network keys or payloads.
- A rolling 1800s **VALID and worker-fsynced** snapshot objective remains. SKIPPED/FAILED still store only safe host-side evidence; no promise to query a wedged MT dispatcher.
- Compare stage deltas only within same host owner + **same unverified radio epoch tag**, monotonic sample sequence and nonnegative counter deltas; this is **observational continuity**, not hardware boot attestation.

## How the next hang can be localized

Read across stages on a valid F2 **before** a lockup; read passive host stream counters after F2 admission becomes impossible:

- allProduced grows but allEnqueued stalls + failed/alloc counters grow => **MT allocation/handoff**.
- allEnqueued grows but allNpiReceived stalls => **OSAL→NPI dispatch**.
- allNpiReceived grows but allFramedQueued stalls => **NPI frame/queue**.
- allFramedQueued grows but allTlSubmitted stalls => **TL submission/backpressure**.
- allTlSubmitted grows while host RX and matched SRSP plateau => **radio actual UART TX completion, ESP UART bridge, USB CDC or host framing**; use independent radio TX_FINISHED and host RAW RX/UNPI counters to further discriminate.
- Host RAW RX grows but UNPI checksum-good frames stall => **framing/corruption/incomplete frames**, not an outright serial silence.
- Everything progresses but AF timeout rises => **specific AF response/host matching**; investigate per-command, not a blanket USB failure.

A single snapshot cannot prove stage *loss*: bounded intervals and source-attributed counters are essential. If the radio ceases all MT responses, native F2 won't arrive either. Passive 60–90s host samples and a 30-minute native SLO breach document that absence without extra polling or restoration.

## Production gate

1. exact-source GitHub native dual CCS build and actual C source harness pass;
2. firmware/host minor2 decoder strictly tested including negative cases;
3. assess NPI critical-section overhead and C stack (new 18 x u32 snapshot 72 bytes);
4. immutable hardware/APP/AC000/NV/security/counter and one-owner acceptance plan;
5. explicit separate guarded flash and single-owner Z2M cutover (only if and when justified), no automatic rollback or factory reset.

The prior known-good ROM/BSL recovery method remains the first outage-restoration action. Observability work must not endanger the currently recovered 107-device Zigbee network.
