# P10 AF refusal and NPI RX parser recovery — offline candidate 2026101104

Status: **source CI PASS; CCS image/link and hardware NOT QUALIFIED**. This branch extends draft #59 (SYS F0 SRSP telemetry and stack-message hardening) and leaves the running 2026101002 coordinator unchanged.

## Failure-stage instrumentation

Existing 15 NPI counters and 8 additional AF counters now expose AF command *submission*, not hypothetical allocator heap occupancy. Instrumentation intercepts exactly the responses of `AF_DataRequest` (normal + extended + final DATA_STORE), `AF_DataRequestSrcRtg`, and `MT_AfDataConfirm`. It records direct AF successes and exact 0x11 Buffer Full, 0x10/0x13 memory and miscellaneous rejection statuses; separate source-route successes/0x11; MAC CCA 0xE1 confirmations vs other non-success confirms.

These counts prove whether the **AF submission returned a status**; they do **not** prove which downstream APS/NWK pool, neighbor table, route request or CSMA resource triggered 0x11. A MAC confirmation happens *after* an accepted request; correlating the two is necessary. Counters are saturating modulo 2^32, reset on boot, and never reveal packet data, destination addresses or keys.

## RX overflow semantics

TI's original `NPITask_transportRXCallBack` executes `for(;;)` on a full ring, which permanently stalls NPI. The replacement has explicit corruption handling:
- If available ring space is insufficient, set a recovery flag; drain the rejected transport callback into a 32-byte stack scratch buffer (no allocation).
- While that flag is set, drop further callback fragments instead of feeding them to the frame parser.
- On the next NPI task event, deallocate the partially constructed UNPI message; discard the entire corrupted circular buffer; reset parser `state`, `LEN`, `FCS` and data counter; only then admit new frames. Never reassemble across an overflow.
- Explicitly set `pMsg=NULL` after a normal completed/invalid FCS, preventing recovery from double-freeing a buffer already transferred to a callback.
- Count overflow callback events and *actually discarded* transport bytes; no automatic Zigbee retransmission or coordinator reset.
- RX resync is intentionally lossy: a command in progress when overflow occurs is dropped and its caller must observe host timeout. No claimed exactly-once commands.

The implementation does not provide hardware UART flow control where none exists, and cannot detect all RX corruption caused by misbehaving upstream USB/ESP bridge. Parser concurrency and sustained overflow must be tested on a spare radio with short bursts across all callback/task interleavings before production use.

## Diagnostic wire contract

Read-only `MT SYS 0xF0`, no request payload; `SRSP 0x61 0xF0` returns **102 data bytes**, composed of v2, flags, 25×u32 little-endian. First 15 counters are unchanged, next eight counters represent AF/CCA status, final two represent RX overflow callbacks and dropped bytes. Previous v1 decoders must reject v2 instead of silently parsing it. Decoder selftest is offline: `python3 firmware/t832/min/npi_diag_decode.py --selftest`. Only invoke F0 through a coordinator-owner-aware Zigbee2MQTT adapter pathway on a qualified new firmware; never open a second serial client against production Z2M.

## Verification and open gates

- Source pin TI SDK 8.32.00.07, exact-match function-scoped anchors, exact modified SDK-file inventory.
- GitHub-hosted C fault injection runs actual patched NPI, AF and parser callbacks: 512 AF results, 256 RX resynchronizations, 512 heap-allocation failure cycles, 256 TX retry/SRSP fairness cycles and 128 stack-message paths.
- Real CCS compile/link/map must succeed on exact newest firmware-source SHA and linked image SRAM/flash budget must remain valid. Compiler flags / project board profile and NVS/TC/route tables remain unchanged.
- Spare CC2674P10 load/stress/USB bridge and Zigbee2MQTT protocol tests still needed. Physical flashing of the actual household coordinator is disallowed until #53 NIB/NVS retention/rollback and 103-key preservation are proven.
- Follow-up specifically targets the **underlying APSDE_DataReq internals** and OSAL free/largest-block telemetry, if a safe SDK API exists. This candidate does not pretend direct AF=APS pool occupancy, and does not indiscriminately raise buffers.
