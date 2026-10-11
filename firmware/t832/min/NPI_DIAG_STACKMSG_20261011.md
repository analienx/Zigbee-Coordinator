# T832-MIN NPI/SRSP diagnostics and stack-message forensic contract

Status: **offline candidate, NOT production qualified**. Source revision `2026101103`; ancestors CAP192 PR #55 / allocation PR #56 / transport PR #57 / SRSP fairness branch. Production device currently advertises `2026101002` and **does not support the new request**. No direct host request must be sent to an older production firmware.

## What changed

- Implemented **read-only** vendor NPI diagnostic command on MT SYS subsystem: SREQ SYS `cmd0=0x21`, `cmd1=0xF0`, **zero-length request payload**. UNPI request wire example: `FE 00 21 F0 D1` (SOF, length, cmd0, cmd1, XOR FCS). Do not send this directly via a second serial client: Zigbee2MQTT/herdsman must retain exclusive ownership of the coordinator transport.
- SRSP is `cmd0=0x61`, `cmd1=0xF0` with precisely **62 bytes**: `u8 ABI_version=1`, `u8 flags`, then **15 × u32 little-endian** counters. All values are aggregated; no network keys, addresses, NVS bytes, device identifiers or command payloads.
- Bit 0 of flags: SRSP priority queue allocated; bit 1: immediate-UART-write retry waiting on one-shot backoff. Other bits reserved and must be zero.
- Decoder: `python3 firmware/t832/min/npi_diag_decode.py --payload-hex "<62 bytes, no UNPI framing>"`, with offline `--selftest`; it does not open any connection.
- `NPITask_getDiagSnapshot` takes a short OSAL critical section only to copy counters. It does not allocate, emit logs, change device status, trigger radio traffic or write NVS.
- `NPITask_processStackMsg` now counts failure to frame the MT message or allocate a queue record; the frame builder has already consumed the original input on failure, avoiding double-frees. Both stack-to-NPI and direct NPI sends increment per-queue counters under their normal critical section.
- An SRSP allocation or task-enqueue failure increments a distinct counter without attempting to allocate a secondary error message during memory pressure.
- `npiAsyncQueueDepth` may include SRSP frames when the dedicated SRSP queue could not be created and normal FIFO fallback is in use. A successful UART write is an **accepted write**, not a physical completed transmission or Zigbee delivery.

## Wire fields (u32 little-endian, starting at byte offset 2)

| Index | Field | Interpretation |
|---|---|---|
| 0 | srsp_depth | Current SRSP priority queue depth |
| 1 | srsp_high_water | Max priority queue depth since boot |
| 2 | async_depth | Current general outgoing queue depth |
| 3 | async_high_water | Max general queue depth |
| 4 | srsp_enqueued | Responses admitted to priority queue |
| 5 | srsp_uart_accepted | Priority SRSPs accepted by UART transport |
| 6 | async_uart_accepted | General-queue frames accepted by UART |
| 7 | tx_immediate_rejects | Synchronous transport-write refusals |
| 8 | tx_rejected_drops | Frames dropped after bounded immediate-write retries |
| 9 | stack_frame_failures | Failed stack message framing |
| 10 | stack_queue_failures | Failed stack message queue record allocation |
| 11 | srsp_allocation_failures | Failed OSAL response allocation |
| 12 | srsp_enqueue_failures | Failed OSAL SRSP task enqueue |
| 13 | rx_frame_failures | Failed host frame wrapper/queue allocation |
| 14 | srsp_queue_fallbacks | Failed SRSP priority-queue creation at boot |

These 32-bit counters restart at boot and may wrap at 2^32. A counter rising alone does **not** establish the cause of ZNP `0x11 ZBufferFull`. In particular, `ZBufferFull` originates from a lower AF/APS/NWK send-stage resource check; this version does not instrument that return path. Correlate against coordinator MAC CCA/status, Z2M AF timings and USB bridge log before changing table or heap sizes.

## Checks and release gate

- Pinned TI SDK and CCS project source patching is fail-closed via exact-matched anchors. A change to unapproved source file inventory or host ABI should fail CI.
- Existing 512-round allocation-ownership tests and 256-round UART-reject/SRSP fairness tests remain mandatory.
- New native test `tests/t832_npi_stackmsg_diag_faults.py` compiles **actual patched stack message / callback and diagnostic C bodies** with mocked OSAL queue, message and frame APIs. It checks SRSP classification, normal AREQ, queue-unavailable fallback, interception, failed framing and queue allocation, 62-byte LE snapshot structure, and zero retained test allocations after 128 rounds.
- Full CCS compile/link/map validation at **exact commit SHA** is required. A green native mock test never proves RF, USB bridge, TI-RTOS concurrency or memory constraints on CC2674P10.
- Physical spare P10 testing should compare baseline queue counters with controlled AREQ burst and AF traffic, measure physical `UART2_EVENT_TX_FINISHED` and host SRSP gap, and verify no loss of necessary security/network traffic. No arbitrary drop cap for generic AREQ traffic.
- Production cutover remains **blocked** by NVS/NIB persistence/rollback [#53](https://github.com/analienx/Zigbee-Coordinator/issues/53), 103-key integrity proof and spare-radio soak. Never flash based on this source CI.

## Follow-up priorities (separate behavioral candidates)

1. Sample host ZNP SYS F0 through a single authorized Zigbee2MQTT adapter-aware path (only after field firmware qualification); correlate with actual AF `0x11`, `0xE1` CCA and heap counters without starting a second serial client.
2. Add narrow `AF_DataRequest` / `APSDE_DataReq` refusal classification for `0x11`, `0x10` and MAC failures, with no additional heap allocations in failure path, then compare queue depths.
3. Revisit upstream NPI RX overflow's terminal `for(;;)` with tested parser resynchronization and an explicit recovery state. Never just remove the loop and process corrupted partial frames.
4. Add sampled free-OSAL-heap/largest-free-block telemetry only with confirmed memory-manager API/locking and zero confidentiality impact; avoid claiming link-map SRAM equals OSAL free heap.
