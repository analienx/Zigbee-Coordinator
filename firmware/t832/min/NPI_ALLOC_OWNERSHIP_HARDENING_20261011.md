# CAP192 NPI allocation ownership hardening — 2026-10-11

Status: **offline source candidate / NOT FLASHABLE / hardware unqualified**.
Base: [CAP192 PR #55](https://github.com/analienx/Zigbee-Coordinator/pull/55), pinned TI SDK 8.32.00.07 `6499c3f`, CC2674P10, actual CAP192 SYS_VERSION 2026101002.
This is a narrow leak fix, NOT a claimed cure for every ZNP `0x11 BUFFER_FULL` condition. Do not inflate heap or queues again without live queue/free-block evidence.

## Why this matters

The production P10 rejected scoped join and AF commands with `ZBufferFull/0x11` after the KitchenSocketLeft OTA had stalled. Earlier captured failures affected unrelated devices, and local UTIL queries also occasionally missed their SRSP. Prior debug showed a successful AF confirmation 36 seconds after accepting the request and batches of buffered callbacks. Both stack queue congestion and host/NPI/ESP/USB transport delays remain plausible; error `0x11` identifies neither OSAL heap exhaustion nor which Z-Stack queue filled.

Allocation leaks are nevertheless **source-proven bugs** that make any temporary resource exhaustion sticky: a failed operation can abandon allocated bytes, reducing the capacity available for subsequent recovery. Increasing linked heap from 6KiB to 32KiB in CAP192 raises headroom, but does not remove such a leak. No live allocator instrumentation proves that the leak was exercised in this incident.

## Exact ownership ledger

| Source and operation | Ownership before success | Transfers only upon | Fixed failure release |
|---|---|---|---|
| `npi_task.c::NPITask_incomingFrameCB` | `pFrame` from MT frame parser, independently allocated queue record and `NPIMSG` wrapper | Valid queue enqueue | release original frame and whichever wrapper/record allocation succeeded when either allocation fails |
| `npi_task.c::NPITask_sendToHost` | framed `NPIMSG` plus `NPI_QueueRec`; input is consumed by `NPIFrame_frameMsg` | Accepted recognized outgoing queue type | release framed buffer, wrapper and record on partial allocation; release all on unsupported type |
| `npi_task.c::NPITask_sendBufToStack` | original incoming message/frame, separate OSAL message wrapper, separately malloc'd payload | `OsalPort_msgSend` returns `OsalPort_SUCCESS` | free OSAL wrapper when payload allocation fails; free payload + wrapper if message-send rejects, then free original input frame/container |
| `npi_client_mt.c::MT_BuildAndSendZToolResponse` | OSAL SRSP message | `OsalPort_msgSend` succeeds | deallocate SRSP if message-send rejected |

**Why send failure is not already handled:** TI's OSAL `msgSend` queues a message only when it finds a valid destination task; on `INVALID_TASK` it returns without consuming or freeing the caller's message. Do not free a successfully queued message because its receiver now owns it.

**What remains open:** If `msgAllocate` for a new SRSP fails, it cannot reply: the ZNP protocol currently has no allocation-free response fallback. We avoid fake `SUCCESS` replies, unsafe reuse of owned buffers, recursion, or an ISR allocator. Instrument this as a counted dropped SRSP and establish a real runtime backpressure design later. The current private `NPITask_sendBufToStack` return initializes `msgStatus=0` even when allocations fail; its caller ignores the result. That is a diagnostic ambiguity, not addressed in this ownership-only PR.

## Additional audited failure mechanisms NOT patched blindly

1. `AF_DataRequest` delegates to `APSDE_DataReq`; immediate `0x11` can be an internal AF/APS/NWK resource refusal even when host UART and SRSP delivery work. **The exact failing queue is unmeasured.**
2. `NPI_SREQRSP` is compiled out in the linked CAP192 build, so SRSP/AREQ share the async TX queue. Stack task priority 5 > NPI 4. Under load SRSPs can be delayed; switching scheduling or defining a separate sync queue is a **separate behavior change**, requiring transaction-order tests, not an allocation patch.
3. `NPITask_transportRXCallBack` contains `for(;;)` on RX-buffer overflow, creating a terminal trap under sufficiently severe traffic. This is dangerous but a distinct recovery-state design: do not turn it into an uncontrolled continuing parser that processes truncated frames.
4. `npi_tl_uart.c` TX error/physical completion and ESP32-S3 USB bridging remain candidate stalls. Direct USB/host-buffer evidence required to attribute the pause.
5. The normal UART frame maximum is far smaller than the configured 1080-byte `NPI_MAX_FRAG_SIZE`, so a hypothetical fragmented-buffer use-after-free in the generic path is not a plausible explanation for observed regular MT frames.

## Validation

- Pinned upstream source patched using exact-match anchors; unexpected SDK commit or changed anchor fails before artifact creation.
- `tests/t832_npi_ownership_faults.py` **compiles the actual patched C function definitions**, mocking only OSAL heap, queue and transport. It exercises independent allocation failures, valid and malformed queue frames, rejected task message sends, successful ownership transfers, and asserts **zero live allocations after each case**, repeated **512 cycles** to catch cumulative loss. Not a real P10 RTOS/RF test.
- GitHub-hosted real CCS linker/image workflows and effective 32KiB OSAL heap/linker geometry remain required at the exact candidate SHA; no local/WSL/self-hosted build is an acceptance substitute.
- Next runtime diagnostic after code review: low-rate counters for `OSAL malloc/message allocation failures`, NPI TX/RX depth + oldest age, failed `OsalPort_msgSend`, AF/APS pending queue, `0x11` return stage, SRSP allocation/enqueue/UART physical completion, UART RX overflow. Sampling should be bounded and lossless enough to determine which subsystem fails first. No unbounded logging, automatic reset, blanket retry or cluster-wide polling flood.
- Release gate: spare CC2674P10 RF/UART/USB integration and load soak; independently qualified original-network backup and NVS restoration (#53), counters and rollback. The live P10 has previously lost readable NIB after `eraseNVM=0`; do not flash this candidate on household hardware based solely on green hosted CI.

References: [HA transport incident #73](https://github.com/analienx/home-assistant-stack/issues/73#issuecomment-6112049034), [P10 NV persistence #53](https://github.com/analienx/Zigbee-Coordinator/issues/53), pinned [TI NPI source](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/6499c3f53fc5fb5806213be695450a7b43fbaf3d/source/ti/zstack/npi/npi_task.c).
