# R4 v4.5: bounded SRSP memory reserve — source-only implementation

Issue: [#180](https://github.com/analienx/Zigbee-Coordinator/issues/180). This
patch is stacked after the v4.4 SRSP scheduler of PR #179.

## Exact allocation trace

Pinned TI 8.33 (`3615ad5d3f4f271258d18a2f5ce1785064ff9a58`):

1. `MT_BuildAndSendZToolResponse` in `npi_client_mt.c` allocates an OSAL
   message of `dataLen+3` and sends it to the NPI task; it cannot guarantee
   a response when the global heap is exhausted.
2. `NPITask_processStackMsg` in `npi_task.c` calls
   `NPIFrame_frameMsg`, which allocates `NPIMSG_msg_t` plus a framed
   `dataLen+5` buffer and releases the original payload.
3. The NPI task then allocates a `NPI_QueueRec` on the same heap and enqueues
   it. The v4.4 separate SRSP FIFO only acts after this stage.
4. `NPITask_ProcessTXQ` hands the frame to the existing `NPITL_writeTL`;
   the qualified nonfragmented transport copies frames at most 255 bytes.

## Implementation

For SRSP (CMD0 type 0x60) of 0–250 payload bytes, the MT producer first
attempts one of **three statically reserved complete-frame slots**. Each
slot contains one queue record, one NPI message object and a 255-byte frame
buffer; the total static footprint is three `sizeof(B4_V45_Slot)` objects.
It copies payload, creates SOF/FCS, and enqueues through the existing v4.4
SRSP queue. **No OSAL heap allocation, OSAL mailbox allocation or second
framing allocation occurs on this path.** The NPI task is still the sole
UART submitter; slots are released after the existing transport has accepted
or rejected its bounded copy. Static memory is never given to the OSAL
allocator. A completed transport-copy release explicitly scrubs the fixed
255-byte frame buffer through volatile stores before returning the slot to
the reserve. Concurrent access uses existing OSAL critical sections.

When all three slots are occupied, or NPI is not initialized, the *unchanged
legacy dynamic path* is attempted; an unsuccessful dynamic attempt remains
an explicit existing causal `AllRspAllocFailed`/send-failure event. The
new internal RAM-only counters are `B4_V45_ReserveUsed`,
`B4_V45_ReserveExhausted` and `B4_V45_ReleaseFault`. They are **not**
represented as minor4 F2 fields: changing F2 wire ABI requires separately
versioned host and radio coordination. No new telemetry claim is made.

This is bounded protection for at most three simultaneously pending SRSPs,
**not** unbounded guaranteed service. Queue saturation, physical HOLD,
hardware failure and independent hangs remain possible. We intentionally do
not globally raise heap size, stack/task priorities or UART timeouts.

## Qualification

A new actual-source C fixture compiles the final MT producer, NPI framing
and v4.4 queue TX functions with sanitizers. It floods unsolicted messages,
forces every OSAL allocation to fail, proves SRSP creation/queued ownership
and physical-copy simulation, deliberately exhausts the reserve, checks
legacy fallback accounting, exercises HOLD, re-use before delayed UART
completion, no invalid heap frees, and negative mutation tests.

The full composite and two exact-head ARM builds must pass before any hardware
consideration; native linker RAM/map checks remain mandatory. The fixture
uses a modeled UART, not real RF/ESP, and this change does **not** prove a
terminal-hang cure or authorize flashing. NV, counters, CCFG, network state
and physical UART ownership are unchanged.

## Additional pinned NPI ingress leak correction

The inbound request path is still heap-dependent, and the static SRSP reserve
does **not** guarantee that an incoming SREQ reaches the MT handler under
total heap exhaustion. However pinned TI `NPITask_sendBufToStack` has two
concrete memory leaks in its original handoff: when its OSAL wrapper allocation
succeeds but the separate payload allocation fails, the wrapper was never
freed; and when OSAL message-send rejects a message, both the payload and
wrapper were leaked. Both can exacerbate later OOM and silent command failure.

The composed source now frees each owned allocation on both paths, sets a
non-success default when allocation fails, and leaves message ownership with
the MT service task only after a successful send. It preserves the existing
NPI→MT OSAL queue and stack-task context. Two RAM-only counters distinguish
allocation failure from send rejection. A separate compiled *actual TI
function* fixture injects both failure sites and send rejection, checks
successful ownership transfer, and rejects mutants restoring the leaks.

Ingress `NPIFrame_collectFrameData` and the endpoint descriptor still need
available heap. Full global-heap exhaustion before request dispatch is not
claimed solved. This patch instead ensures failures don't permanently leak
resources and improves the ability to recover once memory becomes available.
