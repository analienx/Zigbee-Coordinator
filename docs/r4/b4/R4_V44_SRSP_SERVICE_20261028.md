# R4 v4.4: predictable SRSP service — first implementation

Candidate successor to the delivered v4.3 pair. Source and hosted qualification
are separate from radio deployment. The terminal silent hang remains open.

The existing NPI task remains the sole UART submitter. Outgoing MT frames are
classified by their real CMD0 type, independently of `NPI_SREQRSP` (which stays
disabled). SRSPs enter a separate static queue object. Each traffic class stays
FIFO. When both classes have work, up to four SRSPs precede one AREQ; an accepted
UART write is never interrupted. All AREQs retain one FIFO, including data
confirmations and incoming device messages. No traffic is shed or coalesced.

Before sleeping, NPI checks both TX queues, UART busy/HOLD and pending complete
RX frames under its existing critical section. Enqueue and completion post its
existing semaphore. A post between the check and pend remains a semaphore token.
An idle UART with work can progress without a surviving TX event hint; a busy
UART does not cause queue-based self-posting. B1 physical transport HOLD remains
sticky and prevents subsequent physical submissions.

F2 minor4 remains nonce-correlated and carries 248 bytes, below the pinned
250-byte MT limit. Minor1/2 remain 160 bytes and minor3 remains 240 bytes. It
preserves all 18 MT lifecycle fields and all 20 UART/first-fault fields:

| Offset | Minor4 field |
| --- | --- |
| 12 | validity mask `0x01ffffff` |
| 32–48 | real SRSP/AREQ depths, high-water counts, SRSP enqueues |
| 128 | maximum AREQ queue age, ticks |
| 140, 144 | queued framed SRSP and AREQ bytes |
| 148, 152 | high-water framed SRSP and AREQ bytes |
| 157 | minor `4` |
| 160–239 | unchanged UART progress and frozen first physical fault |
| 240 | maximum SRSP queue age, ticks |
| 244 | maximum ready-to-service delay, ticks |

Counts/bytes share one snapshot critical section. Queue age includes the current
oldest pending frame and dequeued-frame maxima. Ready-to-service timing begins
when queued TX becomes transmissible, excluding the preceding UART busy time.
These are RAM-only, boot-local maxima. Convert ticks using the existing
`uartProgress.tickPeriodUs`; unsigned interval arithmetic assumes less than one
full tick-counter wrap. Queue age begins at NPI framing/enqueue, not host request
creation or MT response production. Queued bytes cover framed TX queues, not
the OSAL mailbox, heap overhead or an already-accepted UART copy.

The paired collector records these fields through the existing strict worker,
hash chain and manifest. Offline freshness reports convert ages/gaps to ms.
Older paired hosts reject minor4; deploy the matching host before accepting it.

The separate herdsman correction removes a caller-owned confirmation waiter
when its request fails synchronously, at the writer or asynchronously, while
preserving successful requests' confirmations and unrelated waiters. Expired
waiters delete themselves immediately instead of waiting for a future frame
sweep. It changes host cleanup only, not coordinator recovery behavior.

## Qualification and scope boundary

The composed-source stage executes the final actual TI MT producer, frame
builder, both enqueue APIs, TX selector, task loop and completion callback in a
compiled C fixture with sanitizers. A virtual 115200/8N1 UART adds delayed
completions. The flood feeds 6000 full unsolicited frames with bounded live
allocations, injects SRSP during load, and requires SRSP completion under one
second, FIFO order, at most four SRSPs between AREQs when both classes are
pending, empty queues and zero live allocations after drain. Further cases
exercise lost hints, enqueue before pend, delayed completion, HOLD, tick wrap
and allocation failure. Broken preference, fairness, sleep and completion
variants must fail. Native ARM builds use the same composition and seal the
new function and changed source hashes. The virtual test is software evidence;
it does not prove RF load behavior, ESP forwarding or a terminal-hang repair.

This first candidate intentionally does not claim the following later work:

- Reserved bounded SRSP production/framing resources: frames and records still
  use the existing heap. Extreme heap exhaustion can still prevent an SRSP.
- Heap low-water, task stack margins and an independent terminal-stage fault
  record beyond the existing frozen UART/B1 first-fault telemetry.
- ESP UART-received/USB-forwarded counters: these require a separate bridge
  firmware implementation and management endpoint.
- Physical flood qualification or captured failing-stage evidence for the final
  silent hang. Hosted passes alone do not mark that defect fixed.

No resets, firmware writes, network changes or bridge changes are performed by
source qualification. A deployed candidate requires its own protected paired
delivery and live-service/F2 acceptance receipt.
