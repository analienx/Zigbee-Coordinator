# V6: first overdue operation, with an independent observer

This is the P1 successor to the deployed P0 host capture in PR #185. The live
radio remains `e3a0f3b7`; P0 host source `596e8dc2` captured a real AF pending
warning at 4,001 ms, followed by an AF timeout. It subsequently persisted three
minor4 samples and a V5 flight with advancing NPI/MT/UART counters and drained
queues. P0 functionality is verified; that observation does not locate the
radio/bridge failure stage or establish that the remaining defect is fixed.

## Observer and ownership

A statically constructed 250 ms TI Clock callback runs in the pinned Clock
Swi, independently of the NPI and stack tasks. It performs bounded RAM reads
under the existing OSAL critical section. It allocates nothing, traverses no
queues, posts no work, and performs no UART, NV, RF or recovery operation.
The exact Clock header/implementation and B1-modified stack source are bound
into composition and native sealing. B1's pre-MAC validation, event credit
repair and dispatcher evidence hooks remain in the actual stack loop.

MT entry owns a non-reused boot-local generation and command until its
matching exit. A stale exit cannot clear another owner. Framed messages own
separate queue generations; TX inherits the dequeued frame's generation.
These identifiers are **stage-local**, not an end-to-end request identifier.
Generation exhaustion disables new identity claims rather than reusing IDs.

| Observed stage | Budget | Basis and interpretation |
| --- | --- | --- |
| AF dataRequest/Ext/SrcRtg, SYS ping/version handler | 2 s | Synchronous enqueue/query work; observation is well above normal millisecond execution, before the six-second host deadline |
| Other MT handlers | 8 s | Allows slower NV/startup work; ordinary four-second host latency does not trigger this observation |
| Framed SRSP queue head | 2 s | Leaves four seconds of the normal host deadline for the remainder; queue age starts at admission, not at host send |
| Unsolicited queue head | 60 s | Existing production evidence includes 36.1 s bursts; congestion alone is not classified as a permanent failure |
| Accepted UART TX still busy | 250 ms | Maximum 255-byte frame at 115200 takes under 23 ms at ten bits/byte; budget exceeds ten frame times |

Budgets are diagnostic policy, not hard real-time or permanent-fault claims.
Observation is quantized by the callback interval; callback count, last tick
and maximum scheduling gap expose observer delays. Interrupt masking, a stuck
Clock Swi or a whole-CPU halt can stop the observer too. No instrumentation
can establish progress while its own execution context is stopped.

Four separate immutable records preserve the first overdue observation for
each stage, including command class, owner, entry/observation/age/budget,
pending-state flags, queued bytes, response production, progress counters and
the preceding 16 V5 events. An earlier SRSP queue delay cannot hide a later
MT or UART observation. First-observed ordering is not a claim about which
physical fault happened first.

NPI wake progress, actual stack dispatch entry/return and successful UART
completion are separate. Stack idleness is legitimate: an unchanged dispatch
counter alone is not a deadlock. UART instrumentation observes completion and
the existing busy flag; it never changes transport state or callback ownership.

## Explicit readout and paired delivery

LEN8/minor4 and LEN9 selectors 1/2 (V5) remain unchanged. V6 uses magic `R4D6`,
ABI 6, with the same eight-byte nonce in an explicit nine-byte F2 request.

| Selector | Size | Contents |
| --- | --- | --- |
| 3 | 160 | Observer/live progress, budgets, pending owners and selected frozen stage |
| 4–7 | 248 | Frozen MT/SRSP queue/unsolicited queue/UART record and history |

Selector 3 caches one selected immutable record, rotating among latched stages.
Its selected follow-up uses the same nonce, sequence, native tick and boot
bytes, with a two-second TTL and one-time consumption. Invalid, expired,
cross-page or replayed data is rejected. With no overdue observation, only
the summary is requested. The host exports command classes, never raw frames,
nonces, boot identity, device identities or credentials.

`P7U_B4_STAGE_V6=1` is a separate opt-in, enabled only with a qualified paired
radio image. It alternates V6 and V5 opportunities in the existing sampler,
with four V4 slots following a submitted transaction. Busy skips retain demand
and yield one V4 slot. There is no new timer, forced request, second owner,
extra request after an ordinary sample, or congestion retry burst.

The no-serial worker persists `STAGE` separately from `VALID` and `FLIGHT`,
with strict nested privacy/bounds checks and a fixed 8 KiB record bound.
The passive half-hour exporter keeps stage counters, histories and observed
stages distinct from native VALID counts and host first warnings.

Qualification requires the actual composed C ownership/history/clock tests,
actual owner/Z2M compilation, coherent-pair rejection, no-wire admission,
slot fairness, durable replay/privacy and projection of the compiled-owner
fixture, followed by exact native build/sealing. This candidate has not been
flashed. The host opt-in must remain off until paired deployment qualifies it.

## Remaining independent evidence

RAM records do not survive reset or ROM recovery, and a terminally silent
radio may not permit retrieval. Heap low-water, stack margins and stronger
boot diagnostics remain unavailable until their exact providers and cost are
qualified; zero values must not be substituted for missing measurements.

A read-only sysfs inspection on 2026-10-29 found ESP VID/PID `303a:4002`,
`cdc_acm`, bulk OUT endpoint `02` and bulk IN endpoint `82`. It opened no serial
or USB device. The HA host exposed no usbmon module, debugfs usbmon directory
or `/dev/usbmon0`; no kernel module was loaded. This identifies the USB-facing
boundary, not proof of the internal CC2652P7-to-ESP forwarding stage.

SLZB-OS v3.4.3.dev1 backend source remains required for passive UART-received,
UART error/overrun, successful USB-forward completion/failure, epoch and
monotonic-time counters exposed through management. Public Berry byte reads
require suspending normal transport and are unsuitable. No bridge image,
stream-stealing script or reset is introduced by this candidate.
