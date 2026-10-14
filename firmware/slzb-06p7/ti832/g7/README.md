# G7 transport ownership and MT fairness — NOT FLASHABLE

This overlay follows G5/G6 on the pinned SDK. It targets only MT UART2 callback
mode, without handshake or the legacy NPI_SREQRSP watchdog. It does not change
board pins, RF, CCFG, NV geometry, startup or production network identity.

The original task freed every queued frame even when UART returned a proven
pre-submission error. It also reposted a nonempty TX queue while transport was
busy. G7 retains one head per FIFO until submission or an explicit drop. Each
lane holds at most eight frames, including its retained head. Valid framed MT
SRSP and AREQ commands use separate queues; four accepted or ambiguous SRSP
attempts give a ready AREQ its next turn. Rejections preserve FIFO order and do
not advance the burst. Ambiguous attempts count conservatively for fairness,
but do not emit the UART_ACCEPTED recorder event.

Only ENOTOPEN and EINUSE, verified before DMA in the pinned actual driver, may
retry. There are at most three driver calls per head and a 50 ms tick-domain
head budget. Backoff samples the tick after rejection and waits ceil(5 ms / tick
period) plus one tick to cover unknown tick phase. Expiry is tick-quantized and
task scheduling can delay observation. Unrelated enqueue/RX wakes do not reset
timestamps. INVALID drops; ACCEPTED and AMBIGUOUS never requeue. The TL copy is
retained until its existing callback, independent of task frame lifetime.

A static one-shot ClockP wakes the existing NPI task. A missing completion
callback after a 50 ms tick-domain busy budget latches a transport fault,
discards bounded queued frames and rejects further TX until a new boot. It
does not clear a potentially DMA-owned buffer, cancel UART, reset the radio or
repeat uncertain bytes. RX parsing continues. Timer construction failure or
zero tick period rejects TX explicitly. Counters are RAM-only source evidence,
not host reception, physical idle, retained telemetry or network qualification.

Hosted regressions compile the actual pinned Queue, frame, task, UART API,
lower submit and callback bodies with injected platform boundaries. Original
stuck-busy and lost-ownership controls must fail at their specific assertions.
Post-fix vectors cover repeated rejection, saturation, uncertain outcomes,
inline/late/lost completion, timer/heap failure, wrap/coarse ticks, FIFO,
SRSP-storm AREQ service and RX progress after fault. These remain host tests;
DMA interrupt behavior and physical stress require separate acceptance.

The native stock and CAP192 workflows retain the independent G6 ELF/HEX/NV and
TI-reference CCFG audits and additionally require the real linked UART call
path and UART2.c.obj ownership of weak API symbols. P7U stock20240710 power
binding and fitted-board UART/RF/clock evidence are separate work. All native
artifacts remain NOT_FLASHABLE.
