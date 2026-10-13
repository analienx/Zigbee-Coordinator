# G7 pinned transport findings — implementation still pending

Authority: TI SDK `6499c3f53fc5fb5806213be695450a7b43fbaf3d`.
This is source inspection, not a runtime qualification or F11/F12 acceptance.

## Driver boundary

`source/ti/drivers/UART2.c` implements the weak `UART2_write` through
`UART2_writeTimeout(..., UART2_WAIT_FOREVER)`. Callback mode takes the
`UART2_writeTimeoutBlocking` branch despite that function's name. The
nonblocking branch is not the configured NPI mode and cannot supply its proof.

| Result | Position in actual callback-mode function | Retry interpretation |
|---|---|---|
| `EINVALID` for size zero | Before critical section and write state | Invalid frame; discard without a driver retry |
| `ENOTOPEN` | Before write state or DMA | Proven immediate rejection |
| `EINUSE` | Before write state or DMA | Proven immediate rejection |
| `SUCCESS` | After write state and `UART2Support_dmaStartTx` | Submitted; never retry |
| `ECANCELLED` / `ETIMEOUT` | After DMA start, at function exit | Submission may have occurred; never retry |
| Any other status | No proved pre-submission path | Ambiguous; never retry |

The driver dereferences `handle->object` before those checks. A null handle
requires a caller guard; it is not safely detected by the driver's status path.
The source symbols are weak, so the final native linked path must also exclude
an overriding implementation before these classifications become evidence.

## Existing NPI loss and busy latch

`npi_task.c:NPITask_ProcessTXQ` dequeues, invokes `NPITL_writeTL`, and frees the
frame/record without checking its return. The legacy synchronous variant has
the same unconditional ownership release.

`npi_tl.c:NPITL_writeTL` sets `npiTxActive` before `transportWrite`. The UART
wrapper converts every non-success result to zero transport length. The TL
does not clear `npiTxActive` on this path; its completion callback only clears
it when `Txlen` is nonzero. A proved immediate rejection can therefore lose the
frame and leave the TL busy forever. Replacing all zero returns with retries
would instead risk duplicate transmission after an ambiguous driver result.

Required implementation: propagate explicit outcomes through the actual UART
and TL bodies, clear this attempt's busy latch only for proved rejection, and
retain task ownership until submission or an explicit bounded discard. A
preexisting busy TL must not cause a new driver submission or consume an
attempt. Queue processing must wait for a completion/timer wake, not repost
the semaphore continuously while busy or waiting for retry eligibility.

## Queue and timing constraints

The pinned default MT transport fits a maximum 255-byte frame in the actual
270-byte TL buffer. Oversize input must be rejected before copying; accepting
fragmentation requires a separate lifetime proof because the fragment pointer
can outlive the task's original buffer.

`NPI_SREQRSP` is not enabled for the pinned candidate. Enabling it would add
legacy watchdog and transaction semantics beyond this fix. Classify the
already-framed MT message using validated SOF/length/CMD0 at offset 2, with
type bits `0x60` for SRSP. Maintain two FIFO lanes and count four **submitted**
SRSPs before servicing ready AREQ; rejected attempts must not advance that
count. If one lane is waiting for retry eligibility, the other ready lane may
run without reordering either lane's head.

Use the actual `ClockP_construct`/`ClockP_start`/`ClockP_setTimeout` API for a
one-shot wake. Construction failure must lead to a bounded discard/fallback,
not silent retention with no future wake. Timing is modulo ticks with a known
period and half-range limit. A rejection keeps the original first-attempt
deadline; it must not restart the 50ms budget. Coarse tick resolution and task
scheduling delay must be explicit in acceptance evidence.

Required hosted falsification compiles the actual TI UART dispatch/body and
modified UART/TL/task functions. It must reproduce pre-fix lost ownership and
stuck busy, then test rejection counts/deadline/wrap, no duplicate submitted or
ambiguous frames, callbacks, pending head lifetime, nonspinning timer wake,
SRSP/AREQ FIFO fairness and bounded fallback. Pure policy tests alone cannot
establish these fixes. Native acceptance follows on the exact final SHA.
