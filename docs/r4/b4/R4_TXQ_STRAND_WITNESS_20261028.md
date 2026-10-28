# R4 TXQ strand witness — real producer chain proof (2026-10-28)

**Status:** Source-only candidate on deployed lineage `b97179a` (firmware
`899f179`, host `acaa002`). Not flashed. No hardware, serial, NV, HA,
reset, or re-pair action. Verification is GitHub Actions on the exact
commit only.

## Corrected premises (verified in deployed files)

- Deployed `tools/r4_uart_tx_liveness.py` is already the integrated
  TL-to-B1 version: it hooks the real B1 callback early return with
  `NPITL_abortFailedTx`, compiles the real `b1_management.h` bodies, and
  has five negative mutants. This change does not duplicate that fix.
- F2 causal/progress snapshots are latched inside `OsalPort_enterCS` in
  the B4 v4 handler and in `B4_V43_Snapshot`. A 12 s host-side elapsed
  gap proves no torn read, so no seqlock is added. The only out-of-CS
  sample in `B4_V43_Snapshot` (startup byte at base commit) is a single
  byte copied before the CS; it cannot tear a multi-byte counter and is
  out of scope here.
- `NPITask_sendToHost` exists in pinned TI 3615ad5 only as declaration
  plus definition with no Z-Stack production caller found. The
  production SRSP producer is task-local (below), so no cross-task
  TX_READY flag race is claimed from synthetic `sendToHost` injection.

## Normal AF SRSP pipeline (pinned TI 3615ad5, composed)

`MT_BuildAndSendZToolResponse` (MT/stack task, priority 5) ->
`OsalPort_msgSend(npiTaskID)` -> NPI task (priority 4) `msgReceive` ->
`NPITask_processStackMsg` (frame, enqueue `npiTxQueue`, set
`NPITASK_TX_READY_EVENT`, post) -> TX_READY section of
`NPITask_process` -> `NPITask_ProcessTXQ` (CS, dequeue one) ->
`NPITL_writeTL` -> `NPITLUART_writeTransport` -> UART2 driver ->
ESP32-S3 USB CDC bridge (303a:4002) -> host. Completion:
`NPITLUART_writeCallBack` -> `NPITL_transmissionCallBack` (fragment
continuation without task wake; final fragment wakes) ->
`NPITask_transportTxDoneCallBack` (sets TX_DONE flag, posts semaphore,
ignores size) -> TX_DONE section re-arms TX_READY when queued.
Profile: `NPI_FLOW_CTRL=0`, `NPI_SREQRSP` undefined, so the sync queues
and `syncTransactionInProgress` cannot block ASYNC traffic.

## Where a nonempty queue can persist (exhaustive by source)

| State at F2 snapshot | Meaning | Existing evidence |
|---|---|---|
| depth>0, TxActive=1 | UART completion blocked/never fired | writeAccepted != callbackOk freezes |
| depth>0, HOLD=1 | B1 fail-closed latch; drain refused by design | stateFlags bit1, b1FirstFailure |
| depth>0, idle, no HOLD, submissions advancing | Burst drain in progress | accepted/callbackOk/wakes advance |
| depth>0, idle, no HOLD, no dequeue across two NPI pend entries | Lost TX_DONE wakeup (flag+post dropped) | **new: first-fault kind 6** |

Every other transition to idle was traced and re-arms a wake: in-task
`ProcessTXQ` is re-evaluated by the same TX_READY section (B1 repost
guard), UART success/failure completions post via the TL callback or
`NPITL_abortFailedTx`, and fragment continuation keeps the TL busy
except on failure paths that latch HOLD. A blocked completion keeps
TxActive set. Therefore the only silent radio-side strand is a lost
completion wakeup sitting between an idle TL and a preserved TX_READY
flag with no future post — exactly what the witness confirms.

## Change (passive instrumentation, not a cure)

- `tools/r4_txq_strand_witness.py`: counts real
  `NPITask_ProcessTXQ` dequeues in `npi_task.c` and checks the strand
  inside `B4_V43_Snapshot` (F2 path, snapshot CS held) in `npi_tl.c`.
  Confirmation needs two consecutive F2 snapshots with queued ASYNC
  work, idle TL, no HOLD, and unchanged depth/dequeue count; the first
  snapshot only arms. A pend-entry observer was rejected in review:
  any wake whose body runs dequeues before a second pend entry, so it
  could never confirm the lost-wakeup state it targeted. Kind 6 keeps
  frozen-first semantics (expected field = queued ASYNC depth). No F2
  ABI change: reply stays 240 bytes, minor 3. It never posts, retries,
  reorders, or submits. ASYNC depth is incremented by both NPI
  producers (`NPITask_processStackMsg` and `NPITask_sendToHost`) under
  CS at the pinned B4 stage; either producer's wake dequeues before a
  later snapshot, so depth provenance does not affect confirmation.
- Host validators (`f2_progress_contract.py`,
  `b4_v4_herdsman_overlay.py`, `p7u_diagnostic_worker.cjs`) accept
  first-fault kind 6. Nothing else about the wire contract changes.

## Proof (GitHub-hosted, real C)

`tools/r4_txq_strand_witness_harness.py` compiles the real composed
producer, stack-msg, ProcessTXQ, TL, UART and task-section bodies with
only OSAL/Queue/semaphore/UART2 primitives stubbed:

1. `burst`: 128 real producer frames drain in FIFO order;
   writeAccepted == callbackOk == 128; no strand.
2. `stranded_snapshot`: after a real completion, the completion wake
   is dropped and the remaining producer frames are queued with the TL
   idle and no wake pending; the first F2 snapshot only arms, the
   second latches kind 6 with depth 2; a later host-poll wake drains
   the queue (recovery, record stays frozen).
3. `blocked`: no completion — TL stays busy, no strand, no spin.
4. `failed`: error completion — HOLD latches, busy clears, no false
   callbackOk, no strand.

Negative mutants must fail: removing the snapshot check or the
kind-6 latch (stranded_snapshot), restoring busy self-repost
(blocked), and removing the B1 abort notify (failed). Removing the
check is also the pre-patch control: the same stranded state then
latches nothing.

## ESP bridge boundary (exact unmet proof)

Radio counters prove delivery only to the UART2 driver completion.
With no flow control, ESP RX overrun or CDC stall cannot back-pressure
the CC26 TX, so a host RX freeze with advancing
writeAccepted/callbackOk and depth 0 isolates the ESP32-S3 bridge or
host USB path; kind 6 plus depth>0 isolates the radio lost-wakeup.
The ESP firmware is not in this repo and exposes no forwarding
counters, so ESP-internal drops (UART RX overrun vs CDC IN stall)
remain unproven until ESP-side read-only counters exist. During a
freeze F2 itself shares the stalled path; read the latched kind-6
record after ESP-only recovery without a radio reset (RAM counters
persist). Telemetry is not labelled a cure: if kind 6 ever latches on
hardware, the lost-wakeup mechanism still needs a root-cause fix.

## Falsification attempts (source reasoning, no local runs)

- Fragment-continuation reject: always ends with HOLD latched via
  `NPITLUART_writeTransport`, never a silent idle strand. Rejected.
- `NPITask_sendToHost` TX_READY flag race: no production caller in
  pinned Z-Stack; production enqueue is same-task. Rejected.
- TX_DONE capture race: ISR flag merge is under the HwiP CS and the
  callback is HWI-context; sticky flag plus counting post cannot be
  consumed silently. Rejected as a design race; only an externally
  dropped flag+post (modelled in `stranded_snapshot`) strands it.
- One-OSAL-message-per-wake starvation: each `processStackMsg` enqueue
  posts again, so a burst self-sustains wakeups. Rejected.
