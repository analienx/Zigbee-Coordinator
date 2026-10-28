#!/usr/bin/env python3
"""Passive TXQ strand witness on the accepted P7U R4 composite.

Source reasoning (pinned TI 3615ad5 + B1/B4/AF/F2 composition) shows the
ASYNC TX queue cannot silently persist with an idle TL and no HOLD: every
transition to idle either re-evaluates the queue in the NPI task, posts the
NPI semaphore from the UART completion/abort path, or latches B1 HOLD.
The one state no existing counter can prove after the fact is a lost
completion wakeup. A pend-entry observer cannot confirm it (any wake whose
body runs dequeues first), so confirmation lives where the state is
externally observable: two consecutive F2 snapshots with ASYNC depth
queued, TL idle, no HOLD and no intervening ProcessTXQ dequeue latch the
state once into the existing F2 first-fault record (kind 6).

Passive only: no wake, retry, timeout, reset, queue, ordering, NV, RF or
serial-owner change. The observation never submits or drops a frame.
"""
import hashlib
from pathlib import Path

from r4_uart_tx_liveness import TL, extract, once

TASK = "source/ti/zstack/npi/npi_task.c"
MARKER = "B4_TXQ_STRAND_WITNESS"

HELPER = r"""/* B4_TXQ_STRAND_WITNESS: snapshot-confirmed strand check, called with
 * the F2 snapshot critical section held. Confirms only across two F2
 * snapshots with unchanged ASYNC depth and dequeue count, so normal
 * drain, a blocked completion (TL busy) and B1 HOLD can never confirm.
 * Depth is incremented by both NPI producers (processStackMsg and
 * sendToHost) under CS at the pinned B4 stage; either producer's wake
 * dequeues before a later snapshot, which disarms or moves the counts. */
extern volatile uint32_t B4_NpiAsyncDepth;
extern volatile uint32_t B4_TxqDequeueCount;
static uint32_t B4_TxqSnapSavedDepth = 0u;
static uint32_t B4_TxqSnapSavedDequeues = 0u;
static uint8_t B4_TxqSnapArmed = 0u;
static void B4_TxqSnapshotCheck(void)
{
    if (B4_NpiAsyncDepth != 0u && !npiTxActive &&
        !b1_management_transport_unavailable())
    {
        if (B4_TxqSnapArmed != 0u &&
            B4_TxqSnapSavedDepth == B4_NpiAsyncDepth &&
            B4_TxqSnapSavedDequeues == B4_TxqDequeueCount)
        {
            B4_V43_FirstFault(6u, 0, B4_NpiAsyncDepth, 0u);
            B4_TxqSnapArmed = 0u;
        }
        else
        {
            B4_TxqSnapArmed = 1u;
            B4_TxqSnapSavedDepth = B4_NpiAsyncDepth;
            B4_TxqSnapSavedDequeues = B4_TxqDequeueCount;
        }
    }
    else
    {
        B4_TxqSnapArmed = 0u;
    }
}

"""


def apply(sdk):
    sdk = Path(sdk)
    task_path, tl_path = sdk / TASK, sdk / TL
    task_original = task_path.read_text(encoding="utf-8")
    tl_original = tl_path.read_text(encoding="utf-8")
    if MARKER in task_original or MARKER in tl_original:
        raise ValueError("TXQ_STRAND_WITNESS_ALREADY_APPLIED")
    if "B4_F2_V43_PROGRESS" not in tl_original or "B4_V43_FirstFault" not in tl_original:
        raise ValueError("TXQ_STRAND_WITNESS_REQUIRES_F2_PROGRESS")
    if "else if (!NPITL_checkNpiBusy()" not in task_original:
        raise ValueError("TXQ_STRAND_WITNESS_REQUIRES_B1_REPOST_GUARD")
    text = once(task_original,
        "volatile uint32_t B4_NpiAsyncDepth = 0;",
        "volatile uint32_t B4_NpiAsyncDepth = 0;\n"
        "volatile uint32_t B4_TxqDequeueCount = 0u; /* " + MARKER + " */",
        "STRAND_COUNTER_DEFS")
    process = extract(text, "static void NPITask_ProcessTXQ(void)")
    if process.count("recPtr = Queue_dequeue(npiTxQueue);") != 1:
        raise ValueError("TXQ_STRAND_WITNESS_PROCESS_TXQ_DRIFT")
    ticked = process.replace(
        "recPtr = Queue_dequeue(npiTxQueue);",
        "recPtr = Queue_dequeue(npiTxQueue);\n"
        "    if (recPtr != NULL && B4_TxqDequeueCount != 0xFFFFFFFFu)\n"
        "        ++B4_TxqDequeueCount; /* " + MARKER + " */",
        1)
    text = once(text, process, ticked, "STRAND_DEQUEUE_TICK")
    tl = once(tl_original,
        "void B4_V43_Snapshot(uint8_t *out)\n{",
        HELPER + "void B4_V43_Snapshot(uint8_t *out)\n{",
        "STRAND_SNAPSHOT_HELPER")
    tl = once(tl,
        "    B4_V43_Progress[19] = Clock_tickPeriod;",
        "    B4_V43_Progress[19] = Clock_tickPeriod;\n"
        "    B4_TxqSnapshotCheck(); /* " + MARKER + " */",
        "STRAND_SNAPSHOT_CALL")
    task_path.write_text(text, encoding="utf-8", newline="")
    tl_path.write_text(tl, encoding="utf-8", newline="")
    return {
        "schema": "p7u-r4-txq-strand-witness-v2",
        "source_only": True,
        "passive_observation_only": True,
        "wake_retry_timeout_reset_added": False,
        "queue_order_or_ownership_changed": False,
        "network_nv_or_security_mutation": False,
        "confirm_rule": "TWO_F2_SNAPSHOTS_QUEUED_IDLE_NO_HOLD_NO_DEQUEUE",
        "record": "F2_FIRST_FAULT_KIND_6_FROZEN",
        "before_sha256": {TASK: hashlib.sha256(task_original.encode()).hexdigest(),
                          TL: hashlib.sha256(tl_original.encode()).hexdigest()},
        "modified_sha256": {TASK: hashlib.sha256(text.encode()).hexdigest(),
                            TL: hashlib.sha256(tl.encode()).hexdigest()},
    }
