#!/usr/bin/env python3
"""Passive TXQ pend-strand witness on the accepted P7U R4 composite.

Source reasoning (pinned TI 3615ad5 + B1/B4/AF/F2 composition) shows the
ASYNC TX queue cannot silently persist with an idle TL and no HOLD: every
transition to idle either re-evaluates the queue in the NPI task, posts the
NPI semaphore from the UART completion/abort path, or latches B1 HOLD.
The one state no existing counter can prove after the fact is a lost
TX_DONE wakeup (flag+post dropped after a real UART completion). This
stage latches that state, once, into the existing F2 first-fault record
(kind 6) when the NPI task reaches its pend point twice with ASYNC work
queued, the TL idle, no HOLD, and no intervening TXQ dequeue.

Passive only: no wake, retry, timeout, reset, queue, ordering, NV, RF or
serial-owner change. The observation never submits or drops a frame.
"""
import hashlib
from pathlib import Path

from r4_uart_tx_liveness import extract, once

TASK = "source/ti/zstack/npi/npi_task.c"
MARKER = "B4_TXQ_STRAND_WITNESS"

HELPER = r"""/* B4_TXQ_STRAND_WITNESS: pend-entry observation in the existing NPI task.
 * Confirms a strand only across two pend entries with unchanged ASYNC
 * depth and dequeue count, so a wake already posted (which drains or
 * dequeues before the next pend) can never confirm. Blocked completion
 * (TL busy) and B1 HOLD are distinct, already-observable states and are
 * never counted here. */
static uint32_t B4_TxqPendSavedDepth = 0u;
static uint32_t B4_TxqPendSavedDequeues = 0u;
static uint8_t B4_TxqPendArmed = 0u;
static void B4_TxqPendObserve(void)
{
    uint32_t key;
    uint32_t strandDepth = 0u;
    int strand = 0;
    key = OsalPort_enterCS();
    if (!Queue_empty(npiTxQueue) && !NPITL_checkNpiBusy() &&
        !b1_management_transport_unavailable())
    {
        if (B4_TxqPendArmed != 0u &&
            B4_TxqPendSavedDepth == B4_NpiAsyncDepth &&
            B4_TxqPendSavedDequeues == B4_TxqDequeueCount)
        {
            strand = 1;
            strandDepth = B4_NpiAsyncDepth;
            B4_TxqPendArmed = 0u;
        }
        else
        {
            B4_TxqPendArmed = 1u;
            B4_TxqPendSavedDepth = B4_NpiAsyncDepth;
            B4_TxqPendSavedDequeues = B4_TxqDequeueCount;
        }
    }
    else
    {
        B4_TxqPendArmed = 0u;
    }
    OsalPort_leaveCS(key);
    if (strand) B4_V43_NoteStrand(strandDepth);
}

"""


def apply(sdk):
    sdk = Path(sdk)
    path = sdk / TASK
    original = path.read_text(encoding="utf-8")
    if MARKER in original:
        raise ValueError("TXQ_STRAND_WITNESS_ALREADY_APPLIED")
    if "B4_F2_V43_PROGRESS" not in original or "B4_V43_NoteStrand" not in original:
        raise ValueError("TXQ_STRAND_WITNESS_REQUIRES_F2_PROGRESS")
    if "else if (!NPITL_checkNpiBusy()" not in original:
        raise ValueError("TXQ_STRAND_WITNESS_REQUIRES_B1_REPOST_GUARD")
    text = once(original,
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
        "        ++B4_TxqDequeueCount; /* " + MARKER + ": CS already held */",
        1)
    text = once(text, process, ticked, "STRAND_DEQUEUE_TICK")
    text = once(text,
        "static void NPITask_process(void)\n{",
        HELPER + "static void NPITask_process(void)\n{",
        "STRAND_HELPER")
    text = once(text,
        "        Semaphore_pend(npiSemHandle, BIOS_WAIT_FOREVER);",
        "        B4_TxqPendObserve(); /* " + MARKER + " */\n"
        "        Semaphore_pend(npiSemHandle, BIOS_WAIT_FOREVER);",
        "STRAND_PEND_HOOK")
    path.write_text(text, encoding="utf-8", newline="")
    return {
        "schema": "p7u-r4-txq-strand-witness-v1",
        "source_only": True,
        "passive_observation_only": True,
        "wake_retry_timeout_reset_added": False,
        "queue_order_or_ownership_changed": False,
        "network_nv_or_security_mutation": False,
        "confirm_rule": "TWO_PEND_ENTRIES_QUEUED_IDLE_NO_HOLD_NO_DEQUEUE",
        "record": "F2_FIRST_FAULT_KIND_6_FROZEN",
        "before_sha256": {TASK: hashlib.sha256(original.encode()).hexdigest()},
        "modified_sha256": {TASK: hashlib.sha256(text.encode()).hexdigest()},
    }
