#!/usr/bin/env python3
"""v4.4 first scope: two TX FIFOs, bounded preference, work-based sleep.

Applied after the verified v4.3 source composition. No NPI_SREQRSP, new
transport, dropping/coalescing, reset, NV or RF operation. Resource reservation
and bridge instrumentation are separate changes, not claimed by this patch.
"""
import hashlib
from pathlib import Path
from r4_uart_tx_liveness import extract, once

TASK = "source/ti/zstack/npi/npi_task.c"
SYS = "source/ti/zstack/mt/mt_sys.c"
MARKER = "B4_V44_SRSP_SERVICE"
FIELDS = ("srspQueuedBytes", "asyncQueuedBytes", "srspBytesHighWater",
          "asyncBytesHighWater", "maxSrspQueueAgeTicks", "maxAsyncQueueAgeTicks",
          "maxReadyServiceGapTicks")

# Deliberately retain the original Queue records and frame ownership. All AREQs
# share one FIFO; preserving every AREQ avoids a speculative expendable classifier.
IMPL = r'''
/* B4_V44_SRSP_SERVICE: one consumer, FIFO within each class. At most four
 * SRSPs overtake a pending AREQ. One already-accepted UART write is never
 * preempted. Queue records/frames keep their native allocation ownership. */
#if defined(NPI_SREQRSP) || (NPI_FLOW_CTRL != 0)
#error B4_V44_requires_the_qualified_flow_off_async_transport_profile
#endif
#define B4_V44_SRSP_BURST 4u
static Queue_Struct B4_V44_SrspQueueStruct;
static Queue_Handle B4_V44_SrspQueue;
static uint32_t B4_V44_Bytes[2], B4_V44_BytesHigh[2], B4_V44_MaxAge[2];
static uint32_t B4_V44_ReadySince, B4_V44_MaxReadyGap;
static uint8_t B4_V44_ReadyTracked, B4_V44_SrspRun;

static uint8_t B4_V44_TxReadyLocked(void)
{
    return !b1_management_transport_unavailable() && !NPITL_checkNpiBusy() &&
           (!Queue_empty(B4_V44_SrspQueue) || !Queue_empty(npiTxQueue));
}
static void B4_V44_NoteReadyLocked(void)
{
    if (!B4_V44_ReadyTracked && B4_V44_TxReadyLocked())
    {
        B4_V44_ReadySince = Clock_getTicks();
        B4_V44_ReadyTracked = 1u;
    }
}
static void B4_V44_Enqueue(NPI_QueueRec *recPtr)
{
    uint32_t key = OsalPort_enterCS();
    uint8_t srsp = recPtr->npiMsg->pBufSize >= 5u &&
                  (recPtr->npiMsg->pBuf[2] & 0xe0u) == 0x60u;
    uint8_t cls = srsp ? 0u : 1u;
    recPtr->queuedTick = Clock_getTicks();
    Queue_enqueue(srsp ? B4_V44_SrspQueue : npiTxQueue, &recPtr->_elem);
    B4_V44_Bytes[cls] += recPtr->npiMsg->pBufSize;
    if (B4_V44_Bytes[cls] > B4_V44_BytesHigh[cls])
        B4_V44_BytesHigh[cls] = B4_V44_Bytes[cls];
    if (srsp)
    {
        if (B4_NpiSrspDepth != UINT32_MAX) ++B4_NpiSrspDepth;
        if (B4_NpiSrspEnqueued != UINT32_MAX) ++B4_NpiSrspEnqueued;
        if (B4_NpiSrspDepth > B4_NpiSrspHighWater)
            B4_NpiSrspHighWater = B4_NpiSrspDepth;
    }
    else
    {
        if (B4_NpiAsyncDepth != UINT32_MAX) ++B4_NpiAsyncDepth;
        if (B4_NpiAsyncDepth > B4_NpiAsyncHighWater)
            B4_NpiAsyncHighWater = B4_NpiAsyncDepth;
    }
    B4_V44_NoteReadyLocked();
    npiServiceTaskEvents |= NPITASK_TX_READY_EVENT;
    OsalPort_leaveCS(key);
    Semaphore_post(npiSemHandle);
}
/* Enqueue between the check and pend leaves a semaphore token. Completion
 * does too. Pending TX while UART is busy must NOT self-post or skip pend. */
static void B4_V44_Pend(void)
{
    uint32_t key = OsalPort_enterCS();
    uint8_t ready = B4_V44_TxReadyLocked() || !Queue_empty(npiRxQueue);
    OsalPort_leaveCS(key);
    if (!ready) Semaphore_pend(npiSemHandle, BIOS_WAIT_FOREVER);
}
/* Snapshot is bounded O(1); queue heads are the oldest because both are FIFO.
 * Ticks are unsigned wrap-safe for intervals shorter than one tick wrap. */
void B4_V44_Snapshot(uint8_t *payload)
{
    uint32_t key = OsalPort_enterCS();
    uint32_t now = Clock_getTicks(), i;
    NPI_QueueRec *head;
    for (i = 0u; i < 2u; ++i)
    {
        Queue_Handle q = i == 0u ? B4_V44_SrspQueue : npiTxQueue;
        if (!Queue_empty(q))
        {
            uint32_t age;
            head = (NPI_QueueRec *)Queue_head(q);
            age = now - head->queuedTick;
            if (age > B4_V44_MaxAge[i]) B4_V44_MaxAge[i] = age;
        }
        /* Reserved minor1..3 bytes gain meaning ONLY in minor4. */
        for (uint32_t j = 0u; j < 4u; ++j)
        {
            payload[140u + i*4u + j] = (uint8_t)(B4_V44_Bytes[i] >> (8u*j));
            payload[148u + i*4u + j] = (uint8_t)(B4_V44_BytesHigh[i] >> (8u*j));
        }
    }
    if (B4_V44_ReadyTracked)
    {
        uint32_t gap = now - B4_V44_ReadySince;
        if (gap > B4_V44_MaxReadyGap) B4_V44_MaxReadyGap = gap;
    }
    for (i = 0u; i < 4u; ++i)
    {
        payload[128u+i] = (uint8_t)(B4_V44_MaxAge[1] >> (8u*i));
        payload[240u+i] = (uint8_t)(B4_V44_MaxAge[0] >> (8u*i));
        payload[244u+i] = (uint8_t)(B4_V44_MaxReadyGap >> (8u*i));
        /* Counts and bytes share this same critical-section snapshot. */
        payload[32u+i] = (uint8_t)(B4_NpiSrspDepth >> (8u*i));
        payload[36u+i] = (uint8_t)(B4_NpiSrspHighWater >> (8u*i));
        payload[40u+i] = (uint8_t)(B4_NpiAsyncDepth >> (8u*i));
        payload[44u+i] = (uint8_t)(B4_NpiAsyncHighWater >> (8u*i));
        payload[48u+i] = (uint8_t)(B4_NpiSrspEnqueued >> (8u*i));
    }
    OsalPort_leaveCS(key);
}
'''

CONSUMER = r'''static void NPITask_ProcessTXQ(void)
{
    uint32_t key = OsalPort_enterCS();
    NPI_QueueRec *recPtr;
    uint8_t srsp, cls;
    uint32_t age;
    if (!B4_V44_TxReadyLocked())
    {
        OsalPort_leaveCS(key);
        return;
    }
    if (B4_V44_ReadyTracked)
    {
        uint32_t gap = Clock_getTicks() - B4_V44_ReadySince;
        if (gap > B4_V44_MaxReadyGap) B4_V44_MaxReadyGap = gap;
        B4_V44_ReadyTracked = 0u;
    }
    srsp = !Queue_empty(B4_V44_SrspQueue) &&
           (Queue_empty(npiTxQueue) || B4_V44_SrspRun < B4_V44_SRSP_BURST);
    recPtr = (NPI_QueueRec *)Queue_dequeue(srsp ? B4_V44_SrspQueue : npiTxQueue);
    cls = srsp ? 0u : 1u;
    if (srsp)
    {
        if (B4_NpiSrspDepth) --B4_NpiSrspDepth;
        if (B4_V44_SrspRun < B4_V44_SRSP_BURST) ++B4_V44_SrspRun;
    }
    else
    {
        if (B4_NpiAsyncDepth) --B4_NpiAsyncDepth;
        B4_V44_SrspRun = 0u;
    }
    B4_V44_Bytes[cls] -= recPtr->npiMsg->pBufSize;
    age = Clock_getTicks() - recPtr->queuedTick;
    if (age > B4_V44_MaxAge[cls]) B4_V44_MaxAge[cls] = age;
    OsalPort_leaveCS(key);
    /* Sole NPI TX consumer. Do not hold the queue CS through UART submission.
     * Qualified frame <=255 bytes fits one 270-byte TL copy; no fragmentation. */
    {
        uint8_t afResponse = recPtr->npiMsg->pBufSize >= 6u &&
            recPtr->npiMsg->pBuf[2] == 0x64u && recPtr->npiMsg->pBuf[3] == 0u;
        uint8_t afDataResponse = recPtr->npiMsg->pBufSize >= 6u &&
            recPtr->npiMsg->pBuf[2] == 0x64u && recPtr->npiMsg->pBuf[3] >= 1u &&
            recPtr->npiMsg->pBuf[3] <= 3u;
        uint16_t submitted = NPITL_writeTL(recPtr->npiMsg->pBuf, recPtr->npiMsg->pBufSize);
        if (srsp) B4_AfNpiTick(submitted == recPtr->npiMsg->pBufSize ?
            &B4_AllRspTlSubmitted : &B4_AllRspTlRejected);
        if (afResponse) B4_AfNpiTick(submitted == recPtr->npiMsg->pBufSize ?
            &B4_AfRspDequeued : &B4_AfRspTlRejected);
        if (afDataResponse) B4_AfNpiTick(submitted == recPtr->npiMsg->pBufSize ?
            &B4_AfDataRspTlSubmitted : &B4_AfDataRspTlRejected);
    }
    OsalPort_msgDeallocate(recPtr->npiMsg->pBuf);
    OsalPort_free(recPtr->npiMsg);
    OsalPort_free(recPtr);
}
'''


def apply(sdk):
    sdk = Path(sdk)
    before = {name: (sdk/name).read_text(encoding="utf-8") for name in (TASK, SYS)}
    n, s = before[TASK], before[SYS]
    if MARKER in n or "B4_F2_V43_PROGRESS" not in n:
        raise ValueError("V44_REQUIRES_EXACT_V43_PREDECESSOR")
    n = once(n, '    NPIMSG_msg_t *npiMsg;\n',
             '    NPIMSG_msg_t *npiMsg;\n    uint32_t queuedTick;\n', "V44_RECORD_AGE")
    # Definitions must precede both outgoing APIs but follow globals/prototypes.
    anchor = 'void NPITask_sendToHost(uint8_t *pMsg)\n{'
    n = once(n, anchor, IMPL + "\n" + anchor, "V44_IMPL")
    n = once(n, '    npiTxQueue = Queue_create(NULL, NULL);',
             '    npiTxQueue = Queue_create(NULL, NULL);\n'
             '    Queue_construct(&B4_V44_SrspQueueStruct, NULL);\n'
             '    B4_V44_SrspQueue = Queue_handle(&B4_V44_SrspQueueStruct);', "V44_QUEUE_INIT")
    # IMPL refers to metrics originally declared just before sendToHost.
    # Queue declarations/initialization references precede IMPL in this TI TU.
    globals_start = n.index('#define B4_V44_SRSP_BURST')
    globals_end = n.index('\nstatic uint8_t B4_V44_TxReadyLocked', globals_start)
    globals_text = n[globals_start:globals_end]
    n = n[:globals_start] + n[globals_end:]
    n = once(n, 'static Queue_Handle npiTxQueue;', 'static Queue_Handle npiTxQueue;\n' + globals_text,
             'V44_QUEUE_GLOBALS')
    n = once(n, '#include <ti/sysbios/knl/Task.h>',
             '#include <ti/sysbios/knl/Task.h>\n#include <ti/sysbios/knl/Clock.h>', 'V44_CLOCK')
    for sig in ('void NPITask_sendToHost(uint8_t *pMsg)',
                'static void NPITask_processStackMsg(uint8_t *pMsg)'):
        old = extract(n, sig)
        a = old.index('Queue_enqueue(npiTxQueue, &recPtr->_elem);')
        b = old.index('break;', a)
        block = old[a:b]
        causal = '\n'.join(line for line in block.splitlines()
                           if 'B4_AfNpiTick(' in line)
        new = old[:a] + 'B4_V44_Enqueue(recPtr);\n' + causal + '\n                ' + old[b:]
        if sig.startswith('void NPITask_sendToHost'):
            new = once(new, '    OsalPort_leaveCS(key);',
                '    else\n    {\n        if (recPtr != NULL) OsalPort_free(recPtr);\n'
                '        if (pNPIMsg != NULL)\n        {\n'
                '            OsalPort_msgDeallocate(pNPIMsg->pBuf);\n'
                '            OsalPort_free(pNPIMsg);\n        }\n    }\n\n'
                '    OsalPort_leaveCS(key);', 'V44_DIRECT_SEND_FAILURE_CLEANUP')
        n = once(n, old, new, 'V44_CLASSIFY_' + sig)
    old = extract(n, 'static void NPITask_ProcessTXQ(void)')
    n = once(n, old, CONSUMER.rstrip(), 'V44_CONSUMER')
    n = once(n, '        Semaphore_pend(npiSemHandle, BIOS_WAIT_FOREVER);',
             '        B4_V44_Pend();', 'V44_ATOMIC_PENDING_WORK')
    # Replace the entire old event-gated TX section, retaining RX and ISR merge.
    a = n.index('            // An ASYNC message is ready to send to the Host')
    b = n.index('            // The Transport Layer has received some bytes', a)
    n = n[:a] + '''            /* B4_V44_SRSP_SERVICE: event bits are hints; queue state owns work.
             * Never self-post while busy. Enqueue and completion retain tokens. */
            NPITask_ProcessTXQ();
            key = OsalPort_enterCS();
            if (Queue_empty(npiTxQueue) && Queue_empty(B4_V44_SrspQueue))
                npiServiceTaskEvents &= ~NPITASK_TX_READY_EVENT;
            OsalPort_leaveCS(key);

''' + n[b:]
    callback = extract(n, 'static void NPITask_transportTxDoneCallBack(int size)')
    new = once(callback, '    Semaphore_post(npiSemHandle);',
               '    uint32_t key = OsalPort_enterCS();\n'
               '    B4_V44_NoteReadyLocked();\n    OsalPort_leaveCS(key);\n'
               '    Semaphore_post(npiSemHandle);', 'V44_COMPLETION_WAKE')
    n = once(n, callback, new, 'V44_CALLBACK')
    # Pre-declare Pend, whose implementation follows the existing task loop.
    n = once(n, 'static void NPITask_process(void)\n{',
             'static void B4_V44_Pend(void);\nstatic void NPITask_process(void)\n{', 'V44_PEND_PROTO')
    handler = extract(s, '__attribute__((noinline)) static void B4_SysReadOnlyDiagnosticsV4(uint8_t *pBuf)')
    updated = once(handler, '    uint8_t payload[240] = {0};',
                   '    uint8_t payload[248] = {0};', 'V44_REPLY_SIZE')
    updated = once(updated, 'payload[6] = 240u;', 'payload[6] = 248u;', 'V44_HEADER')
    updated = once(updated, 'payload[157] = 3u;', 'payload[157] = 4u;', 'V44_MINOR')
    # All 25 counters now valid in flow-off profile, including pending AREQ age.
    updated = once(updated, '    payload[12] = 0xECu; payload[13] = 0xFFu; payload[14] = 0xFFu;',
                   '    payload[12] = 0xFFu; payload[13] = 0xFFu; payload[14] = 0xFFu; payload[15] = 1u;',
                   'V44_VALIDITY')
    # Snapshot AFTER earlier reserved-byte initialization and ordinary encoding.
    updated = once(updated, '    MT_BuildAndSendZToolResponse(MT_SRSP_SYS, 0xF2',
                   '    B4_V44_Snapshot(payload);\n    MT_BuildAndSendZToolResponse(MT_SRSP_SYS, 0xF2',
                   'V44_SNAPSHOT')
    s = once(s, handler, updated, 'V44_F2_HANDLER')
    s = once(s, 'static uint32_t B4_V4SampleSequence = 0u;',
             'extern void B4_V44_Snapshot(uint8_t *payload);\nstatic uint32_t B4_V4SampleSequence = 0u;',
             'V44_SNAPSHOT_DECL')
    after = {TASK: n, SYS: s}
    for name, content in after.items():
        (sdk/name).write_text(content, encoding="utf-8", newline="")
    return {"schema": "p7u-srsp-service-v44-first-scope-v1", "minor": 4,
            "reply_bytes": 248, "srsp_burst_bound": 4,
            "fifo_within_each_class": True, "dropped_or_coalesced_traffic": False,
            "resource_reservation_implemented": False, "bridge_counters_implemented": False,
            "fields": list(FIELDS),
            "before_sha256": {p: hashlib.sha256(v.encode()).hexdigest() for p,v in before.items()},
            "modified_sha256": {p: hashlib.sha256(v.encode()).hexdigest() for p,v in after.items()}}
