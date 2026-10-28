#!/usr/bin/env python3
"""R4 v4.5: bounded critical SRSP path bypassing the shared OSAL heap.

This patch is applied after v4.4 on disposable, exact-source TI SDK files.
It does not change the UART owner, NV, counters, RF, transport HOLD or ZNP
host protocol. Three fixed complete-frame slots form a small SRSP reserve.
On reserve saturation the existing dynamic producer remains a fallback.
"""
import hashlib
from pathlib import Path
from r4_uart_tx_liveness import once

CLIENT = "source/ti/zstack/npi/npi_client_mt.c"
TASK = "source/ti/zstack/npi/npi_task.c"
MARKER = "B4_V45_STATIC_SRSP_RESERVE"

RESERVE = r'''
/* B4_V45_STATIC_SRSP_RESERVE. Only complete SRSPs from the MT producer.
 * The ZNP NPI task remains the sole UART owner. Slots never enter OSAL
 * message queues and are not returned to OSAL's shared heap. */
#define B4_V45_POOL_SLOTS 3u
#define B4_V45_FRAME_BYTES 255u
typedef struct {
    NPI_QueueRec rec;
    NPIMSG_msg_t msg;
    uint8_t frame[B4_V45_FRAME_BYTES];
    uint8_t used;
} B4_V45_Slot;
static B4_V45_Slot B4_V45_Slots[B4_V45_POOL_SLOTS];
static volatile uint32_t B4_V45_ReserveUsed = 0u;
static volatile uint32_t B4_V45_ReserveExhausted = 0u;
static volatile uint32_t B4_V45_ReleaseFault = 0u;
extern volatile uint32_t B4_AllRspNpiReceived, B4_AllRspFramedQueued;
extern volatile uint32_t B4_AfRspNpiReceived, B4_AfRspFramedQueued;
static void B4_V45_Tick(volatile uint32_t *value)
{
    uint32_t key = OsalPort_enterCS();
    if (*value != UINT32_MAX) ++(*value);
    OsalPort_leaveCS(key);
}
/* Called from the original MT producer, never from a UART ISR. Preserve
 * data ownership: caller retains pData; this function copies it synchronously.
 * An uninitialized NPI, oversized response, or exhausted reserve falls back
 * to the legacy producer. The latter already records alloc/send failures. */
__attribute__((noinline)) uint8_t B4_V45_SendReservedSrsp(uint8_t cmdType,
    uint8_t cmdId, uint8_t dataLen, const uint8_t *pData)
{
    uint32_t key;
    uint32_t i;
    B4_V45_Slot *slot = NULL;
    uint8_t fcs = 0u;
    if ((cmdType & 0xe0u) != 0x60u || dataLen > 250u ||
        (dataLen != 0u && pData == NULL))
        return 0u;
    key = OsalPort_enterCS();
    if (B4_V44_SrspQueue == NULL)
    {
        OsalPort_leaveCS(key);
        return 0u;
    }
    for (i = 0u; i < B4_V45_POOL_SLOTS; ++i)
    {
        if (!B4_V45_Slots[i].used)
        {
            B4_V45_Slots[i].used = 1u;
            slot = &B4_V45_Slots[i];
            break;
        }
    }
    if (slot == NULL && B4_V45_ReserveExhausted != UINT32_MAX)
        ++B4_V45_ReserveExhausted;
    OsalPort_leaveCS(key);
    if (slot == NULL) return 0u;
    slot->frame[0] = 0xfeu;
    slot->frame[1] = dataLen;
    slot->frame[2] = cmdType;
    slot->frame[3] = cmdId;
    if (dataLen != 0u)
        memcpy(&slot->frame[4], pData, dataLen);
    for (i = 1u; i < (uint32_t)dataLen + 4u; ++i)
        fcs ^= slot->frame[i];
    slot->frame[(uint32_t)dataLen + 4u] = fcs;
    slot->msg.msgType = NPIMSG_Type_ASYNC;
    slot->msg.pBuf = slot->frame;
    slot->msg.pBufSize = (uint16_t)dataLen + 5u;
    slot->rec.npiMsg = &slot->msg;
    B4_V45_Tick(&B4_AllRspNpiReceived);
    B4_V45_Tick(&B4_AllRspFramedQueued);
    if (cmdType == 0x64u && cmdId == 0u)
    {
        B4_V45_Tick(&B4_AfRspNpiReceived);
        B4_V45_Tick(&B4_AfRspFramedQueued);
    }
    B4_V44_Enqueue(&slot->rec);
    B4_V45_Tick(&B4_V45_ReserveUsed);
    return 1u;
}
/* One immutable TL copy is complete before release. Never free a static
 * slot through OSALPort_msgDeallocate or OsalPort_free. */
__attribute__((noinline)) static uint8_t B4_V45_ReleaseReserved(NPI_QueueRec *rec)
{
    uint32_t i, key;
    for (i = 0u; i < B4_V45_POOL_SLOTS; ++i)
    {
        if (rec == &B4_V45_Slots[i].rec)
        {
            key = OsalPort_enterCS();
            if (!B4_V45_Slots[i].used && B4_V45_ReleaseFault != UINT32_MAX)
                ++B4_V45_ReleaseFault;
            B4_V45_Slots[i].used = 0u;
            OsalPort_leaveCS(key);
            return 1u;
        }
    }
    return 0u;
}
'''

def apply(sdk):
    sdk = Path(sdk)
    before = {name:(sdk/name).read_text(encoding="utf-8") for name in (CLIENT,TASK)}
    c,n = before[CLIENT],before[TASK]
    if MARKER in n or "B4_V44_SRSP_SERVICE" not in n or "B4_F2_V42_RESPONSE_LIFECYCLE" not in c:
        raise ValueError("V45_REQUIRES_V44_AND_F2_V42_EXACT_SOURCE")
    # The producer has already marked Produced, but must count Enqueued
    # on successful reserved admission. Do not fake OSAL mailbox counters.
    c = once(c, "void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,",
             "extern uint8_t B4_V45_SendReservedSrsp(uint8_t, uint8_t, uint8_t, const uint8_t *);\n"
             "void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,", "V45_EXTERN")
    c = once(c, "    if (allSrsp) B4_AfRspTick(&B4_AllRspProduced);",
             "    if (allSrsp) B4_AfRspTick(&B4_AllRspProduced);\n"
             "    if (allSrsp && B4_V45_SendReservedSrsp(cmdType, cmdId, dataLen, pData))\n"
             "    {\n"
             "        if (afReg) B4_AfRspTick(&B4_AfRspEnqueued);\n"
             "        B4_AfRspTick(&B4_AllRspEnqueued);\n"
             "        return;\n"
             "    }", "V45_MT_PRODUCER")
    n = once(n, "/* Enqueue between the check and pend leaves a semaphore token.",
             RESERVE + "\n/* Enqueue between the check and pend leaves a semaphore token.",
             "V45_RESERVE")
    n = once(n,
             "    OsalPort_msgDeallocate(recPtr->npiMsg->pBuf);\n"
             "    OsalPort_free(recPtr->npiMsg);\n"
             "    OsalPort_free(recPtr);",
             "    if (!B4_V45_ReleaseReserved(recPtr))\n"
             "    {\n"
             "        OsalPort_msgDeallocate(recPtr->npiMsg->pBuf);\n"
             "        OsalPort_free(recPtr->npiMsg);\n"
             "        OsalPort_free(recPtr);\n"
             "    }", "V45_STATIC_TX_OWNERSHIP")
    after = {CLIENT:c,TASK:n}
    for path,data in after.items():
        (sdk/path).write_text(data,encoding="utf-8",newline="")
    return {
       "schema":"p7u-r4-v45-three-static-srsp-slots-v1",
       "reserve_slots":3,"slot_frame_bytes":255,"legacy_overflow_fallback":True,
       "runtime_heap_dependency_for_reserved_path":False,
       "f2_minor":4,"uart_owner_unchanged":True,
       "reserved_pool_telemetry_in_f2":False,
       "before_sha256":{k:hashlib.sha256(v.encode()).hexdigest() for k,v in before.items()},
       "modified_sha256":{k:hashlib.sha256(v.encode()).hexdigest() for k,v in after.items()}
    }
