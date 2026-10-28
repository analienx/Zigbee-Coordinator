#!/usr/bin/env python3
"""Opt-in SYS F2 (9-byte request) v5 paged fault-localization overlay.

The 8-byte v4 request and 248-byte v4 reply are byte-exact preserved. V5
uses an explicit page selector followed by the same 8-byte nonce. Two
160-byte snapshot pages are cached coherently for a bounded time.
No UART, RF, NV or security mutations; no new serial owner or heap use.
"""
import hashlib
from pathlib import Path
from r4_uart_tx_liveness import extract, once

TASK="source/ti/zstack/npi/npi_task.c"
MT="source/ti/zstack/mt/mt.c"
SYS="source/ti/zstack/mt/mt_sys.c"
MARKER="B4_F2_V5_FLIGHT_RECORDER"

NATIVE=r'''
/* B4_F2_V5_FLIGHT_RECORDER: RAM-only, no ISR allocation, no raw payloads,
 * no IEEE/keys/PAN, no automatic resets or RF actions. 8-byte records. */
#define B4_V5_RING_SIZE 16u
#define B4_V5_PAGE_SIZE 160u
typedef struct {
    uint32_t tick;
    uint16_t command;
    uint8_t stage;
    uint8_t result;
} B4_V5_Event;
static B4_V5_Event B4_V5_Ring[B4_V5_RING_SIZE];
static uint32_t B4_V5_EventTotal, B4_V5_SnapshotSequence;
static uint32_t B4_V5_NpiWakes, B4_V5_NpiLastTick;
static uint32_t B4_V5_MtEntered, B4_V5_MtLastEntered;
static uint32_t B4_V5_MtExited, B4_V5_MtLastExited;
static uint8_t B4_V5_CachedEvents[B4_V5_PAGE_SIZE];
static uint8_t B4_V5_CachedNonce[8];
static uint32_t B4_V5_CachedTick;
static uint8_t B4_V5_CachedValid;
extern void B4_V43_Snapshot(uint8_t *out);
extern volatile uint32_t B4_AllRspProduced, B4_AllRspAllocFailed;
extern volatile uint32_t B4_AllRspFramingFailed, B4_AllRspTlRejected;
static void B4_V5_Put32(uint8_t *p, uint32_t v)
{
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v >> 8);
    p[2]=(uint8_t)(v >> 16); p[3]=(uint8_t)(v >> 24);
}
static void B4_V5_Put16(uint8_t *p, uint16_t v)
{
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v >> 8);
}
static uint32_t B4_V5_Get32(const uint8_t *p)
{
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8u) |
           ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}
/* Executed only on verified task-side ownership transitions. The UART ISR
 * remains represented by the existing v4.3 callback counters, not here. */
void B4_V5_Record(uint8_t stage, uint16_t command, uint8_t result)
{
    uint32_t key, index, tick;
    /* The diagnostic query must never bury the user's incident evidence. */
    if (command == 0x21f2u) return;
    key=OsalPort_enterCS();
    tick=Clock_getTicks();
    if (B4_V5_EventTotal != UINT32_MAX)
    {
        index=B4_V5_EventTotal & (B4_V5_RING_SIZE-1u);
        B4_V5_Ring[index].tick=tick;
        B4_V5_Ring[index].command=command;
        B4_V5_Ring[index].stage=stage;
        B4_V5_Ring[index].result=result;
        ++B4_V5_EventTotal;
    }
    if (stage == 3u)
    {
        if (B4_V5_MtEntered != UINT32_MAX) ++B4_V5_MtEntered;
        B4_V5_MtLastEntered=tick;
    }
    if (stage == 4u)
    {
        if (B4_V5_MtExited != UINT32_MAX) ++B4_V5_MtExited;
        B4_V5_MtLastExited=tick;
    }
    OsalPort_leaveCS(key);
}
void B4_V5_NpiPulse(void)
{
    uint32_t key=OsalPort_enterCS();
    if (B4_V5_NpiWakes != UINT32_MAX) ++B4_V5_NpiWakes;
    B4_V5_NpiLastTick=Clock_getTicks();
    OsalPort_leaveCS(key);
}
static void B4_V5_Header(uint8_t *p, uint8_t page, const uint8_t *nonce,
                         uint32_t seq, uint32_t tick)
{
    uint32_t i;
    p[0]='R';p[1]='4';p[2]='D';p[3]='5';
    p[4]=5u;p[5]=page;
    p[6]=B4_V5_PAGE_SIZE; p[7]=0u;
    for(i=0;i<8u;++i)p[8u+i]=nonce[i];
    if (B4_V4BootValid == 1u)
        for(i=0;i<8u;++i)p[16u+i]=B4_V4BootId[i];
    B4_V5_Put32(p+24u,seq);
    B4_V5_Put32(p+28u,tick);
}
/* Page 1 captures ALL page-2 records under the same CS. The later
 * page-2 request consumes a copy with the SAME nonce/sequence/tick.
 * Only one diagnostic request is allowed by the existing owner. */
void B4_V5_ReadPage1(uint8_t *out, const uint8_t *nonce)
{
    uint8_t progress[80]={0};
    uint32_t i,key,now,seq,available,first,position,active=0u;
    B4_V43_Snapshot(progress); /* owns its own short CS */
    key=OsalPort_enterCS();
    now=Clock_getTicks();seq=++B4_V5_SnapshotSequence;
    B4_V5_Header(out,1u,nonce,seq,now);
    for(i=0u;i<B4_V5_PAGE_SIZE;++i)B4_V5_CachedEvents[i]=0u;
    B4_V5_Header(B4_V5_CachedEvents,2u,nonce,seq,now);
    for(i=0u;i<8u;++i)B4_V5_CachedNonce[i]=nonce[i];
    available=B4_V5_EventTotal < B4_V5_RING_SIZE ? B4_V5_EventTotal : B4_V5_RING_SIZE;
    first=B4_V5_EventTotal < B4_V5_RING_SIZE ? 0u :
         (B4_V5_EventTotal & (B4_V5_RING_SIZE-1u));
    for(i=0u;i<available;++i)
    {
        const B4_V5_Event *e=&B4_V5_Ring[(first+i)&(B4_V5_RING_SIZE-1u)];
        uint8_t *dest=B4_V5_CachedEvents+32u+i*8u;
        B4_V5_Put32(dest,e->tick);
        B4_V5_Put16(dest+4u,e->command);
        dest[6]=e->stage;dest[7]=e->result;
    }
    B4_V5_Put32(out+32u,B4_V5_NpiWakes);
    B4_V5_Put32(out+36u,B4_V5_NpiLastTick);
    B4_V5_Put32(out+40u,B4_V5_MtEntered);
    B4_V5_Put32(out+44u,B4_V5_MtLastEntered);
    B4_V5_Put32(out+48u,B4_V5_MtExited);
    B4_V5_Put32(out+52u,B4_V5_MtLastExited);
    B4_V5_Put32(out+56u,B4_V5_EventTotal);
    B4_V5_Put32(out+60u,B4_V45_ReserveUsed);
    B4_V5_Put32(out+64u,B4_V45_ReserveExhausted);
    B4_V5_Put32(out+68u,B4_V45_ReleaseFault);
    for(i=0u;i<B4_V45_POOL_SLOTS;++i)if(B4_V45_Slots[i].used)++active;
    B4_V5_Put32(out+72u,active);
    B4_V5_Put32(out+76u,B4_AllRspProduced);
    B4_V5_Put32(out+80u,B4_AllRspAllocFailed);
    B4_V5_Put32(out+84u,B4_AllRspFramingFailed);
    B4_V5_Put32(out+88u,B4_AllRspTlRejected);
    B4_V5_Put32(out+92u,B4_V5_Get32(progress+5u*4u));  /* TX callback OK */
    B4_V5_Put32(out+96u,B4_V5_Get32(progress+6u*4u));  /* callback failed */
    B4_V5_Put32(out+100u,B4_V5_Get32(progress+9u*4u)); /* UART RX bytes */
    /* bit0 boot entropy valid; bit1 coherent cached event page exists.
     * Heap byte statistics, independent stack high-water, ESP UART mux
     * visibility and Zigbee stack task heartbeat are NOT measured. */
    B4_V5_Put32(out+104u,(B4_V4BootValid==1u?1u:0u)|2u);
    B4_V5_Put32(out+108u,available);
    B4_V5_Put32(out+112u,Clock_tickPeriod);
    B4_V5_CachedTick=now;
    B4_V5_CachedValid=1u;
    OsalPort_leaveCS(key);
}
uint8_t B4_V5_ReadPage2(uint8_t *out, const uint8_t *nonce)
{
    uint32_t key,i,deadline,elapsed;
    uint8_t valid=1u;
    key=OsalPort_enterCS();
    elapsed=Clock_getTicks()-B4_V5_CachedTick;
    deadline=Clock_tickPeriod ? 2000000u/Clock_tickPeriod : 0u;
    if (!B4_V5_CachedValid || deadline==0u || elapsed>deadline)
        valid=0u;
    for(i=0u;i<8u;++i)
        if(B4_V5_CachedNonce[i]!=nonce[i])valid=0u;
    if(valid)
    {
        for(i=0u;i<B4_V5_PAGE_SIZE;++i)out[i]=B4_V5_CachedEvents[i];
        B4_V5_CachedValid=0u; /* one-time exact-pair retrieval */
    }
    OsalPort_leaveCS(key);
    return valid;
}
'''

SYS_HANDLER=r'''
/* B4_F2_V5_FLIGHT_RECORDER: distinct nine-byte F2 request; eight-byte
 * requests still take the untouched minor4 handler. */
extern void B4_V5_ReadPage1(uint8_t *, const uint8_t *);
extern uint8_t B4_V5_ReadPage2(uint8_t *, const uint8_t *);
__attribute__((noinline)) static void B4_SysReadOnlyDiagnosticsV5(uint8_t *pBuf)
{
    uint8_t payload[160]={0};
    uint8_t page=pBuf[MT_RPC_POS_DAT0];
    const uint8_t *nonce=pBuf+MT_RPC_POS_DAT0+1u;
    if(page==1u)
        B4_V5_ReadPage1(payload,nonce);
    else if(page==2u)
    {
        if(!B4_V5_ReadPage2(payload,nonce))
        {
            /* A stale/unpaired page is not a valid snapshot. Never invent
             * counters or return data from a different request/epoch. */
            payload[0]='R';payload[1]='4';payload[2]='D';payload[3]='5';
            uint32_t i;
            payload[4]=5u;payload[5]=0xffu;
            payload[6]=160u; /* host must reject invalid page 255 */
            for(i=0u;i<8u;++i)payload[8u+i]=nonce[i];
        }
    }
    MT_BuildAndSendZToolResponse(MT_SRSP_SYS,0xF2u,sizeof(payload),payload);
}
'''

def replace_fn(src,sig,old,new,label):
    f=extract(src,sig)
    changed=once(f,old,new,label)
    return once(src,f,changed,label+"_BODY")

def apply(sdk):
    sdk=Path(sdk)
    originals={p:(sdk/p).read_text(encoding="utf-8") for p in (TASK,MT,SYS)}
    n,m,s=(originals[p] for p in (TASK,MT,SYS))
    if (MARKER in n or "B4_V45_STATIC_SRSP_RESERVE" not in n or
            "B4_F2_V43_PROGRESS" not in m or "B4_V44_Snapshot" not in s):
        raise ValueError("V5_REQUIRES_PINNED_V45_FULL_COMPOSITE")
    n=once(n,"static volatile uint32_t B4_V45_ReleaseFault = 0u;",
           "static volatile uint32_t B4_V45_ReleaseFault = 0u;\n"+NATIVE,"V5_STATIC_DEF")
    n=replace_fn(n,"static void NPITask_process(void)",
                 "        B4_V43_Wake();",
                 "        B4_V43_Wake();\n        B4_V5_NpiPulse();","V5_WAKE_PULSE")
    # Record only real TX transitions with the already-existing single
    # NPI TX task. Never log sensitive UART bytes or touch the ISR.
    n=replace_fn(n,"static void NPITask_ProcessTXQ(void)",
                 "        uint16_t submitted = NPITL_writeTL(recPtr->npiMsg->pBuf, recPtr->npiMsg->pBufSize);",
                 "        B4_V5_Record(6u,((uint16_t)recPtr->npiMsg->pBuf[2]<<8u)|recPtr->npiMsg->pBuf[3],0u);\n"
                 "        uint16_t submitted = NPITL_writeTL(recPtr->npiMsg->pBuf, recPtr->npiMsg->pBufSize);\n"
                 "        B4_V5_Record(submitted==recPtr->npiMsg->pBufSize?7u:8u,\n"
                 "            ((uint16_t)recPtr->npiMsg->pBuf[2]<<8u)|recPtr->npiMsg->pBuf[3],\n"
                 "            submitted==recPtr->npiMsg->pBufSize?0u:1u);","V5_TX_TRANSITION")
    n=replace_fn(n,"static void B4_V44_Enqueue(NPI_QueueRec *recPtr)",
                 "    Semaphore_post(npiSemHandle);",
                 "    Semaphore_post(npiSemHandle);\n"
                 "    B4_V5_Record(5u,((uint16_t)recPtr->npiMsg->pBuf[2]<<8u)|recPtr->npiMsg->pBuf[3],0u);",
                 "V5_QUEUE_TRANSITION")
    n=replace_fn(n,
                 "__attribute__((noinline)) uint8_t B4_V45_SendReservedSrsp(uint8_t cmdType,\n    uint8_t cmdId, uint8_t dataLen, const uint8_t *pData)",
                 "    if (slot == NULL) return 0u;",
                 "    if (slot == NULL)\n"
                 "    {\n        B4_V5_Record(9u,((uint16_t)cmdType<<8u)|cmdId,1u);\n"
                 "        return 0u;\n    }", "V5_POOL_EXHAUSTION")
    # Existing wrapper precisely delimits the MT handler; do not instrument
    # background stack execution or claim a separate Zigbee stack heartbeat.
    m=once(m,'#include "b1_management.h"',
           '#include "b1_management.h"\n'
           'extern void B4_V5_Record(uint8_t, uint16_t, uint8_t);',"V5_MT_EXTERN")
    m=once(m,"  B4_V43_Request(1u, pBuf);\n  B4_V43_MT_ProcessIncoming(pBuf);\n  B4_V43_Request(2u, pBuf);",
           "  B4_V43_Request(1u, pBuf);\n"
           "  B4_V5_Record(3u,((uint16_t)pBuf[1]<<8u)|pBuf[2],0u);\n"
           "  B4_V43_MT_ProcessIncoming(pBuf);\n"
           "  B4_V5_Record(4u,((uint16_t)pBuf[1]<<8u)|pBuf[2],0u);\n"
           "  B4_V43_Request(2u, pBuf);","V5_MT_BOUNDARY")
    s=once(s,"uint8_t MT_SysCommandProcessing(uint8_t *pBuf)",
           SYS_HANDLER+"\nuint8_t MT_SysCommandProcessing(uint8_t *pBuf)",
           "V5_HANDLER")
    s=once(s,
           "    case 0xF2:\n      if (pBuf[MT_RPC_POS_LEN] != 8u)\n        status = MT_RPC_ERR_LENGTH;\n      else\n        B4_SysReadOnlyDiagnosticsV4(pBuf);\n      break;",
           "    case 0xF2:\n      if (pBuf[MT_RPC_POS_LEN] == 8u)\n        B4_SysReadOnlyDiagnosticsV4(pBuf);\n"
           "      else if (pBuf[MT_RPC_POS_LEN] == 9u)\n        B4_SysReadOnlyDiagnosticsV5(pBuf);\n"
           "      else\n        status = MT_RPC_ERR_LENGTH;\n      break;","V5_F2_DISPATCH")
    after=dict(zip((TASK,MT,SYS),(n,m,s)))
    for p,t in after.items():(sdk/p).write_text(t,encoding="utf-8",newline="")
    return {
        "schema":"p7u-f2-v5-two-page-ram-flight-recorder-v1",
        "request_bytes":9,"page_bytes":160,"page_count":2,"legacy_f2_len8_preserved":True,
        "flight_events":16,"snapshot_ttl_us":2000000,
        "heap_allocated":False,"read_only":True,"radio_uart_nv_unchanged":True,
        "heap_free_bytes_valid":False,"stack_margin_valid":False,
        "zigbee_stack_task_liveness_valid":False,"bridge_uart_visibility_valid":False,
        "before_sha256":{p:hashlib.sha256(v.encode()).hexdigest() for p,v in originals.items()},
        "modified_sha256":{p:hashlib.sha256(t.encode()).hexdigest() for p,t in after.items()}
    }
