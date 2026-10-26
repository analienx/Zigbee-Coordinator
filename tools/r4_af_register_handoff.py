#!/usr/bin/env python3
"""Exact pinned TI SDK AF SRSP outbound loss/ownership fix and causal diagnostic.
No startup/AF protocol change, no UART ownership or NV mutation.
"""
import hashlib
from pathlib import Path

CLIENT="source/ti/zstack/npi/npi_client_mt.c"
TASK="source/ti/zstack/npi/npi_task.c"
SYS="source/ti/zstack/mt/mt_sys.c"
B1="source/ti/common/nv/b1_management.c"

def one(s,old,new,name):
    if s.count(old)!=1:
        raise ValueError("AF_SSRP_SOURCE_DRIFT_"+name+":"+str(s.count(old)))
    return s.replace(old,new,1)

def apply(sdk):
    sdk=Path(sdk)
    before={}
    after={}
    c=sdk/CLIENT
    source=c.read_text()
    before[CLIENT]=hashlib.sha256(source.encode()).hexdigest()
    source=one(source,'#include "npi_data.h"\n','#include "npi_data.h"\n#include "b1_management.h"\n',
               "CLIENT_B1_HEADER")
    source=one(source,'static uint8_t npiTaskID;\n','''static uint8_t npiTaskID;

/* Source-bounded response lifecycle. All counters are RAM-only and
 * monotonically saturate; none names an endpoint, key or device. */
volatile uint32_t B4_AfRspProduced = 0u;
volatile uint32_t B4_AfRspEnqueued = 0u;
volatile uint32_t B4_AfRspAllocFailed = 0u;
volatile uint32_t B4_AfRspSendFailed = 0u;
static void B4_AfRspTick(volatile uint32_t *p)
{
    uint32_t key = OsalPort_enterCS();
    if (*p != UINT32_MAX) ++(*p);
    OsalPort_leaveCS(key);
}
''',"CLIENT_COUNTERS")
    source=one(source,'''{
    // allocate a message buffer to send message to NPI task.
    uint8_t *pRspMsg = OsalPort_msgAllocate( dataLen + MTRPC_FRAME_HDR_SZ);
''','''{
    /* Only the precise AF_REGISTER SRSP gets causal counters. */
    uint8_t afReg = (cmdType == 0x64u && cmdId == 0x00u);
    uint8_t *pRspMsg;
    if (afReg) B4_AfRspTick(&B4_AfRspProduced);
    pRspMsg = OsalPort_msgAllocate(dataLen + MTRPC_FRAME_HDR_SZ);
''',"CLIENT_PRODUCE")
    source=one(source,'''        // Send the message
        OsalPort_msgSend(npiTaskID, pRspMsg);
    }

    return;
}''','''        /* OsalPort_msgSend takes ownership ONLY on success. Never claim an
         * SRSP was sent on rejection and never leak the unowned message. */
        if (OsalPort_msgSend(npiTaskID, pRspMsg) != 0u)
        {
            if (afReg) B4_AfRspTick(&B4_AfRspSendFailed);
            (void)OsalPort_msgDeallocate(pRspMsg);
            b1_management_transport_failed(B1_ERROR_NPI_QUEUE);
        }
        else if (afReg)
        {
            B4_AfRspTick(&B4_AfRspEnqueued);
        }
    }
    else
    {
        if (afReg) B4_AfRspTick(&B4_AfRspAllocFailed);
        b1_management_transport_failed(B1_ERROR_NPI_QUEUE);
    }
    return;
}''',"CLIENT_SEND_AND_FAILURE")
    c.write_text(source,encoding="utf8",newline="")
    after[CLIENT]=hashlib.sha256(source.encode()).hexdigest()

    p=sdk/TASK;s=p.read_text();before[TASK]=hashlib.sha256(s.encode()).hexdigest()
    s=one(s,'static void NPITask_processStackMsg(uint8_t *pMsg)\n{\n',
          '''/* Only one dispatcher and existing NPI queues. No SRSP priority reorder. */
extern volatile uint32_t B4_AfRspProduced, B4_AfRspEnqueued;
extern volatile uint32_t B4_AfRspAllocFailed, B4_AfRspSendFailed;
volatile uint32_t B4_AfRspNpiReceived = 0u;
volatile uint32_t B4_AfRspFramedQueued = 0u;
volatile uint32_t B4_AfRspFramingFailed = 0u;
volatile uint32_t B4_AfRspDequeued = 0u;
volatile uint32_t B4_AfRspTlRejected = 0u;
static void B4_AfNpiTick(volatile uint32_t *p)
{
    uint32_t key = OsalPort_enterCS();
    if (*p != UINT32_MAX) ++(*p);
    OsalPort_leaveCS(key);
}
static void NPITask_processStackMsg(uint8_t *pMsg)
{
    uint8_t afResponse = (pMsg != NULL && pMsg[1] == 0x64u && pMsg[2] == 0x00u);
    if (afResponse) B4_AfNpiTick(&B4_AfRspNpiReceived);
''',"NPI_TRACE_DEFS")
    i=s.index('static void NPITask_processStackMsg(uint8_t *pMsg)\n{')
    j=s.index('\nstatic void NPITask_ProcessTXQ(void)\n{',i)
    segment=s[i:j]
    segment=one(segment,
            '''                case NPIMSG_Type_ASYNC:
                {
                    Queue_enqueue(npiTxQueue, &recPtr->_elem);
''',
            '''                case NPIMSG_Type_ASYNC:
                {
                    Queue_enqueue(npiTxQueue, &recPtr->_elem);
                    if (afResponse) B4_AfNpiTick(&B4_AfRspFramedQueued);
''',"FRAME_ENQUEUE")
    segment=one(segment,
       '''          OsalPort_msgDeallocate(pNPIMsg->pBuf);
          OsalPort_free(pNPIMsg);
''',
       '''          if (afResponse) B4_AfNpiTick(&B4_AfRspFramingFailed);
          OsalPort_msgDeallocate(pNPIMsg->pBuf);
          OsalPort_free(pNPIMsg);
''',"QUEUE_RECORD_FAILURE")
    # The frame builder already deallocated the original MT payload even if framing fails.
    segment=one(segment,'''    pNPIMsg = NPIFrame_frameMsg(pMsg);
    if(pNPIMsg != NULL)
''','''    pNPIMsg = NPIFrame_frameMsg(pMsg);
    if (afResponse && pNPIMsg == NULL) B4_AfNpiTick(&B4_AfRspFramingFailed);
    if(pNPIMsg != NULL)
''',"FRAME_FAILURE")
    s=s[:i]+segment+s[j:]
    tx_start=s.index('static void NPITask_ProcessTXQ(void)\n{')
    tx_end=s.index('\n#if defined(NPI_SREQRSP)',tx_start)
    tx=s[tx_start:tx_end]
    tx=one(tx,'''        NPITL_writeTL(recPtr->npiMsg->pBuf, recPtr->npiMsg->pBufSize);
''','''        {
            uint8_t afResponse = (recPtr->npiMsg->pBufSize >= 6u &&
                                  recPtr->npiMsg->pBuf[2] == 0x64u &&
                                  recPtr->npiMsg->pBuf[3] == 0x00u);
            uint16_t submitted = NPITL_writeTL(recPtr->npiMsg->pBuf,
                                                recPtr->npiMsg->pBufSize);
            if (afResponse)
            {
                if (submitted == recPtr->npiMsg->pBufSize)
                    B4_AfNpiTick(&B4_AfRspDequeued);
                else
                {
                    B4_AfNpiTick(&B4_AfRspTlRejected);
                    b1_management_transport_failed(B1_ERROR_NPI_QUEUE);
                }
            }
        }
''',"AF_TL_SUBMIT")
    s=s[:tx_start]+tx+s[tx_end:]
    p.write_text(s,encoding="utf8",newline="")
    after[TASK]=hashlib.sha256(s.encode()).hexdigest()

    p=sdk/SYS;s=p.read_text();before[SYS]=hashlib.sha256(s.encode()).hexdigest()
    anchor='uint8_t MT_SysCommandProcessing(uint8_t *pBuf)\n{'
    addition='''/* B4_R4_AF_RESPONSE_TRACE_V1: request SYS F3 empty payload, response 48
 * bytes; only RAM counters and no MT frame, key, EUI or RF metadata. */
extern volatile uint32_t B4_AfRspProduced, B4_AfRspEnqueued;
extern volatile uint32_t B4_AfRspAllocFailed, B4_AfRspSendFailed;
extern volatile uint32_t B4_AfRspNpiReceived, B4_AfRspFramedQueued;
extern volatile uint32_t B4_AfRspFramingFailed, B4_AfRspDequeued, B4_AfRspTlRejected;
static void B4_SysAfResponseTrace(void)
{
    uint8_t payload[48] = {0};
    uint32_t counts[9];
    uint8_t i;
    uint32_t key = OsalPort_enterCS();
    counts[0] = B4_AfRspProduced;
    counts[1] = B4_AfRspEnqueued;
    counts[2] = B4_AfRspAllocFailed;
    counts[3] = B4_AfRspSendFailed;
    counts[4] = B4_AfRspNpiReceived;
    counts[5] = B4_AfRspFramedQueued;
    counts[6] = B4_AfRspFramingFailed;
    counts[7] = B4_AfRspDequeued;
    counts[8] = B4_AfRspTlRejected;
    OsalPort_leaveCS(key);
    payload[0] = 'A'; payload[1] = 'F'; payload[2] = 'R'; payload[3] = '1';
    payload[4] = 1u; payload[6] = sizeof(payload);
    for (i=0u; i<9u; ++i) B4_DiagPutU32(payload + 8u + i*4u, counts[i]);
    MT_BuildAndSendZToolResponse(MT_SRSP_SYS, 0xF3u, sizeof(payload), payload);
}

'''
    s=one(s,anchor,addition+anchor,"F3_HANDLER")
    f2='''    case 0xF2:
      if (pBuf[MT_RPC_POS_LEN] != 8u)
        status = MT_RPC_ERR_LENGTH;
      else
        B4_SysReadOnlyDiagnosticsV4(pBuf);
      break;
'''
    s=one(s,f2,f2+'''    case 0xF3:
      if (pBuf[MT_RPC_POS_LEN] != 0u)
        status = MT_RPC_ERR_LENGTH;
      else
        B4_SysAfResponseTrace();
      break;
''',"F3_DISPATCH")
    p.write_text(s,encoding="utf8",newline="")
    after[SYS]=hashlib.sha256(s.encode()).hexdigest()

    return {"status":"AF_REGISTER_REAL_MT_NPI_OUTBOUND_FAILURE_PATH_CORRECTED",
            "source_modified_sha256":after,"source_before_sha256":before,
            "no_new_serial_owner":True,"no_nv_mutations":True,
            "source_trace_abi":"SYS_F3_AFR1_48_BYTE_RAM_ONLY_NORMAL_MT",
            "loss_paths":["producer_alloc","producer_msg_send","npi_frame","npi_queue_rec","npi_tl_submit"]}
