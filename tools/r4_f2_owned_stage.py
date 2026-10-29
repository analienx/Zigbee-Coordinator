"""Owned operation-age observations on the pinned composed TI source."""
import hashlib,subprocess
from pathlib import Path
from r4_uart_tx_liveness import extract,once,pinned_source,TI_SHA
TASK='source/ti/zstack/npi/npi_task.c'
MT='source/ti/zstack/mt/mt.c'
SYS='source/ti/zstack/mt/mt_sys.c'
TL='source/ti/zstack/npi/npi_tl.c'
STACK='source/ti/zstack/startup/zstackstartup.c'
CLOCK_H='kernel/tirtos7/packages/ti/sysbios/knl/Clock.h'
CLOCK_C='kernel/tirtos7/packages/ti/sysbios/knl/Clock.c'
MARKER='B4_F2_V6_OWNED_STAGE'
CORE=Path(__file__).with_name('r4_f2_owned_core.c').read_text()

def apply(sdk,expected_stack_hash):
 sdk=Path(sdk);before={p:(sdk/p).read_text() for p in (TASK,MT,SYS,TL,STACK)}
 providers={p:pinned_source(sdk,p) for p in (CLOCK_H,CLOCK_C)}
 # B1 already owns startup/dispatcher safety changes. Preserve those exact
 # bytes and reproduce its reviewed predecessor below.
 if hashlib.sha256(before[STACK].encode()).hexdigest()!=expected_stack_hash:
  raise ValueError('V6_B1_STACK_PREIMAGE')
 providers[STACK]=subprocess.check_output(['git','-C',str(sdk),'show',TI_SHA+':'+STACK])
 # B1's exact dispatcher includes the pre-MAC guard, returned-event credit
 # and existing evidence hooks. Reproduce that reviewed predecessor rather
 # than requiring pristine TI or removing B1 logic to satisfy a hash.
 import sys
 b1tools=Path(__file__).resolve().parents[1]/'firmware/slzb-06p7u/r4/b1/tools'
 sys.path.insert(0,str(b1tools))
 from patch_security import patch_startup
 if extract(before[STACK],'static void stackTaskFxn(UArg a0, UArg a1)')!=extract(patch_startup(providers[STACK].decode()),'static void stackTaskFxn(UArg a0, UArg a1)'):
  raise ValueError('V6_STACK_DISPATCH_PREIMAGE')
 if 'Clock_Handle Clock_construct(' not in providers[CLOCK_H].decode() or 'Swi_construct(&Clock_module->swiStruct' not in providers[CLOCK_C].decode():
  raise ValueError('V6_CLOCK_PROVIDER_DRIFT')
 n,m,s,t,z=(before[p] for p in (TASK,MT,SYS,TL,STACK))
 if MARKER in n or 'B4_V46_RefreshNpiPriority' not in n:raise ValueError('V6_PREDECESSOR')
 # Definitions follow V5 ring/queue metadata, prototypes precede NPI consumers.
 decl='\nstatic uint32_t B4_V6_NextLocked(void);\nstatic void B4_V6_StartMonitor(void);\nstatic void B4_V6_TxBegin(uint32_t,uint16_t);\nstatic void B4_V6_TxOffered(uint32_t,uint32_t);\nstatic uint32_t B4_V6_MtQueued(const uint8_t *);\nstatic void B4_V6_MtQueueCancel(uint32_t);\n'
 n=once(n,'static Queue_Handle npiTxQueue;','static Queue_Handle npiTxQueue;'+decl,'V6_PROTOTYPES')
 n=once(n,'    uint32_t queuedTick;','    uint32_t queuedTick;\n    uint32_t ownedStageId;','V6_QUEUE_OWNER')
 predecessor=extract(n,'uint8_t B4_V5_ReadPage2(uint8_t *out, const uint8_t *nonce)')
 n=once(n,predecessor,predecessor+'\n'+CORE,'V6_CORE')
 n=once(n,'static uint32_t B4_V5_NpiWakes, B4_V5_NpiLastTick;','static volatile uint32_t B4_V5_NpiWakes, B4_V5_NpiLastTick;','V6_SHARED_NPI_PULSE')
 n=once(n,'    recPtr->queuedTick = Clock_getTicks();','    recPtr->queuedTick = Clock_getTicks();\n    recPtr->ownedStageId=v5Command==0x61f2u?0u:B4_V6_NextLocked();','V6_ENQUEUE_ID')
 n=once(n,'        B4_V5_Record(6u,v5Cmd,v5Cmd==0xffffu?2u:0u);','        B4_V5_Record(6u,v5Cmd,v5Cmd==0xffffu?2u:0u);\n        B4_V6_TxBegin(recPtr->ownedStageId,v5Cmd);','V6_TX_BEGIN')
 n=once(n,'        uint16_t submitted = NPITL_writeTL(recPtr->npiMsg->pBuf, recPtr->npiMsg->pBufSize);','        uint16_t submitted = NPITL_writeTL(recPtr->npiMsg->pBuf, recPtr->npiMsg->pBufSize);\n        B4_V6_TxOffered(recPtr->ownedStageId,submitted==recPtr->npiMsg->pBufSize);','V6_TX_OFFERED')
 n=once(n,'          msgStatus = OsalPort_msgSend(MTServiceTaskID, (byte *)pOsalMsg);',
  '          uint32_t v6Queued=B4_V6_MtQueued(pOsalMsg->msg);\n          msgStatus = OsalPort_msgSend(MTServiceTaskID, (byte *)pOsalMsg);\n          if(msgStatus!=0u)B4_V6_MtQueueCancel(v6Queued);','V6_NPI_HANDOFF')
 fn=extract(n,'static void NPITask_process(void)')
 n=once(n,fn,once(fn,'    /* Forever loop */','    B4_V6_StartMonitor();\n    /* Forever loop */','V6_MONITOR_START'),'V6_PROCESS')
 m=once(m,'extern void B4_V5_Record(uint8_t, uint16_t, uint8_t);','extern void B4_V5_Record(uint8_t, uint16_t, uint8_t);\nextern uint32_t B4_V6_MtClaim(const uint8_t *,uint16_t);\nextern void B4_V6_MtEnd(uint32_t);','V6_MT_DECL')
 m=once(m,'  B4_V43_Request(1u, pBuf);','  uint32_t v6Owner=B4_V6_MtClaim(pBuf,((uint16_t)pBuf[1]<<8u)|pBuf[2]);\n  B4_V43_Request(1u, pBuf);','V6_MT_BEGIN')
 m=once(m,'  B4_V43_Request(2u, pBuf);','  B4_V43_Request(2u, pBuf);\n  B4_V6_MtEnd(v6Owner);','V6_MT_END')
 z=once(z,'static void stackTaskFxn(UArg a0, UArg a1);','extern void B4_V6_StackPulse(uint32_t,uint32_t);\nstatic void stackTaskFxn(UArg a0, UArg a1);','V6_STACK_DECL')
 z=once(z,'        events = (zstackTasksArr[idx])( 0U, events );','        B4_V6_StackPulse((uint32_t)idx+1u,0u);\n        events = (zstackTasksArr[idx])( 0U, events );\n        B4_V6_StackPulse((uint32_t)idx+1u,1u);','V6_REAL_STACK_DISPATCH')
 t=once(t,'void B4_V43_Complete(int_fast16_t status, uint32_t actual, uint32_t expected)','extern void B4_V6_UartPulse(uint32_t);\nvoid B4_V43_Complete(int_fast16_t status, uint32_t actual, uint32_t expected)','V6_UART_DECL')
 fn=extract(t,'void B4_V43_Complete(int_fast16_t status, uint32_t actual, uint32_t expected)')
 t=once(t,fn,once(fn,'    uint32_t key = OsalPort_enterCS();','    uint32_t key = OsalPort_enterCS();\n    B4_V6_UartPulse(status==UART2_STATUS_SUCCESS && actual==expected);','V6_UART_PULSE'),'V6_UART_FUNCTION')
 handler='''extern void B4_V6_Read(uint8_t *,const uint8_t *,uint8_t);
__attribute__((noinline)) static void B4_SysReadOnlyDiagnosticsV6(uint8_t *pBuf)
{
    uint8_t payload[248]={0};
    uint8_t page=pBuf[MT_RPC_POS_DAT0];
    B4_V6_Read(payload,pBuf+MT_RPC_POS_DAT0+1u,page);
    MT_BuildAndSendZToolResponse(MT_SRSP_SYS,0xF2u,page==3u?160u:248u,payload);
}
'''
 s=once(s,'__attribute__((noinline)) static void B4_SysReadOnlyDiagnosticsV5(uint8_t *pBuf)',handler+'\n__attribute__((noinline)) static void B4_SysReadOnlyDiagnosticsV5(uint8_t *pBuf)','V6_HANDLER')
 s=once(s,'    if(page!=1u && page!=2u)','    if(page>=3u && page<=8u)\n    { B4_SysReadOnlyDiagnosticsV6(pBuf); return; }\n    if(page!=1u && page!=2u)','V6_SELECTOR')
 after=dict(zip((TASK,MT,SYS,TL,STACK),(n,m,s,t,z)))
 for p,text in after.items():(sdk/p).write_text(text,encoding='utf-8',newline='')
 return {'schema':'p7u-f2-v6-owned-stage-v1','clock_period_us':250000,
  'budgets_us':{'mt_fast':2000000,'mt_other':8000000,'npi_handoff':2000000,'srsp_queue':2000000,'async_queue':60000000,'uart':250000},
  'owner_scope':'INGRESS_MT_SHARED_FRAME_LOCAL_QUEUE_TX','frozen_histories':5,'events_per_history':16,
  'legacy_v4_v5_wire_unchanged':True,'automatic_recovery':False,'heap_stack_esp_metrics_available':False,
  'provider_sha256':{p:hashlib.sha256(b).hexdigest() for p,b in providers.items()},
  'before_sha256':{p:hashlib.sha256(text.encode()).hexdigest() for p,text in before.items()},
  'modified_sha256':{p:hashlib.sha256(text.encode()).hexdigest() for p,text in after.items()}}
