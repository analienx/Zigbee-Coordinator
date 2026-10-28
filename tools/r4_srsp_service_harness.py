#!/usr/bin/env python3
"""Hosted execution of the final composed TI producer, framer and task loop.

Virtual UART runs at 115200/8N1, with explicit delayed completion scheduling.
This is a software flood/interleaving test, not physical RF/ESP qualification.
"""
import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from r4_uart_tx_liveness import extract
from r4_srsp_service import TASK, SYS

PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
typedef uint8_t uint8;
typedef uint16_t uint16;
#define TRUE 1
#define FALSE 0
#define NPI_FLOW_CTRL 0
#define NPITASK_TX_READY_EVENT 0x10u
#define NPITASK_TRANSPORT_RX_EVENT 2u
#define NPITASK_TRANSPORT_TX_DONE_EVENT 4u
#define NPITASK_FRAME_RX_EVENT 8u
#define NPITASK_MRDY_EVENT 0x80u
#define BIOS_WAIT_FOREVER (~0u)
#define MTRPC_POS_LEN 0
#define MTRPC_POS_CMD0 1
#define MTRPC_POS_CMD1 2
#define MTRPC_FRAME_HDR_SZ 3
#define MT_SOF 0xfe
#define INTERCEPT 1
#define ECHO 2
#define NONE 0
typedef struct Queue_Elem {struct Queue_Elem *next,*prev;} Queue_Elem;
typedef Queue_Elem Queue_Struct;
typedef Queue_Elem *Queue_Handle;
static void Queue_construct(Queue_Struct*q,void*p){(void)p;q->next=q->prev=q;}
static Queue_Handle Queue_handle(Queue_Struct*q){return q;}
static int Queue_empty(Queue_Handle q){return q->next==q;}
static void Queue_enqueue(Queue_Handle q,Queue_Elem*e){
 e->prev=q->prev;e->next=q;q->prev->next=e;q->prev=e;
}
static void *Queue_dequeue(Queue_Handle q){
 assert(!Queue_empty(q));Queue_Elem*e=q->next;q->next=e->next;e->next->prev=q;return e;
}
static void *Queue_head(Queue_Handle q){assert(!Queue_empty(q));return q->next;}
typedef struct {uint8_t msgType;uint16_t pBufSize;uint8_t*pBuf;} NPIMSG_msg_t;
typedef enum {NPIMSG_Type_ASYNC=0,NPIMSG_Type_SYNCRSP=2} NPIMSG_Type;
static Queue_Struct aq,rq;
static Queue_Handle npiTxQueue=&aq,npiRxQueue=&rq;
static unsigned cs_depth,posts,tokens,loops,live_alloc,allocation_fail;
static unsigned flood_left=5968, produced_areq=32, peak_alloc;
static void make_message(unsigned srsp,unsigned id,unsigned len);
static uint32_t now_us,uart_due;
static int busy,held;
static jmp_buf done;
static uint8_t npiServiceTaskId=1;
static uint8_t npiTaskID=1;
static uint32_t npiServiceTaskEvents;
static uint16_t TX_DONE_ISR_EVENT_FLAG,MRDY_ISR_EVENT_FLAG,TRANSPORT_RX_ISR_EVENT_FLAG;
static void*npiSemHandle=(void*)1;
static void(*incomingTXEventAppCBFunc)(uint8_t*);
static unsigned incomingTXReroute;
static uint32_t OsalPort_enterCS(void){return cs_depth++;}
static void OsalPort_leaveCS(uint32_t k){assert(cs_depth==k+1);--cs_depth;}
static uint32_t Clock_getTicks(void){return now_us/10u;}
static int NPITL_checkNpiBusy(void){return busy;}
static int b1_management_transport_unavailable(void){return held;}
static void Semaphore_post(void*s){assert(s==npiSemHandle);++posts;++tokens;}
static void NPITask_transportTxDoneCallBack(int);
static void NPITask_processStackMsg(uint8_t*);
static void NPITask_ProcessTXQ(void);
static void B4_V44_Pend(void);
static void b1_evidence_note_npi_wake(void){
 assert(++loops<250000u);now_us+=50u;
 if(busy && now_us>=uart_due){busy=0;NPITask_transportTxDoneCallBack(1);}
 if(flood_left && live_alloc<192){
  make_message(0,++produced_areq,250);--flood_left;
  if(flood_left==3000)make_message(1,1,20);
 }
}
static void B4_V43_Wake(void){}
static void *OsalPort_malloc(size_t n){if(allocation_fail)return NULL;void*p=malloc(n);assert(p);++live_alloc;if(live_alloc>peak_alloc)peak_alloc=live_alloc;return p;}
static void OsalPort_free(void*p){if(p){assert(live_alloc);--live_alloc;free(p);}}
static void*OsalPort_msgAllocate(size_t n){return OsalPort_malloc(n);}
static unsigned OsalPort_msgDeallocate(void*p){OsalPort_free(p);return 0;}
static uint8_t*mail[20000];static unsigned mail_in,mail_out;
static unsigned OsalPort_msgSend(unsigned id,uint8_t*p){assert(id==1 && mail_in<20000);mail[mail_in++]=p;Semaphore_post(npiSemHandle);return 0;}
static uint8_t*OsalPort_msgReceive(unsigned id){(void)id;return mail_out<mail_in?mail[mail_out++]:NULL;}
static void NPIFrame_collectFrameData(void){}
static unsigned NPIRxBuf_GetRxBufCount(void){return 0;}
static void NPITask_processRXQ(void){assert(0);}
static uint32_t srsp_sent,areq_sent,max_srsp_us,max_areq_gap,last_areq_at;
static uint32_t last_srsp_id,last_areq_id;
static uint16_t NPITL_writeTL(uint8_t*p,uint16_t n){
 assert(!cs_depth && !busy && !held && n>=9 && n<=255);
 uint32_t stamp,id;memcpy(&stamp,p+4,4);id=p[8]|((uint32_t)p[9]<<8);
 uint32_t latency=now_us-stamp+(n*10000000u+115199u)/115200u;
 if((p[2]&0xe0)==0x60){assert(id>last_srsp_id);last_srsp_id=id;++srsp_sent;if(latency>max_srsp_us)max_srsp_us=latency;}
 else{assert(id>last_areq_id);last_areq_id=id;++areq_sent;uint32_t gap=srsp_sent-last_areq_at;if(gap>max_areq_gap)max_areq_gap=gap;last_areq_at=srsp_sent;}
 busy=1;uart_due=now_us+(n*10000000u+115199u)/115200u+2000u;return n;
}
static unsigned injection;
static void make_message(unsigned srsp,unsigned id,unsigned len);
static void Semaphore_pend(void*s,unsigned timeout){
 assert(s==npiSemHandle && timeout==BIOS_WAIT_FOREVER && !cs_depth);
 if(tokens){--tokens;return;}
 if(injection){unsigned mode=injection;injection=0;
  if(mode==1){make_message(1,60001,20);assert(tokens);--tokens;return;}
  if(mode==2){assert(busy);now_us=uart_due;busy=0;NPITask_transportTxDoneCallBack(1);assert(tokens);--tokens;return;}
 }
 if(busy){now_us=uart_due;busy=0;NPITask_transportTxDoneCallBack(1);assert(tokens);--tokens;return;}
 longjmp(done,1);
}
#define MT_RPC_POS_DAT0 3
#define MT_SRSP_SYS 0x61u
static uint8_t B4_V4BootId[8];
static uint32_t B4_V4BootValid, B4_V4ResetReason=255, B4_V4SampleSequence;
static void B4_V43_Snapshot(uint8_t*p){memset(p,0,80);}
static void B4_DiagPutU32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(v>>(8*i));}
'''

MAIN = r'''
static void make_message(unsigned srsp,unsigned id,unsigned len){
 uint8_t data[250]={0};memcpy(data,&now_us,4);data[4]=id;data[5]=id>>8;
 MT_BuildAndSendZToolResponse(srsp?0x64u:0x44u,srsp?1u:0x81u,len,data);
}
int main(int argc,char**argv){
 (void)argc;(void)argv;Queue_construct(&aq,NULL);Queue_construct(&rq,NULL);
 Queue_construct(&B4_V44_SrspQueueStruct,NULL);B4_V44_SrspQueue=Queue_handle(&B4_V44_SrspQueueStruct);
 /* Real producer -> OSAL mailbox -> real framer -> real task queues.
  * Feed 6000 full 250-byte unsolicited messages over >130s of virtual
  * wire time, with bounded live allocations. Inject SRSP during the flood. */
 for(unsigned i=1;i<=32;++i)make_message(0,i,250);
 if(!setjmp(done))NPITask_process();
 assert(srsp_sent==1 && areq_sent==6000 && max_srsp_us<1000000u);
 assert(!busy && !live_alloc && !B4_NpiSrspDepth && !B4_NpiAsyncDepth);
 assert(!B4_V44_Bytes[0] && !B4_V44_Bytes[1]);
 assert(B4_V44_BytesHigh[1]>10000u && B4_V44_MaxAge[1]>0);
 /* Both framing entry points use class selection. Pending SRSPs cannot
  * starve AREQs; each class remains FIFO, including mixed AF messages. */
 for(unsigned i=2;i<=61;++i)make_message(1,i,20);
 for(unsigned i=6001;i<=6012;++i)make_message(0,i,50);
 while(mail_out<mail_in)NPITask_processStackMsg(OsalPort_msgReceive(1));
 last_areq_at=srsp_sent;
 if(!setjmp(done))NPITask_process();
 assert(srsp_sent==61 && areq_sent==6012 && max_areq_gap<=4u);
 /* Lost hint/token must not strand queued, transmissible work. */
 make_message(1,62,20);NPITask_processStackMsg(OsalPort_msgReceive(1));
 tokens=0;npiServiceTaskEvents=0;
 if(!setjmp(done))NPITask_process();
 assert(srsp_sent==62 && !live_alloc);
 /* Enqueue after the atomic check, before pend: semaphore remembers it. */
 injection=1;
 if(!setjmp(done))NPITask_process();
 assert(srsp_sent==63 && !live_alloc);
 /* Delayed completion: no loop without progress while UART busy. */
 make_message(1,60002,20);make_message(0,6013,20);
 NPITask_processStackMsg(OsalPort_msgReceive(1));NPITask_processStackMsg(OsalPort_msgReceive(1));
 NPITask_ProcessTXQ();assert(busy);tokens=0;injection=2;
 unsigned before=loops;
 if(!setjmp(done))NPITask_process();
 assert(loops-before<6 && !live_alloc && areq_sent==6013 && srsp_sent==64);
 /* An enqueue while UART busy must neither submit nor manufacture tokens. */
 make_message(0,6014,20);NPITask_processStackMsg(OsalPort_msgReceive(1));
 busy=1;tokens=0;unsigned p=posts;B4_V44_Pend();assert(posts==p+1);
 NPITask_ProcessTXQ();busy=0;tokens=0;assert(!live_alloc);
 /* Transport HOLD retains pending work, does not re-post/spin/submit. */
 make_message(1,60003,20);NPITask_processStackMsg(OsalPort_msgReceive(1));
 held=1;tokens=0;before=loops;
 if(!setjmp(done))NPITask_process();
 assert(loops==before && B4_NpiSrspDepth==1);held=0;
 if(!setjmp(done))NPITask_process();
 /* Tick wrap: elapsed queue age must remain small and unsigned. */
 now_us=100;B4_V44_MaxAge[0]=0;
 make_message(1,60004,20);NPITask_processStackMsg(OsalPort_msgReceive(1));
 ((NPI_QueueRec*)Queue_head(B4_V44_SrspQueue))->queuedTick=UINT32_MAX-9u;
 NPITask_ProcessTXQ();assert(B4_V44_MaxAge[0]==20u);busy=0;tokens=0;
 uint8_t snap[248]={0};B4_V44_Snapshot(snap);
 uint8_t request[11]={8,0x21,0xf2,1,2,3,4,5,6,7,8};
 B4_SysReadOnlyDiagnosticsV4(request);
 uint8_t *diag=OsalPort_msgReceive(1);
 assert(diag && diag[0]==248 && diag[1]==0x61 && diag[2]==0xf2);
 assert(diag[3+157]==4 && diag[3+6]==248 && diag[3+15]==1);
 assert(!memcmp(diag+3+132,request+3,8));
 assert(!memcmp(diag+3+140,snap+140,16));
 assert(!memcmp(diag+3+240,snap+240,8));OsalPort_msgDeallocate(diag);
 assert(!live_alloc && !cs_depth && !B4_V44_Bytes[0] && !B4_V44_Bytes[1]);
 /* Actual allocation failure cleanup does not leak queue records. */
 allocation_fail=1;make_message(1,60005,20);allocation_fail=0;assert(!live_alloc);
 printf("V44_FLOOD_PASS max_srsp_us=%u areq_max_srsp_gap=%u loops=%u bytes_high=%u peak_allocations=%u\n",max_srsp_us,max_areq_gap,loops,B4_V44_BytesHigh[1],peak_alloc);
 return 0;
}
'''


def exercise(sdk):
    sdk = Path(sdk)
    task = (sdk/TASK).read_text()
    client = (sdk/"source/ti/zstack/npi/npi_client_mt.c").read_text()
    frame = (sdk/"source/ti/zstack/npi/npi_frame_mt.c").read_text()
    sys_source = (sdk/SYS).read_text()
    # Extract complete real bodies, not a Python simulation of scheduling.
    names = ["static uint8_t B4_V44_TxReadyLocked(void)",
             "static void B4_V44_NoteReadyLocked(void)",
             "static void B4_V44_Enqueue(NPI_QueueRec *recPtr)",
             "static void B4_V44_Pend(void)",
             "void B4_V44_Snapshot(uint8_t *payload)",
             "static void B4_AfNpiTick(volatile uint32_t *p)",
             "void NPITask_sendToHost(uint8_t *pMsg)",
             "static void NPITask_processStackMsg(uint8_t *pMsg)",
             "static void NPITask_ProcessTXQ(void)",
             "static void NPITask_transportTxDoneCallBack(int size)",
             "static void NPITask_process(void)"]
    record = task[task.index('typedef struct NPI_QueueRec_t'):task.index('} NPI_QueueRec;')+len('} NPI_QueueRec;')]
    globals_ = task[task.index('#define B4_V44_SRSP_BURST'):task.index('static uint8_t B4_V44_ReadyTracked')]
    globals_ += 'static uint8_t B4_V44_ReadyTracked, B4_V44_SrspRun;\n'
    counters = sorted(set(re.findall(r'volatile uint32_t (B4_(?:AllRsp|AfDataRsp|AfRsp|Npi)[A-Za-z]+)', task+client+sys_source)))
    counter_src = '\n'.join('static uint32_t '+name+';' for name in counters if name != 'B4_NpiUartTxFinishedCallback')
    tick = extract(client, 'static void B4_AfRspTick(volatile uint32_t *p)')
    producer = extract(client, 'void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,\n                                  uint8_t dataLen, uint8_t *pData)')
    framer = extract(frame, 'NPIMSG_msg_t *NPIFrame_frameMsg(uint8_t *pIncomingMsg)')
    fcs = extract(frame, 'uint8_t npiframe_calcMTFCS(uint8_t *msg_ptr, uint8_t len)')
    source = PREFIX + record + '\n' + globals_ + counter_src + '\n' + tick + '\n' + producer + '\n' + fcs + '\n' + framer
    source += '\n' + '\n'.join(extract(task, n) for n in names)
    source += '\n' + extract(sys_source, '__attribute__((noinline)) static void B4_SysReadOnlyDiagnosticsV4(uint8_t *pBuf)') + '\n' + MAIN
    cc = shutil.which('cc') or shutil.which('gcc')
    if not cc: raise RuntimeError('V44_HOSTED_C_COMPILER_REQUIRED')
    def run(label, text, should_pass):
        with tempfile.TemporaryDirectory(prefix='p7u-v44-') as td:
            p=Path(td);(p/'actual.c').write_text(text)
            compiled=subprocess.run([cc,'-std=c11','-O1','-g','-fsanitize=address,undefined',
                '-fno-omit-frame-pointer','-Wall','-Wextra','-Wno-unused-function',
                str(p/'actual.c'),'-o',str(p/'actual')],capture_output=True,text=True,timeout=30)
            if compiled.returncode:raise RuntimeError('V44_COMPILE_'+label+':'+compiled.stderr[-4500:])
            result=subprocess.run([str(p/'actual')],capture_output=True,text=True,timeout=25)
            if (result.returncode==0) != should_pass:
                raise RuntimeError('V44_RUNTIME_'+label+':'+result.stdout[-2000:]+result.stderr[-4000:])
            return result.stdout.strip()
    output=run('flood',source,True)
    mutants = {
        'no_srsp_preference': ('Queue_empty(npiTxQueue) || B4_V44_SrspRun < B4_V44_SRSP_BURST', 'Queue_empty(npiTxQueue)'),
        'areq_starvation': ('Queue_empty(npiTxQueue) || B4_V44_SrspRun < B4_V44_SRSP_BURST', '1'),
        'event_only_sleep': ('if (!ready) Semaphore_pend', 'if (1) Semaphore_pend'),
        'busy_spin': ('B4_V44_TxReadyLocked() || !Queue_empty(npiRxQueue)',
                      '!Queue_empty(npiTxQueue) || !Queue_empty(B4_V44_SrspQueue) || !Queue_empty(npiRxQueue)'),
    }
    for label,(old,new) in mutants.items():
        if source.count(old)!=1:raise RuntimeError('V44_MUTATION_ANCHOR_'+label)
        run(label,source.replace(old,new,1),False)
    callback=extract(task,'static void NPITask_transportTxDoneCallBack(int size)')
    old='    Semaphore_post(npiSemHandle);'
    if callback.count(old)!=1:raise RuntimeError('V44_CALLBACK_MUTATION_ANCHOR')
    run('lost_completion',source.replace(callback,callback.replace(old,'',1),1),False)
    return {'schema':'p7u-v44-actual-composite-flood-v1','status':'PASS',
            'actual_c_functions':names,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
            'result':output,'negative_mutants':[*mutants,'lost_completion'],
            'physical_uart_rf_or_esp_exercised':False,'virtual_baud':115200,
            'unsolicited_frames':6000,'srsp_deadline_us':1000000}
