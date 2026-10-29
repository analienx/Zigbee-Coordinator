"""Focused compiled checks of the actual composed owned-stage code, run on Actions."""
import hashlib,shutil,subprocess,tempfile
from pathlib import Path
from r4_uart_tx_liveness import extract
from r4_f2_owned_stage import TASK,MT,SYS,TL,STACK
PREFIX=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
static uint32_t now,cs,transport;
#define Clock_tickPeriod 10u
static uint32_t Clock_getTicks(void){return now;}
static uint32_t OsalPort_enterCS(void){return cs++;}
static void OsalPort_leaveCS(uint32_t k){assert(cs==k+1);--cs;}
typedef struct {unsigned period;bool startFlag;} Clock_Params;
typedef struct {int unused;} Clock_Struct;
static void (*checkpoint)(uintptr_t);
static void Clock_Params_init(Clock_Params *p){memset(p,0,sizeof(*p));}
static void *Clock_construct(Clock_Struct *s,void (*cb)(uintptr_t),unsigned t,const Clock_Params *p){
 assert(t==25000u && p->period==t && p->startFlag);checkpoint=cb;return s;}
typedef struct {uint32_t tick;uint16_t command;uint8_t stage,result;} B4_V5_Event;
static B4_V5_Event B4_V5_Ring[16];
static uint32_t B4_V5_RingCount,B4_V5_RingWriteIndex,B4_V5_EventTotal;
static uint32_t B4_AllRspProduced,B4_V44_Bytes[2],B4_V5_NpiWakes,B4_V5_NpiLastTick;
static uint32_t B4_V4BootValid;
static uint8_t B4_V4BootId[8];
typedef struct {uint8_t *pBuf;uint16_t pBufSize;} Msg;
typedef struct {uint32_t queuedTick,ownedStageId;Msg *npiMsg;} NPI_QueueRec;
typedef NPI_QueueRec **Queue_Handle;
static NPI_QueueRec *srsp,*areq;
#define B4_V44_SrspQueue (&srsp)
#define npiTxQueue (&areq)
static bool Queue_empty(Queue_Handle q){assert(cs);return !*q;}
static NPI_QueueRec *Queue_head(Queue_Handle q){assert(cs);return *q;}
static uint16_t B4_V5_CommandFromFrame(const uint8_t *p,uint16_t n){return p&&n>=5?((uint16_t)p[2]<<8)|p[3]:0xffffu;}
static void B4_V5_Put32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(v>>(8*i));}
static void B4_V5_PutEvent(uint8_t *p,const B4_V5_Event *e){B4_V5_Put32(p,e->tick);p[4]=e->command;p[5]=e->command>>8;p[6]=e->stage;p[7]=e->result;}
static uint32_t B4_V5_Get32(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static void B4_V43_Snapshot(uint8_t *p){assert(cs);memset(p,0,80);B4_V5_Put32(p+32,transport);}
'''
TEST=r'''
static void clear(void){
 memset(B4_V6_Faults,0,sizeof(B4_V6_Faults));B4_V6_Mt=(B4_V6_Owner){0};
 B4_V6_Tx=(B4_V6_Owner){0};srsp=areq=NULL;transport=B4_V6_TxSubmitted=0;
 memset(B4_V6_Ingress,0,sizeof(B4_V6_Ingress));
 B4_V6_FirstStage=0;assert(!cs);
}
int main(void){
 uint8_t page[250],nonce[8]={1,2,3,4,5,6,7,8},frame[6]={0xfe,1,0x64,1,0,0};
 Msg msg={frame,6};NPI_QueueRec q={100,99,&msg};uint32_t id,other;
 B4_V6_StartMonitor();assert(B4_V6_Started && checkpoint);
 now=100;id=B4_V6_MtBegin(0x2401);assert(id && B4_V6_Mt.command==0x2401);
 B4_V5_RingCount=16;B4_V5_RingWriteIndex=20;B4_V5_EventTotal=20;
 for(unsigned i=0;i<16;++i)B4_V5_Ring[i]=(B4_V5_Event){i,0x2401,3,0};
 now=200099;checkpoint(0);assert(!B4_V6_FirstStage);
 now=200100;checkpoint(0);assert(B4_V6_FirstStage==1 && B4_V6_Faults[0].words[1]==id);
 assert(B4_V6_Faults[0].words[2]==0x2401 && B4_V6_Faults[0].history[0].tick==4);
 assert(!B4_V5_NpiWakes); // Clock alone observes a stuck task.
 B4_V6_MtEnd(id);now++;other=B4_V6_MtBegin(0x2401);B4_V6_MtEnd(id);
 assert(B4_V6_Mt.id==other);B4_V6_MtEnd(other);assert(!B4_V6_Mt.id);
 B4_V5_Ring[4].tick=999;now=900100;checkpoint(0);
 assert(B4_V6_Faults[0].words[4]==200100 && B4_V6_Faults[0].history[0].tick==4);
 B4_V6_Read(page,nonce,3);uint32_t sequence=B4_V5_Get32(page+24);
 memset(page,0xaa,sizeof(page));B4_V6_Read(page,nonce,4);
 assert(!memcmp(page,"R4D6",4) && page[4]==6 && page[5]==4 && page[6]==248);
 assert(!memcmp(page+8,nonce,8) && B4_V5_Get32(page+32)==1 && page[248]==0xaa);
 assert(B4_V5_Get32(page+120)==4 && B4_V5_Get32(page+96)==16);
 assert(B4_V5_Get32(page+24)==sequence);B4_V6_Read(page,nonce,4);assert(page[5]==255);
 clear();now=100;id=B4_V6_MtBegin(0x2121);now+=400000;checkpoint(0);
 assert(!B4_V6_FirstStage); // Ordinary four-second host latency != generic MT overdue.
 now+=400000;checkpoint(0);assert(B4_V6_FirstStage==1);B4_V6_MtEnd(id);
 clear();srsp=&q;now=200100;checkpoint(0);assert(B4_V6_FirstStage==2);
 now++;id=B4_V6_MtBegin(0x2402);now+=200000;checkpoint(0);
 assert(B4_V6_FirstStage==2 && B4_V6_Faults[0].words[0]==1); // Queue did not mask later MT.
 B4_V6_MtEnd(id);clear();areq=&q;now=4000100;checkpoint(0);assert(!B4_V6_FirstStage);
 now=6000100;checkpoint(0);assert(B4_V6_FirstStage==3); // Existing 36s backlog is not 60s overdue.
 clear();transport=2;srsp=&q;now=9000100;checkpoint(0);assert(!B4_V6_FirstStage); // B1 HOLD not queue deadlock.
 clear();now=100;B4_V6_TxBegin(8,0x6401);transport=1;
 now+=100000;checkpoint(0);assert(!B4_V6_FirstStage); // Offer not returned: no accepted-TX claim.
 B4_V6_TxOffered(8,1);checkpoint(0);assert(B4_V6_FirstStage==4 && B4_V6_Faults[3].words[1]==8);
 clear();now=100;B4_V6_TxBegin(9,0x6401);B4_V6_TxOffered(8,0);
 assert(B4_V6_Tx.id==9);B4_V6_TxOffered(9,1);transport=0;now+=30000;checkpoint(0);
 assert(!B4_V6_Tx.id && !B4_V6_FirstStage); // Callback before submit return is safe.
 B4_V6_UartPulse(1);B4_V6_UartPulse(0);assert(B4_V6_UartDone==1 && B4_V6_UartLast==now);
 B4_V6_StackPulse(3,0);assert(B4_V6_StackService==3);B4_V6_StackPulse(3,1);
 assert(B4_V6_StackDone==1 && !B4_V6_StackService);
 clear();now=UINT32_MAX-100;id=B4_V6_MtBegin(0x2403);now=200000;checkpoint(0);
 assert(B4_V6_Faults[0].words[5]==200101);B4_V6_MtEnd(id);
 clear();now=100;id=B4_V6_MtBegin(0x2401);now=99;checkpoint(0);assert(!B4_V6_FirstStage);B4_V6_MtEnd(id);
 B4_V6_Ordinal=UINT32_MAX;assert(!B4_V6_MtBegin(0x2401) && B4_V6_IdExhausted);
 memset(page,0xaa,sizeof(page));B4_V6_Read(page,nonce,3);assert(page[6]==160 && page[160]==0xaa);
 assert(B4_V5_Get32(page+32)==5 && B4_V5_Get32(page+92)==0 && !cs);
 B4_V6_Ordinal=1000;clear();uint8_t request[3]={1,0x24,1};now=100;
 id=B4_V6_MtQueued(request);now+=200000;checkpoint(0);
 assert(B4_V6_Faults[4].words[0]==5 && B4_V6_Faults[4].words[1]==id);
 other=B4_V6_MtClaim(request,0x2401);assert(other==id && B4_V6_Mt.id==id && !B4_V6_Ingress[0].owner.id);
 B4_V6_MtQueueCancel(id);assert(B4_V6_Mt.id==id);B4_V6_MtEnd(id);
 id=B4_V6_MtQueued(request);B4_V6_MtQueueCancel(id);assert(!B4_V6_Ingress[0].owner.id);
 puts("V6_OWNED_STAGE_ACTUAL_C_PASS");return 0;
}
'''
def exercise(sdk):
 sdk=Path(sdk);n=(sdk/TASK).read_text();a=n.index('/* B4_F2_V6_OWNED_STAGE:');b=n.index('/* B4_F2_V6_OWNED_STAGE_END */',a)
 source=PREFIX+n[a:b]+TEST
 checks={
  'clock_started_in_owner_once':extract(n,'static void NPITask_process(void)').count('B4_V6_StartMonitor();')==1,
  'independent_callback_not_called_by_task':'B4_V6_Checkpoint(' not in extract(n,'static void NPITask_process(void)'),
  'frame_generation_on_enqueue':'recPtr->ownedStageId=v5Command==0x61f2u?0u:B4_V6_NextLocked();' in extract(n,'static void B4_V44_Enqueue(NPI_QueueRec *recPtr)'),
  'actual_stack_dispatch_pair':'B4_V6_StackPulse((uint32_t)idx+1u,0u);\n        events = (zstackTasksArr[idx])( 0U, events );\n        B4_V6_StackPulse((uint32_t)idx+1u,1u);' in (sdk/STACK).read_text(),
  'mt_owned_pair':'B4_V6_MtEnd(v6Owner);' in extract((sdk/MT).read_text(),'void MT_ProcessIncoming(uint8_t *pBuf)'),
  'actual_uart_pulse':'B4_V6_UartPulse(status==UART2_STATUS_SUCCESS && actual==expected);' in extract((sdk/TL).read_text(),'void B4_V43_Complete(int_fast16_t status, uint32_t actual, uint32_t expected)'),
 }
 if not all(checks.values()):raise ValueError('V6_INTEGRATION_'+str(checks))
 cc=shutil.which('cc') or shutil.which('gcc')
 if not cc:raise RuntimeError('V6_CC_REQUIRED')
 def run(text,passed):
  with tempfile.TemporaryDirectory(prefix='v6-owned-') as d:
   d=Path(d);p=d/'owned.c';exe=d/'owned';p.write_text(text)
   c=subprocess.run([cc,'-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=undefined,bounds',str(p),'-o',str(exe)],capture_output=True,text=True,timeout=30)
   if c.returncode:raise RuntimeError('V6_COMPILE\n'+c.stderr[-4000:])
   r=subprocess.run([str(exe)],capture_output=True,text=True,timeout=15)
   if (r.returncode==0)!=passed:raise RuntimeError('V6_RESULT\n'+r.stdout+r.stderr[-2000:])
 run(source,True)
 mutants={'stale_mt_exit':('owner && B4_V6_Mt.id==owner','owner'),
  'overwrite_frozen':(' || f->words[0]',''),
  'ignore_hold':('if (!(transport&2u))','if (1)'),
  'generic_four_second_false_positive':('2000000u : 8000000u','2000000u : 3000000u')}
 for name,(old,new) in mutants.items():
  if source.count(old)!=1:raise ValueError('V6_MUTANT_DRIFT_'+name)
  run(source.replace(old,new,1),False)
 return {'status':'PASS','schema':'p7u-v6-owned-stage-actual-c-v1','checks':checks,
  'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'negative_mutants':list(mutants),'physical_scheduling_proven':False}
