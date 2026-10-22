"""Extract real retained ZDO startup bodies into a hosted EOT-ordering oracle.

The full transport correlation lives in b1_management.c and a native NPI
source harness. This oracle proves the stack handler cannot call BDB before
the admitted request's wire-completion event (one attempt per boot).
"""
import argparse
from pathlib import Path
from patch_zdapp import extract_function
from patch_mt_zdo_retained import HELPER_NAME, STARTUP_SIGNATURE

PREAMBLE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define TRUE 1
#define ZSuccess 0
#define ZSUCCESS 0
#define SUCCESS 0
#define ZFailure 1
#define ZG_BUILD_COORDINATOR_TYPE 1
#define ZG_DEVICE_COORDINATOR_TYPE coordinator
#define MT_RPC_POS_CMD0 1
#define MT_RPC_POS_CMD1 2
#define MT_RPC_FRAME_HDR_SZ 3
#define MT_RPC_CMD_SREQ 0x20
#define MT_RPC_CMD_SRSP 0x60
#define MT_RPC_CMD_TYPE_MASK 0xe0
#define MT_RPC_SYS_ZDO 5
#define B1_RETAINED_STARTUP_EVENT 0x00010000u
#define B1_RETAINED_STARTUP_EXPIRE_EVENT 0x00020000u
#define B1_RETAINED_STARTUP_TIMEOUT_MS 1000u
#define B1_ERROR_STARTUP_TX_TIMEOUT 0x68u
#define B1_PHASE_BDB 2u
#define B1_STARTUP_IDLE 0u
#define B1_STARTUP_WAIT_SRSP_TX 1u
#define B1_STARTUP_QUEUED 2u
#define B1_STARTUP_RUNNING 3u
#define B1_STARTUP_READY 4u
#define B1_STARTUP_FAILED 5u
enum {ZCD_NV_NIB, ZCD_NV_STARTUP_OPTION,
      ZCD_NV_BDBNODEISONANETWORK, ZCD_NV_LOGICAL_TYPE};
static uint32_t Clock_tickPeriod=1000u, now_ticks;
static uint32_t Clock_getTicks(void) {return now_ticks;}
static uint32_t b1_startup_admitted_tick;
static int held,candidate,security_valid,coordinator,read_fault,bdb_latch,timer_fail,ready;
static uint8_t ZDAppTaskID=7u, startup_state;
static uint16_t lengths[4];
static uint8_t values[4],response;
static unsigned bdb_calls,response_calls,reads,queued_events,security_latches,timer_starts,timer_stops,failures,phase_calls;
static int b1_nv_runtime_hold_active(void) {return held;}
static int b1_nv_existing_header_candidate(void) {return candidate;}
static int b1_sec_restored_network_validated(void) {return security_valid;}
static int b1_management_network_ready(void) {return ready;}
static uint8_t b1_startup_admit(uint8_t sub,uint8_t cmd)
{assert(sub==0x65u&&cmd==0x40u);
 if(startup_state!=B1_STARTUP_IDLE)return 0;
 startup_state=B1_STARTUP_WAIT_SRSP_TX;return 1;}
static uint8_t b1_startup_begin(void)
{if(startup_state!=B1_STARTUP_QUEUED)return 0;
 startup_state=B1_STARTUP_RUNNING;return 1;}
static void b1_startup_fail(uint8_t code) {(void)code;++failures;startup_state=B1_STARTUP_FAILED;}
static void b1_management_transport_failed(uint8_t code) {(void)code;held=1;}
static unsigned observer_priority_raises, observer_priority_restores;
static int task_priority=5;
static void *Task_self(void) {return &task_priority;}
static int Task_setPri(void *self,int pri)
{assert(self==&task_priority && (pri==3 || pri==5));
 int old=task_priority; task_priority=pri;
 if(pri==3) ++observer_priority_raises; else ++observer_priority_restores;
 return old;}
static uint8_t b1_startup_state(void) {return startup_state;}
static int b1_management_get_hold_active(void) {return held;}
static void b1_startup_note_phase(uint8_t phase,uint8_t status,uint16_t idx)
{assert(phase==B1_PHASE_BDB);assert(status==0xffu||status==0u);(void)idx;++phase_calls;}
static uint16_t osal_nv_item_len(uint16_t id)
{assert(id<4);return lengths[id];}
static uint8_t osal_nv_read(uint16_t id,uint16_t offset,uint16_t count,void *out)
{assert(id>0&&id<4&&offset==0&&count==1);++reads;
 if(read_fault==(int)id)return 10;
 *(uint8_t *)out=values[id];return ZSUCCESS;}
static void bdb_StartCommissioning(uint8_t mode)
{assert(mode==0);++bdb_calls;if(bdb_latch)held=1;}
static uint8_t OsalPortTimers_startTimer(uint8_t task,uint32_t event,uint32_t ms)
{assert(task==ZDAppTaskID&&event==B1_RETAINED_STARTUP_EXPIRE_EVENT&&ms==1000u);
 ++timer_starts;return timer_fail?ZFailure:SUCCESS;}
static uint8_t OsalPortTimers_stopTimer(uint8_t task,uint32_t event)
{assert(task==ZDAppTaskID&&event==B1_RETAINED_STARTUP_EXPIRE_EVENT);
 ++timer_stops;return SUCCESS;}
static uint8_t OsalPort_setEvent(uint8_t task,uint32_t event)
{assert(task==ZDAppTaskID&&event==B1_RETAINED_STARTUP_EVENT);
 ++queued_events;return SUCCESS;}
static void b1_security_runtime_hold_latch(void)
{++security_latches;held=1;}
static void MT_BuildAndSendZToolResponse(uint8_t type,uint8_t cmd,uint8_t count,void *data)
{assert(type==(MT_RPC_CMD_SRSP|MT_RPC_SYS_ZDO)&&cmd==0x40&&count==1);
 ++response_calls;response=*(uint8_t *)data;}
'''

MAIN = r'''
static void reset_case(void)
{held=0;candidate=1;security_valid=1;coordinator=1;read_fault=-1;bdb_latch=0;timer_fail=0;ready=0;
 lengths[0]=116;for(unsigned i=1;i<4;i++)lengths[i]=1;
 values[1]=0;values[2]=TRUE;values[3]=0;
 startup_state=B1_STARTUP_IDLE;bdb_calls=response_calls=reads=queued_events=0;
 security_latches=timer_starts=timer_stops=failures=phase_calls=0;response=0xff;
 observer_priority_raises=observer_priority_restores=0;task_priority=5;
 now_ticks=1u;b1_startup_admitted_tick=0u;}
static void invoke(int success)
{uint8_t request[]={2,MT_RPC_CMD_SREQ|MT_RPC_SYS_ZDO,0x40,0,0};
 unsigned before=response_calls;MT_ZdoStartupFromApp(request);
 assert(response_calls==before+1&&response==(success?ZSuccess:ZFailure));}
static void wire_eot(void)
{assert(startup_state==B1_STARTUP_WAIT_SRSP_TX);
 startup_state=B1_STARTUP_QUEUED;b1_startup_post_run();}
int main(void)
{
 reset_case();invoke(1);assert(reads==3&&timer_starts==1&&queued_events==0&&bdb_calls==0);
 assert(observer_priority_raises==1&&observer_priority_restores==0&&task_priority==3);
 invoke(0);assert(bdb_calls==0&&queued_events==0);
 b1_mt_zdo_retained_startup_event();assert(bdb_calls==0);
 wire_eot();assert(queued_events==1&&bdb_calls==0);
 b1_mt_zdo_retained_startup_event();assert(bdb_calls==1&&security_latches==0&&timer_stops==1&&phase_calls==2);
 b1_mt_zdo_retained_startup_event();assert(bdb_calls==1);
 /* Directly exercise the extracted real checkpoint in ARMED-style running
  * state. No trace UART operation or semaphore is allowed, and each phase
  * updates only RAM. The MT response stub aborts on any unplanned frame. */
 reset_case();startup_state=B1_STARTUP_RUNNING;assert(b1_startup_checkpoint(B1_PHASE_BDB));
 assert(phase_calls==1&&response_calls==0&&bdb_calls==0);
 held=1;assert(!b1_startup_checkpoint(B1_PHASE_BDB));
 assert(phase_calls==2&&response_calls==0);
 reset_case();timer_fail=1;invoke(0);assert(failures==1&&startup_state==B1_STARTUP_FAILED);
 assert(observer_priority_raises==0&&observer_priority_restores==0);
 reset_case();held=1;invoke(0);assert(reads==0);
 reset_case();candidate=0;invoke(0);assert(reads==0);
 reset_case();security_valid=0;invoke(0);assert(reads==0);
 reset_case();coordinator=0;invoke(0);assert(reads==0);
 for(unsigned n=0;n<3;n++){const uint16_t v[]={0,115,117};
  reset_case();lengths[0]=v[n];invoke(0);assert(reads==0);}
 for(unsigned id=1;id<4;id++){
  reset_case();lengths[id]=0;invoke(0);assert(reads==0);
  reset_case();lengths[id]=2;invoke(0);assert(reads==0);
  reset_case();read_fault=(int)id;invoke(0);}
 reset_case();values[1]=3;invoke(0);
 reset_case();values[2]=0;invoke(0);
 reset_case();values[2]=2;invoke(0);
 reset_case();values[3]=1;invoke(0);
 reset_case();bdb_latch=1;invoke(1);wire_eot();
 b1_mt_zdo_retained_startup_event();assert(held&&security_latches==1&&bdb_calls==1);
 reset_case();invoke(1);now_ticks+=1001u;wire_eot();
 assert(failures==1&&held&&bdb_calls==0&&queued_events==0);
 puts("PINNED_TI_RETAINED_MT_ZDO_STARTUP_EOT_PASS no_BDB_before_EOT=1 one_attempt=1 timeout=1");
 return 0;
}
'''

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    source=args.source.read_text()
    signatures=(
        "static uint32_t b1_startup_timeout_ticks(void)",
        "void b1_stack_startup_observer_priority(uint8_t admitted)",
        "void b1_startup_post_run(void)",
        "int b1_startup_checkpoint(uint8_t phase)",
        "static __attribute__((noinline)) uint8_t b1_mt_zdo_retained_valid(void)",
        "__attribute__((noinline)) uint8_t "+HELPER_NAME+"(uint8_t subsystem, uint8_t command)",
        "void b1_mt_zdo_retained_startup_event(void)",
        STARTUP_SIGNATURE.removesuffix("\n{"),
    )
    bodies="\n\n".join(extract_function(source,s) for s in signatures)
    if ("Semaphore_pend" in bodies or "Semaphore_construct" in bodies or
            "B1_STARTUP_TRACE_COMMAND" in bodies or
            bodies.count("b1_startup_checkpoint(uint8_t phase)")!=1):
        raise ValueError("Blocking diagnostic trace regressed into actual startup")
    if bodies.count("retValue = "+HELPER_NAME+"(0x65u, 0x40u);")!=1:
        raise ValueError("Actual MT ZDO startup does not call the qualified retained helper")
    args.output.write_text(PREAMBLE+bodies+MAIN)
    print("PINNED_TI_RETAINED_MT_ZDO_STARTUP_EOT_EXTRACTED")

if __name__=="__main__":
    main()
