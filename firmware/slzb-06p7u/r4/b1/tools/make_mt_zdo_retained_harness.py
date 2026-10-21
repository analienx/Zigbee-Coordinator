"""Extract the actual patched TI ZDO startup entry and retained guard for hosted C."""
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
#define B1_RETAINED_STARTUP_DELAY_MS 30u
enum {ZCD_NV_NIB, ZCD_NV_STARTUP_OPTION,
      ZCD_NV_BDBNODEISONANETWORK, ZCD_NV_LOGICAL_TYPE};
static int held, candidate, security_valid, coordinator, read_fault, bdb_latch;
static uint8_t ZDAppTaskID=7;
uint8_t b1_retained_startup_state;
static uint16_t lengths[4];
static uint8_t values[4], response;
static unsigned bdb_calls, response_calls, reads, queued_events, security_latches;
static int timer_fail;
static int b1_nv_runtime_hold_active(void) {return held;}
static int b1_nv_existing_header_candidate(void) {return candidate;}
static int b1_sec_restored_network_validated(void) {return security_valid;}
static uint16_t osal_nv_item_len(uint16_t id)
{assert(id<4);return lengths[id];}
static uint8_t osal_nv_read(uint16_t id,uint16_t offset,uint16_t count,void *out)
{
 assert(id>0&&id<4&&offset==0&&count==1);
 ++reads;
 if(read_fault==(int)id) {
  return 10;
 }
 *(uint8_t*)out=values[id];
 return ZSUCCESS;
}
static void bdb_StartCommissioning(uint8_t mode)
{assert(mode==0);++bdb_calls;if(bdb_latch)held=1;}
static uint8_t OsalPortTimers_startTimer(uint8_t task,uint32_t event,uint32_t ms)
{assert(task==ZDAppTaskID&&event==0x00010000u&&ms==30u);
 if(timer_fail)return ZFailure;
 ++queued_events;return SUCCESS;}
static void b1_security_runtime_hold_latch(void)
{++security_latches;held=1;}
static void MT_BuildAndSendZToolResponse(uint8_t type,uint8_t cmd,uint8_t count,void *data)
{assert(type==(MT_RPC_CMD_SRSP|MT_RPC_SYS_ZDO)&&cmd==0x40&&count==1);
 ++response_calls;response=*(uint8_t*)data;}
'''


MAIN = r'''
static void reset_case(void)
{held=0;candidate=1;security_valid=1;coordinator=1;read_fault=-1;bdb_latch=0;
 lengths[0]=116;for(unsigned i=1;i<4;i++)lengths[i]=1;
 values[1]=0;values[2]=TRUE;values[3]=0;
 b1_retained_startup_state=0;bdb_calls=0;response_calls=0;reads=0;queued_events=0;
 security_latches=0;timer_fail=0;response=0xff;}
static void invoke_expected(int success,unsigned expected_events)
{uint8_t request[]={2,MT_RPC_CMD_SREQ|MT_RPC_SYS_ZDO,0x40,0,0};
 MT_ZdoStartupFromApp(request);
 assert(response_calls==1&&response==(success?ZSuccess:ZFailure));
 assert(queued_events==expected_events&&bdb_calls==0);}
static void invoke(int success) {invoke_expected(success,(unsigned)success);}
int main(void)
{
 reset_case();invoke(1);assert(reads==3);
 b1_mt_zdo_retained_startup_event();assert(bdb_calls==1&&security_latches==0);
 b1_mt_zdo_retained_startup_event();assert(bdb_calls==1); /* one run per boot */
 reset_case();timer_fail=1;invoke(0);assert(queued_events==0&&b1_retained_startup_state==0);
 reset_case();held=1;invoke(0);assert(reads==0);
 reset_case();candidate=0;invoke(0);assert(reads==0);
 reset_case();security_valid=0;invoke(0);assert(reads==0);
 reset_case();coordinator=0;invoke(0);assert(reads==0);
 for(unsigned n=0;n<3;n++) {
  const uint16_t bad_nib[]={0,115,117};
  reset_case();lengths[0]=bad_nib[n];invoke(0);assert(reads==0);
 }
 for(unsigned id=1;id<4;id++) {
  for(unsigned n=0;n<=2;n+=2) {
   reset_case();lengths[id]=(uint16_t)n;invoke(0);assert(reads==0);
  }
  reset_case();read_fault=(int)id;invoke(0);
 }
 reset_case();values[1]=3;invoke(0);
 reset_case();values[2]=0;invoke(0);
 reset_case();values[2]=2;invoke(0);
 reset_case();values[3]=1;invoke(0);
 reset_case();bdb_latch=1;invoke(1);assert(queued_events==1&&bdb_calls==0);
 b1_mt_zdo_retained_startup_event();assert(held&&security_latches==1&&bdb_calls==1);
 puts("PINNED_TI_RETAINED_MT_ZDO_STARTUP_ASYNC_PASS immediate_srsp=1 queued_events=1 bdb_mode=0 one_attempt=1");
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text()
    valid = extract_function(
        source, "static __attribute__((noinline)) uint8_t b1_mt_zdo_retained_valid(void)")
    helper = extract_function(
        source, "static __attribute__((noinline)) uint8_t " + HELPER_NAME + "(void)")
    event = extract_function(source, "void b1_mt_zdo_retained_startup_event(void)")
    startup = extract_function(source, STARTUP_SIGNATURE.removesuffix("\n{"))
    if startup.count("retValue = " + HELPER_NAME + "();") != 1:
        raise ValueError("Actual MT ZDO startup does not call the qualified retained helper")
    args.output.write_text(PREAMBLE + valid + "\n\n" + helper + "\n\n" + event + "\n\n" + startup + MAIN)
    print("PINNED_TI_RETAINED_MT_ZDO_STARTUP_EXTRACTED")


if __name__ == "__main__":
    main()
