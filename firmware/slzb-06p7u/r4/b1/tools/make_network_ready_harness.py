"""N30: compile the actual patched TI ZDApp_ChangeState C body.

B1 reports restored NETWORK_READY only after the ZDO coordinator transition,
NWK frame-counter readback/persist and cached security validation. SYS_PING,
MT availability, factory blank, or an untrusted state change never suffice.
The RTOS/event/flash boundary is synthetic: not hardware network acceptance.
"""
from pathlib import Path
import argparse
from patch_zdapp import extract_function

PREAMBLE = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "b1_management.h"
#define DEV_INIT 0u
#define DEV_ZB_COORD 9u
#define TRUE 1u
#define FALSE 0u
#define ZSUCCESS 0u
#define NV_ITEM_UNINIT 9u
#define ZDO_STATE_CHANGE_EVT 0x0100u
typedef uint8_t devStates_t;
static devStates_t devState=DEV_INIT;
static unsigned events;
static uint8_t FrameCounterUpdated, existing_candidate, valid_security;
static uint16_t marker_length=1u;
static uint8_t marker_value=0x55u, marker_init_fail, marker_bad_readback;
static unsigned marker_creates, marker_writes;
static unsigned irq_depth;
uintptr_t b1_management_test_disable(void)
{ assert(irq_depth==0);irq_depth=1;return 0xABu; }
void b1_management_test_restore(uintptr_t key)
{ assert(key==0xABu && irq_depth==1);irq_depth=0; }
static void OsalPort_setEvent(uint8_t task,uint16_t event)
{ assert(task==7u && event==ZDO_STATE_CHANGE_EVT);++events; }
#define ZDAppTaskID 7u
static int b1_nv_existing_header_candidate(void){return existing_candidate;}
static int b1_sec_restored_network_validated(void){return valid_security;}
static int b1_nv_runtime_hold_active(void){return b1_management_nv_security_hold_active();}
static uint16_t osal_nv_item_len(uint16_t item)
{assert(item==0x60u);return marker_length;}
static uint8_t osal_nv_item_init(uint16_t item,uint16_t len,void *value)
{
  assert(item==0x60u && len==1u && marker_length==0u);
  ++marker_creates;
  if(marker_init_fail)return 10u;
  marker_length=len;marker_value=*(uint8_t *)value;return NV_ITEM_UNINIT;
}
static uint8_t osal_nv_read(uint16_t item,uint16_t off,uint16_t len,void *value)
{
  assert(item==0x60u && off==0u && len==1u && marker_length==1u);
  *(uint8_t *)value=marker_bad_readback?0u:marker_value;return ZSUCCESS;
}
static uint8_t osal_nv_write(uint16_t item,uint16_t len,void *value)
{
  assert(item==0x60u && len==1u && marker_length==1u);
  ++marker_writes;
  if(marker_init_fail)return 10u;
  marker_value=*(uint8_t *)value;return ZSUCCESS;
}
'''

MAIN=r'''
static void check_status(int ready)
{
  uint8_t frame[11]={8u,0x21u,0xF1u,'B','1','Q','1',1u,8u,0u,0u};
  uint8_t reply[B1_STATUS_REPLY_SIZE]={0}, err=0xFFu;
  assert(b1_management_mt_filter(frame,reply,&err)==B1_MT_STATUS);
  assert(memcmp(reply,"B1S1",4u)==0);
  assert((reply[9]&8u)==(ready?8u:0u));
  assert(reply[6]==(ready?B1_STAGE_NETWORK_READY:reply[6]));
  assert(b1_management_network_ready()==ready);
  assert(irq_depth==0);
}
int main(int argc,char **argv)
{
  assert(argc==2);const char *s=argv[1];
  existing_candidate=1u;valid_security=1u;FrameCounterUpdated=1u;
  b1_management_note_nv_candidate();
  if(strcmp(s,"no_mt")!=0) b1_management_note_mt_registered();
  if(strncmp(s,"marker_",7)==0) {
    if(strcmp(s,"marker_missing")==0 || strcmp(s,"marker_write_fail")==0 ||
       strcmp(s,"marker_readback")==0) marker_length=0u;
    if(strcmp(s,"marker_unconfigured")==0)marker_value=0u;
    if(strcmp(s,"marker_length")==0)marker_length=2u;
    if(strcmp(s,"marker_write_fail")==0)marker_init_fail=1u;
    if(strcmp(s,"marker_readback")==0)marker_bad_readback=1u;
    ZDApp_ChangeState(DEV_ZB_COORD);
    if(strcmp(s,"marker_missing")==0 || strcmp(s,"marker_existing")==0 ||
       strcmp(s,"marker_unconfigured")==0) {
      assert(devState==DEV_ZB_COORD && events==1u && marker_value==0x55u);
      assert(marker_creates==(strcmp(s,"marker_missing")==0?1u:0u));
      assert(marker_writes==(strcmp(s,"marker_unconfigured")==0?1u:0u));
      check_status(1);
      ZDApp_ChangeState(DEV_ZB_COORD);
      assert(events==1u); /* repeated notification never writes again */
    } else {
      assert(devState==DEV_INIT && events==0u && b1_nv_runtime_hold_active());
      if(strcmp(s,"marker_length")==0)assert(marker_length==2u && marker_creates==0u);
      check_status(0);
    }
    puts("B1_ORDINARY_HERDSMAN_MARKER_ONLY_AFTER_COORDINATOR_PASS");return 0;
  }
  if(strcmp(s,"no_nv")==0) {
    existing_candidate=0u;
  } else if(strcmp(s,"no_security")==0) {
    valid_security=0u;
  } else if(strcmp(s,"no_counter")==0) {
    FrameCounterUpdated=0u;
  } else if(strcmp(s,"no_mt")==0) {
    /* The positive coordinator transition alone cannot synthesize MT registration. */
  } else if(strcmp(s,"healthy") && strcmp(s,"after_nv_hold") &&
            strcmp(s,"after_security_hold") && strcmp(s,"after_transport_hold") &&
            strcmp(s,"loss_of_coordinator") && strcmp(s,"loss_then_regain") &&
            strcmp(s,"premature")) {
    return 2;
  }
  if(strcmp(s,"premature")==0) {
    ZDApp_ChangeState(DEV_INIT);
    check_status(0);assert(events==0);
    ZDApp_ChangeState(DEV_ZB_COORD);
    check_status(1);
  } else {
    ZDApp_ChangeState(DEV_ZB_COORD);
    check_status(strcmp(s,"healthy")==0 || strncmp(s,"after_",6)==0 ||
                 strcmp(s,"loss_of_coordinator")==0 || strcmp(s,"loss_then_regain")==0);
  }
  if(strcmp(s,"loss_of_coordinator")==0 || strcmp(s,"loss_then_regain")==0) {
    ZDApp_ChangeState(DEV_INIT);
    assert(devState==DEV_INIT && events==2);
    check_status(0);
    if(strcmp(s,"loss_then_regain")==0) {
      ZDApp_ChangeState(DEV_ZB_COORD);
      assert(devState==DEV_ZB_COORD && events==3);
      /* Native callback must not recycle an earlier restore/counter proof.
       * A new boot-time security attestation is required before READY. */
      check_status(0);
    }
  } else if(strcmp(s,"after_nv_hold")==0) {
    b1_management_hold_nv(B1_ERROR_NV_BACKEND);
    check_status(0);
    assert((b1_management_mt_registered() && !b1_management_network_ready()));
  } else if(strcmp(s,"after_security_hold")==0) {
    b1_security_runtime_hold_latch();
    check_status(0);
  } else if(strcmp(s,"after_transport_hold")==0) {
    b1_management_transport_failed(B1_ERROR_NPI_RX_OVERFLOW);
    check_status(0);
  }
  assert(irq_depth==0);
  printf("B1_N30_ACTUAL_ZDO_STATE_LIFECYCLE_PASS %s\n",s);
  return 0;
}
'''


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    source=a.source.read_text(encoding='utf-8')
    body=extract_function(source,"void ZDApp_ChangeState( devStates_t state )")
    if "b1_management_note_zdo_state" not in body:
        raise RuntimeError("B1_N30_UNLINKED_ZDO_READY_OBSERVATION")
    publisher=extract_function(source,"static uint8_t b1_znp_publish_configured(void)")
    authorizer=extract_function(source,"int b1_znp_configured_init_authorized(void)")
    a.output.write_text(PREAMBLE+'static uint8_t b1_configured_init_active;\n'+
                        authorizer+publisher+body+MAIN,encoding='utf-8')
    print("B1_N30_ACTUAL_ZDO_CHANGE_STATE_EXTRACTED")


if __name__=='__main__':
    main()
