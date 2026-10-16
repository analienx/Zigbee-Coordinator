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
#define ZDO_STATE_CHANGE_EVT 0x0100u
typedef uint8_t devStates_t;
static devStates_t devState=DEV_INIT;
static unsigned events;
static uint8_t FrameCounterUpdated, existing_candidate, valid_security;
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
            strcmp(s,"loss_of_coordinator") && strcmp(s,"premature")) {
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
                 strcmp(s,"loss_of_coordinator")==0);
  }
  if(strcmp(s,"loss_of_coordinator")==0) {
    ZDApp_ChangeState(DEV_INIT);
    assert(devState==DEV_INIT && events==2);
    check_status(0);
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
    a.output.write_text(PREAMBLE+body+MAIN,encoding='utf-8')
    print("B1_N30_ACTUAL_ZDO_CHANGE_STATE_EXTRACTED")


if __name__=='__main__':
    main()
