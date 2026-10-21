"""Actual TI stack task body; stackInit is the deliberate MAC boundary.

Healthy execution stops on entering the boundary; this proves admission order,
not complete stack/NPI/RTOS behavior. NPI tests exercise its separate real body.
"""
import argparse
from pathlib import Path
from patch_zdapp import extract_function

PREAMBLE=r'''
#include <stdint.h>
#include <setjmp.h>
#include <assert.h>
#include <stdio.h>
typedef uintptr_t UArg;
#define NPI 1
#define ZNP_NPI 1
#define TRUE 1u
#define FALSE 0u
#define ZSUCCESS 0u
#define NV_ITEM_UNINIT 9u
#define ZG_BUILD_COORDINATOR_TYPE 1u
#define ZG_UNIQUE_LINK_KEY 0u
#define BIOS_WAIT_FOREVER UINT32_MAX
#define OSALPORT_CLEAN_UP_TIMERS_EVT 1u
static jmp_buf boundary;
static uint8_t valid; static unsigned checks,mac_calls,sem_calls;
static uint8_t stackServiceId,zstackTasksCnt=1;
static void *stackSemHandle,*npiInitializationMutexHandle;
static uint32_t task_events,*event_pointer=&task_events,**pTasksEvents=&event_pointer;
static uint32_t event_fn(uint8_t id,uint32_t ev) {(void)id;return ev;}
static uint32_t (*zstackTasksArr[])(uint8_t,uint32_t)={event_fn};
static int b1_sec_validate_restored(void) {++checks;return valid;}
static void stackInit(void) {++mac_calls;longjmp(boundary,1);}
static void OsalPortTimers_registerCleanupEvent(uint8_t id,uint16_t ev) {(void)id;(void)ev;}
static void Semaphore_pend(void *s,uint32_t timeout) {(void)s;(void)timeout;++sem_calls;}
static uint32_t OsalPort_enterCS(void) {return 0;}
static void OsalPort_leaveCS(uint32_t key) {(void)key;}
static uint8_t held, init_status, zgZdoDirectCB, retained_direct_cb;
static unsigned init_calls;
static uint8_t zgApsLinkKeyType, zgUseDefaultTCLK, other_global;
static struct {uint16_t id,len;void *buf;} zgItemTable[] = {
  {1u,1u,&zgZdoDirectCB},{2u,1u,&other_global},{0u,0u,NULL}};
static int b1_nv_runtime_hold_active(void) {return held;}
static void b1_nv_runtime_hold_latch(void) {held=1u;}
static uint8_t zgItemInit(uint16_t id,uint16_t len,void *buf,uint8_t setDefault)
{
  (void)len;(void)setDefault;++init_calls;
  if(id==1u) *(uint8_t *)buf=retained_direct_cb; /* simulated existing NV read */
  return init_status;
}
'''
MAIN=r'''
int main(void)
{
  valid=FALSE_PLACEHOLDER;
  if(setjmp(boundary)==0) stackTaskFxn(0,0);
  assert(checks==1 && mac_calls==0 && sem_calls==0);
  valid=1;
  if(setjmp(boundary)==0) stackTaskFxn(0,0);
  assert(checks==2 && mac_calls==1 && sem_calls==0);
  /* Actual patched zgInitItems: retained callback0 stays unchanged in NV,
   * while selected ZNP enables runtime callbacks only after complete init. */
  retained_direct_cb=0u; zgZdoDirectCB=0u; init_status=ZSUCCESS;
  zgInitItems(0u);
  assert(init_calls==2u && zgZdoDirectCB==TRUE && retained_direct_cb==0u && !held);
  zgZdoDirectCB=0u; init_calls=0u; init_status=NV_ITEM_UNINIT;
  zgInitItems(0u);
  assert(init_calls==2u && zgZdoDirectCB==TRUE && !held);
  zgZdoDirectCB=0u; init_calls=0u; init_status=1u;
  zgInitItems(0u);
  assert(init_calls==1u && held && zgZdoDirectCB==0u && retained_direct_cb==0u);
  init_calls=0u; init_status=ZSUCCESS;
  zgInitItems(0u);
  assert(init_calls==0u && held && zgZdoDirectCB==0u);
  puts("B1_ACTUAL_STACK_TASK_PRE_MAC_SECURITY_GATE_PASS"); return 0;
}
'''.replace('FALSE_PLACEHOLDER','0')


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    source=a.source.read_text(encoding='utf-8')
    body=extract_function(source,'static void stackTaskFxn(UArg a0, UArg a1)')
    globals_source=(a.source.parent.parent/'stack/sys/zglobals.c').read_text(encoding='utf-8')
    globals_body=extract_function(globals_source,'void zgInitItems( uint8_t setDefault )')
    if 'zgZdoDirectCB = TRUE;' not in globals_body or 'b1_item_status' not in globals_body:
        raise RuntimeError('B1_ZNP_RUNTIME_CALLBACK_SOURCE_GUARD_MISSING')
    a.output.write_text(PREAMBLE+globals_body+body+MAIN,encoding='utf-8')
    print('B1_ACTUAL_STACK_TASK_SECURITY_ORDER_EXTRACTED')


if __name__=='__main__':
    main()
