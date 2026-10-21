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
  check_bdb_restore_hold();
  puts("B1_ACTUAL_STACK_TASK_PRE_MAC_SECURITY_GATE_PASS"); return 0;
}
'''.replace('FALSE_PLACEHOLDER','0')


# Compile the real BDB consumer and its real noinline failure helper. ZDO is
# the deliberate boundary here; full ZDO bodies are compiled by native CI.
# This proves that a distinct restore error or a late HOLD cannot take TI's
# on-network-clearing fallback, rather than mocking the guard itself.
BDB_PREAMBLE = r'''
#define BDB_COMMISSIONING_MODE_INITIATOR_TL 1u
#define BDB_COMMISSIONING_MODE_NWK_STEERING 2u
#define BDB_COMMISSIONING_MODE_FINDING_BINDING 8u
#define BDB_COMMISSIONING_MODE_INITIALIZATION 16u
#define BDB_COMMISSIONING_MODE_PARENT_LOST 32u
#define BDB_COMMISSIONING_MODES 15u
#define BDB_FINDING_BINDING_CAPABILITY_ENABLED 0
#define BDB_CHANGE_COMMISSIONING_STATE 1u
#define BDB_COMMISSIONING_STATE_STEERING_ON_NWK 2u
#define BDB_COMMISSIONING_STATE_START_RESUME 3u
#define BDB_TC_LINK_KEY_EXCHANGE_NOT_ACTIVE 0u
#define BDB_INITIALIZATION 4u
#define ZDO_INITDEV_RESTORED_NETWORK_STATE 0u
#define ZDO_INITDEV_NEW_NETWORK_STATE 1u
#define ZCD_NV_BDBNODEISONANETWORK 0xF5u
static struct {uint8_t bdbCommissioningMode,bdbNodeIsOnANetwork;} bdbAttributes;
static struct {uint8_t bdbTCExchangeState,bdbCommissioningState;} bdbCommissioningProcedureState;
static uint8_t bdb_initialization,bdb_TaskID;
static uint8_t restore_result,late_restore_hold;
static unsigned restore_calls,on_network_clears,commissioning_failures;
static void b1_security_runtime_hold_latch(void){held=1u;}
static uint32_t OsalPortTimers_getTimerTimeout(uint8_t id,uint16_t ev)
{(void)id;(void)ev;return 0u;}
static void OsalPort_setEvent(uint8_t id,uint16_t ev){(void)id;(void)ev;}
static void bdb_nwkSteeringDeviceOnNwk(void){}
static void bdb_reportCommissioningState(uint8_t state,uint8_t okay)
{(void)state;if(!okay)++commissioning_failures;}
static void bdb_setNodeIsOnANetwork(uint8_t value)
{if(!value)++on_network_clears;bdbAttributes.bdbNodeIsOnANetwork=value;}
static uint8_t osal_nv_read(uint16_t id,uint16_t off,uint16_t len,void *out)
{assert(id==ZCD_NV_BDBNODEISONANETWORK && off==0u && len==1u);*(uint8_t *)out=TRUE;return ZSUCCESS;}
static uint8_t ZDOInitDevice(uint16_t delay)
{assert(delay==0u);++restore_calls;if(late_restore_hold)held=1u;return restore_result;}
'''

BDB_CASES = r'''
static void check_bdb_restore_hold(void)
{
  unsigned scenario;
  for(scenario=0u;scenario<5u;++scenario)
  {
    held=(scenario==4u);bdb_initialization=0u;
    bdbAttributes.bdbCommissioningMode=0u;
    bdbAttributes.bdbNodeIsOnANetwork=TRUE;
    bdbCommissioningProcedureState.bdbTCExchangeState=0u;
    restore_calls=on_network_clears=commissioning_failures=0u;
    restore_result=scenario==1u?ZDO_INITDEV_NEW_NETWORK_STATE:
                   scenario==2u?0xFFu:ZDO_INITDEV_RESTORED_NETWORK_STATE;
    late_restore_hold=(scenario==3u);
    bdb_StartCommissioning(0u);
    if(scenario==1u)
    {
      /* Preserve TI's genuine, non-HOLD NEW-state behavior. */
      assert(!held && on_network_clears==1u && commissioning_failures==1u);
    }
    else
    {
      assert(bdbAttributes.bdbNodeIsOnANetwork==TRUE);
      assert(on_network_clears==0u && commissioning_failures==0u);
      assert(restore_calls==(scenario==4u?0u:1u));
      assert(held==(scenario>=2u));
    }
  }
  puts("B1_ACTUAL_BDB_RESTORE_HOLD_PRESERVES_ON_NETWORK_PASS");
}
'''


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
    zdapp_source=(a.source.parent.parent/'stack/zdo/zd_app.c').read_text(encoding='utf-8')
    zdo=extract_function(zdapp_source,'uint8_t ZDOInitDeviceEx( uint16_t startDelay, uint8_t mode)')
    restore=extract_function(zdapp_source,'uint8_t ZDApp_RestoreNetworkState( void )')
    secinit=extract_function(zdapp_source,'void ZDApp_SecInit( uint8_t state )')
    if ('B1_ZDO_RESTORE_HOLD_PROPAGATION' not in zdo or
        zdo.index('ZDApp_SecInit( networkStateNV );') > zdo.index('devState = DEV_INIT') or
        'ZDApp_SecInit( networkStateNV );\n  if (b1_nv_runtime_hold_active()) return 0xFFu;' not in zdo or
        'if (!b1_nwk_restored && b1_sec_restored_network_validated())' not in restore or
        '(!ZDApp_RestoreNwkKey(TRUE) || b1_nv_runtime_hold_active())' not in restore or
        'ZDSecMgrInit(state);\n  if (b1_nv_runtime_hold_active()) return;' not in secinit):
        raise RuntimeError('B1_ZDO_RESTORE_FAILURE_PROPAGATION_MISSING')
    for sig in ('void ZDApp_NetworkInit( uint16_t delay )',
                'void ZDApp_NetworkStartEvt( void )',
                'void ZDApp_ChangeState( devStates_t state )'):
        if sig+'\n{\n  if (b1_nv_runtime_hold_active()) return;' not in extract_function(zdapp_source,sig):
            raise RuntimeError('B1_ZDO_HELD_NETWORK_BOUNDARY_MISSING')
    bdb_source=(a.source.parent.parent/'stack/bdb/bdb.c').read_text(encoding='utf-8')
    helper=extract_function(bdb_source,'static uint8_t b1_bdb_restore_failed(uint8_t status)')
    commissioning=extract_function(bdb_source,'void bdb_StartCommissioning(uint8_t mode)')
    if ('if (b1_bdb_restore_failed(b1_restore_result)) return;' not in commissioning or
        commissioning.index('if (b1_bdb_restore_failed(b1_restore_result)) return;') >
        commissioning.index('      bdb_setNodeIsOnANetwork(FALSE);')):
        raise RuntimeError('B1_BDB_RESTORE_HOLD_CONSUMER_MISSING')
    a.output.write_text(PREAMBLE+BDB_PREAMBLE+globals_body+body+helper+commissioning+BDB_CASES+MAIN,encoding='utf-8')
    print('B1_ACTUAL_STACK_TASK_SECURITY_ORDER_EXTRACTED')


if __name__=='__main__':
    main()
