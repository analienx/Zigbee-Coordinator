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
    a.output.write_text(PREAMBLE+body+MAIN,encoding='utf-8')
    print('B1_ACTUAL_STACK_TASK_SECURITY_ORDER_EXTRACTED')


if __name__=='__main__':
    main()
