"""Compile actual patched TI stackTaskFxn with deterministic RTOS stubs.

Proves returned-bit wakeup and concurrent-post event preservation, and
exposes the no-repost mutant as a reproducible failure (no hardware).
"""
import argparse
from pathlib import Path
from patch_zdapp import extract_function

PREAMBLE = r'''
#include <assert.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdio.h>
typedef unsigned long UArg;
#define BIOS_WAIT_FOREVER (~0u)
#define NPI 1
#define OSALPORT_CLEAN_UP_TIMERS_EVT 1u
static jmp_buf verdict;
static unsigned credits, consumed, calls, concurrency;
static unsigned event0, event1, sem_token, mutex_token;
static void *stackSemHandle=&sem_token, *npiInitializationMutexHandle=&mutex_token;
static uint32_t *pTasksEvents[]={&event0,&event1};
static const uint8_t zstackTasksCnt=2;
static uint8_t stackServiceId=0;
static void stackInit(void) {}
static void OsalPortTimers_registerCleanupEvent(uint8_t s,uint32_t e)
{assert(s==0 && e==OSALPORT_CLEAN_UP_TIMERS_EVT);}
static uint32_t OsalPort_enterCS(void) {return 0u;}
static void OsalPort_leaveCS(uint32_t x) {(void)x;}
static void Semaphore_post(void *s)
{assert(s==stackSemHandle); ++credits;}
static void Semaphore_pend(void *s,uint32_t timeout)
{
 assert(timeout==BIOS_WAIT_FOREVER);
 if(s==npiInitializationMutexHandle)return;
 assert(s==stackSemHandle);
 if(consumed>=3u)longjmp(verdict,1);
 if(credits==0u)longjmp(verdict,2);
 --credits;++consumed;
}
static uint32_t handler0(uint8_t id,uint32_t events)
{
 assert(id==0u);
 ++calls;
 if(events & 1u) {
  assert(events==3u);
  if(concurrency) {event0 |= 4u;Semaphore_post(stackSemHandle);}
  return events & ~1u;
 }
 if(events & 2u) {return events & ~2u;}
 if(events & 4u) {return events & ~4u;}
 assert(0);return 0u;
}
static uint32_t handler1(uint8_t id,uint32_t events)
{assert(id==0u && !events);return 0u;}
typedef uint32_t (*Handler)(uint8_t,uint32_t);
static const Handler zstackTasksArr[]={handler0,handler1};
'''
MAIN=r'''
int main(int argc,char **argv)
{
 assert(argc==2);
 concurrency=argv[1][0]=='c';
 credits=1;event0=3u;event1=0u;consumed=calls=0u;
 int code=setjmp(verdict);
 if(code==0)stackTaskFxn(0,0);
 if(concurrency) {
  assert(code==1 && calls==3 && event0==0u);
 } else {
  assert(code==2 && calls==2 && event0==0u);
 }
 puts("ACTUAL_TI_DISPATCH_RETURNED_BITS_REDELIVERY_PASS");
 return 0;
}
'''

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--mutant",action="store_true")
    a=parser.parse_args()
    s=extract_function(a.source.read_text(),"static void stackTaskFxn(UArg a0, UArg a1)")
    marker="if (events != 0u) Semaphore_post(stackSemHandle);"
    if s.count(marker)!=1:
        raise RuntimeError("DISPATCHER_SEMAPHORE_REPOST_NOT_PRESENT")
    if a.mutant:s=s.replace(marker,"/* deliberately removed mutant wakeup */")
    if "*(pTasksEvents[idx]) |= events;" not in s:
        raise RuntimeError("PINNED_EVENT_OWNERSHIP_MISSING")
    a.output.write_text(PREAMBLE+s+"\n"+MAIN)
    print("ACTUAL_TI_DISPATCH_EXTRACTED_REPOST_MUTANT" if a.mutant else "ACTUAL_TI_DISPATCH_EXTRACTED")

if __name__=="__main__":
    main()
