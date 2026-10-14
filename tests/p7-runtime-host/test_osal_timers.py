#!/usr/bin/env python3
"""Actual TI OSAL timer functions, structures and clock-boundary regressions."""
import argparse,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import osal_overlay as overlay
FIXTURE=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define OsalPort_SUCCESS 0
#define OsalPort_NO_TIMER_AVAIL 1
#define OsalPort_INVALIDPARAMETER 2
typedef void (*ClockP_Fxn)(uintptr_t);
typedef void (*OsalPort_TimerCback)(void *);
typedef void *OsalPort_TimerID;
typedef struct {uint32_t period,timeout;bool active;uintptr_t arg;ClockP_Fxn callback;} MockClock;
typedef MockClock *ClockP_Handle;
typedef struct {uint32_t period;bool startFlag;uintptr_t arg;} ClockP_Params;
static unsigned live,fail_clock,fail_alloc,callback_a,callback_b;
static uint32_t tick_period=10;
static void *last_argument;
static void *OsalPort_malloc(size_t n) {if(fail_alloc)return NULL;live++;return calloc(1,n);}
static void OsalPort_free(void *p) {assert(p && live);live--;free(p);}
static uintptr_t OsalPort_enterCS(void) {return 0;}
static void OsalPort_leaveCS(uintptr_t key) {(void)key;}
static uint32_t ClockP_getSystemTickPeriod(void) {return tick_period;}
static void ClockP_Params_init(ClockP_Params *p) {memset(p,0,sizeof(*p));}
static ClockP_Handle ClockP_create(ClockP_Fxn callback,uint32_t timeout,ClockP_Params *p) {
  if(fail_clock)return NULL;MockClock *c=calloc(1,sizeof(*c));assert(c);
  c->callback=callback;c->period=p->period;c->timeout=timeout;c->active=p->startFlag;c->arg=p->arg;return c;
}
static void ClockP_stop(ClockP_Handle c) {assert(c);c->active=false;}
static void ClockP_start(ClockP_Handle c) {assert(c);c->active=true;}
static void ClockP_setTimeout(ClockP_Handle c,uint32_t ticks) {assert(c);c->timeout=ticks;}
static void ClockP_setPeriod(ClockP_Handle c,uint32_t ticks) {assert(c);c->period=ticks;}
static uint32_t ClockP_getTimeout(ClockP_Handle c) {assert(c);return c->timeout;}
static bool ClockP_isActive(ClockP_Handle c) {assert(c);return c->active;}
static void ClockP_delete(ClockP_Handle c) {assert(c);free(c);}
static void timerCb(uintptr_t arg) {(void)arg;}
static void first(void *arg) {callback_a++;last_argument=arg;}
static void second(void *arg) {callback_b++;last_argument=arg;}
'''
TEST=r'''
int main(int argc,char **argv) {
  assert(argc==2);const char *mode=argv[1];
  if(!strncmp(mode,"schedule-",9)) {
    OsalPort_TimerID handle=NULL;
    if(!strcmp(mode,"schedule-alloc"))fail_alloc=1;
    if(!strcmp(mode,"schedule-clock"))fail_clock=1;
    uint8_t status=OsalPort_setTimer(10,first,(void*)1,&handle);
    if(fail_clock || fail_alloc) {assert(status==OsalPort_NO_TIMER_AVAIL && !handle && !live);}
    else {
      assert(status==OsalPort_SUCCESS);
      if(!strcmp(mode,"schedule-update")) {
        assert(OsalPort_setTimer(20,second,(void*)2,&handle)==OsalPort_SUCCESS);
        OsalPort_clockFunc((uintptr_t)handle);assert(callback_a==0 && callback_b==1 && last_argument==(void*)2);
      } else if(!strcmp(mode,"schedule-stop")) {
        OsalPort_stopTimer(&handle);assert(!((OsalPort_ScheduleEntry*)handle)->clock->active);
      } else OsalPort_clockFunc((uintptr_t)handle);
      assert(OsalPort_deleteTimer(&handle)==OsalPort_SUCCESS && !handle && !live);
    }
  } else {
    if(!strcmp(mode,"timer-coarse"))tick_period=2000;
    if(!strcmp(mode,"timer-clock"))fail_clock=1;
    if(!strcmp(mode,"timer-alloc"))fail_alloc=1;
    uint8_t status=createTimerEntry(1,2,!strcmp(mode,"timer-wrap")?UINT32_MAX:100,false);
    if(!strcmp(mode,"timer-wrap"))assert(status==OsalPort_INVALIDPARAMETER && !pTimerEntries && !live);
    else if(fail_clock || fail_alloc)assert(status==OsalPort_NO_TIMER_AVAIL && !pTimerEntries && !live);
    else {
      assert(status==OsalPort_SUCCESS && pTimerEntries);
      if(!strcmp(mode,"timer-restart"))assert(createTimerEntry(1,2,200,false)==OsalPort_SUCCESS);
      if(!strcmp(mode,"timer-reload")) {
        assert(createTimerEntry(1,2,200,true)==OsalPort_SUCCESS);
        assert(pTimerEntries->reload && pTimerEntries->clockHandle->period==20000);
        assert(createTimerEntry(1,2,300,false)==OsalPort_SUCCESS);
        assert(!pTimerEntries->reload && pTimerEntries->clockHandle->period==0);
      }
      if(!strcmp(mode,"timer-coarse"))assert(pTimerEntries->clockHandle->timeout==50 && OsalPortTimers_getTimerTimeout(1,2)==100);
      ClockP_delete(pTimerEntries->clockHandle);OsalPort_free(pTimerEntries);assert(!live);
    }
  }
  puts("OSAL_TIMER_LIFETIME_RESTART_AND_CALLBACK_PASS");return 0;
}
'''
def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={path:(a.sdk/path).read_text() for path in (overlay.PORT,overlay.TIMERS)};patched=overlay.patch(original)
    timer_type=re.search(r"typedef struct\s*\{[^}]*\}\s*TimerEntry_t;",original[overlay.TIMERS]).group()
    schedule_type=re.search(r"typedef struct _osalPort_schedule_t\s*\{[^}]*\}\s*OsalPort_ScheduleEntry;",original[overlay.PORT]).group()
    controls=("schedule-success","schedule-alloc","timer-success","timer-alloc","timer-clock")
    for version,texts in (("pre",original),("post",patched)):
        body=FIXTURE+timer_type+schedule_type+"\nstatic TimerEntry_t *pTimerEntries;\n"
        body+=overlay.function(texts[overlay.TIMERS],"getTimerEntry")+overlay.function(texts[overlay.TIMERS],"createTimerEntry")
        body+=overlay.function(texts[overlay.TIMERS],"OsalPortTimers_getTimerTimeout")
        body+="\n".join(overlay.function(texts[overlay.PORT],name) for name in ("OsalPort_clockFunc","OsalPort_setTimer","OsalPort_stopTimer","OsalPort_deleteTimer"))+TEST
        cfile=a.out/(version+"-timers.c");binary=cfile.with_suffix("");cfile.write_text(body)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-unused-function","-Wno-misleading-indentation",
            "-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",str(cfile),"-o",str(binary)],check=True)
        for case in (*controls,"schedule-clock","schedule-update","schedule-stop","timer-restart","timer-reload","timer-coarse","timer-wrap"):
            run=subprocess.run([str(binary),case],capture_output=True,text=True,
                env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"},timeout=15)
            assert (run.returncode!=0)==(version=="pre" and case not in controls),(version,case,run.stdout,run.stderr)
            (a.out/(version+"-"+case+".log")).write_text(run.stdout+run.stderr)
    print("PINNED_OSAL_TIMER_12_CASES_PER_VERSION_WITH_PRE_FIX_FALSIFICATION_PASS")
if __name__=="__main__":main()
