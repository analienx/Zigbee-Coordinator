#!/usr/bin/env python3
"""Compile actual V47 NPI C functions and exercise priority/timeout mutants.

The B1 event is verified against the composed MT ZDO C. Scheduler and clock
are deterministic stubs: passing this is NOT a physical state9 qualification.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

from r4_srsp_service import TASK
from r4_startup_ingress_priority import ZDO, MARKER

PREFIX = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define NPITASK_PRIORITY 4
#define B1_STARTUP_RUNNING 3u
#define B4_V46_SRSP_PRIORITY 6
typedef struct { int priority; } Task_Struct;
typedef Task_Struct* Task_Handle;
static Task_Struct npiTaskStruct={4};
static unsigned int Task_numPriorities=8;
static uint32_t Clock_tickPeriod=250000u;
static uint32_t tick;
static unsigned cs_depth, scheduler_depth, priority_changes;
static uint8_t startup_state, transport_hold;
typedef struct { uint8_t count; } FakeQueue;
static FakeQueue queue_record;
static FakeQueue* B4_V44_SrspQueue=&queue_record;
static int Queue_empty(FakeQueue *q) {return q->count==0;}
static uint32_t Clock_getTicks(void){return tick;}
static uint8_t b1_startup_state(void){return startup_state;}
static uint8_t b1_management_transport_unavailable(void){return transport_hold;}
static uint32_t OsalPort_enterCS(void){++cs_depth;return cs_depth;}
static void OsalPort_leaveCS(uint32_t key){assert(key==cs_depth);--cs_depth;}
static unsigned int Task_disable(void){assert(!cs_depth);return scheduler_depth++;}
static void Task_restore(unsigned int key){assert(!cs_depth);assert(scheduler_depth==key+1);--scheduler_depth;}
static Task_Handle Task_handle(Task_Struct* p){return p;}
static int Task_getPri(Task_Handle p){return p->priority;}
static int Task_setPri(Task_Handle p,int n){
    assert(scheduler_depth && !cs_depth && p==&npiTaskStruct);
    assert(n>0 && (unsigned)n<Task_numPriorities);
    ++priority_changes; int old=p->priority;p->priority=n;return old;
}
"""

MAIN = r"""
int main(void){
    assert(npiTaskStruct.priority==4 && !priority_changes);
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    /* No startup boost before the real retained B1 event dispatch. */
    startup_state=1;B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==4);
    startup_state=2;B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==4);
    startup_state=3;B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==6);
    assert(!cs_depth && !scheduler_depth);
    tick+=359u;B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==6);
    /* READY is real B1 state, not an assumed post-SRSP condition. */
    startup_state=4;B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    startup_state=3;B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==6);
    tick+=361u;B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    /* Fatal transport HOLD never extends or arms startup priority. */
    transport_hold=1;B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==4);
    transport_hold=0;startup_state=5;B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==4);
    /* Bounded clock-wrap behavior still deboosts. */
    startup_state=3;tick=0xfffffff0u;B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==6);
    tick+=361u;B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    /* V46 existing SRSP service remains intact outside startup. */
    startup_state=0;queue_record.count=1;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==6);
    queue_record.count=0;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    /* Fail safe when RTOS cannot represent priority 6. */
    Task_numPriorities=6;startup_state=3;
    B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==4);
    Task_numPriorities=8;
    assert(!cs_depth && !scheduler_depth);
    printf("V47_ACTUAL_NPI_C_PRIORITY_WINDOW_PASS changes=%u\n",priority_changes);
    return 0;
}
"""

def function(source, signature):
    key=signature+"\n{"
    if source.count(key)!=1:
        raise ValueError("V47_AMBIGUOUS_FUNCTION_"+signature)
    at=source.index(key)
    begin=source.index("{",at)
    depth=0
    for i in range(begin,len(source)):
        if source[i]=="{":depth+=1
        elif source[i]=="}":
            depth-=1
            if depth==0:return source[at:i+1]
    raise ValueError("V47_UNBALANCED_SOURCE")

def exercise(sdk):
    sdk=Path(sdk)
    n=(sdk/TASK).read_text()
    z=(sdk/ZDO).read_text()
    a=n.index("/* "+MARKER)
    b=n.index("__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)\n{",a)
    prefix=n[a:b]
    if (prefix.count(MARKER)!=1 or "B4_V47_ArmStartupNpi" not in prefix or
        n.count("B4_V47_ArmStartupNpi")!=1):
        raise ValueError("V47_OWNER_SOURCE_DRIFT")
    real_function=function(n,"__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)")
    if (z.count("B4_V47_ArmStartupNpi();")!=1 or
        z.count("bdb_StartCommissioning(0); /* Initialize original network only, once per boot. */")!=1):
        raise ValueError("V47_EXACT_B1_DISPATCH_DRIFT")
    start=z.index("void b1_mt_zdo_retained_startup_event(void)")
    excerpt=z[start:start+1600]
    if not (excerpt.index("if (!b1_startup_begin()) return;") <
            excerpt.index("B4_V47_ArmStartupNpi();") <
            excerpt.index("bdb_StartCommissioning(0);")):
        raise ValueError("V47_NOT_IN_RETAINED_B1_EVENT")
    code=PREFIX+prefix+"\n"+real_function+"\n"+MAIN
    cc=shutil.which("cc") or shutil.which("gcc")
    if not cc:raise RuntimeError("V47_HOSTED_C_COMPILER_REQUIRED")
    def build_run(label,c,expected_success):
        with tempfile.TemporaryDirectory(prefix="p7u-v47-c-") as d:
            root=Path(d);source=root/"test.c";exe=root/"test"
            source.write_text(c)
            build=subprocess.run([cc,"-std=c11","-O0","-g","-Wall","-Wextra",
                "-Werror","-Wno-unused-variable","-Wno-unused-function",
                str(source),"-o",str(exe)],capture_output=True,text=True,timeout=30)
            if build.returncode:
                raise RuntimeError("V47_NATIVE_C_COMPILE_"+label+": "+build.stderr[-3500:])
            result=subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
            if (result.returncode==0)!=expected_success:
                raise RuntimeError("V47_NATIVE_C_MUTANT_"+label+": "+result.stdout[-300:]+result.stderr[-800:])
            return result.stdout.strip()
    positive=build_run("actual_v47_window",code,True)
    mutants={
      "no_startup_ingress_preemption":(
          "int priority = (urgent || startup) && Task_numPriorities",
          "int priority = urgent && Task_numPriorities"),
      "ignore_terminal_transport_hold":(
          "if (startup && (b1_startup_state() != B1_STARTUP_RUNNING ||\n        b1_management_transport_unavailable()))",
          "if (startup && (b1_startup_state() != B1_STARTUP_RUNNING ||\n        0))"),
      "unbounded_window":(
          "#define B4_V47_STARTUP_US 90000000u",
          "#define B4_V47_STARTUP_US 120000000u"),
    }
    for name,(old,new) in mutants.items():
        if code.count(old)!=1:raise ValueError("V47_MUTANT_ANCHOR_"+name)
        build_run(name,code.replace(old,new,1),False)
    return {
        "status":"PASS","schema":"p7u-v47-real-npi-c-model-v1",
        "modeled_only":True,"hardware_accepted":False,
        "changed_task_source_sha256":hashlib.sha256(n.encode()).hexdigest(),
        "changed_mt_zdo_sha256":hashlib.sha256(z.encode()).hexdigest(),
        "mutants_rejected":list(mutants),
        "result":positive,
    }
