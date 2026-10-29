#!/usr/bin/env python3
"""Actual final C queues/producers with an explicit competing-task scheduler model.

TI Task API stubs assert calls occur outside OSAL critical sections. This model
does not prove real RTOS timings; genuine native and hardware gates remain.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
from r4_srsp_reserve_harness import build_source, MAIN as RESERVE_MAIN
from r4_srsp_service import TASK

TASK_MODEL=r'''
#define NPITASK_PRIORITY 4
typedef struct {int priority;} Task_Struct;
typedef Task_Struct *Task_Handle;
static Task_Struct npiTaskStruct={4};
static unsigned int Task_numPriorities=8u;
static unsigned scheduler_depth,priority_changes;
static void assert_admission_committed(void);
void B4_V46_RefreshNpiPriority(void);
static Task_Handle Task_handle(Task_Struct*p){return p;}
static unsigned int Task_disable(void){assert(!cs_depth);return scheduler_depth++;}
static void Task_restore(unsigned int key){assert(!cs_depth && scheduler_depth==key+1);--scheduler_depth;}
static int Task_getPri(Task_Handle h){assert(h==&npiTaskStruct);return h->priority;}
static int Task_setPri(Task_Handle h,int p){
 assert(!cs_depth && scheduler_depth && h==&npiTaskStruct && p>0 && (unsigned)p<Task_numPriorities);
 if(p==6)assert_admission_committed();
 int old=h->priority;h->priority=p;++priority_changes;return old;
}
'''

MAIN=r'''
static void make_message(unsigned srsp,unsigned id,unsigned len){
 uint8_t data[250]={0};memcpy(data,&now_us,4);data[4]=id;data[5]=id>>8;
 MT_BuildAndSendZToolResponse(srsp?0x64u:0x44u,srsp?1u:0x81u,len,data);
}
static void complete(void){assert(busy);now_us=uart_due;virtual_complete_write();}
static void drain(void){tokens=0;if(!setjmp(done))NPITask_process();}
/* The pinned TI stack runs at 5. A runnable NPI at <=5 cannot preempt
 * this explicit 35-second stack slice. No queue preference can change that.
 * Hwi UART completion is independent of this task selection model. */
static void contended_submit(void){
 if(npiTaskStruct.priority<=5)now_us+=35000000u;
 NPITask_ProcessTXQ();assert(busy);complete();
}
int main(void){
 Queue_construct(&aq,NULL);Queue_construct(&rq,NULL);
 Queue_construct(&B4_V44_SrspQueueStruct,NULL);B4_V44_SrspQueue=Queue_handle(&B4_V44_SrspQueueStruct);
 flood_left=0;assert(npiTaskStruct.priority==4 && !priority_changes);
 /* Real reserved producer must allow the existing owner to preempt stack5. */
 make_message(1,1,20);assert(npiTaskStruct.priority==6 && !scheduler_depth && !cs_depth);
 contended_submit();assert(completed_srsp==1 && max_srsp_us<1000000u);
 B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
 /* Ordinary AREQ traffic alone never requests the critical priority. */
 make_message(0,1,20);while(mail_out<mail_in)NPITask_processStackMsg(OsalPort_msgReceive(1));
 B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
 NPITask_ProcessTXQ();complete();
 /* Fill reserve and explicitly exercise dynamic overflow's own hook. */
 for(unsigned i=2;i<=4;++i)make_message(1,i,20);
 assert(B4_NpiSrspDepth==3 && npiTaskStruct.priority==6);
 npiTaskStruct.priority=4; /* independent dynamic-path precondition */
 make_message(1,5,20);assert(npiTaskStruct.priority==6 && B4_NpiSrspDepth==4);
 assert(mail_out==mail_in);drain();
 assert(npiTaskStruct.priority==4 && completed_srsp==5 && !live_alloc);
 /* The owner restores base priority on its next pend after queue drain. */
 make_message(1,6,20);NPITask_ProcessTXQ();assert(busy && npiTaskStruct.priority==6);
 tokens=0;unsigned before=loops;drain();
 assert(loops-before<6 && npiTaskStruct.priority==4 && completed_srsp==6);
 /* Physical HOLD must suppress priority escalation as well as TX. */
 held=1;make_message(1,7,20);assert(npiTaskStruct.priority==4);
 tokens=0;before=loops;drain();assert(loops==before && npiTaskStruct.priority==4 && !busy);
 held=0;drain();assert(completed_srsp==7 && npiTaskStruct.priority==4);
 /* A config with no priority6 must never call an out-of-range Task API. */
 Task_numPriorities=6;make_message(1,8,20);assert(npiTaskStruct.priority==4);
 Task_numPriorities=8;B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==6);
 drain();assert(npiTaskStruct.priority==4 && completed_srsp==8);
 /* Essential AREQ fairness and all frame/slot ownership remain covered by
  * the same final TX loop, including callbacks while the UART is busy. */
 for(unsigned i=9;i<=20;++i)make_message(1,i,20);
 for(unsigned i=2;i<=6;++i)make_message(0,i,20);
 while(mail_out<mail_in)NPITask_processStackMsg(OsalPort_msgReceive(1));
 last_areq_at=srsp_sent;max_areq_gap=0;drain();
 assert(max_areq_gap<=4 && !busy && !live_alloc && !B4_NpiSrspDepth && !B4_NpiAsyncDepth);
 assert(!cs_depth && !scheduler_depth && !B4_V45_ReleaseFault && npiTaskStruct.priority==4);
 printf("V46_PRIORITY_PASS modeled_max_srsp_us=%u changes=%u areq_gap=%u\n",max_srsp_us,priority_changes,max_areq_gap);
 return 0;
}
'''


def exercise(sdk):
    sdk=Path(sdk)
    source=build_source(sdk,prefix_extra=TASK_MODEL,external_v5_hooks=True)
    anchor="extern uint8_t B4_V45_SendReservedSrsp"
    if source.count(anchor)!=1:raise ValueError("V46_COUNTER_FIXTURE_ANCHOR")
    source=source.replace(anchor,"static void assert_admission_committed(void){\n"
        " assert(B4_AllRspEnqueued>=B4_AllRspNpiReceived);\n"
        " assert(B4_AfDataRspEnqueued>=B4_AfDataRspNpiReceived);\n}\n"+anchor,1)
    if source.count(RESERVE_MAIN)!=1:raise ValueError("V46_FIXTURE_MAIN_DRIFT")
    source=source.replace(RESERVE_MAIN,MAIN,1)
    cc=shutil.which("cc") or shutil.which("gcc")
    if not cc:raise RuntimeError("V46_COMPILER_REQUIRED")
    def run(name,text,ok):
        with tempfile.TemporaryDirectory(prefix="v46-priority-") as td:
            p=Path(td);(p/"test.c").write_text(text)
            build=subprocess.run([cc,"-std=c11","-O1","-g","-Wall","-Wextra","-Wno-unused-function",
                "-fsanitize=address,undefined","-fno-omit-frame-pointer",str(p/"test.c"),"-o",str(p/"test")],
                capture_output=True,text=True,timeout=30)
            if build.returncode:raise RuntimeError("V46_COMPILE_"+name+"\n"+build.stderr[-6000:])
            result=subprocess.run([str(p/"test")],capture_output=True,text=True,timeout=30)
            if (result.returncode==0)!=ok:raise RuntimeError("V46_ASSERT_"+name+"\n"+result.stdout[-1500:]+result.stderr[-4500:])
            return result.stdout.strip()
    result=run("actual_final_queues_priority",source,True)
    mutants={
      "priority_not_above_stack":("#define B4_V46_SRSP_PRIORITY 6","#define B4_V46_SRSP_PRIORITY 5"),
      "never_restore_base_priority":("int priority = urgent && Task_numPriorities", "int priority = 1 && Task_numPriorities"),
      "reserved_boost_missing":("        B4_AfRspTick(&B4_AllRspEnqueued);\n        B4_V46_RefreshNpiPriority();", "        B4_AfRspTick(&B4_AllRspEnqueued);"),
      "dynamic_boost_missing":("            B4_AfRspTick(&B4_AllRspEnqueued);\n            B4_V46_RefreshNpiPriority();", "            B4_AfRspTick(&B4_AllRspEnqueued);"),
      "preempt_before_admission_counted":("        B4_AfRspTick(&B4_AllRspEnqueued);\n        B4_V46_RefreshNpiPriority();", "        B4_V46_RefreshNpiPriority();\n        B4_AfRspTick(&B4_AllRspEnqueued);"),
    }
    for name,(old,new) in mutants.items():
        if source.count(old)!=1:raise ValueError("V46_MUTANT_DRIFT_"+name)
        run(name,source.replace(old,new,1),False)
    return {"schema":"p7u-final-srsp-task-priority-actual-c-v1","status":"PASS",
      "actual_producer_and_queue_bodies":True,"task_scheduler":"EXPLICIT_SOFTWARE_MODEL_NOT_REAL_RTOS",
      "task_source_sha256":hashlib.sha256((sdk/TASK).read_bytes()).hexdigest(),
      "fixture_sha256":hashlib.sha256(source.encode()).hexdigest(),"negative_mutants":list(mutants),
      "result":result,"physical_hardware_validated":False}
