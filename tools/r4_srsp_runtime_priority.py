#!/usr/bin/env python3
"""Bound already-produced SRSP service against a runnable higher-priority stack.

Applied after V5. Keep TI's initialization priority and original UART owner.
This is a repair candidate for observed queue delays, not a silent-hang cure.
"""
import hashlib
import argparse
import json
import re
from pathlib import Path
from r4_uart_tx_liveness import extract, once
from r4_srsp_service import TASK

MARKER = "B4_V46_PENDING_SRSP_TASK_PRIORITY"
CLIENT = "source/ti/zstack/npi/npi_client_mt.c"
HELPER = r'''
/* B4_V46_PENDING_SRSP_TASK_PRIORITY. TI initializes Stack(5) before NPI(4).
 * Keep that startup contract. Only an already-framed pending SRSP elevates
 * the SAME NPI owner to 6; ordinary traffic and physical HOLD retain 4.
 * A busy UART still pends normally. No second writer or frame preemption.
 *
 * Call only after producer CS/ownership/admission-counter cleanup, and
 * before NPI's own pend. A priority change may immediately preempt MT.
 * Task_restore can re-enable interrupts: never call from an OSAL CS.
 * Scheduler locking makes the queue predicate and priority update atomic
 * with respect to task producers. UART ISRs do not enqueue MT SRSPs.
 */
#define B4_V46_SRSP_PRIORITY 6
__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)
{
    unsigned int schedulerKey = Task_disable();
    uint32_t key = OsalPort_enterCS();
    uint8_t urgent = B4_V44_SrspQueue != NULL &&
                     !b1_management_transport_unavailable() &&
                     !Queue_empty(B4_V44_SrspQueue);
    OsalPort_leaveCS(key);
    /* Unsupported RTOS configurations preserve the original safe priority.
     * Native qualification must independently bind numPriorities >= 8. */
    int priority = urgent && Task_numPriorities > B4_V46_SRSP_PRIORITY ?
                   B4_V46_SRSP_PRIORITY : NPITASK_PRIORITY;
    Task_Handle task = Task_handle(&npiTaskStruct);
    if (Task_getPri(task) != priority)
        (void)Task_setPri(task, priority);
    Task_restore(schedulerKey);
}

'''


def apply(sdk):
    sdk=Path(sdk);path=sdk/TASK
    if path.is_symlink() or not path.is_file():
        raise ValueError("V46_UNTRUSTED_NPI_SOURCE")
    client_path=sdk/CLIENT
    if client_path.is_symlink() or not client_path.is_file():
        raise ValueError("V46_UNTRUSTED_MT_PRODUCER")
    original=path.read_text();s=original;client_original=client_path.read_text();c=client_original
    if MARKER in s or "B4_F2_V5_FLIGHT_RECORDER" not in s or "B4_V45_STATIC_SRSP_RESERVE" not in s:
        raise ValueError("V46_REQUIRES_EXACT_V5_RESERVED_SOURCE")
    if s.count("#define NPITASK_PRIORITY 4")!=1:
        raise ValueError("V46_INITIALIZATION_PRIORITY_DRIFT")
    anchor="/* Called from the original MT producer, never from a UART ISR. Preserve"
    s=once(s,anchor,HELPER+anchor,"V46_HELPER_BEFORE_PRODUCERS")
    declaration="extern uint8_t B4_V45_SendReservedSrsp(uint8_t, uint8_t, uint8_t, const uint8_t *);"
    c=once(c,declaration,"extern void B4_V46_RefreshNpiPriority(void);\n"+declaration,"V46_MT_DECLARATION")
    # Complete admission counters before the scheduler can preempt the MT
    # producer. Do not expose a physically submitted but uncounted enqueue.
    for indent,label in (("        ","RESERVED"),("            ","DYNAMIC")):
        old=indent+"B4_AfRspTick(&B4_AllRspEnqueued);\n"+indent+"return;"
        new=indent+"B4_AfRspTick(&B4_AllRspEnqueued);\n"+indent+"B4_V46_RefreshNpiPriority();\n"+indent+"return;"
        c=once(c,old,new,"V46_"+label+"_COMMITTED_ADMISSION")
    old=extract(s,"static void B4_V44_Pend(void)")
    new=once(old,"{\n    uint32_t key = OsalPort_enterCS();",
        "{\n    B4_V46_RefreshNpiPriority();\n    uint32_t key = OsalPort_enterCS();","V46_OWNER_RESTORE_BEFORE_PEND")
    s=once(s,old,new,"V46_PEND_FUNCTION")
    path.write_text(s,encoding="utf-8",newline="")
    client_path.write_text(c,encoding="utf-8",newline="")
    return {"schema":"p7u-srsp-runtime-task-priority-v1","initial_npi_priority":4,
        "pending_srsp_priority":6,"minimum_native_task_priorities":8,
        "same_npi_uart_owner":True,"priority_api_inside_osal_cs":False,
        "ordinary_priority_restored_at_owner_pend":True,"physical_hardware_validated":False,
        "before_sha256":{TASK:hashlib.sha256(original.encode()).hexdigest(),CLIENT:hashlib.sha256(client_original.encode()).hexdigest()},
        "modified_sha256":{TASK:hashlib.sha256(s.encode()).hexdigest(),CLIENT:hashlib.sha256(c.encode()).hexdigest()}}


def transform_syscfg(source):
    """Change the pinned live Task setting, not generated kernel C."""
    if MARKER in source or source.count('const Task = scripting.addModule("/ti/sysbios/knl/Task");')!=1:
        raise ValueError("V46_SYSCFG_TASK_MODULE_DRIFT")
    pattern=r"(?m)^([ \t]*)Task\.numPriorities[ \t]*=[ \t]*6;[ \t]*$"
    assignments=re.findall(r"(?m)^[ \t]*Task\.numPriorities[ \t]*=.*$",source)
    if len(assignments)!=1 or len(re.findall(pattern,source))!=1:
        raise ValueError("V46_SYSCFG_PRIORITY_PREIMAGE_DRIFT")
    return re.sub(pattern,lambda m:m.group(1)+"// "+MARKER+": preserve init4/stack5, allow transient6.\n"+
                  m.group(1)+"Task.numPriorities = 8;",source,count=1)


def configure_syscfg(syscfg, task_source, receipt):
    for path in (syscfg,task_source):
        if path.is_symlink() or not path.is_file() or not str(path.resolve()).startswith('/tmp/'):
            raise ValueError("V46_SYSCFG_REQUIRES_DISPOSABLE_NATIVE_INPUT")
    task=task_source.read_bytes()
    if MARKER.encode() not in task:raise ValueError("V46_SYSCFG_WITHOUT_PRIORITY_COMPONENT")
    if receipt.exists() or receipt.is_symlink():raise ValueError("V46_SYSCFG_RECEIPT_ALREADY_EXISTS")
    before=syscfg.read_bytes();after=transform_syscfg(before.decode().replace('\r\n','\n')).encode()
    result={"schema":"p7u-srsp-task-priority-syscfg-v1","task_priorities":8,
            "before_syscfg_sha256":hashlib.sha256(before).hexdigest(),
            "after_syscfg_sha256":hashlib.sha256(after).hexdigest(),
            "npi_source_sha256":hashlib.sha256(task).hexdigest(),"flash_authorized":False}
    syscfg.write_bytes(after);receipt.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--syscfg',type=Path,required=True)
    parser.add_argument('--task-source',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(configure_syscfg(args.syscfg,args.task_source,args.receipt)))
