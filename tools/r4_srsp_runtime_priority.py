#!/usr/bin/env python3
"""Bound already-produced SRSP service against a runnable higher-priority stack.

Applied after V5. Keep TI's initialization priority and original UART owner.
This is a repair candidate for observed queue delays, not a silent-hang cure.
"""
import hashlib
from pathlib import Path
from r4_uart_tx_liveness import extract, once
from r4_srsp_service import TASK

MARKER = "B4_V46_PENDING_SRSP_TASK_PRIORITY"
HELPER = r'''
/* B4_V46_PENDING_SRSP_TASK_PRIORITY. TI initializes Stack(5) before NPI(4).
 * Keep that startup contract. Only an already-framed pending SRSP elevates
 * the SAME NPI owner to 6; ordinary traffic and physical HOLD retain 4.
 * A busy UART still pends normally. No second writer or frame preemption.
 *
 * Call only after producer CS/ownership cleanup, and before NPI's own pend.
 * Task_restore can re-enable interrupts: never call from an OSAL CS.
 * Scheduler locking makes the queue predicate and priority update atomic
 * with respect to task producers. UART ISRs do not enqueue MT SRSPs.
 */
#define B4_V46_SRSP_PRIORITY 6
__attribute__((noinline)) static void B4_V46_RefreshNpiPriority(void)
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
    original=path.read_text();s=original
    if MARKER in s or "B4_F2_V5_FLIGHT_RECORDER" not in s or "B4_V45_STATIC_SRSP_RESERVE" not in s:
        raise ValueError("V46_REQUIRES_EXACT_V5_RESERVED_SOURCE")
    if s.count("#define NPITASK_PRIORITY 4")!=1:
        raise ValueError("V46_INITIALIZATION_PRIORITY_DRIFT")
    anchor="/* Called from the original MT producer, never from a UART ISR. Preserve"
    s=once(s,anchor,HELPER+anchor,"V46_HELPER_BEFORE_PRODUCERS")
    signature="__attribute__((noinline)) uint8_t B4_V45_SendReservedSrsp(uint8_t cmdType,"
    start=s.index(signature);end=s.index("/* Preserve FIFO across reserve exhaustion",start)
    producer=s[start:end]
    updated=once(producer,"    B4_V45_Tick(&B4_V45_ReserveUsed);\n    return 1u;",
        "    B4_V45_Tick(&B4_V45_ReserveUsed);\n    B4_V46_RefreshNpiPriority();\n    return 1u;","V46_RESERVED_PRODUCER")
    s=once(s,producer,updated,"V46_RESERVED_FUNCTION")
    signature="__attribute__((noinline)) uint8_t B4_V45_QueueDynamicSrsp(uint8_t *pMsg)"
    old=extract(s,signature)
    new=once(old,"    NPITask_processStackMsg(pMsg);\n    return 1u;",
        "    NPITask_processStackMsg(pMsg);\n    B4_V46_RefreshNpiPriority();\n    return 1u;","V46_DYNAMIC_PRODUCER")
    s=once(s,old,new,"V46_DYNAMIC_FUNCTION")
    old=extract(s,"static void B4_V44_Pend(void)")
    new=once(old,"{\n    uint32_t key = OsalPort_enterCS();",
        "{\n    B4_V46_RefreshNpiPriority();\n    uint32_t key = OsalPort_enterCS();","V46_OWNER_RESTORE_BEFORE_PEND")
    s=once(s,old,new,"V46_PEND_FUNCTION")
    path.write_text(s,encoding="utf-8",newline="")
    return {"schema":"p7u-srsp-runtime-task-priority-v1","initial_npi_priority":4,
        "pending_srsp_priority":6,"minimum_native_task_priorities":8,
        "same_npi_uart_owner":True,"priority_api_inside_osal_cs":False,
        "ordinary_priority_restored_at_owner_pend":True,"physical_hardware_validated":False,
        "before_sha256":{TASK:hashlib.sha256(original.encode()).hexdigest()},
        "modified_sha256":{TASK:hashlib.sha256(s.encode()).hexdigest()}}
