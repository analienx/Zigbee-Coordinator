#!/usr/bin/env python3
"""V52: free expired OSAL timers without waiting for the lowest Stack service.

Source facts at the pinned TI SDK 3615ad5d
(ti154stack/common/osal_port/osal_port_posix/osal_port_timers.c, linked by
the ZNP projectspec):
  * every one-shot timer start that finds no active (task, event) entry
    allocates a TimerEntry_t (OsalPort_malloc) plus a dynamic TI-RTOS Clock
    object (ClockP_create -> Clock_create, heap);
  * on expiry timerCb (Clock Swi context) unlinks the entry and APPENDS it
    to pDeleteTimerEntries by walking that whole list, then posts
    OSALPORT_CLEAN_UP_TIMERS_EVT to the Stack service registered last;
  * only ZStackTaskProcessEvent, the LAST of the 10 Stack services and so
    the first to starve under TI lowest-index-first selection, frees them.
A Stack whose lower services stay ready therefore leaks heap per expiry
and spends ever more Swi time (above every task, NPI included) per expiry.

This stage changes no timer timing, event or ordering semantics:
  1. timerCb prepends in O(1); the cleanup frees the whole list in any order;
  2. OsalPortTimers_cleanUpTimers gains an unlocked empty fast path, so the
     Stack task can call it after EVERY dispatch (zstackstartup.c, V52);
  3. RAM-only counters, read by the NPI owner as part of B1E6: starts,
     restarts, expiries, allocation failures, deferred-list depth/max,
     cleanups, frees, active timers, and for the NWK task per event bit the
     timer starts and minimum timeout (which NWK events are timer-driven).
"""
import hashlib
from pathlib import Path

from r4_uart_tx_liveness import once

TIMERS = "source/ti/ti154stack/common/osal_port/osal_port_posix/osal_port_timers.c"
PRISTINE_SHA256 = "c763b770e08fda02f6bb63210c9fc8689982d02f6c3a1546a74b1dbe9d759f26"
MARKER = "B4_V52_OSAL_TIMER_DEFERRED_FREE_AND_EVIDENCE"
TIMER_EVIDENCE_SIZE = 104

STATE_ANCHOR = "static TimerEntry_t* pDeleteTimerEntries = NULL;\n"

STATE = r"""
/* B4_V52_OSAL_TIMER_DEFERRED_FREE_AND_EVIDENCE: see the V52 stage receipt.
 * Counters are touched by tasks inside OsalPort CS (Hwi off) and by the
 * Clock Swi, which a task cannot preempt; Hwis never touch them. */
typedef struct
{
    uint32_t oneShot, reload, restart, expiry, createFail, cleanups, freed;
    uint16_t deferred, deferredMax, freedMax, active, activeMax;
    uint16_t probeStarts[16], probeMinMs[16];
    uint8_t probeTask, lastFailTask;
} B4_V52_Timers_t;
static B4_V52_Timers_t B4_V52_Timers = { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
                                          { 0u }, { 0u }, 0xFFu, 0xFFu };

static void B4_V52_Inc32(uint32_t *value)
{
    if (*value != 0xFFFFFFFFu) ++*value;
}

static void B4_V52_Inc16(uint16_t *value)
{
    if (*value != 0xFFFFu) ++*value;
}

/* Stack task, once, right after nwk_init(): per-bit evidence for NWK. */
void B4_V52_TimerProbe(uint8_t taskId)
{
    B4_V52_Timers.probeTask = taskId;
}

/* Inside createTimerEntry's CS. */
static void B4_V52_NoteStart(uint8_t taskId, uint32_t eventId, uint32_t timeout)
{
    uint8_t bit;
    if (taskId != B4_V52_Timers.probeTask) return;
    for (bit = 0u; bit < 16u; ++bit)
    {
        if ((eventId & (1uL << bit)) == 0u) continue;
        if (B4_V52_Timers.probeStarts[bit] == 0u || timeout < B4_V52_Timers.probeMinMs[bit])
            B4_V52_Timers.probeMinMs[bit] = timeout > 0xFFFFu ? 0xFFFFu : (uint16_t)timeout;
        B4_V52_Inc16(&B4_V52_Timers.probeStarts[bit]);
    }
}

static void B4_V52_NoteFail(uint8_t taskId)
{
    B4_V52_Inc32(&B4_V52_Timers.createFail);
    B4_V52_Timers.lastFailTask = taskId;
}

static void B4_V52_Put32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value; out[1] = (uint8_t)(value >> 8u);
    out[2] = (uint8_t)(value >> 16u); out[3] = (uint8_t)(value >> 24u);
}

static void B4_V52_Put16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)value; out[1] = (uint8_t)(value >> 8u);
}

/* NPI owner context: 104 bytes at B1E6 offset 96. One short CS copy. */
__attribute__((noinline)) void B4_V52_TimerSnapshot(uint8_t *out)
{
    static B4_V52_Timers_t s;
    uintptr_t key = OsalPort_enterCS();
    uint8_t j;
    s = B4_V52_Timers;
    OsalPort_leaveCS(key);
    B4_V52_Put32(out + 0u, s.oneShot);
    B4_V52_Put32(out + 4u, s.reload);
    B4_V52_Put32(out + 8u, s.restart);
    B4_V52_Put32(out + 12u, s.expiry);
    B4_V52_Put32(out + 16u, s.createFail);
    B4_V52_Put32(out + 20u, s.cleanups);
    B4_V52_Put32(out + 24u, s.freed);
    B4_V52_Put16(out + 28u, s.deferred);
    B4_V52_Put16(out + 30u, s.deferredMax);
    B4_V52_Put16(out + 32u, s.freedMax);
    B4_V52_Put16(out + 34u, s.active);
    B4_V52_Put16(out + 36u, s.activeMax);
    out[38] = s.probeTask;
    out[39] = s.lastFailTask;
    for (j = 0u; j < 16u; ++j)
    {
        B4_V52_Put16(out + 40u + 2u * j, s.probeStarts[j]);
        B4_V52_Put16(out + 72u + 2u * j, s.probeStarts[j] ? s.probeMinMs[j] : 0xFFFFu);
    }
}
"""

STOP_DELETE = ("        ClockP_stop(pTimerEntry->clockHandle);\n"
               "        ClockP_delete(pTimerEntry->clockHandle);\n")

CLEANUP_HEAD = ("void OsalPortTimers_cleanUpTimers(void)\n{\n"
                "  uintptr_t key = OsalPort_enterCS();\n")
CLEANUP_HEAD_NEW = ("void OsalPortTimers_cleanUpTimers(void)\n{\n"
                    "  /* B4_V52: unlocked empty fast path for the per-dispatch Stack call;\n"
                    "   * a concurrent Swi prepend is simply freed by the next call. */\n"
                    "  if (*(TimerEntry_t * volatile *)&pDeleteTimerEntries == NULL) return;\n"
                    "  uint16_t b4v52Freed = 0u;\n"
                    "  uintptr_t key = OsalPort_enterCS();\n")
CLEANUP_LOOP = ("        ClockP_delete(current->clockHandle);\n"
                "        OsalPort_free(current);\n"
                "        current = next;\n")
CLEANUP_LOOP_NEW = CLEANUP_LOOP + "        B4_V52_Inc16(&b4v52Freed);\n"
CLEANUP_TAIL = "    pDeleteTimerEntries = NULL;\n  }\n"
CLEANUP_TAIL_NEW = ("    pDeleteTimerEntries = NULL;\n"
                    "    B4_V52_Inc32(&B4_V52_Timers.cleanups);\n"
                    "    B4_V52_Timers.freed += b4v52Freed;\n"
                    "    if (b4v52Freed > B4_V52_Timers.freedMax) B4_V52_Timers.freedMax = b4v52Freed;\n"
                    "    B4_V52_Timers.deferred = 0u;\n"
                    "  }\n")

CB_EVENT = ("    /* Set event */\n"
            "    OsalPort_setEvent( pTimerEntry->taskId, pTimerEntry->eventId );\n")
CB_EVENT_NEW = CB_EVENT + "    B4_V52_Inc32(&B4_V52_Timers.expiry);\n"

CB_APPEND = """        // add the element in the removal list, to be freed
        // outside of SWI context
        TimerEntry_t *pDeleteTimerEntry = pDeleteTimerEntries;
        pTimerEntry->pNext = NULL; // remove node from linked list above
        if(pDeleteTimerEntry == NULL)
        {
            pDeleteTimerEntries = pTimerEntry;
        }
        else
        {
            while(pDeleteTimerEntry->pNext != NULL)
            {
                pDeleteTimerEntry = pDeleteTimerEntry->pNext;
            }
            pDeleteTimerEntry->pNext = pTimerEntry;
        }
"""
CB_PREPEND = """        // B4_V52: add the element to the removal list in O(1), to be freed
        // outside of SWI context (the cleanup frees the list in any order)
        pTimerEntry->pNext = pDeleteTimerEntries;
        pDeleteTimerEntries = pTimerEntry;
        B4_V52_Inc16(&B4_V52_Timers.deferred);
        if (B4_V52_Timers.deferred > B4_V52_Timers.deferredMax)
            B4_V52_Timers.deferredMax = B4_V52_Timers.deferred;
        if (B4_V52_Timers.active) --B4_V52_Timers.active;
"""

RESTART = ("        //reset the time out\n"
           "        ClockP_stop(pNewTimerEntry->clockHandle);\n"
           "        ClockP_setTimeout(pNewTimerEntry->clockHandle, timeoutTicks);\n"
           "        ClockP_start(pNewTimerEntry->clockHandle);\n")
RESTART_NEW = RESTART + ("        B4_V52_Inc32(&B4_V52_Timers.restart);\n"
                         "        B4_V52_NoteStart(taskId, eventId, timeout);\n")

ALLOC = "        pNewTimerEntry = OsalPort_malloc(sizeof(TimerEntry_t));\n"
ALLOC_NEW = ALLOC + "        if (pNewTimerEntry == NULL) B4_V52_NoteFail(taskId);\n"

CREATED = ("                ClockP_start(pNewTimerEntry->clockHandle);\n"
           "\n"
           "                status = OsalPort_SUCCESS;\n")
CREATED_NEW = CREATED + ("                B4_V52_Inc32(reload ? &B4_V52_Timers.reload : &B4_V52_Timers.oneShot);\n"
                         "                B4_V52_Inc16(&B4_V52_Timers.active);\n"
                         "                if (B4_V52_Timers.active > B4_V52_Timers.activeMax)\n"
                         "                    B4_V52_Timers.activeMax = B4_V52_Timers.active;\n"
                         "                B4_V52_NoteStart(taskId, eventId, timeout);\n")

CLOCK_FAIL = ("            else\n"
              "            {\n"
              "                OsalPort_free(pNewTimerEntry);\n"
              "            }\n")
CLOCK_FAIL_NEW = ("            else\n"
                  "            {\n"
                  "                B4_V52_NoteFail(taskId);\n"
                  "                OsalPort_free(pNewTimerEntry);\n"
                  "            }\n")


def apply(sdk):
    path = Path(sdk) / TIMERS
    if path.is_symlink() or not path.is_file():
        raise ValueError("V52_TIMERS_FILE_REQUIRED")
    before = path.read_text()
    if MARKER in before:
        raise ValueError("V52_TIMERS_ALREADY_APPLIED")
    if hashlib.sha256(before.encode()).hexdigest() != PRISTINE_SHA256:
        raise ValueError("V52_TIMERS_REQUIRES_PRISTINE_TI_3615AD5D")
    text = once(before, STATE_ANCHOR, STATE_ANCHOR + STATE, "V52_TIMER_STATE")
    text = once(text, STOP_DELETE, STOP_DELETE +
                "        if (B4_V52_Timers.active) --B4_V52_Timers.active;\n",
                "V52_TIMER_STOP_ACTIVE")
    text = once(text, CLEANUP_HEAD, CLEANUP_HEAD_NEW, "V52_CLEANUP_FAST_PATH")
    text = once(text, CLEANUP_LOOP, CLEANUP_LOOP_NEW, "V52_CLEANUP_COUNT")
    text = once(text, CLEANUP_TAIL, CLEANUP_TAIL_NEW, "V52_CLEANUP_TOTALS")
    text = once(text, CB_EVENT, CB_EVENT_NEW, "V52_TIMER_EXPIRY")
    text = once(text, CB_APPEND, CB_PREPEND, "V52_TIMER_O1_DEFERRED_PREPEND")
    text = once(text, RESTART, RESTART_NEW, "V52_TIMER_RESTART")
    text = once(text, ALLOC, ALLOC_NEW, "V52_TIMER_ALLOC_FAIL")
    text = once(text, CREATED, CREATED_NEW, "V52_TIMER_CREATED")
    text = once(text, CLOCK_FAIL, CLOCK_FAIL_NEW, "V52_TIMER_CLOCK_FAIL")
    if (text.count(MARKER) != 1 or "while(pDeleteTimerEntry->pNext != NULL)" in text or
            text.count("OsalPortTimers_cleanUpTimers(void)") != 1 or
            text.count("B4_V52_NoteFail(taskId);") != 2):
        raise ValueError("V52_TIMERS_SCOPE_DRIFT")
    path.write_text(text, encoding="utf-8", newline="")
    return {
        "schema": "p7u-v52-osal-timers-v1",
        "file": TIMERS,
        "deferred_free_owner": "STACK_TASK_AFTER_EVERY_DISPATCH_AND_ZSTACK_SERVICE",
        "swi_deferred_append": "O1_PREPEND",
        "timer_timing_or_event_semantics_changed": False,
        "b1e6_timer_evidence_bytes": TIMER_EVIDENCE_SIZE,
        "root_cause_proven": False,
        "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
        "modified_sha256": hashlib.sha256(text.encode()).hexdigest(),
    }
