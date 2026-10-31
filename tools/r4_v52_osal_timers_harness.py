#!/usr/bin/env python3
"""Compile the EMITTED V52 osal_port_timers.c and reject behavior mutants.

The whole composed TI file is compiled with ClockP/OSAL stubs (ASan/UBSan):
one-shot expiry defers the entry and its dynamic Clock object exactly as
TI does, the deferred list is prepended in O(1), cleanup frees everything
and its empty fast path takes no critical section, restarts, reload
timers, stops and allocation failures keep their TI semantics, and the
NWK probe records per-event-bit starts and the minimum timeout. Hosted
model only: no claim about hardware timing or the NWK storm root cause.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

from r4_v52_osal_timers import TIMERS, MARKER

STUB = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define OsalPort_SUCCESS 0u
#define OsalPort_INVALIDPARAMETER 2u
#define OsalPort_NO_TIMER_AVAIL 9u
typedef void (*ClockP_Fxn)(uintptr_t);
typedef struct { uint32_t period; bool startFlag; uintptr_t arg; } ClockP_Params;
typedef struct { ClockP_Fxn fxn; uint32_t timeout, period; uintptr_t arg; int started; } ClockObj;
typedef ClockObj *ClockP_Handle;
static unsigned cs_depth, cs_entries, clocks_live, entries_live, fail_malloc, fail_clock;
static uint32_t task_events[16];
static ClockObj *last_clock;
static uintptr_t OsalPort_enterCS(void) { ++cs_entries; return ++cs_depth; }
static void OsalPort_leaveCS(uintptr_t key) { assert(key == cs_depth); --cs_depth; }
static void *OsalPort_malloc(uint32_t n)
{ if (fail_malloc) { --fail_malloc; return NULL; } ++entries_live; return calloc(1u, n); }
static void OsalPort_free(void *p) { assert(p != NULL); --entries_live; free(p); }
static uint8_t OsalPort_setEvent(uint8_t task, uint32_t event)
{ assert(task < 16u); task_events[task] |= event; return 0u; }
static void ClockP_Params_init(ClockP_Params *p) { memset(p, 0, sizeof(*p)); }
static ClockP_Handle ClockP_create(ClockP_Fxn fxn, uint32_t timeout, ClockP_Params *p)
{
    ClockObj *c;
    if (fail_clock) { --fail_clock; return NULL; }
    c = calloc(1u, sizeof(*c)); assert(c != NULL);
    c->fxn = fxn; c->timeout = timeout; c->period = p->period; c->arg = p->arg; c->started = p->startFlag;
    ++clocks_live; last_clock = c; return c;
}
static void ClockP_delete(ClockP_Handle c) { --clocks_live; free(c); }
static void ClockP_start(ClockP_Handle c) { c->started = 1; }
static void ClockP_stop(ClockP_Handle c) { c->started = 0; }
static void ClockP_setTimeout(ClockP_Handle c, uint32_t t) { c->timeout = t; }
static uint32_t ClockP_getTimeout(ClockP_Handle c) { return c->timeout; }
static uint32_t ClockP_getSystemTickPeriod(void) { return 10u; }
"""

MAIN = r"""
static void fire(ClockObj *c) { assert(cs_depth == 0u && c->started); c->fxn(c->arg); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
int main(void)
{
    ClockObj *a, *b, *r;
    TimerEntry_t *ea, *eb;
    uint8_t out[104 + 8];
    unsigned before, i;
    OsalPortTimers_registerCleanupEvent(9u, 0x8000u);
    /* 1. One-shot start allocates an entry and a dynamic Clock (TI). */
    assert(OsalPortTimers_startTimer(2u, 0x40u, 5u) == OsalPort_SUCCESS);
    a = last_clock; ea = pTimerEntries;
    assert(clocks_live == 1u && entries_live == 1u && a->timeout == 500u && a->period == 0u);
    assert(B4_V52_Timers.oneShot == 1u && B4_V52_Timers.active == 1u);
    /* 2. Expiry posts the event, defers BOTH objects and asks for cleanup. */
    fire(a);
    assert(task_events[2] == 0x40u && (task_events[9] & 0x8000u) && pTimerEntries == NULL);
    assert(pDeleteTimerEntries == ea && clocks_live == 1u && entries_live == 1u);
    assert(B4_V52_Timers.expiry == 1u && B4_V52_Timers.deferred == 1u && B4_V52_Timers.active == 0u);
    /* 3. Re-arming the same (task, event) after expiry allocates again; the
     * deferred list grows by O(1) PREPEND, newest first. */
    assert(OsalPortTimers_startTimer(2u, 0x40u, 5u) == OsalPort_SUCCESS);
    b = last_clock; eb = pTimerEntries; assert(b != a && eb != ea && entries_live == 2u);
    fire(b);
    assert(pDeleteTimerEntries == eb && eb->pNext == ea && ea->pNext == NULL);
    assert(B4_V52_Timers.deferred == 2u && B4_V52_Timers.deferredMax == 2u);
    /* 4. Cleanup frees every deferred entry and Clock; the empty fast path
     * then takes no critical section at all. */
    OsalPortTimers_cleanUpTimers();
    assert(clocks_live == 0u && entries_live == 0u && pDeleteTimerEntries == NULL);
    assert(B4_V52_Timers.cleanups == 1u && B4_V52_Timers.freed == 2u && B4_V52_Timers.freedMax == 2u);
    assert(B4_V52_Timers.deferred == 0u);
    before = cs_entries; OsalPortTimers_cleanUpTimers(); assert(cs_entries == before);
    assert(B4_V52_Timers.cleanups == 1u);
    /* 5. Restart of an ACTIVE timer reuses it (TI); reload never defers. */
    assert(OsalPortTimers_startTimer(3u, 0x1u, 7u) == OsalPort_SUCCESS);
    a = last_clock;
    (void)OsalPortTimers_startTimer(3u, 0x1u, 9u);
    assert(entries_live == 1u && a->timeout == 900u && B4_V52_Timers.restart == 1u);
    assert(OsalPortTimers_startReloadTimer(4u, 0x2u, 3u) == OsalPort_SUCCESS);
    r = last_clock; assert(r->period == 300u && B4_V52_Timers.reload == 1u && B4_V52_Timers.active == 2u);
    fire(r); fire(r);
    assert(task_events[4] == 0x2u && pDeleteTimerEntries == NULL && B4_V52_Timers.expiry == 4u);
    /* 6. Stop frees immediately and leaves the active count consistent. */
    assert(OsalPortTimers_stopTimer(3u, 0x1u) == OsalPort_SUCCESS && B4_V52_Timers.active == 1u);
    assert(OsalPortTimers_stopTimer(4u, 0x2u) == OsalPort_SUCCESS && B4_V52_Timers.active == 0u);
    assert(clocks_live == 0u && entries_live == 0u);
    /* 7. Allocation and Clock creation failures are counted per task. */
    fail_malloc = 1u; assert(OsalPortTimers_startTimer(5u, 0x4u, 1u) == OsalPort_NO_TIMER_AVAIL);
    fail_clock = 1u; assert(OsalPortTimers_startTimer(6u, 0x4u, 1u) == OsalPort_NO_TIMER_AVAIL);
    assert(B4_V52_Timers.createFail == 2u && B4_V52_Timers.lastFailTask == 6u && entries_live == 0u);
    /* 8. NWK probe: per event bit (nwk.h 0x2070 here) starts and min timeout. */
    B4_V52_TimerProbe(2u);
    assert(OsalPortTimers_startTimer(2u, 0x2070u, 30u) == OsalPort_SUCCESS);
    (void)OsalPortTimers_startTimer(2u, 0x2070u, 3u);
    assert(OsalPortTimers_startTimer(7u, 0x10u, 1u) == OsalPort_SUCCESS);
    /* 9. A thousand expiries without cleanup stay O(1) each and are freed. */
    for (i = 0u; i < 1000u; ++i)
    {
        assert(OsalPortTimers_startTimer(8u, 0x80u, 2u) == OsalPort_SUCCESS);
        fire(last_clock);
    }
    assert(B4_V52_Timers.deferred == 1000u && B4_V52_Timers.deferredMax == 1000u);
    OsalPortTimers_cleanUpTimers();
    assert(B4_V52_Timers.freedMax == 1000u && B4_V52_Timers.freed == 1002u && entries_live == 2u);
    memset(out, 0xA5, sizeof(out));
    B4_V52_TimerSnapshot(out);
    assert(get32(out + 0) == 1005u && get32(out + 4) == 1u && get32(out + 8) == 2u);
    assert(get32(out + 12) == 1004u && get32(out + 16) == 2u && get32(out + 20) == 2u);
    assert(get32(out + 24) == 1002u && get16(out + 28) == 0u && get16(out + 30) == 1000u);
    assert(get16(out + 32) == 1000u && get16(out + 34) == 2u && get16(out + 36) == 3u);
    assert(out[38] == 2u && out[39] == 6u);
    for (i = 0u; i < 16u; ++i)
    {
        int storm = i == 4u || i == 5u || i == 6u || i == 13u;
        assert(get16(out + 40 + 2 * i) == (storm ? 2u : 0u));
        assert(get16(out + 72 + 2 * i) == (storm ? 3u : 0xFFFFu));
    }
    for (i = 104u; i < sizeof(out); ++i) assert(out[i] == 0xA5u);
    assert(cs_depth == 0u);
    printf("V52_OSAL_TIMERS_REAL_C_PASS\n");
    return 0;
}
"""

MUTANTS = {
    "tail_append_restored": (
        "        pTimerEntry->pNext = pDeleteTimerEntries;\n        pDeleteTimerEntries = pTimerEntry;\n",
        "        pTimerEntry->pNext = NULL;\n"
        "        if (pDeleteTimerEntries == NULL) pDeleteTimerEntries = pTimerEntry;\n"
        "        else { TimerEntry_t *x = pDeleteTimerEntries; while (x->pNext) x = x->pNext; x->pNext = pTimerEntry; }\n"),
    "fast_path_removed": (
        "  if (*(TimerEntry_t * volatile *)&pDeleteTimerEntries == NULL) return;\n", ""),
    "freed_not_counted": ("        B4_V52_Inc16(&b4v52Freed);\n", ""),
    "deferred_not_reset": ("    B4_V52_Timers.deferred = 0u;\n", ""),
    "restart_not_counted": ("        B4_V52_Inc32(&B4_V52_Timers.restart);\n", ""),
    "probe_ignores_event_bits": ("        if ((eventId & (1uL << bit)) == 0u) continue;\n", ""),
    "probe_min_not_minimum": (
        "timeout < B4_V52_Timers.probeMinMs[bit])", "timeout > B4_V52_Timers.probeMinMs[bit])"),
    "expiry_not_counted": ("    B4_V52_Inc32(&B4_V52_Timers.expiry);\n", ""),
    "clock_failure_not_counted": (
        "                B4_V52_NoteFail(taskId);\n                OsalPort_free(pNewTimerEntry);\n",
        "                OsalPort_free(pNewTimerEntry);\n"),
    "snapshot_offset_shifted": (
        "    B4_V52_Put32(out + 24u, s.freed);", "    B4_V52_Put32(out + 28u, s.freed);"),
}


def compose(sdk):
    text = (Path(sdk) / TIMERS).read_text()
    if text.count(MARKER) != 1:
        raise ValueError("V52_TIMERS_HARNESS_MARKER")
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#include"))
    return STUB + body + "\n" + MAIN


def exercise(sdk):
    code = compose(sdk)
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        raise RuntimeError("V52_NATIVE_C_COMPILER_REQUIRED")

    def build(name, source, should_pass):
        with tempfile.TemporaryDirectory(prefix="p7u-v52-timers-") as td:
            unit, exe = Path(td) / "t.c", Path(td) / "t"
            unit.write_text(source, encoding="utf-8")
            built = subprocess.run(
                [cc, "-std=c11", "-O0", "-g", "-Wall", "-Wextra", "-Werror",
                 "-Wno-unused-function", "-Wno-unused-parameter",
                 "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                 str(unit), "-o", str(exe)], capture_output=True, text=True, timeout=60)
            if built.returncode:
                raise RuntimeError("V52_TIMERS_C_COMPILE_" + name + ": " + built.stderr[-3000:])
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
            if (run.returncode == 0) != should_pass:
                raise RuntimeError("V52_TIMERS_MUTANT_NOT_REJECTED_" + name + ": " +
                                   run.stdout[-400:] + run.stderr[-800:])
            return run.stdout.strip()

    output = build("actual", code, True)
    rejected = []
    for label, (old, new) in MUTANTS.items():
        if code.count(old) != 1:
            raise ValueError("V52_TIMERS_MUTANT_PREIMAGE_" + label + " occurrences=" + str(code.count(old)))
        build(label, code.replace(old, new, 1), False)
        rejected.append("timers:" + label)
    return {"schema": "p7u-v52-emitted-osal-timers-actual-c-v1", "status": "PASS",
            "timers_sha256": hashlib.sha256((Path(sdk) / TIMERS).read_bytes()).hexdigest(),
            "compiled_actual_osal_port_timers": True, "negative_mutants_rejected": rejected,
            "hosted_model_only": True, "nwk_storm_root_cause_proven": False, "output": output}
