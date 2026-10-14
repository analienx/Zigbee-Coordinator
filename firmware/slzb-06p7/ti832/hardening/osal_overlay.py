#!/usr/bin/env python3
"""Repair existing TI timer result, lifetime and callback handling."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from runtime_overlay import function,replace
BASE="source/ti/ti154stack/common/osal_port/osal_port_posix/"
PORT=BASE+"osal_port.c"
TIMERS=BASE+"osal_port_timers.c"
def patch(texts):
    out=dict(texts);source=out[TIMERS]
    old=function(source,"createTimerEntry")
    new=replace(old,"    uint32_t timeoutTicks = (timeout * (1000 / ClockP_getSystemTickPeriod()));",
        "    uint32_t period = ClockP_getSystemTickPeriod();\n"
        "    uint64_t ticks = period ? ((uint64_t)timeout * 1000u + period - 1u) / period : 0;\n"
        "    if (!period || ticks > UINT32_MAX) return OsalPort_INVALIDPARAMETER;\n"
        "    uint32_t timeoutTicks = (uint32_t)ticks;", "timer_timeout_no_wrap")
    new=replace(new,"        ClockP_setTimeout(pNewTimerEntry->clockHandle, timeoutTicks);\n"
        "        ClockP_start(pNewTimerEntry->clockHandle);",
        "        ClockP_setTimeout(pNewTimerEntry->clockHandle, timeoutTicks);\n"
        "        ClockP_setPeriod(pNewTimerEntry->clockHandle, reload ? timeoutTicks : 0);\n"
        "        pNewTimerEntry->reload = reload;\n"
        "        ClockP_start(pNewTimerEntry->clockHandle);\n"
        "        status = OsalPort_SUCCESS;", "timer_restart_mode_and_status")
    source=replace(source,old,new,"create_timer")
    old=function(source,"OsalPortTimers_getTimerTimeout")
    new=replace(old,"        timeout = timeoutTicks / (1000 / ClockP_getSystemTickPeriod());",
        "        timeout = (uint32_t)((uint64_t)timeoutTicks * ClockP_getSystemTickPeriod() / 1000u);",
        "timer_remaining_ms")
    out[TIMERS]=replace(source,old,new,"timer_get_timeout")
    source=out[PORT];old=function(source,"OsalPort_setTimer")
    new=replace(old,"    if(pClockHandle == NULL)","    if(pClockHandle == NULL || cback == NULL)","callback_required")
    new=replace(new,"        if(entry->clock == NULL)\n        {\n            return OsalPort_NO_TIMER_AVAIL;",
        "        if(entry->clock == NULL)\n        {\n            OsalPort_free(entry);\n            return OsalPort_NO_TIMER_AVAIL;",
        "schedule_create_failure_free")
    new=replace(new,"        // Re-enable interrupts\n        OsalPort_leaveCS(key);",
        "        entry->cback = cback;\n        entry->arg = arg;\n"
        "        // Re-enable interrupts\n        OsalPort_leaveCS(key);", "schedule_updated_callback")
    source=replace(source,old,new,"schedule_lifetime")
    old=function(source,"OsalPort_stopTimer")
    new=replace(old,"        ClockP_stop(*pClockHandle);",
        "        OsalPort_ScheduleEntry *entry = (OsalPort_ScheduleEntry *)*pClockHandle;\n"
        "        if (entry->clock) ClockP_stop(entry->clock);", "stop_actual_clock")
    out[PORT]=replace(source,old,new,"schedule_stop")
    return out
def apply(sdk,output):
    before={path:(sdk/path).read_text() for path in (PORT,TIMERS)};after=patch(before)
    for path,text in after.items():(sdk/path).write_text(text)
    report={"qualification":"P7_OSAL_TIMER_SOURCE_FIXES","flash_authorized":False,
            "files":{path:{"input_sha256":hashlib.sha256(before[path].encode()).hexdigest(),
                           "output_sha256":hashlib.sha256(text.encode()).hexdigest()} for path,text in after.items()}}
    output.mkdir(parents=True,exist_ok=True)
    (output/"OSAL-HARDENING-SOURCE.json").write_text(json.dumps(report,indent=2)+"\n")
    return report
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();print(json.dumps(apply(a.sdk,a.out),sort_keys=True))
