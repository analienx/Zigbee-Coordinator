#!/usr/bin/env python3
"""Compile the *emitted* V49 TI NPI refresh function, not a string-only fixture.

Uses the exact V47 retained-event/clock helper and V46 Refresh emitted in the
composed SDK. Stubbed scheduler, clock and B1 attestation are deterministic;
this is a hosted functional model, NOT evidence of hardware coordinator state9.
Negative mutants must fail the *same* compiled assertions.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

from r4_srsp_service import TASK
from r4_ready_npi_priority import MARKER
from r4_startup_ingress_priority_harness import PREFIX as V47_PREFIX, function

STUB = V47_PREFIX.replace(
    "#define B1_STARTUP_RUNNING 3u",
    "#define B1_STARTUP_RUNNING 3u\n#define B1_STARTUP_READY 4u")
STUB += """
static uint8_t network_attested;
static uint8_t b1_management_network_ready(void) { return network_attested; }
"""

MAIN = r"""
int main(void)
{
    /* No authorization merely because B1's startup enum says READY. */
    startup_state=4;network_attested=1;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    /* Real retained event is the only source of eligibility. */
    startup_state=3;network_attested=0;
    B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==6);
    tick+=359u;B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==6);
    /* A formerly READY enum without live coordinator attestation is not proof. */
    startup_state=4;network_attested=0;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    network_attested=1;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==6);
    /* Revoked attestation while READY must immediately deboost. */
    network_attested=0;B4_V46_RefreshNpiPriority();
    assert(npiTaskStruct.priority==4);
    /* Expired RUNNING must NOT continue at 6 or permanently lose eligibility. */
    startup_state=3;network_attested=0;
    tick+=2u;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    assert(B4_V47_Armed);
    tick+=400u;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    /* Actual authenticated READY even after expiry retains the original owner. */
    startup_state=4;network_attested=1;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==6);
    /* READY-but-unattested after a network exit must not remain priority6. */
    network_attested=0;B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    /* Explicit HOLD/FAILED deboost, including after a long startup. */
    network_attested=1;transport_hold=1;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    transport_hold=0;startup_state=5;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    /* A new authorized startup only gets the original 90s running budget. */
    startup_state=3;network_attested=0;
    B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==6);
    tick+=360u;B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    assert(B4_V47_Armed);
    /* The old V46 pending SRSP boost remains unchanged. */
    startup_state=0;queue_record.count=1;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==6);
    queue_record.count=0;
    B4_V46_RefreshNpiPriority();assert(npiTaskStruct.priority==4);
    /* No out-of-range scheduling on narrow RTOS configs. */
    Task_numPriorities=6;startup_state=3;
    B4_V47_ArmStartupNpi();assert(npiTaskStruct.priority==4);
    Task_numPriorities=8;
    assert(!cs_depth && !scheduler_depth);
    printf("V49_REFRESH_REAL_C_PASS changes=%u\n",priority_changes);
    return 0;
}
"""


def compose(sdk):
    task=(Path(sdk)/TASK).read_text()
    if task.count(MARKER)!=1:
        raise ValueError("V49_COMPOSED_MARKER_DRIFT")
    start=task.index("/* B4_V47_BOUNDED_B1_STARTUP_NPI")
    end=task.index("__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)\n{",start)
    helpers=task[start:end]
    refresh=function(task,"__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)")
    for item in ("b1_management_network_ready()", "B4_V47_ActiveLocked(retained_ready)",
                 "B4_V47_Armed", "B4_V46_SRSP_PRIORITY"):
        if item not in (helpers+refresh) and item!="B4_V46_SRSP_PRIORITY":
            raise ValueError("V49_COMPOSED_FUNCTION_MISSING_"+item)
    return task,STUB+helpers+"\n"+refresh+"\n"+MAIN


def exercise(sdk):
    source,code=compose(sdk)
    cc=shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        raise RuntimeError("V49_NATIVE_C_COMPILER_REQUIRED")
    def build(name,body,should_pass):
        with tempfile.TemporaryDirectory(prefix="p7u-v49-c-") as td:
            root=Path(td);unit=root/"v49.c";exe=root/"v49"
            unit.write_text(body,encoding="utf-8")
            built=subprocess.run(
                [cc,"-std=c11","-O0","-Wall","-Wextra","-Werror",
                 "-Wno-unused-variable","-Wno-unused-function",str(unit),"-o",str(exe)],
                capture_output=True,text=True,timeout=30)
            if built.returncode:
                raise RuntimeError("V49_C_COMPILE_"+name+": "+built.stderr[-3000:])
            run=subprocess.run([str(exe)],capture_output=True,text=True,timeout=15)
            if (run.returncode==0)!=should_pass:
                raise RuntimeError("V49_MUTANT_NOT_REJECTED_"+name+": "+
                                   run.stdout[-500:]+run.stderr[-500:])
            return run.stdout.strip()
    positive=build("real_refresh",code,True)
    mutants={
        "priority_not_retained":(
            "int priority = (urgent || startup) &&",
            "int priority = urgent &&"),
        "stale_ready_without_attestation":(
            "b1_management_network_ready() &&",
            "1u &&"),
        "stale_ready_recheck_missing":(
            "!b1_management_network_ready())",
            "0u)"),
        "slow_start_eligibility_lost":(
            "    /* Do not destroy eligibility for a slow but valid READY.\n",
            "    B4_V47_Armed = 0u;\n    /* Do not destroy eligibility for a slow but valid READY.\n"),
        "running_unbounded_boost":(
            "    /* Do not destroy eligibility for a slow but valid READY.\n",
            "    if (B4_V47_Armed) return 1u;\n    /* Do not destroy eligibility for a slow but valid READY.\n"),
        "ready_requires_original_window":(
            "    if (retained_ready) return 1u;",
            "    if (retained_ready && (uint32_t)(Clock_getTicks() - B4_V47_StartTick) < B4_V47_WindowTicks) return 1u;"),
        "hold_not_deboosted":(
            "    if (startup && (b1_management_transport_unavailable() ||",
            "    if (startup && (0u ||"),
    }
    for label,(old,new) in mutants.items():
        if code.count(old)!=1:
            raise ValueError("V49_MUTANT_PREIMAGE_"+label+" occurrences="+str(code.count(old)))
        build(label,code.replace(old,new,1),False)
    return {
        "schema":"p7u-v49-emitted-npi-refresh-actual-c-v1",
        "status":"PASS",
        "production_task_sha256":hashlib.sha256(source.encode()).hexdigest(),
        "compiled_actual_refresh":True,
        "negative_mutants_rejected":list(mutants),
        "hosted_model_only":True,
        "hardware_state9_proven":False,
        "output":positive,
    }
