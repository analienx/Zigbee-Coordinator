#!/usr/bin/env python3
"""V49: preserve existing NPI UART owner scheduling after native READY.

V48 physically reached the B1 READY milestone, but final post-READY B1P1
could not be received. V47 intentionally dropped priority6 at READY, letting
the continuously runnable priority5 Stack strand ordinary priority4 NPI.
This patch keeps the original NPI owner at 6 ONLY after an actual B1 admitted
retained startup reached attested READY, until reset/transport HOLD. Incomplete
RUNNING retains the original 90-second deadline. No second UART, NV, network
formation, event synthesis, or relaxed final coordinator-state proof.
"""
import hashlib
import json
from pathlib import Path
from r4_uart_tx_liveness import once

TASK = "source/ti/zstack/npi/npi_task.c"
MARKER = "B4_V49_RETAINED_READY_NPI_OWNER"

def apply(sdk):
    p = Path(sdk)/TASK
    if not p.is_file() or p.is_symlink():
        raise ValueError("V49_NATIVE_NPI_REQUIRED")
    original = p.read_text()
    if MARKER in original:
        raise ValueError("V49_ALREADY_APPLIED")
    if ("B4_V47_BOUNDED_B1_STARTUP_NPI" not in original or
        "B4_V46_PENDING_SRSP_TASK_PRIORITY" not in original or
        "B4_F2_V6_OWNED_STAGE" not in original):
        raise ValueError("V49_REQUIRES_V48_V47_NPI")
    updated = once(original,
        "static uint8_t B4_V47_ActiveLocked(void)\n{",
        "static uint8_t B4_V47_ActiveLocked(uint8_t retained_ready)\n{",
        "V49_RETREADY_CLOCK_ARGUMENT")
    updated = once(updated,
        "    if (!B4_V47_Armed) return 0u;\n"
        "    if ((uint32_t)(Clock_getTicks() - B4_V47_StartTick) <",
        "    if (!B4_V47_Armed) return 0u;\n"
        "    /* " + MARKER + ": READY is already security-attested by B1;\n"
        "     * keep the same sleeping NPI owner serviceable beyond the\n"
        "     * original transient startup budget. This does not arm it. */\n"
        "    if (retained_ready) return 1u;\n"
        "    if ((uint32_t)(Clock_getTicks() - B4_V47_StartTick) <",
        "V49_READY_OVER_WINDOW")
    updated = once(updated,
        "__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)\n"
        "{\n"
        "    unsigned int schedulerKey = Task_disable();",
        "__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)\n"
        "{\n"
        "    /* Query B1 state outside the TI event critical section. */\n"
        "    uint8_t retained_ready = b1_startup_state() == B1_STARTUP_READY &&\n"
        "        !b1_management_transport_unavailable();\n"
        "    unsigned int schedulerKey = Task_disable();",
        "V49_READY_STATE_OUTSIDE_CS")
    updated = once(updated,
        "    uint8_t startup = B4_V47_ActiveLocked();",
        "    uint8_t startup = B4_V47_ActiveLocked(retained_ready);",
        "V49_READY_SAME_NPI_OWNER")
    updated = once(updated,
        "    if (startup && (b1_startup_state() != B1_STARTUP_RUNNING ||\n"
        "        b1_management_transport_unavailable()))\n"
        "        startup = 0u;",
        "    /* An actual READY retains the boost; HOLD/FAILED always deboost. */\n"
        "    uint8_t current_state = b1_startup_state();\n"
        "    if (startup && (b1_management_transport_unavailable() ||\n"
        "        (current_state != B1_STARTUP_RUNNING &&\n"
        "         current_state != B1_STARTUP_READY)))\n"
        "        startup = 0u;",
        "V49_READY_OR_RUNNING_ONLY")
    if (updated.count(MARKER) != 1 or
        updated.count("B4_V47_ActiveLocked(retained_ready)") != 1 or
        updated.count("B4_V46_RefreshNpiPriority(void)\n{") != 1):
        raise ValueError("V49_SOURCE_SCOPE_DRIFT")
    p.write_text(updated,encoding="utf-8",newline="")
    return {"schema":"p7u-v49-retained-ready-npi-owner-v1",
            "before_sha256":hashlib.sha256(original.encode()).hexdigest(),
            "modified_sha256":hashlib.sha256(updated.encode()).hexdigest(),
            "only_existing_npi_owner":True,
            "network_ready_must_be_attested_by_b1":True,
            "running_timeout_unchanged":True,
            "hold_deboost":True,
            "normal_unarmed_priority_unchanged":True,
            "flash_authorized":False}
