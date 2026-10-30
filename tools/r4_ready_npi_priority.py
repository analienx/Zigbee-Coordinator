#!/usr/bin/env python3
"""V49: retain sole NPI task priority only for genuinely attested READY.

V48 executed ZDApp but the final post-READY request timed out. This is one
hypothesis, not proof of the SRSP loss mechanism. RUNNING still has the V47
90-second scheduling budget; expiration must not permanently revoke eligibility
for a later legitimate READY. HOLD, FAILED, lost coordinator attestation and
unarmed normal operation must not inherit the READY priority boost.
"""
import hashlib
from pathlib import Path
from r4_uart_tx_liveness import once

TASK = "source/ti/zstack/npi/npi_task.c"
MARKER = "B4_V49_RETAINED_READY_NPI_OWNER"


def apply(sdk):
    p = Path(sdk) / TASK
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
        "    /* " + MARKER + ": READY must be genuinely attested, not stale state.\n"
        "     * Keeping eligibility does not keep RUNNING at high priority. */\n"
        "    if (retained_ready) return 1u;\n"
        "    if ((uint32_t)(Clock_getTicks() - B4_V47_StartTick) <",
        "V49_READY_OVER_WINDOW")
    updated = once(updated,
        "    B4_V47_Armed = 0u;\n"
        "    return 0u;\n}",
        "    /* Do not destroy eligibility for a slow but valid READY.\n"
        "     * Ordinary RUNNING is already deboosted after 90 seconds. */\n"
        "    return 0u;\n}",
        "V49_SLOW_START_ELIGIBILITY_NO_REARM")
    updated = once(updated,
        "__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)\n"
        "{\n"
        "    unsigned int schedulerKey = Task_disable();",
        "__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)\n"
        "{\n"
        "    /* Read the actual B1 coordinator attestation, not a stale enum. */\n"
        "    uint8_t retained_ready = b1_startup_state() == B1_STARTUP_READY &&\n"
        "        b1_management_network_ready() &&\n"
        "        !b1_management_transport_unavailable();\n"
        "    unsigned int schedulerKey = Task_disable();",
        "V49_READY_ATTESTATION_OUTSIDE_CS")
    updated = once(updated,
        "    uint8_t startup = B4_V47_ActiveLocked();",
        "    uint8_t startup = B4_V47_ActiveLocked(retained_ready);",
        "V49_READY_SAME_NPI_OWNER")
    updated = once(updated,
        "    if (startup && (b1_startup_state() != B1_STARTUP_RUNNING ||\n"
        "        b1_management_transport_unavailable()))\n"
        "        startup = 0u;",
        "    /* Revalidate after sampling the clock and entering this refresh. */\n"
        "    uint8_t current_state = b1_startup_state();\n"
        "    if (startup && (b1_management_transport_unavailable() ||\n"
        "        (current_state == B1_STARTUP_READY &&\n"
        "         !b1_management_network_ready()) ||\n"
        "        (current_state != B1_STARTUP_RUNNING &&\n"
        "         current_state != B1_STARTUP_READY)))\n"
        "        startup = 0u;",
        "V49_READY_REVOKED_ATTESTATION_DEBOOST")
    if (updated.count(MARKER) != 1 or
        updated.count("B4_V47_ActiveLocked(retained_ready)") != 1 or
        updated.count("B4_V46_RefreshNpiPriority(void)\n{") != 1):
        raise ValueError("V49_SOURCE_SCOPE_DRIFT")
    p.write_text(updated, encoding="utf-8", newline="")
    return {"schema": "p7u-v49-retained-ready-npi-owner-v2",
            "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "modified_sha256": hashlib.sha256(updated.encode()).hexdigest(),
            "only_existing_npi_owner": True,
            "network_ready_must_be_attested_by_b1": True,
            "slow_start_ready_eligible_without_running_priority_extension": True,
            "running_timeout_unchanged": True,
            "hold_deboost": True,
            "normal_unarmed_priority_unchanged": True,
            "flash_authorized": False}
