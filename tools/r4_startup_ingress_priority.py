#!/usr/bin/env python3
"""V47 startup-only NPI scheduler window on the *composed* B1 + V46 + V6 source.

This hypothesis-driven source change neither changes the original network nor
creates a second UART owner. B1's SRSP-EOT barrier remains authoritative: arm
only from the genuine deferred retained-start event, never from admission.
The existing NPI task remains priority 4 except for the bounded startup window
and the already-implemented V46 pending-response priority.
"""
import argparse
import hashlib
import json
from pathlib import Path

from r4_srsp_service import TASK
from r4_uart_tx_liveness import once

ZDO = "source/ti/zstack/mt/mt_zdo.c"
MARKER = "B4_V47_BOUNDED_B1_STARTUP_NPI"
WINDOW_US = 90_000_000

# Insert before the existing V46 function in the same NPI owner C source.
NPI_PREFIX = r"""/* B4_V47_BOUNDED_B1_STARTUP_NPI
 * This is an ingress scheduling bridge, not a new transport or network start.
 * Clock_getTicks and Clock_tickPeriod are the real native SYS/BIOS clock.
 * Time-window expiry is applied on the NEXT existing NPI priority refresh.
 * With no pending work NPI sleeps; the priority does not consume CPU.
 */
#define B4_V47_STARTUP_US 90000000u
static volatile uint8_t B4_V47_Armed;
static uint32_t B4_V47_StartTick, B4_V47_WindowTicks;
static uint8_t B4_V47_ActiveLocked(void)
{
    if (!B4_V47_Armed) return 0u;
    if ((uint32_t)(Clock_getTicks() - B4_V47_StartTick) <
        B4_V47_WindowTicks) return 1u;
    B4_V47_Armed = 0u;
    return 0u;
}
__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void);
__attribute__((noinline)) void B4_V47_ArmStartupNpi(void)
{
    /* Only B1's genuine ZDApp retained-event Stack task may arm. */
    if (b1_startup_state() != B1_STARTUP_RUNNING) return;
    unsigned int schedulerKey = Task_disable();
    uint32_t key = OsalPort_enterCS();
    if (Clock_tickPeriod != 0u &&
        Task_numPriorities > B4_V46_SRSP_PRIORITY)
    {
        uint32_t ticks = B4_V47_STARTUP_US / Clock_tickPeriod +
            ((B4_V47_STARTUP_US % Clock_tickPeriod) != 0u);
        if (ticks > 0u && ticks < 0x80000000u)
        {
            B4_V47_StartTick = Clock_getTicks();
            B4_V47_WindowTicks = ticks;
            B4_V47_Armed = 1u;
        }
    }
    OsalPort_leaveCS(key);
    Task_restore(schedulerKey);
    B4_V46_RefreshNpiPriority();
}

"""

def apply(sdk):
    sdk = Path(sdk)
    task = sdk / TASK
    zdo = sdk / ZDO
    if any(p.is_symlink() or not p.is_file() for p in (task, zdo)):
        raise ValueError("V47_EXACT_COMPOSITE_FILES_REQUIRED")
    n0, z0 = task.read_text(), zdo.read_text()
    if MARKER in n0 or MARKER in z0:
        raise ValueError("V47_ALREADY_APPLIED")
    if ("B4_V46_PENDING_SRSP_TASK_PRIORITY" not in n0 or
        "B4_F2_V6_OWNED_STAGE" not in n0 or
        "B1_RETAINED_STARTUP_EVENT" not in z0 or
        "b1_mt_zdo_retained_startup_event" not in z0):
        raise ValueError("V47_COMPOSITE_PREIMAGE_DRIFT")
    anchor = "__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)\n{"
    n = once(n0, anchor, NPI_PREFIX + anchor, "V47_HELPER_B1_AND_V46")
    n = once(n,
        "    OsalPort_leaveCS(key);\n    /* Unsupported RTOS configurations preserve the original safe priority.",
        "    uint8_t startup = B4_V47_ActiveLocked();\n"
        "    OsalPort_leaveCS(key);\n"
        "    if (startup && b1_startup_state() != B1_STARTUP_RUNNING)\n"
        "        startup = 0u;\n"
        "    /* Unsupported RTOS configurations preserve the original safe priority.",
        "V47_WINDOW_IN_V46_OWNER")
    n = once(n,
        "int priority = urgent && Task_numPriorities > B4_V46_SRSP_PRIORITY ?",
        "int priority = (urgent || startup) && Task_numPriorities > B4_V46_SRSP_PRIORITY ?",
        "V47_BOUNDED_INGRESS_PRIORITY")

    # Unlike the TI upstream handler, this B1 event is the real retained path.
    declaration = "void b1_mt_zdo_retained_startup_event(void)\n{"
    z = once(z0, declaration,
        "extern void B4_V47_ArmStartupNpi(void);\n" + declaration,
        "V47_EXACT_B1_EVENT")
    # Before entering potentially long BDB work, preserve existing milestones.
    original = (
        "  b1_evidence_milestone(B1_M_BDB_ENTRY, 0u);\n"
        "  bdb_StartCommissioning(0); /* Initialize original network only, once per boot. */"
    )
    corrected = (
        "  b1_evidence_milestone(B1_M_BDB_ENTRY, 0u);\n"
        "  B4_V47_ArmStartupNpi(); /* sole NPI owner, bounded to startup */\n"
        "  bdb_StartCommissioning(0); /* Initialize original network only, once per boot. */"
    )
    z = once(z, original, corrected, "V47_BEFORE_GUARDED_BDB0")

    task.write_text(n, encoding="utf-8", newline="")
    zdo.write_text(z, encoding="utf-8", newline="")
    return {
        "schema": "p7u-v47-bounded-b1-npi-ingress-v1",
        "root_cause_proven": False,
        "initial_npi_priority": 4,
        "startup_npi_priority": 6,
        "stack_priority": 5,
        "maximum_startup_window_us": WINDOW_US,
        "deboost": "state-not-running-or-next-refresh-after-timeout",
        "remains_single_npi_owner": True,
        "changes_bdb_mode": False,
        "changes_nv_or_ccfg": False,
        "flash_authorized": False,
        "before_sha256": {
            TASK: hashlib.sha256(n0.encode()).hexdigest(),
            ZDO: hashlib.sha256(z0.encode()).hexdigest(),
        },
        "modified_sha256": {
            TASK: hashlib.sha256(n.encode()).hexdigest(),
            ZDO: hashlib.sha256(z.encode()).hexdigest(),
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists() or args.receipt.is_symlink():
        raise ValueError("V47_RECEIPT_ALREADY_EXISTS")
    result = apply(args.sdk)
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result))
