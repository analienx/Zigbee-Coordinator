"""R4 B4 optional v4 SYS F2 nonce + source-qualified one-shot radio boot ID.

Applies ONLY after the pinned B4 v3 overlay in disposable /tmp TI SDK.
Never replaces v3, never opens another UART, never reads keys or NV,
never retries entropy, never generates entropy in the F2 handler.
Independent v4 acceptance/hardware gate remains required.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

TI_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
MT_SYS = "source/ti/zstack/mt/mt_sys.c"
NPI_TASK = "source/ti/zstack/npi/npi_task.c"
MARKER = "B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE"
V4_BYTES = 160

# Boot entropy obtained ONCE in already-existing NPI task context after the
# queue/RTOS task is ready but BEFORE NPITL_initTL enables host requests.
# The genuine TI donor SysConfig already declares TRNG.addInstance().
# Bounded failure => no boot capability, no boot ID, no retry.
BOOT_SOURCE = r"""
/* B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE: bounded one-time boot provenance.
 * Never invoke entropy generation during an MT command, ISR, or within CS.
 */
uint8_t B4_V4BootId[8] = {0};
volatile uint32_t B4_V4BootValid = 0u;
volatile uint32_t B4_V4ResetReason = 0xFFu;
static void B4_V4BootInitialize(void)
{
    TRNG_Params params;
    TRNG_Handle handle;
    uint8_t sample[8] = {0};
    uint32_t resetSource;
    uint32_t i;
    uint8_t nonzero = 0u;
    int_fast16_t trngResult;
    /* Re-entry after any partial task restart must NOT reuse previous
     * entropy. No UART is open yet; all writes precede host observations.
     */
    for (i = 0u; i < sizeof(B4_V4BootId); ++i)
        B4_V4BootId[i] = 0u;
    B4_V4BootValid = 0u;
    B4_V4ResetReason = 0xFFu;
    /* Actual pinned CC13x2x7/CC26x2x7 ROM/driverlib provider.
     * Reset cause is NOT entropy and never interpreted as generation ID. */
    resetSource = SysCtrlResetSourceGet();
    if (resetSource <= 0xFEu)
        B4_V4ResetReason = resetSource;

    TRNG_init();
    TRNG_Params_init(&params);
    params.returnBehavior = TRNG_RETURN_BEHAVIOR_BLOCKING;
    params.timeout = 25u; /* RTOS ticks, strictly bounded at boot only */
    handle = TRNG_open(0, &params); /* existing SysConfig TRNG instance */
    if (handle == NULL)
        return;
    trngResult = TRNG_getRandomBytes(handle, sample, sizeof(sample));
    if (trngResult != TRNG_STATUS_SUCCESS)
    {
        /* Pinned TRNGCC26XX_waitForResult may time out while the
         * request is STILL queued: it ignores SemaphoreP_pend's return
         * and reads the driver's error returnStatus. TRNG_close merely
         * destructs the semaphore. Cancel the job first, so its ISR
         * cannot later post a destroyed semaphore or write our stack.
         * TRNG_cancelOperation safely removes the job under HwiP CS.
         */
        (void)TRNG_cancelOperation(handle);
        TRNG_close(handle);
        return; /* capability already zero; UART startup proceeds */
    }
    for (i = 0u; i < sizeof(sample); ++i)
        nonzero |= sample[i];
    if (nonzero != 0u)
    {
        for (i = 0u; i < sizeof(sample); ++i)
            B4_V4BootId[i] = sample[i];
        B4_V4BootValid = 1u; /* never modified again until boot */
    }
    TRNG_close(handle);
    /* No key/NV operations and no second entropy attempt on failure. */
}
"""

V4_HANDLER = r"""
/* B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE: separate F2, 8-byte nonce echoed.
 * This is a correlation token, not authentication or a hardware MAC.
 */
extern uint8_t B4_V4BootId[8];
extern volatile uint32_t B4_V4BootValid;
extern volatile uint32_t B4_V4ResetReason;
static uint32_t B4_V4SampleSequence = 0u;
__attribute__((noinline)) static void B4_SysReadOnlyDiagnosticsV4(uint8_t *pBuf)
{
    uint8_t payload[160] = {0};
    uint32_t srsp_depth, srsp_high_water, async_depth, async_high_water;
    uint32_t srsp_enqueued, uart_finished, boot_ok, reset_reason, seq;
    uint32_t i;
    uint32_t key = OsalPort_enterCS();
    srsp_depth = B4_NpiSrspDepth;
    srsp_high_water = B4_NpiSrspHighWater;
    async_depth = B4_NpiAsyncDepth;
    async_high_water = B4_NpiAsyncHighWater;
    srsp_enqueued = B4_NpiSrspEnqueued;
    uart_finished = B4_NpiUartTxFinishedEvents;
    boot_ok = B4_V4BootValid;
    reset_reason = B4_V4ResetReason;
    seq = ++B4_V4SampleSequence;
    if (boot_ok == 1u)
        for (i = 0u; i < 8u; ++i)
            payload[16u + i] = B4_V4BootId[i];
    OsalPort_leaveCS(key);
    payload[0] = 'R'; payload[1] = '4'; payload[2] = 'D'; payload[3] = '4';
    payload[4] = 4u;  /* major; minor at byte 157 */
    payload[6] = 160u; /* LE size 160 */
    if (boot_ok == 1u)
        payload[8] = 0x01u; /* bit 0: sourced boot entropy exists */
    payload[12] = 0x2Cu;
#if defined(NPI_SREQRSP)
    payload[12] = 0x3Fu;
    B4_DiagPutU32(payload + 32, srsp_depth);
    B4_DiagPutU32(payload + 36, srsp_high_water);
    B4_DiagPutU32(payload + 48, srsp_enqueued);
#endif
    B4_DiagPutU32(payload + 28, seq);
    B4_DiagPutU32(payload + 40, async_depth);
    B4_DiagPutU32(payload + 44, async_high_water);
    B4_DiagPutU32(payload + 52, uart_finished);
    /* Validated 8-byte MT request token, echoed byte-exactly. */
    for (i = 0u; i < 8u; ++i)
        payload[132u + i] = pBuf[MT_RPC_POS_DAT0 + i];
    /* 140..155 is ZERO: no manufactured full-image build digest. */
    payload[156] = (uint8_t)reset_reason; /* 0xFF means unknown */
    payload[157] = 1u; /* v4 ABI minor */
    if (reset_reason != 0xFFu)
        payload[158] = 0x01u; /* reset-source-valid, NOT boot-token proof */
    /* byte 159 remains reserved zero */
    MT_BuildAndSendZToolResponse(MT_SRSP_SYS, 0xF2, sizeof(payload), payload);
}
"""

def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)

def once(s, old, new):
    if s.count(old) != 1:
        raise ValueError("guarded v4 TI source anchor drift: " + old[:84])
    return s.replace(old, new, 1)

def plan(root):
    root = Path(root)
    if not root.is_dir() or root.is_symlink() or not str(root.resolve()).startswith("/tmp/"):
        raise ValueError("v4 patch only to disposable /tmp TI SDK")
    if git(root, "rev-parse", "HEAD").decode().strip() != TI_SHA:
        raise ValueError("wrong pinned TI SDK")
    originals = {}
    for path in (MT_SYS, NPI_TASK):
        f = root / path
        if not f.is_file() or f.is_symlink():
            raise ValueError("pinned TI file missing")
        originals[path] = f.read_text()
    sys, task = originals[MT_SYS], originals[NPI_TASK]
    if (MARKER in sys or MARKER in task or "case 0xF2:" in sys or
            "B4_SysReadOnlyDiagnosticsV4" in sys):
        raise ValueError("v4 already present or SYS F2 conflict")
    if ("B4_EXPERIMENTAL_DIAG_READ_ONLY" not in sys or
            "B4_NpiSrspEnqueued" not in task or
            "B4_NpiUartTxFinishedEvents" not in sys):
        raise ValueError("v4 requires source-qualified B4 v3 first")
    # Assert TI donor really has a named TRNG instance in its ZNP SysConfig;
    # actual generated instance/linkage is still independently checked by CCS.
    header = git(root, "show", TI_SHA +
                 ":source/ti/devices/cc13x2x7_cc26x2x7/driverlib/sys_ctrl.h").decode()
    trng = git(root, "show", TI_SHA + ":source/ti/drivers/TRNG.h").decode()
    trng_driver = git(root, "show", TI_SHA +
                      ":source/ti/drivers/trng/TRNGCC26XX.c").decode()
    if ("SysCtrlResetSourceGet(" not in header or
            "TRNG_getRandomBytes(" not in trng or
            "TRNG_cancelOperation(" not in trng or
            "TRNG_RETURN_BEHAVIOR_BLOCKING" not in trng or
            "SemaphoreP_pend(&object->operationSemaphore, object->semaphoreTimeout);" not in trng_driver or
            "SemaphoreP_destruct(&object->operationSemaphore);" not in trng_driver or
            "TRNG_cancelOperation(TRNG_Handle handle)" not in trng_driver):
        raise ValueError("pinned TI boot entropy timeout cancellation source unsupported")
    # Exact F2 must be unassigned in pinned SYS definitions; do not silently
    # reuse a reserved command in MT header or existing dispatcher.
    mt_h = git(root, "show", TI_SHA + ":source/ti/zstack/mt/mt.h").decode()
    import re
    numbers = [int(n, 0) for n in re.findall(
        r"^\s*#define\s+MT_SYS_[A-Za-z_0-9]+\s+(0[xX][0-9a-fA-F]+|\d+)\b", mt_h, re.M)]
    # B1 already owns SYS F1 for its HOLD/status ABI. Reserve both B1 F1
    # and existing diagnostic F0; this new versioned query uses SYS F2.
    if 242 in numbers:
        raise ValueError("SYS F2 already reserved by pinned TI")
    sys = once(sys,
        "uint8_t MT_SysCommandProcessing(uint8_t *pBuf)",
        V4_HANDLER + "\nuint8_t MT_SysCommandProcessing(uint8_t *pBuf)")
    sys = once(sys,
        """    case 0xF0:
      if (pBuf[MT_RPC_POS_LEN] != 0)
        status = MT_RPC_ERR_LENGTH;
      else
        B4_SysReadOnlyDiagnostics();
      break;""",
        """    case 0xF0:
      if (pBuf[MT_RPC_POS_LEN] != 0)
        status = MT_RPC_ERR_LENGTH;
      else
        B4_SysReadOnlyDiagnostics();
      break;
    case 0xF2:
      if (pBuf[MT_RPC_POS_LEN] != 8u)
        status = MT_RPC_ERR_LENGTH;
      else
        B4_SysReadOnlyDiagnosticsV4(pBuf);
      break;""")
    task = once(task,
        '#include "npi_task.h"',
        '#include "npi_task.h"\n#include <ti/drivers/TRNG.h>\n#include <ti/devices/cc13x2x7_cc26x2x7/driverlib/sys_ctrl.h>')
    task = once(task,
        "void NPITask_inititializeTask(void)\n{",
        BOOT_SOURCE + "\nvoid NPITask_inititializeTask(void)\n{")
    # One-shot boot provenance precedes opening NPI UART/receiving host frames.
    task = once(task, "    NPIClient_saveNPITaskInfo(npiServiceTaskId);",
        "    NPIClient_saveNPITaskInfo(npiServiceTaskId);\n\n"
        "    B4_V4BootInitialize(); /* task context: once, before NPI UART */")
    return {MT_SYS: (originals[MT_SYS], sys),
            NPI_TASK: (originals[NPI_TASK], task)}

def apply(root):
    changes = plan(root)
    evidence = {
        "schema": "r4-b4-v4-native-overlay-v1",
        "stage": "PATCHED_DISPOSABLE_TI_NOT_NATIVE_PROOF",
        "sdk_sha": TI_SHA, "command": "SYS_F2", "request_bytes": 8,
        "payload_bytes": V4_BYTES, "boot_entropy": "TRNG_GET_RANDOM_BYTES_ONCE_IN_NPI_TASK",
        "boot_cap_on_failure": 0,
        "trng_timeout_cancellation": "CANCEL_QUEUED_JOB_BEFORE_SEMAPHORE_DESTRUCT",
        "full_image_build_digest": "NOT_CLAIMED",
        "flash_authorized": False, "physical_verified": False,
        "files": {},
    }
    for path, (before, after) in changes.items():
        (Path(root) / path).write_text(after, encoding="utf-8", newline="")
        evidence["files"][path] = {
            "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(after.encode()).hexdigest()}
    return evidence

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sdk", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    a = p.parse_args()
    receipt = apply(a.sdk)
    a.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))

if __name__ == "__main__":
    main()
