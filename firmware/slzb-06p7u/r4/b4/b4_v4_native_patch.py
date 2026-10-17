"""B4 v4 isolated candidate: additive F1 alongside unchanged, proven F0.

Applies ONLY after b4_native_patch.py's exact source-verified v3 overlay in
a disposable exact-SHA TI 8.33 SDK. One-shot opportunistic TRNG in the
existing NPI task before its ready semaphore (finite timeout), never from
the MT command handler; failed crypto leaves boot capability bit0 clear.
Hardware/stack/fairness are NOT qualified by a hosted build.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from b4_native_patch import TI_SHA, MT_SYS, NPI_TASK, NPI_UART
from b4_v4_protocol import V4_RESPONSE_BYTES

MARKER = "B4_V4_NONCE_AND_BOOT_DIAGNOSTICS"
TRNG_HEADER = "source/ti/drivers/TRNG.h"

V4_BOOT_INIT = r"""
/* B4_V4_NONCE_AND_BOOT_DIAGNOSTICS: boot identity from bounded one-shot
 * hardware TRNG attempt. No entropy work, NV access or retry in SYS F1.
 * A failure leaves the radio epoch capability EXPLICITLY unavailable.
 */
volatile uint32_t B4_V4BootLo = 0;
volatile uint32_t B4_V4BootHi = 0;
volatile uint32_t B4_V4ResetReason = 0;
volatile uint32_t B4_V4BootReady = 0;
static void B4_V4InitializeBootOnce(void)
{
    uint8_t bytes[8] = {0};
    uint32_t reason = SysCtrlResetSourceGet();
    TRNG_Params params;
    TRNG_Handle handle;
    int_fast16_t status;
    uint32_t lo, hi, key;
    /* This task initialization path executes once per radio firmware boot. */
    B4_V4ResetReason = reason;
    TRNG_init();
    TRNG_Params_init(&params);
    params.returnBehavior = TRNG_RETURN_BEHAVIOR_BLOCKING;
    /* Clock_tickPeriod is microseconds, semaphoreTimeout uses RTOS ticks.
     * Bound NPI startup delay to <=100ms, never WAIT_FOREVER. */
    params.timeout = (100000u + Clock_tickPeriod - 1u) / Clock_tickPeriod;
    handle = TRNG_open(0, &params);
    if (handle == NULL)
        return;
    status = TRNG_getRandomBytes(handle, bytes, sizeof(bytes));
    if (status != TRNG_STATUS_SUCCESS)
    {
        /* Pinned TRNGCC26XX_waitForResult may return after SemaphoreP timeout
         * while the entropy job is STILL queued. Cancel it before close;
         * never destroy an operationSemaphore with a live ISR producer. */
        TRNG_cancelOperation(handle);
        TRNG_close(handle);
        return;
    }
    TRNG_close(handle);
    lo = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8)
         | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
    hi = (uint32_t)bytes[4] | ((uint32_t)bytes[5] << 8)
         | ((uint32_t)bytes[6] << 16) | ((uint32_t)bytes[7] << 24);
    if ((lo | hi) == 0u)
        return;
    key = OsalPort_enterCS();
    B4_V4BootLo = lo;
    B4_V4BootHi = hi;
    B4_V4BootReady = 1u;
    OsalPort_leaveCS(key);
}
"""
V4_HANDLER = r"""
/* B4_V4_NONCE_AND_BOOT_DIAGNOSTICS: 160B, exact 8B host nonce echo.
 * Source fingerprint is a provenance tag of the overlay generator, not an
 * attestation of the compiled ELF, and must not be called a binary digest.
 */
extern volatile uint32_t B4_V4BootLo, B4_V4BootHi, B4_V4ResetReason, B4_V4BootReady;
static uint32_t B4_V4SampleSequence = 0;
__attribute__((noinline)) static void B4_V4ReadOnlyDiagnostics(const uint8_t *nonce)
{
    uint8_t payload[160] = {0};
    uint32_t values[6];
    uint32_t seq, bootlo, boothi, ready, resetreason, key;
    uint8_t i;
    key = OsalPort_enterCS();
    values[0] = B4_NpiSrspDepth;
    values[1] = B4_NpiSrspHighWater;
    values[2] = B4_NpiAsyncDepth;
    values[3] = B4_NpiAsyncHighWater;
    values[4] = B4_NpiSrspEnqueued;
    values[5] = B4_NpiUartTxFinishedEvents;
    bootlo = B4_V4BootLo;
    boothi = B4_V4BootHi;
    ready = B4_V4BootReady;
    resetreason = B4_V4ResetReason;
    seq = ++B4_V4SampleSequence;
    OsalPort_leaveCS(key);
    payload[0] = 'R'; payload[1] = '4'; payload[2] = 'D'; payload[3] = '4';
    payload[4] = 4;       /* ABI major 4 */
    payload[6] = 160;     /* explicit exact length LE */
    payload[8] = (uint8_t)(2u | ((ready != 0u) ? 1u : 0u)); /* nonce + boot */
    payload[12] = 0x2C;  /* async NPI 2,3 + UART TX pin event index5 */
#if defined(NPI_SREQRSP)
    payload[12] = 0x3F;  /* all six proven NPI/UART metric producers */
    B4_DiagPutU32(payload + 32, values[0]);
    B4_DiagPutU32(payload + 36, values[1]);
    B4_DiagPutU32(payload + 48, values[4]);
#endif
    B4_DiagPutU32(payload + 40, values[2]);
    B4_DiagPutU32(payload + 44, values[3]);
    B4_DiagPutU32(payload + 52, values[5]);
    B4_DiagPutU32(payload + 28, seq);
    if (ready != 0u) {
        B4_DiagPutU32(payload + 16, bootlo);
        B4_DiagPutU32(payload + 20, boothi);
        payload[154] = 1u; /* boot status: entropy generated this boot */
    }
    /* uptime=0 until a source-qualified monotonic provider is added. */
    for (i = 0; i < 8u; ++i)
        payload[132u + i] = nonce[i];  /* no key, no EUI, no PAN or RF */
    B4_DiagPutU32(payload + 140, resetreason);
    B4_DiagPutU32(payload + 144, __B4_V4_FP_LO__);
    B4_DiagPutU32(payload + 148, __B4_V4_FP_HI__);
    /* minor 0, reserved bits 0; no fake ABI extensions. */
    MT_BuildAndSendZToolResponse(MT_SRSP_SYS, 0xF1, sizeof(payload), payload);
}
"""

def _git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args],
                                   stderr=subprocess.DEVNULL)

def plan(root, v3_receipt):
    root = Path(root)
    if not root.is_dir() or root.is_symlink() or not str(root.resolve()).startswith("/tmp/"):
        raise ValueError("v4 candidate source restricted to disposable /tmp pinned SDK")
    if _git(root, "rev-parse", "HEAD").decode().strip() != TI_SHA:
        raise ValueError("pinned TI source mismatch")
    old = json.loads(Path(v3_receipt).read_text())
    if (old.get("ti_sha") != TI_SHA or
        old.get("stage") != "PATCHED_DISPOSABLE_SDK_NOT_LINKED" or
        old.get("f0_opcode") != "0xF0" or
        old.get("valid_counter_indices") != [0,1,2,3,4,5] or
        set(old.get("written", {})) != {MT_SYS, NPI_TASK, NPI_UART}):
        raise ValueError("genuine preceding B4 v3 patch receipt required")
    original = {}
    for path in (MT_SYS, NPI_TASK, NPI_UART):
        f = root / path
        if not f.is_file() or f.is_symlink():
            raise ValueError("pinned TI source path unavailable")
        data = f.read_bytes()
        if hashlib.sha256(data).hexdigest() != old["written"][path]["after_sha256"]:
            raise ValueError("v3 source SHA mismatch, no v4 patch")
        src = _git(root, "show", TI_SHA + ":" + path)
        if hashlib.sha256(src).hexdigest() != old["written"][path]["before_sha256"]:
            raise ValueError("v3 native receipt cannot bind pinned upstream")
        original[path] = data.decode("utf-8")
    rng = _git(root, "show", TI_SHA + ":" + TRNG_HEADER).decode()
    if not all(key in rng for key in ("TRNG_getRandomBytes(", "TRNG_open(",
               "TRNG_close(", "TRNG_cancelOperation(", "TRNG_Params_init(", "TRNG_STATUS_SUCCESS",
               "TRNG_RETURN_BEHAVIOR_BLOCKING", "timeout")):
        raise ValueError("TRNG pinned 8.33 API incompatible")
    sys = original[MT_SYS]
    task = original[NPI_TASK]
    if MARKER in sys or MARKER in task or "case 0xF1:" in sys:
        raise ValueError("v4 source already added or collision")
    if sys.count("uint8_t MT_SysCommandProcessing(uint8_t *pBuf)") != 1:
        raise ValueError("TI dispatcher source drift")
    if task.count("void NPITask_task(void)\n{") != 1:
        raise ValueError("NPI task bootstrap source drift")
    if task.count("    NPITask_inititializeTask();") != 1 or task.count("    Semaphore_post(npiInitializationMutexHandle);") != 1:
        raise ValueError("NPI task init/ready handshake source drift")
    if task.find("    NPITask_inititializeTask();") >= task.find("    Semaphore_post(npiInitializationMutexHandle);"):
        raise ValueError("NPI ready signal precedes initialized task")
    if "B4_NpiSrspDepth" not in sys or "B4_NpiUartTxFinishedEvents" not in sys:
        raise ValueError("v3 native B4 queue/UART metric dependency absent")
    from b4_native_patch import B4_FUNCTION
    if B4_FUNCTION not in sys:
        raise ValueError("full unaltered v3 native diagnostics handler required")
    fingerprint = hashlib.sha256((V4_BOOT_INIT + V4_HANDLER + TI_SHA).encode()).digest()[:8]
    tag = int.from_bytes(fingerprint, "little")
    if tag == 0:
        raise ValueError("zero source fingerprint")
    handler = V4_HANDLER.replace("__B4_V4_FP_LO__", str(tag & 0xffffffff) + "u").replace(
        "__B4_V4_FP_HI__", str((tag >> 32) & 0xffffffff) + "u")
    sys = sys.replace("uint8_t MT_SysCommandProcessing(uint8_t *pBuf)",
                      handler + "\nuint8_t MT_SysCommandProcessing(uint8_t *pBuf)", 1)
    dispatch = "    case 0xF0:\n      if (pBuf[MT_RPC_POS_LEN] != 0)"
    if sys.count(dispatch) != 1:
        raise ValueError("v3 exact F0 LEN gate changed")
    sys = sys.replace(dispatch, """    case 0xF1:
      if (pBuf[MT_RPC_POS_LEN] != 8)
        status = MT_RPC_ERR_LENGTH;
      else
        B4_V4ReadOnlyDiagnostics(pBuf + MT_RPC_POS_DAT0);
      break;
""" + dispatch, 1)
    includes = '#include "npi_task.h"'
    if task.count(includes) != 1:
        raise ValueError("NPI task include anchor moved")
    task = task.replace(includes, includes +
        '\n#include <ti/drivers/TRNG.h>\n#include <driverlib/sys_ctrl.h>', 1)
    task = task.replace("void NPITask_task(void)\n{", V4_BOOT_INIT + "\nvoid NPITask_task(void)\n{", 1)
    task = task.replace("    NPITask_inititializeTask();",
        "    NPITask_inititializeTask();\n    B4_V4InitializeBootOnce();", 1)
    return {MT_SYS: (original[MT_SYS], sys), NPI_TASK: (original[NPI_TASK], task)}, tag

def apply(root, v3_receipt):
    changes, tag = plan(root, v3_receipt)
    receipt = {
        "schema": "r4-b4-v4-native-addon-v1",
        "stage": "SOURCE_PATCHED_NOT_NATIVE_LINKED",
        "parent_v3_verified": True,
        "ti_sha": TI_SHA,
        "opcode": "0xF1",
        "response_length": V4_RESPONSE_BYTES,
        "request_nonce_bytes": 8,
        "source_fingerprint64": "0x%016x" % tag,
        "entropy_policy": "ONE_SHOT_IN_NPI_START_BEFORE_READY;TICK_CONVERTED_TIMEOUT;CANCEL_BEFORE_CLOSE;FAIL_CLOSED",
        "boot_epoch": "UNVERIFIED_UNTIL_TRUE_NATIVE_AND_PHYSICAL",
        "host_installed": False,
        "written": {},
    }
    for path, (old, new) in changes.items():
        (Path(root) / path).write_text(new, encoding="utf-8", newline="")
        receipt["written"][path] = {
            "before_sha256": hashlib.sha256(old.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(new.encode()).hexdigest(),
        }
    return receipt

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sdk", type=Path, required=True)
    p.add_argument("--v3-receipt", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    args = p.parse_args()
    result = apply(args.sdk, args.v3_receipt)
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
