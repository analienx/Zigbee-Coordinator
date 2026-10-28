#!/usr/bin/env python3
"""Source-pinned NPI UART TX error-unwind on the accepted P7U R4 composite.

Repairs a conditional TI 8.33 dead-busy path. No timeouts, retries, resets,
new serial owners, radio parameters, RF, NV, CCFG, or security modifications.
"""
from pathlib import Path
import hashlib
import subprocess

TL = "source/ti/zstack/npi/npi_tl.c"
UART = "source/ti/zstack/npi/npi_tl_uart.c"
MARKER = "B4_R4_UART_TX_ERROR_UNWIND_V1"
TI_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"

def pinned_source(sdk, relative):
    """Bind inspected bytes to the immutable SDK, including dirty trees."""
    path = sdk / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError("TI_UART2_UNTRUSTED_SOURCE_" + relative)
    original = subprocess.check_output(
        ["git", "-C", str(sdk), "show", TI_SHA + ":" + relative],
        stderr=subprocess.PIPE)
    actual = path.read_bytes()
    if actual != original:
        raise ValueError("TI_UART2_PINNED_BYTES_DRIFT_" + relative)
    return actual

def once(s: str, before: str, after: str, name: str) -> str:
    n = s.count(before)
    if n != 1:
        raise ValueError(f"UART_TX_LIVENESS_SOURCE_DRIFT_{name}_{n}")
    return s.replace(before, after, 1)

def extract(s: str, signature: str) -> str:
    anchor = signature + "\n{"
    if s.count(anchor) != 1:
        raise ValueError("UART_TX_LIVENESS_FUNCTION_AMBIGUOUS_" + signature)
    pos = s.index(anchor)
    depth = 0
    for k in range(pos + len(signature) + 1, len(s)):
        if s[k] == "{":
            depth += 1
        elif s[k] == "}":
            depth -= 1
            if depth == 0:
                return s[pos:k + 1]
    raise ValueError("UART_TX_LIVENESS_FUNCTION_UNBALANCED_" + signature)

def verify_ti_uart2_callback_ownership(sdk):
    """Verify exact pinned TI software completion guards, without changing driver."""
    sdk = Path(sdk)
    driver_bytes = pinned_source(sdk, "source/ti/drivers/uart2/UART2CC26X2.c")
    common_bytes = pinned_source(sdk, "source/ti/drivers/UART2.c")
    driver = driver_bytes.decode("utf-8")
    common = common_bytes.decode("utf-8")
    success = extract(driver, "static void UART2CC26X2_hwiIntWrite(uintptr_t arg)")
    if (success.count("(object->writeCount == 0) && object->writeInUse") != 1
            or success.count("object->writeCallback(handle,") != 1
            or success.count("object->writeInUse = false;") != 1):
        raise ValueError("TI_UART2_SUCCESS_SINGLE_CALLBACK_GUARD_DRIFT")
    if success.index("object->writeInUse = false;") > success.index("object->writeCallback(handle,"):
        raise ValueError("TI_UART2_SUCCESS_CALLBACK_OWNERSHIP_ORDER")
    cancel = extract(common, "void __attribute__((weak)) UART2_writeCancel(UART2_Handle handle)")
    if (cancel.count("if (object->writeInUse)") != 1
            or cancel.count("object->writeCallback(handle,") != 1
            or "UART2_STATUS_ECANCELLED" not in cancel):
        raise ValueError("TI_UART2_CANCEL_SINGLE_CALLBACK_GUARD_DRIFT")
    if cancel.index("object->writeInUse = false;") > cancel.index("object->writeCallback(handle,"):
        raise ValueError("TI_UART2_CANCEL_CALLBACK_OWNERSHIP_ORDER")
    if ("return UART2_STATUS_EINUSE;" not in common or
            "object->writeInUse          = true;" not in common):
        raise ValueError("TI_UART2_WRITE_IN_USE_ADMISSION_DRIFT")
    return {
        "schema": "p7u-ti-8_33-callback-ownership-v2",
        "ti_sdk_sha": TI_SHA,
        "source_bytes_equal_pinned_git_blobs": True,
        "uart2_driver_sha256": hashlib.sha256(driver_bytes).hexdigest(),
        "uart2_generic_sha256": hashlib.sha256(common_bytes).hexdigest(),
        "normal": "IN_USE_AND_ZERO_COUNT_CLEARED_BEFORE_CALLBACK",
        "cancel": "IN_USE_CLEARED_BEFORE_CALLBACK",
        "physical_irq_duplication_disproved": False,
        "hardware_or_nv_changed": False,
    }


def apply(sdk):
    sdk = Path(sdk)
    originals = {name: (sdk / name).read_text(encoding="utf-8") for name in (TL, UART)}
    t, u = originals[TL], originals[UART]
    if MARKER in t or MARKER in u:
        raise ValueError("UART_TX_LIVENESS_ALREADY_APPLIED")
    if "static volatile bool npiTxActive = FALSE;" not in t:
        raise ValueError("UART_TX_LIVENESS_MISSING_BUSY_STATE")
    # Mark TX non-busy ONLY if the lower-layer UART did not accept the write.
    original = extract(t, "uint16 NPITL_writeTL(uint8 *buf, uint16 len)")
    altered = once(original,
        "    len = transportWrite(npiTxBufLen);",
        """    len = transportWrite(npiTxBufLen);
    if (len == 0u)
    {
        /* B4_R4_UART_TX_ERROR_UNWIND_V1: no UART callback will complete a
         * synchronously rejected write. Discard unstarted fragments; keep
         * npiTxActive FALSE. B1 physical HOLD, if latched, still forbids
         * subsequent UART writes; this does not recover the transport. */
        npiTxActive = FALSE;
        npiTxBufLen = 0u;
        msgFrag = NULL;
        msgFragLen = 0u;
    }""",
        "SYNC_FAILURE_RELEASE")
    t = once(t, original, altered, "WRITE_FUNCTION")

    # The driver callback owns one already-accepted write. On failure it
    # must not report a successful TX, but must release the NPI busy state
    # and notify the existing task. B1 HOLD still blocks physical writes.
    hook = """/* B4_R4_UART_TX_ERROR_UNWIND_V1: called on failed UART completion only.
 * Caller holds no radio/network state locks; notification posts existing
 * NPI task event. An immediate write failure is handled in NPITL_writeTL. */
void NPITL_abortFailedTx(void)
{
    uint32_t key = OsalPort_enterCS();
    npiTxActive = FALSE;
    npiTxBufLen = 0u;
    msgFrag = NULL;
    msgFragLen = 0u;
    OsalPort_leaveCS(key);
    if (taskTxCB != NULL)
    {
        taskTxCB(0);
    }
}

"""
    t = once(t,
        "uint16 NPITL_readTL(uint8 *buf, uint16 len)\n{",
        hook + "uint16 NPITL_readTL(uint8 *buf, uint16 len)\n{",
        "ABORT_FUNCTION")
    callback = extract(u, "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)")
    # B1 already stops the write callback on a genuine UART failure and
    # latches physical transport HOLD. Unwind the lower-layer busy state
    # on that *actual* early-return path; never weaken B1 HOLD or claim TX.
    if ("b1_management_transport_failed(B1_ERROR_UART_WRITE);" not in callback
            or "b1_startup_tx_result((uint16_t)size, 1);" not in callback):
        raise ValueError("UART_TX_LIVENESS_B1_FAIL_CLOSED_PREIMAGE_DRIFT")
    updated = once(callback,
        """        OsalPort_leaveCS(key);
        return; /* Do not claim completed host write after failure. */""",
        """        OsalPort_leaveCS(key);
        NPITL_abortFailedTx(); /* preserve B1 HOLD; no false TX completion */
        return; /* Do not claim completed host write after failure. */""",
        "B1_CALLBACK_EARLY_FAILURE_UNWIND")
    u = once(u, callback, updated, "CALLBACK_FUNCTION")
    u = once(u,
        "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status);",
        """/* B4_R4_UART_TX_ERROR_UNWIND_V1: original NPI TL remains sole owner. */
extern void NPITL_abortFailedTx(void);
static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status);""",
        "CALLBACK_DECLARATION")
    modified = {TL: t, UART: u}
    for name, content in modified.items():
        (sdk / name).write_text(content, encoding="utf-8", newline="")
    return {
        "schema": "p7u-r4-uart-tx-error-unwind-v1",
        "source_only": True,
        "network_nv_or_security_mutation": False,
        "single_physical_uart_owner": True,
        "on_sync_reject": "clear_busy_and_unstarted_fragments",
        "on_async_callback_failure": "clear_busy_and_post_existing_npi_task",
        "before_sha256": {name: hashlib.sha256(content.encode()).hexdigest() for name, content in originals.items()},
        "modified_sha256": {name: hashlib.sha256(content.encode()).hexdigest() for name, content in modified.items()},
    }
