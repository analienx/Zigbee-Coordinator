"""Pinned TI 8.33 NPI/MT transport-only qualification; no device operations.

This profile deliberately never initializes NVOCMP or the Zigbee/MAC stack.
The original TI NPI UART/frame/queue owner answers genuine SYS_PING/VERSION.
The source receipt does not establish native compilation or physical delivery.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
B1_TOOLS = HERE.parent / "b1" / "tools"
sys.path.insert(0, str(B1_TOOLS))
import patch_management
from patch_zdapp import extract_function

PROFILE = "transport-only"
PROFILE_ID = "r4-p7u-transport-boot-beacon-v2"
SDK_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
MAIN = "source/ti/zstack/startup/main.c"
MT = "source/ti/zstack/mt/mt.c"
SYS = "source/ti/zstack/mt/mt_sys.c"
NPI = "source/ti/zstack/npi/npi_task.c"
UART = "source/ti/zstack/npi/npi_tl_uart.c"
PINS = dict(patch_management.PINS, **patch_management.EXTRA_PINS)
PINS.update({
    MAIN: "608adc97370be3910a96f5dcc356d0feffb79d70",
    "source/ti/zstack/npi/npi_tl_uart.h": "2d99c64a8eb04898b6a7f198c22ec30e6a17db61",
    "source/ti/zstack/npi/npi_config.h": "646a238c55e6ffc663b5b64e237d93bd678c3450",
})

MAIN_BODY = '''__attribute__((noinline)) int r4q_transport_start(void)
{
    /* TI C runtime, power/clock setup and SYS/BIOS remain genuine. */
    VIMSConfigure(VIMS_BASE, TRUE, TRUE);
#if defined(USE_CACHE_RAM)
    VIMSModeSet(VIMS_BASE, VIMS_MODE_DISABLED);
#else
    VIMSModeSet(VIMS_BASE, VIMS_MODE_ENABLED);
#endif
    Board_initGeneral();

    /* No NV API loading, initNV, stackTask_init, MAC or RF startup. */
    Semaphore_Params semParam;
    Semaphore_Params_init(&semParam);
    semParam.mode = ti_sysbios_knl_Semaphore_Mode_COUNTING;
    Semaphore_construct(&npiInitializationMutex, 0, &semParam);
    npiInitializationMutexHandle = Semaphore_handle(&npiInitializationMutex);
    if (npiInitializationMutexHandle == NULL)
    {
        r4q_transport_failed(R4Q_ERROR_NPI_SEMAPHORE);
        return 1;
    }
    /* Exactly one original NPI task and UART owner. */
    extern void NPITask_createTask(void);
    NPITask_createTask();
    BIOS_start();
    return 0;
}

int main()
{
    return r4q_transport_start();
}'''

ACCEPT = '''__attribute__((noinline)) uint8_t r4q_accept_frame(const uint8_t *frame)
{
    return frame != NULL && frame[0] == 0u && frame[1] == 0x21u &&
           (frame[2] == 1u || frame[2] == 2u);
}'''
MT_BODY = '''void MT_ProcessIncoming(uint8_t *pBuf)
{
    /* No subsystem dispatch table or mutation-capable command is reachable. */
    if (r4q_accept_frame(pBuf)) (void)MT_SysCommandProcessing(pBuf);
}'''
SYS_BODY = '''uint8_t MT_SysCommandProcessing(uint8_t *pBuf)
{
    if (pBuf == NULL || pBuf[0] != 0u || pBuf[1] != 0x21u)
        return MT_RPC_ERR_LENGTH;
    switch (pBuf[2])
    {
    case MT_SYS_PING: MT_SysPing(); return MT_RPC_SUCCESS;
    case MT_SYS_VERSION: MT_SysVersion(); return MT_RPC_SUCCESS;
    default: return MT_RPC_ERR_COMMAND_ID;
    }
}'''
SEND_BODY = '''static uint8_t NPITask_sendBufToStack( NPIMSG_msg_t *pMsg )
{
    if (pMsg == NULL) return 1u;
    if (pMsg->pBuf != NULL && pMsg->pBufSize >= MT_RPC_FRAME_HDR_SZ &&
        pMsg->pBufSize == (uint16_t)(MT_RPC_FRAME_HDR_SZ + pMsg->pBuf[0]) &&
        !r4q_transport_unavailable())
    {
        MT_ProcessIncoming((uint8 *)pMsg->pBuf);
    }
    /* Same original NPI message ownership; never forward to a stack task. */
    OsalPort_msgDeallocate(pMsg->pBuf);
    OsalPort_free(pMsg);
    return 0u;
}'''
NPI_ENTRY = '''Void NPITask_Fxn(UArg a0, UArg a1)
{
    /* No Zigbee/MT task exists in this qualification profile. */
    NPITask_task();
}'''

# One delayed, unsolicited diagnostic frame from the existing NPI/MT TX owner.
# It distinguishes UART/NPI startup from the receive/dispatch path if observed.
# A short delay lets the Ethernet-to-UART bridge accept the monitoring socket.
# This is deliberately not a normal coordinator/production frame.
NPI_TASK_BODY = '''void NPITask_task(void)
{
    NPITask_inititializeTask();
    if (!r4q_npi_initialized()) return;
    Semaphore_post(npiInitializationMutexHandle);

    /* Clock_tickPeriod is microseconds per SYS/BIOS tick. */
    Task_sleep((2000000u + Clock_tickPeriod - 1u) / Clock_tickPeriod);
    {
        uint8_t phase = 0xA7u;
        MT_BuildAndSendZToolResponse(0x41u, 0xF7u, 1u, &phase);
    }
    NPITask_process();
}'''


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text_sha(text: str) -> str:
    return sha(text.encode("utf-8"))


def once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise ValueError("TRANSPORT_PROFILE_SOURCE_DRIFT_" + label)
    return text.replace(old, new, 1)


def replace_function(text: str, signature: str, replacement: str) -> str:
    return once(text, extract_function(text, signature), replacement, signature)


def identity(source_sha: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("TRANSPORT_PROFILE_REQUIRES_FULL_SOURCE_SHA")
    return (PROFILE_ID + ":" + source_sha + "\0").encode("ascii")


def transform(texts: dict[str, str], source_sha: str) -> dict[str, str]:
    """Pure, exact-preimage validated transformation; no source writes on error."""
    marker = identity(source_sha)
    for relative, expected in PINS.items():
        if relative not in texts or patch_management.blob(texts[relative]) != expected:
            raise ValueError("TRANSPORT_PROFILE_PINNED_DONOR_MISMATCH " + relative)
    result = {}
    main = replace_function(texts[MAIN], "int main()", MAIN_BODY)
    main = once(main, '#include "nvocmp.h"',
                '#include "nvocmp.h"\n#include "r4_transport_only_support.c"\n'
                '#if !defined(NPI) || !defined(ZNP_NPI) || !defined(NPI_USE_UART)\n'
                '#error Qualification requires the original UART ZNP NPI profile\n#endif\n'
                'const char r4q_build_identity[] __attribute__((used, retain)) = "'
                + marker[:-1].decode("ascii") + '";', "MAIN_SUPPORT")
    result[MAIN] = main
    mt = replace_function(texts[MT], "void MT_ProcessIncoming(uint8_t *pBuf)", MT_BODY)
    mt = once(mt, MT_BODY, ACCEPT + "\n\n" + MT_BODY, "MT_ACCEPT_GUARD")
    result[MT] = mt
    sys_source = replace_function(texts[SYS], "uint8_t MT_SysCommandProcessing(uint8_t *pBuf)", SYS_BODY)
    # Keep the genuine donor response builders as independently auditable functions.
    for name in ("MT_SysPing", "MT_SysVersion"):
        sys_source = once(sys_source, "static void " + name + "(void)\n{",
                          "static __attribute__((noinline)) void " + name + "(void)\n{", name)
    result[SYS] = sys_source
    # Reuse the reviewed original-owner allocation, overflow and UART failure guards,
    # but remove B1 admission/status/runtime dependencies from this purpose-built profile.
    npi = patch_management.patch_npi(texts[NPI])
    npi = replace_function(npi, "Void NPITask_Fxn(UArg a0, UArg a1)", NPI_ENTRY)
    npi = replace_function(npi, "static uint8_t NPITask_sendBufToStack( NPIMSG_msg_t *pMsg )", SEND_BODY)
    npi = replace_function(npi, "void NPITask_task(void)", NPI_TASK_BODY)
    npi = once(npi, '#include <ti/drivers/dpl/ClockP.h>',
               '#include <ti/drivers/dpl/ClockP.h>\n#include <ti/sysbios/knl/Clock.h>',
               "NPI_DIAGNOSTIC_DELAY_CLOCK")
    uart = patch_management.patch_uart(texts[UART])
    # Transport-only qualification has no retained-network startup at all.
    # Preserve the original, single TI UART owner and its error handling, but
    # remove B1's startup-specific EOT hook rather than linking B1 state into
    # a supposedly isolated no-NV, no-stack diagnostic image.
    callback_signature = (
        "static void b1_startup_uart_event(UART2_Handle handle, uint32_t event,\n"
        "                                 uint32_t data, void *userArg)"
    )
    uart = once(uart, extract_function(uart, callback_signature) + "\n",
                "", "TRANSPORT_ONLY_REMOVE_B1_EOT_CALLBACK")
    uart = once(
        uart,
        "    params.eventCallback = b1_startup_uart_event;\n"
        "    params.eventMask |= UART2_EVENT_TX_FINISHED;\n",
        "", "TRANSPORT_ONLY_REMOVE_B1_EOT_SUBSCRIPTION")
    for hook in (
        "    b1_startup_tx_result((uint16_t)size, 1);\n",
        "        b1_startup_tx_submit(TransportTxBuf, TransportTxLen);\n",
        "        b1_startup_tx_accepted(TransportTxLen, b1_write_status == UART2_STATUS_SUCCESS);\n",
    ):
        uart = once(uart, hook, "", "TRANSPORT_ONLY_REMOVE_" + hook.strip())
    if "b1_startup_" in uart:
        raise ValueError("TRANSPORT_ONLY_RETAINED_STARTUP_HOOK_LEAK")
    names = {
        '"b1_management.h"': '"r4_transport_only_support.h"',
        "b1_management_transport_failed": "r4q_transport_failed",
        "b1_management_note_npi_initialized": "r4q_note_npi_initialized",
        "b1_evidence_note_npi_wake": "r4q_note_npi_wake",
        "b1_management_npi_initialized": "r4q_npi_initialized",
        "b1_management_transport_unavailable": "r4q_transport_unavailable",
        "b1_management_note_uart_opened": "r4q_note_uart_opened",
        "B1_ERROR_": "R4Q_ERROR_",
    }
    for old, new in names.items():
        npi, uart = npi.replace(old, new), uart.replace(old, new)
    npi = npi.replace("B1 management supports", "R4 qualification supports")
    if ("b1_management" in npi + uart or "B1_ERROR_" in npi + uart
            or "b1_evidence_" in npi + uart):
        raise ValueError("TRANSPORT_PROFILE_UNEXPECTED_B1_RUNTIME_DEPENDENCY")
    if npi.count("r4q_note_npi_wake();") != 1:
        raise ValueError("TRANSPORT_PROFILE_GENUINE_NPI_WAKE_HOOK_MISSING")
    result[NPI], result[UART] = npi, uart
    for name in ("r4_transport_only_support.c", "r4_transport_only_support.h"):
        content = (HERE / name).read_text(encoding="utf-8")
        result["source/ti/zstack/startup/" + name] = content
        # Quote includes resolve in the original SDK NPI source directory too.
        if name.endswith(".h"):
            result["source/ti/zstack/npi/" + name] = content
    return result


def read_donor(sdk: Path) -> dict[str, str]:
    result = {}
    for relative in PINS:
        path = sdk / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("TRANSPORT_PROFILE_DONOR_FILE_UNAVAILABLE " + relative)
        result[relative] = path.read_text(encoding="utf-8")
    return result


def apply(sdk: Path, source_sha: str, receipt: Path) -> dict:
    if receipt.exists() or receipt.is_symlink():
        raise ValueError("TRANSPORT_PROFILE_RECEIPT_EXISTS")
    originals = read_donor(sdk)
    changed = transform(originals, source_sha)
    # Check all outputs first; caller must supply a disposable unmodified SDK.
    for relative in changed:
        path = sdk / relative
        if path.is_symlink() or (relative not in originals and path.exists()):
            raise ValueError("TRANSPORT_PROFILE_OUTPUT_EXISTS_OR_SYMLINK " + relative)
    report = {
        "schema": "r4-p7u-transport-profile-source-v1",
        "profile": PROFILE,
        "profile_id": PROFILE_ID,
        "source_sha": source_sha,
        "ti_sdk_sha": SDK_SHA,
        "donor_git_blobs": PINS,
        "changed_sources_sha256": {name: text_sha(text) for name, text in changed.items()},
        "profile_build_identity": identity(source_sha)[:-1].decode("ascii"),
        "allowed_requests": [{"cmd0": "0x21", "cmd1": "0x01", "length": 0},
                             {"cmd0": "0x21", "cmd1": "0x02", "length": 0}],
        "nv_initialization": False,
        "zigbee_stack_initialization": False,
        "extra_uart_owner": False,
        "requires_generated_board_audit": True,
        "status": "SOURCE_ONLY_NATIVE_AND_BOARD_PROOF_REQUIRED",
        "native_compilation_verified": False,
        "physical_uart_verified": False,
        "network_commissioned": False,
        "flash_authorized": False,
    }
    for relative, content in changed.items():
        (sdk / relative).write_text(content, encoding="utf-8", newline="\n")
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    result = apply(args.sdk, args.source_sha, args.receipt)
    print(json.dumps({key: result[key] for key in ("status", "profile", "source_sha", "flash_authorized")}))


if __name__ == "__main__":
    main()
