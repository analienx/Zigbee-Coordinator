"""Exact pinned TI existing-owner HOLD management overlay, no device access.

prepare() validates all preimages before the caller writes any file. F0 is
reserved unchanged. F1 is a distinct strict B1 status ABI; no stock herdsman
integration or physical transport claim is made by this source overlay.
"""
import hashlib
import re

PINS = {
    "source/ti/zstack/mt/mt.c": "a106d1cef7a666ed285478443c2ca2b220c7fb03",
    "source/ti/zstack/mt/mt.h": "0435d72c67a2f280c3069de2fcd87a6b88b4dc21",
    "source/ti/zstack/mt/mt_sys.c": "ef45121d6276d9c78da577f6153800cbdb45df9c",
    "source/ti/zstack/mt/mt_rpc.h": "69333bfe5a5b945e88ed81999261f0490c552d83",
    "source/ti/zstack/npi/npi_task.c": "5cdf187965fa6700554dc390f64abd7c69cdfa44",
    "source/ti/zstack/startup/zstackstartup.c": "72073f7a90d3de183533e84c3396e239343731e5",
}
HERDSMAN_PIN = "0968f979d558874b17396c96b66382d4236bbdcd"
HERDSMAN_BLOB = "d24d1e10e7025b140c2b9b16ea24f635d9c5ce62"
HERDSMAN_PATH = "src/adapter/z-stack/znp/definition.ts"


def blob(text):
    raw = text.encode("utf-8")
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def once(text, before, after, label):
    if text.count(before) != 1:
        raise RuntimeError("BLOCKED: B1 management anchor " + label)
    return text.replace(before, after, 1)


def audit_collision(mt_h, definition):
    if blob(definition) != HERDSMAN_BLOB:
        raise RuntimeError("BLOCKED: B1 herdsman exact blob mismatch")
    sys_body = definition.split("[Subsystem.SYS]: [", 1)[1].split("[Subsystem.MAC]: [", 1)[0]
    ids = [int(n) for n in re.findall(r"\bID:\s*(\d+)", sys_body)]
    ti_ids = [int(n, 16) for n in re.findall(r"^#define\s+MT_SYS_\w+\s+(0x[0-9A-Fa-f]+)\s*$", mt_h, re.M)]
    if not ids or 0xF1 in ids or 0xF1 in ti_ids or 0xF0 in ti_ids:
        raise RuntimeError("BLOCKED: F1 collision or F0 reservation changed")
    return {"command": "MT SYS 0xF1", "f0": "unchanged/reserved",
            "herdsman_blob": HERDSMAN_BLOB, "herdsman_max_sys_id": max(ids),
            "herdsman_sys_entries": len(ids)}


def patch_mt(text):
    text = once(text, '#include "mt.h"', '#include "mt.h"\n#include "b1_management.h"', "MT header")
    return once(text, "  /* check length */\n", """  /* B1 existing MT owner: read-only status or bounded HOLD rejection. */
  {
    uint8_t b1_reply[B1_STATUS_REPLY_SIZE];
    uint8_t b1_error = MT_RPC_ERR_PARAMETER;
    uint8_t b1_action = b1_management_mt_filter(pBuf, b1_reply, &b1_error);
    if (b1_action != B1_MT_CONTINUE)
    {
      if (b1_action == B1_MT_STATUS)
        MT_BuildAndSendZToolResponse(0x61u, B1_STATUS_COMMAND,
                                    B1_STATUS_REPLY_SIZE, b1_reply);
      else if (b1_action == B1_MT_REJECT &&
               ((rsp[1] & MT_RPC_CMD_TYPE_MASK) == MT_RPC_CMD_SREQ))
      {
        rsp[0] = b1_error;
        MT_BuildAndSendZToolResponse(((uint8_t)MT_RPC_CMD_SRSP |
                                     (uint8_t)MT_RPC_SYS_RES0), 0,
                                    MT_RPC_FRAME_HDR_SZ, rsp);
      }
      return;
    }
  }

  /* check length */
""", "MT dispatch")


def patch_npi(text):
    text = once(text, '#include "npi_task.h"', '#include "npi_task.h"\n#include "b1_management.h"\n'
                '#if defined(NPI_SREQRSP) || (NPI_FLOW_CTRL != 0)\n'
                '#error B1 management supports pinned UART flow-off non-NPI_SREQRSP profile only\n#endif', "NPI header")
    text = once(text, "    npiRxQueue = Queue_create(NULL, NULL);", """    npiRxQueue = Queue_create(NULL, NULL);
    if (npiTxQueue == NULL || npiRxQueue == NULL)
    {
        if (npiTxQueue != NULL) Queue_delete(&npiTxQueue);
        if (npiRxQueue != NULL) Queue_delete(&npiRxQueue);
        b1_management_transport_failed(B1_ERROR_NPI_QUEUE);
        return;
    }""", "NPI queue allocation")
    text = once(text, "    npiSemHandle = Semaphore_handle(&structSem);", """    npiSemHandle = Semaphore_handle(&structSem);
    if (npiSemHandle == NULL)
    {
        b1_management_transport_failed(B1_ERROR_NPI_SEMAPHORE);
        return;
    }""", "NPI semaphore")
    text = once(text, "    npiServiceTaskId = OsalPort_registerTask(Task_self(), npiSemHandle, &npiServiceTaskEvents);", """    npiServiceTaskId = OsalPort_registerTask(Task_self(), npiSemHandle, &npiServiceTaskEvents);
    if (npiServiceTaskId >= 15u) /* pinned OSAL provider MAX_TASKS */
    {
        b1_management_transport_failed(B1_ERROR_NPI_REGISTER);
        return;
    }""", "NPI registered task")
    text = once(text, "                  &NPITask_MRDYEventCB );", "                  &NPITask_MRDYEventCB );\n"
                "    b1_management_note_npi_initialized();", "NPI initialized")
    text = once(text, "    NPITask_inititializeTask();\n\n    Semaphore_post(npiInitializationMutexHandle);", """    NPITask_inititializeTask();
    if (!b1_management_npi_initialized()) return; /* NOT_OBSERVABLE */

    Semaphore_post(npiInitializationMutexHandle);""", "NPI bounded initialization exit")
    text = once(text, "    MTServiceTaskID = MTTask_getServiceTaskId();", """    if (!b1_management_get_hold_active())
    {
        if (!b1_management_mt_registered())
            b1_management_transport_failed(B1_ERROR_MT_NOT_REGISTERED);
        else
            MTServiceTaskID = MTTask_getServiceTaskId();
    }
    /* HOLD has no stack/MT task registration. Its frames stay with this
     * original NPI owner and enter the gated real MT dispatcher below. */""", "NPI hold does not read unregistered MT task")
    text = once(text, "    uint8 *pReq = (uint8 *)pMsg->pBuf;", """    uint8 *pReq = (uint8 *)pMsg->pBuf;
    if (b1_management_get_hold_active())
    {
        MT_ProcessIncoming(pReq);
        OsalPort_msgDeallocate(pMsg->pBuf);
        OsalPort_free(pMsg);
        return 0;
    }""", "NPI hold stays in existing owner")
    # Stock TI flow-off RX callback spins forever when the ring buffer fills.
    # The parser cannot safely re-synchronize after losing an arbitrary byte.
    # Stop receiving/parsing; do not form an unbounded ISR busy-loop and do
    # not claim management status is observable after transport corruption.
    text = once(text,
        "static void NPITask_transportRXCallBack(int size)\n{",
        "static void NPITask_transportRXCallBack(int size)\n{\n"
        "    if (b1_management_transport_unavailable()) return;\n"
        "    if (size <= 0)\n"
        "    {\n"
        "        if (size < 0)\n"
        "            b1_management_transport_failed(B1_ERROR_NPI_RX_OVERFLOW);\n"
        "        return;\n"
        "    }", "NPI RX callback refuses invalid/failed input")
    text = once(text,
        "        // Trap here for pending buffer overflow. If NPI_FLOW_CTRL is\n"
        "        // enabled, increase size of RxBuf to handle larger frames from host.\n"
        "        for(;;);",
        "        /* Lost bytes make the parser unsafe. Sticky transport HOLD:\n"
        "         * drop remaining traffic instead of spinning in an ISR. */\n"
        "        b1_management_transport_failed(B1_ERROR_NPI_RX_OVERFLOW);\n"
        "        return;",
        "NPI overflow no infinite loop")
    # Do not parse incomplete bytes or repeatedly repost the RX event once
    # the transport is irreversibly unavailable.
    text = once(text,
        "                NPIFrame_collectFrameData();\n\n"
        "                if (NPIRxBuf_GetRxBufCount() == 0)",
        "                if (b1_management_transport_unavailable())\n"
        "                {\n"
        "                    npiServiceTaskEvents &= ~NPITASK_TRANSPORT_RX_EVENT;\n"
        "                }\n"
        "                else\n"
        "                {\n"
        "                    NPIFrame_collectFrameData();\n"
        "                }\n\n"
        "                if (b1_management_transport_unavailable() ||\n"
        "                    NPIRxBuf_GetRxBufCount() == 0)",
        "NPI parser cannot resume after lost bytes")
    # An already-queued framed request must not be sent to MT/stack after
    # a transport corruption event. Return ownership to the original queue.
    text = once(text,
        "    recPtr = Queue_dequeue(npiRxQueue);\n\n"
        "    if (recPtr != NULL)",
        "    recPtr = Queue_dequeue(npiRxQueue);\n\n"
        "    if (recPtr != NULL && b1_management_transport_unavailable())\n"
        "    {\n"
        "        OsalPort_msgDeallocate(recPtr->npiMsg->pBuf);\n"
        "        OsalPort_free(recPtr->npiMsg);\n"
        "        OsalPort_free(recPtr);\n"
        "        return;\n"
        "    }\n"
        "    if (recPtr != NULL)",
        "NPI queued frame ownership on transport loss")
    text = once(text,
        "static void NPITask_incomingFrameCB(uint8_t frameSize, uint8_t *pFrame,\n"
        "                                    NPIMSG_Type msgType)\n{",
        "static void NPITask_incomingFrameCB(uint8_t frameSize, uint8_t *pFrame,\n"
        "                                    NPIMSG_Type msgType)\n{\n"
        "    if (b1_management_transport_unavailable())\n"
        "    {\n"
        "        OsalPort_msgDeallocate(pFrame);\n"
        "        return;\n"
        "    }",
        "NPI drop incoming framed data after transport loss")
    # With only one allocation succeeding, stock TI leaked the other
    # object and the incoming frame. The bounded failure is sticky instead.
    text = once(text,
        "    if ((recPtr != NULL) && (npiMsgPtr != NULL))",
        "    if ((recPtr != NULL) && (npiMsgPtr != NULL))",
        "NPI callback allocation exact-body anchor")
    start = "static void NPITask_incomingFrameCB(uint8_t frameSize, uint8_t *pFrame,\n                                    NPIMSG_Type msgType)\n{"
    end = "// -----------------------------------------------------------------------------\n//! \\brief      RX Callback provided to Transport Layer for RX Event"
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError("BLOCKED: NPI callback end boundaries changed")
    before, after = text.split(end, 1)
    old = "    }\n}\n\n"
    replacement = ("    }\n"
        "    else\n"
        "    {\n"
        "        if (recPtr != NULL) OsalPort_free(recPtr);\n"
        "        if (npiMsgPtr != NULL) OsalPort_free(npiMsgPtr);\n"
        "        OsalPort_msgDeallocate(pFrame);\n"
        "        b1_management_transport_failed(B1_ERROR_NPI_QUEUE);\n"
        "    }\n"
        "}\n\n")
    start_index = before.rfind(start)
    if start_index < 0 or before[start_index:].count(old) != 1 or not before.endswith(old):
        raise RuntimeError("BLOCKED: NPI callback terminator changed")
    text = before[:-len(old)] + replacement + end + after
    return text


def patch_uart(text):
    text = once(text, '#include "npi_tl_uart.h"', '#include "npi_tl_uart.h"\n#include "b1_management.h"', "UART header")
    text = once(text, "    uartHandle = UART2_open(CONFIG_DISPLAY_UART, &params);", """    uartHandle = UART2_open(CONFIG_DISPLAY_UART, &params);
    if (uartHandle == NULL)
    {
        b1_management_transport_failed(B1_ERROR_UART_OPEN);
        return;
    }
    b1_management_note_uart_opened();""", "UART NULL before read")
    # Initial read arming is the only readTransport call for the pinned flow-off
    # profile. A failed initial read may not count as an initialized transport.
    anchor = "    TransportRxLen = 0;\n    UART2_read(uartHandle, &isrRxBuf[0], UART_ISR_BUF_SIZE, NULL);"
    # Two occurrences include the callback re-arm and the public read function.
    if text.count(anchor) != 2:
        raise RuntimeError("BLOCKED: UART read/re-arm anchors changed")
    text = text.replace(anchor, """    TransportRxLen = 0;
    /* Read callback may have just latched HOLD after lost bytes. Re-arming
     * that UART would cause an unbounded stream of corrupt callbacks. */
    if (!b1_management_transport_unavailable() &&
        UART2_read(uartHandle, &isrRxBuf[0], UART_ISR_BUF_SIZE, NULL) != UART2_STATUS_SUCCESS)
        b1_management_transport_failed(B1_ERROR_UART_READ);""")
    text = once(text,
        "    key = OsalPort_enterCS();\n\n    if (size)",
        "    key = OsalPort_enterCS();\n"
        "    if (status != UART2_STATUS_SUCCESS)\n"
        "    {\n"
        "        /* A UART driver error can invalidate delivered bytes. */\n"
        "        b1_management_transport_failed(B1_ERROR_UART_READ);\n"
        "        OsalPort_leaveCS(key);\n"
        "        return; /* No copy, NPI callback, or UART read rearm. */\n"
        "    }\n"
        "    if (b1_management_transport_unavailable())\n"
        "    {\n"
        "        OsalPort_leaveCS(key);\n"
        "        return; /* No reads/responses from failed physical transport */\n"
        "    }\n\n    if (size)",
        "UART callback cannot revive transport after RX loss")
    # Both async completion and synchronous submission must report failed TX.
    # Never claim a host SRSP was actually transmitted after UART2 failure.
    text = once(text,
        """static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)
{
    uint32_t key;
    key = OsalPort_enterCS();""",
        """static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)
{
    uint32_t key;
    key = OsalPort_enterCS();
    if (status != UART2_STATUS_SUCCESS || b1_management_transport_unavailable())
    {
        if (status != UART2_STATUS_SUCCESS)
            b1_management_transport_failed(B1_ERROR_UART_WRITE);
        OsalPort_leaveCS(key);
        return; /* Do not claim completed host write after failure. */
    }""", "UART TX callback completion status")
    text = once(text,
        """    if(UART2_write(uartHandle, TransportTxBuf, TransportTxLen, NULL) != UART2_STATUS_SUCCESS )
    {
      TransportTxLen = 0;
    }""",
        """    if (b1_management_transport_unavailable())
    {
        TransportTxLen = 0; /* No more writes on failed transport. */
    }
    else if (UART2_write(uartHandle, TransportTxBuf, TransportTxLen, NULL) != UART2_STATUS_SUCCESS)
    {
        TransportTxLen = 0;
        b1_management_transport_failed(B1_ERROR_UART_WRITE);
    }""", "UART TX immediate submission status")
    return text


def prepare(sdk, definition):
    texts = {}
    for path, expected in PINS.items():
        text = (sdk / path).read_text(encoding="utf-8")
        if blob(text) != expected:
            raise RuntimeError("BLOCKED: management pinned TI blob mismatch: " + path)
        texts[path] = text
    collision = audit_collision(texts["source/ti/zstack/mt/mt.h"], definition)
    # Caller supplies the additional SHA-pinned UART/client/OSAL/heap inputs
    # listed in EXTRA_PINS below; all are validated before preparing mutations.
    for path, expected in EXTRA_PINS.items():
        text = (sdk / path).read_text(encoding="utf-8")
        if blob(text) != expected:
            raise RuntimeError("BLOCKED: management prerequisite blob mismatch: " + path)
        texts[path] = text
    modified = {
        "source/ti/zstack/mt/mt.c": patch_mt(texts["source/ti/zstack/mt/mt.c"]),
        "source/ti/zstack/npi/npi_task.c": patch_npi(texts["source/ti/zstack/npi/npi_task.c"]),
        "source/ti/zstack/npi/npi_tl_uart.c": patch_uart(texts["source/ti/zstack/npi/npi_tl_uart.c"]),
    }
    return modified, {"source_pins": dict(PINS, **EXTRA_PINS), "collision": collision,
                      "transport": "single original NPI owner; HOSTED_SYNTHETIC until exact native build",
                      "readiness": "no NETWORK_READY capability; no host receipt attestation"}


# Filled with Git blob IDs of exact prerequisite sources, not a URL trust claim.
EXTRA_PINS = {
    "source/ti/zstack/npi/npi_tl_uart.c": "a94366343eff09bbb9ecb3006b861e60ab09d826",
    "source/ti/zstack/npi/npi_client_mt.c": "3120060c1c7dfe9499f20f6b4f0dae00c3644d98",
    "source/ti/ti154stack/common/osal_port/osal_port_posix/osal_port.c": "b3fc4325f0df14a153d28e1294815d332be20309",
    "source/ti/ti154stack/common/heapmgr/rtos_heaposal.h": "b6e96bcbf2f00a4cbb790524a7f4d976d4081d7a",
    "source/ti/zstack/npi/npi_frame_mt.c": "dbf854ec9013247b06638fa551a8b712c733ea78",
    "source/ti/zstack/npi/npi_data.h": "7c12b70e2b81fecd24495f2659534225f2950c81",
    "source/ti/zstack/npi/npi_tl.c": "622009f6de216289d31e22e38d8780d6d58378f9",
}
