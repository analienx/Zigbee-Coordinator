"""Read-only vendor NPI telemetry over a dedicated MT SYS opcode (pinned TI SDK).

Produces no per-packet logs, task allocations, NV writes, or external effects.
The snapshot represents transmit *acceptance*, not physical delivery.
"""
import hashlib
from npi_srsp_fairness_patch import replace_in_function

TASK = "source/ti/zstack/npi/npi_task.c"
HEADER = "source/ti/zstack/npi/npi_task.h"
SYS = "source/ti/zstack/mt/mt_sys.c"
CLIENT = "source/ti/zstack/npi/npi_client_mt.c"

FIELDS = (
    "srspDepth", "srspHighWater", "asyncDepth", "asyncHighWater",
    "srspEnqueued", "srspTxAccepted", "asyncTxAccepted",
    "txImmediateRejects", "txRejectedDrops",
    "stackFrameFailed", "stackQueueFailed",
    "srspAllocFailed", "srspEnqueueFailed", "rxFrameFailed",
    "srspQueueFallback"
)

def append(sdk, path, tail, changes):
    p=sdk/path
    old=p.read_bytes()
    if tail.encode() in old:
        raise ValueError("Already appended: "+path)
    new=old+tail.encode()
    p.write_bytes(new)
    changes.append({"path":path,"before_sha256":hashlib.sha256(old).hexdigest(),
                    "after_sha256":hashlib.sha256(new).hexdigest()})

def apply(sdk, replace_exact, changes):
    fields = "\n".join("    uint32_t "+f+";" for f in FIELDS)
    replace_exact(sdk, HEADER,
        '#include "npi_data.h"\n',
        '#include "npi_data.h"\n#include <stdint.h>\n',changes)
    replace_exact(sdk, HEADER,
        "extern void NPITask_sendToHost(uint8_t *pMsg);\n",
        "extern void NPITask_sendToHost(uint8_t *pMsg);\n"
        "\n"
        "/* BSEED read-only counters, unversioned C ABI; wire format is versioned. */\n"
        "typedef struct NPITask_DiagSnapshot_s {\n"+fields+"\n"
        "    uint8_t flags;\n"
        "} NPITask_DiagSnapshot;\n"
        "extern void NPITask_getDiagSnapshot(NPITask_DiagSnapshot *dst);\n"
        "extern void NPITask_noteSrspAllocFailure(void);\n"
        "extern void NPITask_noteSrspEnqueueFailure(void);\n", changes)

    replace_exact(sdk, TASK,
        "static uint8_t npiSrspBurst;\n",
        "static uint8_t npiSrspBurst;\n"
        "static volatile uint32_t npiAsyncQueueDepth;\n"
        "static volatile uint32_t npiAsyncQueueHighWater;\n"
        "static volatile uint32_t npiSrspEnqueued;\n"
        "static volatile uint32_t npiSrspTxAccepted;\n"
        "static volatile uint32_t npiAsyncTxAccepted;\n"
        "static volatile uint32_t npiStackFrameFailed;\n"
        "static volatile uint32_t npiStackQueueFailed;\n"
        "static volatile uint32_t npiSrspAllocFailed;\n"
        "static volatile uint32_t npiSrspEnqueueFailed;\n"
        "static volatile uint32_t npiRxFrameFailed;\n", changes)

    # Enqueue, increment and backpressure diagnostics for both frame origins.
    for signature in ("void NPITask_sendToHost(uint8_t *pMsg)\n{",
                      "static void NPITask_processStackMsg(uint8_t *pMsg)\n{"):
        replace_in_function(sdk, signature, [
            ("++npiSrspQueueDepth;\n", "++npiSrspQueueDepth;\n"
             "                        ++npiSrspEnqueued;\n"),
            ("Queue_enqueue(npiTxQueue, &recPtr->_elem);\n",
             "Queue_enqueue(npiTxQueue, &recPtr->_elem);\n"
             "                        ++npiAsyncQueueDepth;\n"
             "                        if (npiAsyncQueueDepth > npiAsyncQueueHighWater)\n"
             "                            npiAsyncQueueHighWater = npiAsyncQueueDepth;\n")
        ], changes)
    replace_in_function(sdk, "static void NPITask_processStackMsg(uint8_t *pMsg)\n{", [
        ("    pNPIMsg = NPIFrame_frameMsg(pMsg);\n",
         "    pNPIMsg = NPIFrame_frameMsg(pMsg);\n"
         "    if (pNPIMsg == NULL)\n"
         "    {\n"
         "        ++npiStackFrameFailed;\n"
         "        return; // Frame builder already consumed original pMsg.\n"
         "    }\n"),
        ("            /* Fail - couldn't get queue record */\n",
         "            /* Fail - couldn't get queue record */\n"
         "          ++npiStackQueueFailed;\n")
    ], changes)
    replace_in_function(sdk, "static void NPITask_incomingFrameCB(uint8_t frameSize, uint8_t *pFrame,\n                                    NPIMSG_Type msgType)\n{",[
        ("        // The frame callback owns pFrame even when either wrapper fails.\n",
         "        ++npiRxFrameFailed;\n"
         "        // The frame callback owns pFrame even when either wrapper fails.\n")
    ], changes)
    replace_in_function(sdk, "static void NPITask_ProcessTXQ(void)\n{",[
        ("    recPtr = Queue_dequeue(selectedQueue);\n",
         "    recPtr = Queue_dequeue(selectedQueue);\n"
         "    if (!selectedSrsp && recPtr && npiAsyncQueueDepth)\n"
         "        --npiAsyncQueueDepth;\n"),
        ("                if (selectedSrsp) ++npiSrspQueueDepth;\n",
         "                if (selectedSrsp) ++npiSrspQueueDepth;\n"
         "                else ++npiAsyncQueueDepth;\n"),
        ("            // Accepted write consumes this record below.\n",
         "            // Accepted by UART driver, NOT proof it reached the host.\n"
         "            if (selectedSrsp) ++npiSrspTxAccepted;\n"
         "            else ++npiAsyncTxAccepted;\n")
    ], changes)

    # Export an atomic snapshot via existing critical section; no heap needed.
    snapshot = [
        '\n/* Read-only diagnostic export: no GPIO, NV or runtime allocations. */',
        'void NPITask_getDiagSnapshot(NPITask_DiagSnapshot *dst)',
        '{',
        '    if (!dst) return;',
        '    uint32_t key = OsalPort_enterCS();'
    ]
    sources = (
        "npiSrspQueueDepth", "npiSrspQueueHighWater",
        "npiAsyncQueueDepth", "npiAsyncQueueHighWater",
        "npiSrspEnqueued", "npiSrspTxAccepted", "npiAsyncTxAccepted",
        "npiTxImmediateRejects", "npiTxRejectedDrops",
        "npiStackFrameFailed", "npiStackQueueFailed",
        "npiSrspAllocFailed", "npiSrspEnqueueFailed", "npiRxFrameFailed",
        "npiSrspQueueFallback"
    )
    for name, source in zip(FIELDS, sources):
        snapshot.append("    dst->"+name+" = "+source+";")
    snapshot += [
        "    dst->flags = (uint8_t)((npiSrspTxQueue != NULL ? 1u : 0u) |",
        "                           (npiTxRetryPending ? 2u : 0u));",
        "    OsalPort_leaveCS(key);",
        "}",
        "void NPITask_noteSrspAllocFailure(void)",
        "{",
        "    uint32_t key = OsalPort_enterCS();",
        "    ++npiSrspAllocFailed;",
        "    OsalPort_leaveCS(key);",
        "}",
        "void NPITask_noteSrspEnqueueFailure(void)",
        "{",
        "    uint32_t key = OsalPort_enterCS();",
        "    ++npiSrspEnqueueFailed;",
        "    OsalPort_leaveCS(key);",
        "}",
        ""
    ]
    append(sdk,TASK,"\n".join(snapshot),changes)
    replace_exact(sdk,CLIENT,
        '#include "npi_client.h"\n',
        '#include "npi_client.h"\n#include "npi_task.h"\n',changes)
    replace_exact(sdk,CLIENT,
        "            OsalPort_msgDeallocate(pRspMsg);\n",
        "            NPITask_noteSrspEnqueueFailure();\n"
        "            OsalPort_msgDeallocate(pRspMsg);\n",changes)
    replace_exact(sdk,CLIENT,
        "    }\n"
        "\n"
        "    return;\n",
        "    }\n"
        "    else\n"
        "    {\n"
        "        NPITask_noteSrspAllocFailure();\n"
        "    }\n"
        "\n"
        "    return;\n",changes)

    # Dedicated vendor MT SYS command 0xF0, read-only: version 1, flags,
    # then 15 uint32 LE counters. No credential, keys, address or radio state.
    replace_exact(sdk,SYS,
        '#include "mt_sys.h"\n',
        '#include "mt_sys.h"\n#include "npi_task.h"\n'
        '#define BSEED_MT_SYS_NPI_DIAG 0xF0u\n',changes)
    replace_exact(sdk,SYS,
        "uint8_t MT_SysCommandProcessing(uint8_t *pBuf)\n",
        "static void MT_SysBseedNpiDiag(void);\n"
        "uint8_t MT_SysCommandProcessing(uint8_t *pBuf)\n",changes)
    replace_exact(sdk,SYS,
        "    default:\n"
        "      status = MT_RPC_ERR_COMMAND_ID;\n",
        "    case BSEED_MT_SYS_NPI_DIAG:\n"
        "      if (pBuf[MT_RPC_POS_LEN] != 0)\n"
        "        status = MT_RPC_ERR_LENGTH;\n"
        "      else\n"
        "        MT_SysBseedNpiDiag();\n"
        "      break;\n"
        "    default:\n"
        "      status = MT_RPC_ERR_COMMAND_ID;\n",changes)
    cb=[
        "",
        "#if defined(MT_SYS_FUNC)",
        "static void MT_SysBseedNpiDiag(void)",
        "{",
        "    NPITask_DiagSnapshot s;",
        "    NPITask_getDiagSnapshot(&s);",
        "    uint8_t reply[2 + "+str(len(FIELDS))+" * 4] = {1u, s.flags};",
        "    const uint32_t value[] = {"+", ".join("s."+x for x in FIELDS)+"};",
        "    for (uint8_t i = 0; i < "+str(len(FIELDS))+"u; ++i)",
        "    {",
        "        uint32_t v = value[i];",
        "        for (uint8_t b = 0; b < 4u; ++b)",
        "            reply[2 + 4u*i + b] = (uint8_t)(v >> (8u*b));",
        "    }",
        "    MT_BuildAndSendZToolResponse(MT_SRSP_SYS, BSEED_MT_SYS_NPI_DIAG,",
        "                                 (uint8_t)sizeof(reply), reply);",
        "}",
        "#endif",
        ""
    ]
    append(sdk,SYS,"\n".join(cb),changes)
    return [TASK,HEADER,SYS,CLIENT]
