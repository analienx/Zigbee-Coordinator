#!/usr/bin/env python3
"""Fix pinned TI NPI inbound ownership loss under allocator/send failure.

The existing NPI→MT OSAL queue remains the only request handoff. No
new task/transport owner, direct MT call or change to radio security.
"""
import hashlib
from pathlib import Path
from r4_uart_tx_liveness import extract, once

TASK="source/ti/zstack/npi/npi_task.c"
MARKER="B4_V45_INGRESS_FAILURE_OWNERSHIP"

def apply(sdk):
    sdk=Path(sdk)
    path=sdk/TASK
    before=path.read_text(encoding="utf-8")
    if MARKER in before or "B4_V45_STATIC_SRSP_RESERVE" not in before:
        raise ValueError("V45_INGRESS_REQUIRES_RESERVED_SRSP_SOURCE")
    sig="static uint8_t NPITask_sendBufToStack( NPIMSG_msg_t *pMsg )"
    old=extract(before,sig)
    new=once(old,"    uint8_t msgStatus = 0;",
        "    /* Allocation failure is not an accepted OSAL submission. */\n"
        "    uint8_t msgStatus = 1u;", "INGRESS_ERROR_DEFAULT")
    new=once(new, "        if(pOsalMsg->msg) {\n\n"
        "          memcpy(pOsalMsg->msg, pReq, (MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN]) );\n\n"
        "          msgStatus = OsalPort_msgSend( MTServiceTaskID, (byte *)pOsalMsg );\n"
        "        }",
        """        if (pOsalMsg->msg != NULL)
        {
            memcpy(pOsalMsg->msg, pReq,
                   MT_RPC_FRAME_HDR_SZ + pReq[MT_RPC_POS_LEN]);
            msgStatus = OsalPort_msgSend(MTServiceTaskID, (byte *)pOsalMsg);
            if (msgStatus != 0u)
            {
                /* Send rejection transfers no ownership; release both. */
                B4_V45_Tick(&B4_V45_IngressSendFailed);
                OsalPort_free(pOsalMsg->msg);
                (void)OsalPort_msgDeallocate((uint8_t *)pOsalMsg);
            }
        }
        else
        {
            /* Previous TI code leaked the allocated OSAL header here. */
            B4_V45_Tick(&B4_V45_IngressAllocFailed);
            (void)OsalPort_msgDeallocate((uint8_t *)pOsalMsg);
        }""", "INGRESS_PARTIAL_ALLOCATION_UNWIND")
    new=once(new,
        "    OsalPort_msgDeallocate(pMsg->pBuf);",
        "    if (pOsalMsg == NULL) B4_V45_Tick(&B4_V45_IngressAllocFailed);\n"
        "    OsalPort_msgDeallocate(pMsg->pBuf);", "INGRESS_HEADER_ALLOC_COUNT")
    patched=once(before,old,new,"INGRESS_FUNCTION")
    patched=once(patched,sig+"\n{",
        "/* "+MARKER+": RAM-only, boot-local saturation counters. */\n"
        "static volatile uint32_t B4_V45_IngressAllocFailed = 0u;\n"
        "static volatile uint32_t B4_V45_IngressSendFailed = 0u;\n"
        +sig+"\n{", "INGRESS_COUNTER_DEFS")
    path.write_text(patched,encoding="utf-8",newline="")
    return {"schema":"p7u-r4-v45-npi-ingress-ownership-v1",
       "osal_wrapper_partial_failure_freed":True,
       "send_rejection_releases_payload_and_wrapper":True,
       "osal_message_owner_unchanged":True,
       "host_telemetry_exported":False,
       "before_sha256":hashlib.sha256(before.encode()).hexdigest(),
       "modified_sha256":hashlib.sha256(patched.encode()).hexdigest()}
