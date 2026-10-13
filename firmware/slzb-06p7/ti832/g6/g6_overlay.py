#!/usr/bin/env python3
"""Pinned P7 G6 overlay, applied AFTER G5 DIAG; source edits only in hosted CI.

F10 ownership fixes and F15 overflow recovery are independent SDK deltas.
All replacements validate exact unique anchors before any file is written.
No startup/NV/CCFG/linker control flow is changed by this overlay.
"""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from pathlib import Path
G5=Path(__file__).resolve().parents[1]/"g5"
sys.path.insert(0,str(G5))
import diag_overlay as diag

TASK="source/ti/zstack/npi/npi_task.c"
FRAME="source/ti/zstack/npi/npi_frame_mt.c"
UART="source/ti/zstack/npi/npi_tl_uart.c"
RX="source/ti/zstack/npi/npi_rxbuf.c"
TL="source/ti/zstack/npi/npi_tl.c"
SYS="source/ti/zstack/mt/mt_sys.c"
INC='#include "p7_g6.h" /* P7G6 */\n'

def replace(text, anchor, value, label):
    if text.count(anchor)!=1: raise ValueError(f"ANCHOR_{label}:{text.count(anchor)}")
    return text.replace(anchor,value,1)

def function(text, name):
    # Select a definition, never a forward declaration; brace-balanced body.
    matches=list(re.finditer(r"(?m)^[^\n;]*\b"+re.escape(name)+r"\([^;]*?\)\s*\{",text))
    if len(matches)!=1: raise ValueError("FUNCTION_NOT_UNIQUE_"+name)
    start=matches[0].start(); pos=text.index("{",matches[0].start()); depth=1; end=pos+1
    while depth:
        if text[end]=="{": depth+=1
        elif text[end]=="}": depth-=1
        end+=1
    return text[start:end]

def patch(texts):
    out=dict(texts)
    # Add one timebase include to every instrumented file. Replace ONLY calls
    # emitted by the pinned G5 overlay; preserve its two pre-BIOS boot records.
    for rel in sorted({p[0] for p in diag.PATCHES}):
        t=out[rel]
        t=replace(t,diag.INC,diag.INC+INC,"include_"+rel)
        t,n=re.subn(r'(p7_diag_record(?:_isr)?\([^;\n]+), 0\);',r'\1, p7_g6_now());',t)
        expected=sum(len(re.findall(r'p7_diag_record(?:_isr)?\(',p[2])) for p in diag.PATCHES if p[0]==rel)
        if n!=expected: raise ValueError(f"TIMEBASE_COUNT_{rel}:{n}!={expected}")
        out[rel]=t

    # F10: frameMsg consumes the incoming buffer even on failure. Own each
    # resulting allocation exactly once until it has actually been enqueued.
    old=function(out[TASK],"NPITask_sendToHost")
    new=replace(old,"                //error\n                break;",
        "                OsalPort_msgDeallocate(pNPIMsg->pBuf);\n"
        "                OsalPort_free(pNPIMsg);\n"
        "                OsalPort_free(recPtr); /* P7G6:F10 unsupported */\n                break;","send_type")
    new=replace(new,"    OsalPort_leaveCS(key);",
        "    else\n    {\n"
        "        if (pNPIMsg != NULL) {\n"
        "            OsalPort_msgDeallocate(pNPIMsg->pBuf);\n"
        "            OsalPort_free(pNPIMsg);\n        }\n"
        "        if (recPtr != NULL) OsalPort_free(recPtr);\n"
        "    } /* P7G6:F10 partial allocation */\n\n    OsalPort_leaveCS(key);","send_alloc")
    out[TASK]=replace(out[TASK],old,new,"send_function")
    # Reverse direction: failure of payload allocation must release the header.
    old=function(out[TASK],"NPITask_sendBufToStack")
    new=replace(old,"    uint8_t msgStatus = 0;","    uint8_t msgStatus = 1; /* allocation failure, not success */","stack_status")
    new=replace(new,"          msgStatus = OsalPort_msgSend( MTServiceTaskID, (byte *)pOsalMsg );",
        "          msgStatus = OsalPort_msgSend( MTServiceTaskID, (byte *)pOsalMsg );\n"
        "          if (msgStatus != 0) {\n"
        "              OsalPort_free(pOsalMsg->msg);\n"
        "              OsalPort_msgDeallocate(pOsalMsg);\n"
        "          } /* P7G6:F10 rejected message send retains ownership */","stack_send")
    new=replace(new,"        }\n\n    }","        }\n        else {\n"
        "            OsalPort_msgDeallocate(pOsalMsg);\n"
        "        } /* P7G6:F10 payload allocation */\n\n    }","stack_alloc")
    out[TASK]=replace(out[TASK],old,new,"stack_function")

    # F15: drop the entire lost batch in O(1), latch task-side resynchronization.
    # While latched every incoming batch is discarded. Parser/free is task-only.
    out[TL]+="\n/* P7G6:F15 transport batch discard; caller holds OSAL critical section. */\nvoid p7_g6_discard_tl(void) { npiRxBufHead = npiRxBufTail; }\n"
    out[RX]+="\n/* P7G6:F15 ring discard; NPI task holds OSAL critical section. */\nvoid p7_g6_discard_ring(void) { RxBufHead = RxBufTail; }\n"
    out[TASK]=replace(out[TASK],INC,INC+
        "extern void p7_g6_discard_tl(void);\nextern void p7_g6_discard_ring(void);\n"
        "extern void p7_g6_reset_parser(void);\n","rx_prototypes")
    out[TASK]=replace(out[TASK],"    if ( size < NPIRxBuf_GetRxBufAvail() )",
        "    uint32_t rxKey = OsalPort_enterCS();\n"
        "    if (!p7_g6_rx_resync && size < NPIRxBuf_GetRxBufAvail())","rx_guard")
    out[TASK]=replace(out[TASK],"        for(;;);",
        "        p7_g6_discard_tl();\n        p7_g6_rx_resync = 1;\n"
        "        TRANSPORT_RX_ISR_EVENT_FLAG = NPITASK_TRANSPORT_RX_EVENT;\n"
        "        Semaphore_post(npiSemHandle); /* P7G6:F15 recover, never trap */","rx_trap")
    old=function(out[TASK],"NPITask_transportRXCallBack")
    out[TASK]=replace(out[TASK],old,old[:-1]+"    OsalPort_leaveCS(rxKey);\n}","rx_unlock")
    out[TASK]=replace(out[TASK],"                NPIFrame_collectFrameData();",
        "                if (p7_g6_rx_resync) {\n"
        "                    key = OsalPort_enterCS();\n"
        "                    p7_g6_discard_ring();\n"
        "                    OsalPort_leaveCS(key);\n"
        "                    p7_g6_reset_parser(); /* task-owned partial buffer */\n"
        "                    key = OsalPort_enterCS();\n"
        "                    p7_g6_rx_resync = 0;\n"
        "                    OsalPort_leaveCS(key);\n                }\n"
        "                NPIFrame_collectFrameData();","rx_recovery")
    out[FRAME]=replace(out[FRAME],"    while (NPIRxBuf_GetRxBufCount())\n    {",
        "    while (NPIRxBuf_GetRxBufCount())\n    {\n"
        "        if (p7_g6_rx_resync) return; /* P7G6:F15 task will resync */","parser_yield")
    # Clear pointer after normal delivery/free: it is no longer parser-owned.
    out[FRAME]=replace(out[FRAME],
        "                /* Reset the state, send or discard the buffers at this point */\n                state = NPIFRAMEMT_SOP_STATE;",
        "                /* Reset the state, send or discard the buffers at this point */\n"
        "                pMsg = NULL; /* P7G6:F15 ownership transferred/released */\n"
        "                state = NPIFRAMEMT_SOP_STATE;","parser_complete")
    out[FRAME]+="\n/* P7G6:F15 called only by NPI task while ISR batches are being discarded. */\n"
    out[FRAME]+="void p7_g6_reset_parser(void) {\n"
    out[FRAME]+="    if (state != NPIFRAMEMT_SOP_STATE && pMsg != NULL) OsalPort_msgDeallocate(pMsg);\n"
    out[FRAME]+="    pMsg = NULL; state = NPIFRAMEMT_SOP_STATE;\n"
    out[FRAME]+="    LEN_Token = 0; FSC_Token = 0; tempDataLen = 0;\n}\n"

    out[UART]=replace(out[UART],"    params.writeCallback = NPITLUART_writeCallBack;",
        "    params.writeCallback = NPITLUART_writeCallBack;\n"
        "    params.eventCallback = p7_g6_uart_event;\n"
        "    params.eventMask |= UART2_EVENT_TX_FINISHED; /* P7G6:physical idle */","uart_subscribe")
    out[UART]=replace(out[UART],'#include <ti/drivers/UART2.h>\n','#include <ti/drivers/UART2.h>\n'+
        "static void p7_g6_uart_event(UART2_Handle handle, uint32_t event, uint32_t data, void *arg) {\n"
        "    (void)handle; (void)data; (void)arg;\n"
        "    if (event & UART2_EVENT_TX_FINISHED)\n"
        "        p7_diag_record_isr(P7D_UART_TX_FINISHED, 0, p7_g6_now());\n"
        "} /* P7G6:may aggregate multiple frames; never proves host reception */\n","uart_callback")
    # Only this offline image gains SYS F0. Validate length before touching data.
    out[SYS]=replace(out[SYS],'#include "mt_sys.h"\n','#include "mt_sys.h"\n'+INC,"sys_include")
    anchor="  switch (pBuf[MT_RPC_POS_CMD1])\n  {"
    out[SYS]=replace(out[SYS],anchor,anchor+
        "\n    case P7_G6_CMD:\n    {\n"
        "      uint8_t response[P7_G6_MAX];\n"
        "      size_t len = p7_g6_response(pBuf + MT_RPC_FRAME_HDR_SZ, pBuf[MT_RPC_POS_LEN],\n"
        "          (pBuf[MT_RPC_POS_CMD0] & MT_RPC_CMD_TYPE_MASK) == MT_RPC_CMD_SREQ,\n"
        "          response, sizeof(response));\n"
        "      MT_BuildAndSendZToolResponse(MT_RPC_CMD_SRSP | MT_RPC_SYS_SYS,\n"
        "          P7_G6_CMD, (uint8_t)len, response);\n"
        "      break;\n    } /* P7G6:versioned read-only endpoint */","sys_dispatch")
    return out

def apply(sdk, examples, output):
    paths=sorted({p[0] for p in diag.PATCHES}|{RX,TL,SYS})
    original={p:(sdk/p).read_text() for p in paths}
    patched=patch(original) # all exact anchors validated before writes
    spec=examples/diag.PROJECTSPEC
    text=spec.read_text()
    entry=diag.DIAG_FILE_ENTRY.replace("p7_crashdiag.c","p7_g6.c")
    text=replace(text,diag.DIAG_FILE_ENTRY,diag.DIAG_FILE_ENTRY+entry,"g6_projectspec")
    for p,t in patched.items(): (sdk/p).write_text(t)
    spec.write_text(text)
    for name in ("p7_g6.c","p7_g6.h"):
        (sdk/"source/ti/zstack/startup"/name).write_bytes((Path(__file__).parent/name).read_bytes())
    manifest={"qualification":"G6_NOT_FLASHABLE", "sdk_sha":diag.SDK_SHA,
        "examples_sha":diag.EXAMPLES_SHA,"mt_endpoint_enabled":True,
        "runtime_qualified":False,"hardware_qualified":False,"flash_authorized":False,
        "clock_source":"Clock_getTicks", "clock_resolution":"Clock_tickPeriod microseconds",
        "clock_origin":"BIOS per boot; pre-BIOS boot records unavailable",
        "reboot_unique_identity_known":False,
        "reliability_features":["F10 allocation ownership", "F15 RX overflow resynchronization"],
        "files":{p:{"input_sha256":hashlib.sha256(original[p].encode()).hexdigest(),
                    "output_sha256":hashlib.sha256(patched[p].encode()).hexdigest()} for p in paths}}
    output.mkdir(parents=True,exist_ok=True)
    (output/"G6-OVERLAY-MANIFEST.json").write_text(json.dumps(manifest,indent=2)+"\n")
    return manifest

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--examples",type=Path,required=True); p.add_argument("--out",type=Path,required=True)
    a=p.parse_args(); print(json.dumps(apply(a.sdk,a.examples,a.out),indent=2))
