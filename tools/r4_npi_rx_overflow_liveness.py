#!/usr/bin/env python3
"""Source-pinned P7U R4 NPI RX-overflow liveness repair (NO LIVE ACTION).

The pinned TI NPI receive callback enters an unconditional for(;;) when
its 270-byte ring cannot admit the next UART RX chunk. Preserve memory
safety by dropping the entire incomplete MT receive stream, resetting
the partial-frame parser on the owning NPI task (not the UART callback),
and accepting subsequent UART frames. Never replay partial frames.

This eliminates a source-demonstrable permanent trap IF RX overflow is
the actual trigger; it is not a claim that the production hang was
caused by RX overflow. Does not access UART, NV, network or GPIO.
"""
import argparse
import hashlib
import json
from pathlib import Path

from r4_uart_tx_liveness import extract, once

TASK = "source/ti/zstack/npi/npi_task.c"
FRAME = "source/ti/zstack/npi/npi_frame_mt.c"
FRAME_H = "source/ti/zstack/npi/npi_frame.h"
RX = "source/ti/zstack/npi/npi_rxbuf.c"
RX_H = "source/ti/zstack/npi/npi_rxbuf.h"
PATHS = (TASK, FRAME, FRAME_H, RX, RX_H)
MARKER = "B4_R4_RX_OVERFLOW_DROP_V1"


def patch_sources(before: dict[str, str]) -> dict[str, str]:
    if set(before) != set(PATHS):
        raise ValueError("NPI_RX_REQUIRED_SOURCE_MISSING")
    if any(MARKER in text for text in before.values()):
        raise ValueError("NPI_RX_ALREADY_PATCHED")
    n, f, fh, r, rh = (before[path] for path in PATHS)
    if ("NPIFrame_collectFrameData" not in n or
            "NPIRxBuf_Read(size);" not in n or
            "NPI_TL_BUF_SIZE" not in r or
            "OsalPort_msgDeallocate" not in f):
        raise ValueError("NPI_RX_TI_833_PREIMAGE_DRIFT")

    # The flag is written by the existing UART RX callback, which runs in
    # its existing critical section. Only the NPI task resets parser state.
    n = once(n, "uint32_t npiServiceTaskEvents;",
        """uint32_t npiServiceTaskEvents;
/* B4_R4_RX_OVERFLOW_DROP_V1: loss notification, not an auto-reset. */
static volatile uint8_t B4_R4_RxOverflowPending = 0u;""",
        "RX_FLAG")

    handler_sig = "static void NPITask_transportRXCallBack(int size)"
    original = extract(n, handler_sig)
    if ("for(;;);" not in original or
            "NPIRxBuf_GetRxBufAvail()" not in original or
            "TRANSPORT_RX_ISR_EVENT_FLAG" not in original):
        raise ValueError("NPI_RX_FATAL_OVERFLOW_BRANCH_CHANGED")
    repaired = once(original, "        for(;;);",
        """        /* B4_R4_RX_OVERFLOW_DROP_V1: never lock the radio in ISR.
         * The current UART chunk and prior incomplete frame are invalid.
         * Defer buffer/parser discard to the owning NPI task. */
        B4_R4_RxOverflowPending = 1u;
        TRANSPORT_RX_ISR_EVENT_FLAG = NPITASK_TRANSPORT_RX_EVENT;
        Semaphore_post(npiSemHandle);""", "REMOVE_PERMANENT_SPIN")
    n = once(n, original, repaired, "RX_CALLBACK")
    n = once(n, "                NPIFrame_collectFrameData();",
        """                /* B4_R4_RX_OVERFLOW_DROP_V1: discard only in task
                 * context. Do not deallocate MT parser storage from ISR. */
                if (B4_R4_RxOverflowPending != 0u)
                {
                    uint32_t rxKey = OsalPort_enterCS();
                    B4_R4_RxOverflowPending = 0u;
                    NPIRxBuf_DiscardAll();
                    OsalPort_leaveCS(rxKey);
                    NPIFrame_resetAfterRxOverflow();
                }
                NPIFrame_collectFrameData();""", "RX_DISCARD_TASK_SIDE")

    # Drop both received ring fragments and previous frame state. A
    # corrupted partial command MUST NOT be delivered to MT/Z-Stack.
    r = once(r, "uint16 NPIRxBuf_GetRxBufCount(void)\n{",
        """/* B4_R4_RX_OVERFLOW_DROP_V1: only called by existing NPI task. */
void NPIRxBuf_DiscardAll(void)
{
    RxBufHead = RxBufTail;
}

uint16 NPIRxBuf_GetRxBufCount(void)
{""", "RING_DISCARD")
    rh = once(rh, "uint16 NPIRxBuf_GetRxBufAvail();",
        """uint16 NPIRxBuf_GetRxBufAvail();
/* B4_R4_RX_OVERFLOW_DROP_V1: discard incomplete ring after overflow. */
void NPIRxBuf_DiscardAll(void);""", "RING_HEADER")

    f = once(f, "void NPIFrame_collectFrameData(void)\n{",
        """/* B4_R4_RX_OVERFLOW_DROP_V1: called only from NPI task.
 * Discard partial MT message rather than accepting any corrupted SREQ. */
void NPIFrame_resetAfterRxOverflow(void)
{
    if (state != NPIFRAMEMT_SOP_STATE && pMsg != NULL)
    {
        OsalPort_msgDeallocate(pMsg);
    }
    pMsg = NULL;
    state = NPIFRAMEMT_SOP_STATE;
    tempDataLen = 0u;
    LEN_Token = 0u;
}

void NPIFrame_collectFrameData(void)
{""", "FRAME_RESET")
    fh = once(fh, "extern void NPIFrame_collectFrameData(void);",
        """extern void NPIFrame_collectFrameData(void);
/* B4_R4_RX_OVERFLOW_DROP_V1: NPI-task-only parser resynchronization. */
extern void NPIFrame_resetAfterRxOverflow(void);""", "FRAME_HEADER")
    return dict(zip(PATHS, (n, f, fh, r, rh)))


def apply(sdk: Path) -> dict:
    sdk = sdk.resolve(strict=True)
    originals = {}
    for path in PATHS:
        target = sdk / path
        if target.is_symlink() or not target.is_file():
            raise ValueError("NPI_RX_UNTRUSTED_PATH_" + path)
        originals[path] = target.read_text(encoding="utf-8")
    changes = patch_sources(originals)
    for path, body in changes.items():
        (sdk / path).write_text(body, encoding="utf-8", newline="")
    return {
        "schema": "p7u-r4-npi-rx-overflow-liveness-v1",
        "conditional_source_defect_removed": True,
        "production_root_cause_proven": False,
        "npi_task_parser_only_reset": True,
        "uart_owner_changed": False,
        "nv_or_security_changed": False,
        "before_sha256": {k: hashlib.sha256(v.encode()).hexdigest()
                          for k, v in originals.items()},
        "modified_sha256": {k: hashlib.sha256(v.encode()).hexdigest()
                            for k, v in changes.items()},
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk", required=True, type=Path)
    p.add_argument("--receipt", type=Path)
    args = p.parse_args()
    result = apply(args.sdk)
    if args.receipt:
        if args.receipt.exists():
            raise SystemExit("RECEIPT_ALREADY_EXISTS")
        args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    print(json.dumps(result, sort_keys=True))
