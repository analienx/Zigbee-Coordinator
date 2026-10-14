#!/usr/bin/env python3
"""Lower-layer G7 delta, composed with g7_task_overlay for task ownership.

Applied after G6. No source writes until all exact anchors have succeeded.
Using this delta alone does not establish task ownership/retry/fairness.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "g6"))
from g6_overlay import function, replace

TL = "source/ti/zstack/npi/npi_tl.c"
UART = "source/ti/zstack/npi/npi_tl_uart.c"

UART_WRITE = '''uint16 NPITLUART_writeTransport(uint16 len)
{
    uint32_t key = OsalPort_enterCS();
    int_fast16_t status;
    p7_uart_result = P7_SUBMIT_INVALID;
    TransportTxLen = 0;
    if (!uartHandle || !TransportTxBuf || !len || len > NPI_TL_BUF_SIZE) {
        OsalPort_leaveCS(key);
        return 0;
    }
    TransportTxLen = len;
    status = UART2_write(uartHandle, TransportTxBuf, len, NULL);
    if (status == UART2_STATUS_SUCCESS) {
        p7_uart_result = P7_SUBMIT_ACCEPTED;
    } else if (status == UART2_STATUS_ENOTOPEN || status == UART2_STATUS_EINUSE) {
        p7_uart_result = P7_SUBMIT_REJECTED;
        TransportTxLen = 0;
    } else if (status == UART2_STATUS_EINVALID) {
        p7_uart_result = P7_SUBMIT_INVALID;
        TransportTxLen = 0;
    } else {
        /* Cancellation/timeout/unknown can follow submission. Keep the copied
         * buffer and busy ownership until the existing completion callback. */
        p7_uart_result = P7_SUBMIT_AMBIGUOUS;
    }
    OsalPort_leaveCS(key);
    return TransportTxLen;
}'''

TL_WRITE = '''uint16 NPITL_writeTL(uint8 *buf, uint16 len)
{
    uint32_t key = OsalPort_enterCS();
    uint16 written;
    p7_tl_result = P7_SUBMIT_BUSY;
    if (NPITL_checkNpiBusy()) {
        OsalPort_leaveCS(key);
        return 0;
    }
    p7_tl_result = P7_SUBMIT_INVALID;
    /* Pinned MT frames fit in one TL buffer. Never leave a fragment pointing
     * into a frame whose task-level ownership might subsequently end. */
    if (!buf || !len || len > NPI_TL_BUF_SIZE) {
        OsalPort_leaveCS(key);
        return 0;
    }
    msgFrag = NULL;
    msgFragLen = 0;
    memcpy(npiTxBuf, buf, len);
    npiTxBufLen = len;
    npiTxActive = TRUE;
    written = transportWrite(len);
    p7_tl_result = p7_g7_uart_outcome();
    if (p7_tl_result == P7_SUBMIT_REJECTED || p7_tl_result == P7_SUBMIT_INVALID) {
        npiTxActive = FALSE;
        npiTxBufLen = 0;
    } else {
        txPktCount++;
    }
    OsalPort_leaveCS(key);
    return written;
}'''


def patch(texts):
    out = dict(texts)
    for rel, name, replacement, state, getter in [
        (UART, "NPITLUART_writeTransport", UART_WRITE, "p7_uart_result", "p7_g7_uart_outcome"),
        (TL, "NPITL_writeTL", TL_WRITE, "p7_tl_result", "p7_g7_tl_outcome")]:
        source = out[rel]
        original = function(source, name)
        # Require the genuine predecessor, not merely a same-named function.
        if rel == TL:
            if "len = transportWrite(npiTxBufLen);" not in original or "txPktCount++;" not in original:
                raise ValueError("UNEXPECTED_TI_TL_PREDECESSOR")
        elif "UART2_write(uartHandle, TransportTxBuf, TransportTxLen, NULL)" not in original:
            raise ValueError("UNEXPECTED_TI_UART_PREDECESSOR")
        source = replace(source, '#include "npi_config.h"\n',
                         '#include "npi_config.h"\n#include "p7_g7_transport.h"\n',
                         "g7_include_" + rel)
        declaration = f"static p7_submit_result_t {state} = P7_SUBMIT_INVALID;\n"
        source = replace(source, original, declaration + replacement,
                         "g7_submit_" + rel)
        source += f"\np7_submit_result_t {getter}(void) {{ return {state}; }}\n"
        out[rel] = source
    return out
