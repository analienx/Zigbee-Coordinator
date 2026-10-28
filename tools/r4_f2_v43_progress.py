#!/usr/bin/env python3
"""F2 minor3: request progress and first UART fault, on the v4.3 composite.

RAM-only instrumentation in existing owners. No retries, NV, reset or RF action.
The 240-byte reply fits the pinned 250-byte MT payload maximum.
"""
import hashlib
from pathlib import Path
from r4_uart_tx_liveness import TL, UART, extract, once

TASK = "source/ti/zstack/npi/npi_task.c"
MT = "source/ti/zstack/mt/mt.c"
SYS = "source/ti/zstack/mt/mt_sys.c"
FIELDS = ("npiRequests", "mtEntered", "mtReturned", "uartWriteAccepted",
          "uartWriteRejected", "uartCallbackOk", "uartCallbackError",
          "uartLengthMismatch", "stateFlags", "uartRxBytes", "firstFaultKind",
          "firstFaultStatusBits", "firstFaultExpected", "firstFaultActual",
          "firstFaultFlags", "firstFaultTick", "firstFaultCommand", "npiWakes",
          "b1FirstFailure", "tickPeriodUs")

def progress_source(tl):
    start = tl.index("/* B4_F2_V43_PROGRESS. No allocation")
    snapshot = extract(tl, "void B4_V43_Snapshot(uint8_t *out)")
    end = tl.index(snapshot, start) + len(snapshot)
    # Only the timer and existing startup-status accessor are fixture stubs.
    return """static uint32_t B4_test_tick = 1234u;
#define Clock_tickPeriod 10u
static uint32_t Clock_getTicks(void) { return B4_test_tick; }
void b1_startup_snapshot(uint8_t reply[B1_STARTUP_REPLY_SIZE]) {
 memset(reply, 0, B1_STARTUP_REPLY_SIZE); reply[9] = b1_management_first_error;
}
""" + tl[start:end]
DECL = """
/* B4_F2_V43_PROGRESS: existing TL owns these RAM-only diagnostics. */
extern void B4_V43_Request(unsigned stage, const uint8_t *frame);
extern void B4_V43_Wake(void);
extern void B4_V43_Submit(int_fast16_t status, uint32_t expected);
extern void B4_V43_Complete(int_fast16_t status, uint32_t actual, uint32_t expected);
extern void B4_V43_Receive(int_fast16_t status, uint32_t actual);
extern void B4_V43_Snapshot(uint8_t *out);
"""
IMPL = r"""
/* B4_F2_V43_PROGRESS. No allocation, payload copy, NV or UART operation. */
static uint32_t B4_V43_Progress[20] = {0};
static uint32_t B4_V43_LastCommand = 0u;
static uint32_t B4_V43_MtActive = 0u;
static void B4_V43_Tick(unsigned index, uint32_t count)
{
    uint32_t old = B4_V43_Progress[index];
    B4_V43_Progress[index] = count > 0xffffffffu - old ? 0xffffffffu : old + count;
}
static uint32_t B4_V43_Flags(void)
{
    return (npiTxActive ? 1u : 0u) |
           (b1_management_transport_unavailable() ? 2u : 0u) |
           (B4_V43_MtActive ? 4u : 0u) |
           (B4_V43_Progress[10] ? 8u : 0u) | (B4_V43_LastCommand << 16u);
}
static void B4_V43_FirstFault(uint32_t kind, int_fast16_t status,
                              uint32_t expected, uint32_t actual)
{
    if (B4_V43_Progress[10] != 0u) return;
    B4_V43_Progress[11] = (uint32_t)(int32_t)status;
    B4_V43_Progress[12] = expected;
    B4_V43_Progress[13] = actual;
    B4_V43_Progress[14] = B4_V43_Flags();
    B4_V43_Progress[15] = Clock_getTicks();
    B4_V43_Progress[16] = B4_V43_LastCommand;
    B4_V43_Progress[10] = kind; /* publish frozen record last, while CS held */
}
void B4_V43_Request(unsigned stage, const uint8_t *frame)
{
    uint32_t key;
    if (stage > 2u || frame == NULL || (frame[1] & 0xe0u) != 0x20u ||
        (frame[1] == 0x21u && frame[2] == 0xf2u)) return;
    key = OsalPort_enterCS();
    B4_V43_Tick(stage, 1u);
    if (stage != 2u) B4_V43_LastCommand = ((uint32_t)frame[1] << 8u) | frame[2];
    if (stage == 1u) { if (B4_V43_MtActive != 0xffffffffu) ++B4_V43_MtActive; }
    if (stage == 2u && B4_V43_MtActive) --B4_V43_MtActive;
    OsalPort_leaveCS(key);
}
void B4_V43_Wake(void)
{
    uint32_t key = OsalPort_enterCS();
    B4_V43_Tick(17u, 1u);
    OsalPort_leaveCS(key);
}
void B4_V43_Submit(int_fast16_t status, uint32_t expected)
{
    uint32_t key = OsalPort_enterCS();
    B4_V43_Tick(status == UART2_STATUS_SUCCESS ? 3u : 4u, 1u);
    if (status != UART2_STATUS_SUCCESS) B4_V43_FirstFault(1u, status, expected, 0u);
    OsalPort_leaveCS(key);
}
void B4_V43_Complete(int_fast16_t status, uint32_t actual, uint32_t expected)
{
    uint32_t key = OsalPort_enterCS();
    if (status != UART2_STATUS_SUCCESS) {
        B4_V43_Tick(6u, 1u); B4_V43_FirstFault(2u, status, expected, actual);
    } else if (actual != expected) {
        B4_V43_Tick(7u, 1u); B4_V43_FirstFault(3u, status, expected, actual);
    } else if (!b1_management_transport_unavailable()) B4_V43_Tick(5u, 1u);
    else B4_V43_FirstFault(5u, status, expected, actual);
    OsalPort_leaveCS(key);
}
void B4_V43_Receive(int_fast16_t status, uint32_t actual)
{
    uint32_t key = OsalPort_enterCS();
    if (status == UART2_STATUS_SUCCESS) B4_V43_Tick(9u, actual);
    else B4_V43_FirstFault(4u, status, 0u, actual);
    OsalPort_leaveCS(key);
}
void B4_V43_Snapshot(uint8_t *out)
{
    uint8_t startup[B1_STARTUP_REPLY_SIZE];
    uint32_t i, j, key;
    key = OsalPort_enterCS();
    b1_startup_snapshot(startup);
    B4_V43_Progress[8] = B4_V43_Flags();
    B4_V43_Progress[18] = startup[9];
    B4_V43_Progress[19] = Clock_tickPeriod;
    for (i = 0u; i < 20u; ++i)
        for (j = 0u; j < 4u; ++j) out[i*4u+j] = (uint8_t)(B4_V43_Progress[i] >> (8u*j));
    OsalPort_leaveCS(key);
}
"""


def apply(sdk):
    sdk = Path(sdk)
    paths = (TL, UART, TASK, MT, SYS)
    before = {name: (sdk/name).read_text(encoding="utf-8") for name in paths}
    if any("B4_F2_V43_PROGRESS" in text for text in before.values()):
        raise ValueError("F2_V43_ALREADY_APPLIED")
    t, u, n, m, s = (before[name] for name in paths)
    if "B4_R4_UART_TX_ERROR_UNWIND_V1" not in t:
        raise ValueError("F2_V43_REQUIRES_TX_UNWIND")
    t = once(t, '#include "npi_tl.h"', '#include "npi_tl.h"\n#include "b1_management.h"\n#include <ti/sysbios/knl/Clock.h>', "PROGRESS_TL_HEADERS")
    # The status constant is an API constant, not a locally invented number.
    t = once(t, '#include "b1_management.h"', '#include "b1_management.h"\n#include <ti/drivers/UART2.h>', "PROGRESS_UART_STATUS")
    t = once(t, "static volatile bool npiTxActive = FALSE;",
             "static volatile bool npiTxActive = FALSE;\n" + IMPL, "PROGRESS_RAM_OWNER")
    for name, text in ((UART, u), (TASK, n), (MT, m)):
        changed = once(text, '#include "b1_management.h"', '#include "b1_management.h"\n' + DECL, "PROGRESS_DECL_"+name)
        if name == UART: u = changed
        elif name == TASK: n = changed
        else: m = changed
    u = once(u, "    TransportTxLen = len;", "    TransportTxLen = len;", "PROGRESS_TRANSPORT_LENGTH")
    write_sig = "uint16 NPITLUART_writeTransport(uint16 len)"
    writer = extract(u, write_sig)
    tail = """            b1_management_transport_failed(B1_ERROR_UART_WRITE);
        }
    }"""
    writer_new = once(writer, tail, tail[:-5] + "        B4_V43_Submit(b1_write_status, len);\n    }", "PROGRESS_SUBMISSION_RESULT")
    u = once(u, writer, writer_new, "PROGRESS_WRITER")
    cb = "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)"
    original = extract(u, cb)
    changed = once(original, "    key = OsalPort_enterCS();", "    key = OsalPort_enterCS();\n    B4_V43_Complete(status, (uint32_t)size, TransportTxLen);", "PROGRESS_COMPLETION")
    u = once(u, original, changed, "PROGRESS_CALLBACK")
    cb = "static void NPITLUART_readCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)"
    original = extract(u, cb)
    changed = once(original, "    key = OsalPort_enterCS();", "    key = OsalPort_enterCS();\n    B4_V43_Receive(status, (uint32_t)size);", "PROGRESS_RX")
    u = once(u, original, changed, "PROGRESS_RX_CALLBACK")
    n = once(n, "    uint8 *pReq = (uint8 *)pMsg->pBuf;",
             "    uint8 *pReq = (uint8 *)pMsg->pBuf;\n    B4_V43_Request(0u, pReq);", "PROGRESS_NPI_REQUEST")
    n = once(n, "        b1_evidence_note_npi_wake();", "        b1_evidence_note_npi_wake();\n        B4_V43_Wake();", "PROGRESS_NPI_WAKE")
    signature = "void MT_ProcessIncoming(uint8_t *pBuf)"
    renamed = "static void B4_V43_MT_ProcessIncoming(uint8_t *pBuf)"
    wrapper = renamed + ";\n" + signature + "\n{\n  B4_V43_Request(1u, pBuf);\n  B4_V43_MT_ProcessIncoming(pBuf);\n  B4_V43_Request(2u, pBuf);\n}\n\n" + renamed
    m = once(m, signature + "\n{", wrapper + "\n{", "PROGRESS_MT_BOUNDARY")
    signature = "__attribute__((noinline)) static void B4_SysReadOnlyDiagnosticsV4(uint8_t *pBuf)"
    handler = extract(s, signature)
    updated = once(handler, "    uint8_t payload[160] = {0};", "    uint8_t payload[240] = {0};", "PROGRESS_F2_SIZE")
    updated = once(updated, "payload[6] = 160u;", "payload[6] = 240u;", "PROGRESS_F2_HEADER")
    updated = once(updated, "    seq = ++B4_V4SampleSequence;", "    seq = ++B4_V4SampleSequence;\n    B4_V43_Snapshot(payload + 160u);", "PROGRESS_F2_SNAPSHOT")
    updated = once(updated, "payload[157] = 2u;", "payload[157] = 3u;", "PROGRESS_F2_MINOR")
    s = once(s, handler, updated, "PROGRESS_F2_HANDLER")
    s = once(s, "static uint32_t B4_V4SampleSequence = 0u;", DECL + "\nstatic uint32_t B4_V4SampleSequence = 0u;", "PROGRESS_F2_DECL")
    after = dict(zip(paths, (t, u, n, m, s)))
    for name, data in after.items():
        (sdk/name).write_text(data, encoding="utf-8", newline="")
    return {"schema": "p7u-f2-v43-progress-v1", "minor": 3, "reply_bytes": 240,
            "progress_fields": list(FIELDS), "progress_offset": 160,
            "first_fault_latched_until_boot": True, "network_or_nv_changed": False,
            "before_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k,v in before.items()},
            "modified_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k,v in after.items()}}
