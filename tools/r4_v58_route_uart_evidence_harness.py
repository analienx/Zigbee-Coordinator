#!/usr/bin/env python3
"""Compile the EMITTED V58 mt_zdo.c / npi_tl_uart.c code and reject mutants.

The harness cuts the V58 blocks, the real MT_ZdoExtRouteDisc and the real
B4_NpiUartTxFinishedCallback out of the composed SDK files and links them
against API-boundary stubs (NLME, MT reply, Clock, OsalPort, B1 EOT). The TI
NWK library stays closed: the stub only models rtDiscTable occupancy.
"""
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

from r4_v58_route_uart_evidence import MTZDO, UART, MARKER_ZDO, MARKER_UART

PRELUDE = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t ZStatus_t;
#define ZSuccess 0x00u
#define ZNwkTableFull 0xC7u
#define MT_RPC_FRAME_HDR_SZ 3
#define MT_RPC_CMD_SRSP 0x60u
#define MT_RPC_SYS_ZDO 0x05u
#define MT_ZDO_EXT_ROUTE_DISC 0x45u
#define UART2_EVENT_FRAMING (0x01)
#define UART2_EVENT_PARITY (0x02)
#define UART2_EVENT_BREAK (0x04)
#define UART2_EVENT_OVERRUN (0x08)
#define UART2_EVENT_TX_BEGIN (0x10)
#define UART2_EVENT_TX_FINISHED (0x20)
typedef void *UART2_Handle;
typedef struct { uint8_t rreqId; uint16_t srcAddress; uint16_t previousNode;
                 uint8_t forwardCost; uint8_t residualCost; uint8_t expiryTime; } rtDiscEntry_t;
typedef uint8_t rreqTableIndex_t;
static rreqTableIndex_t gMAX_RREQ_ENTRIES = 40u;
static rtDiscEntry_t rtDiscTable[40];
static uint32_t ticks = 1000u, cs_depth, cs_enters;
static uint32_t Clock_getTicks(void) { return ticks; }
static uint32_t OsalPort_enterCS(void) { ++cs_depth; ++cs_enters; return 7u; }
static void OsalPort_leaveCS(uint32_t key) { assert(key == 7u); assert(cs_depth); --cs_depth; }
static uint16_t OsalPort_buildUint16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
/* NLME stub: occupy `add` entries, then answer `answer`. */
static ZStatus_t answer; static unsigned add, nlme_calls; static uint16_t nlme_dst;
static uint8_t nlme_opt, nlme_radius;
static ZStatus_t NLME_RouteDiscoveryRequest(uint16_t dst, uint8_t opt, uint8_t radius)
{
    unsigned i, n = 0u;
    ++nlme_calls; nlme_dst = dst; nlme_opt = opt; nlme_radius = radius;
    for (i = 0u; i < 40u && n < add; ++i)
        if (rtDiscTable[i].expiryTime == 0u) { rtDiscTable[i].expiryTime = 10u; rtDiscTable[i].srcAddress = 0u; ++n; }
    return answer;
}
static uint8_t reply_cmd0, reply_cmd1, reply_len, reply_status; static unsigned replies;
static void MT_BuildAndSendZToolResponse(uint8_t cmd0, uint8_t cmd1, uint8_t len, uint8_t *data)
{ reply_cmd0 = cmd0; reply_cmd1 = cmd1; reply_len = len; reply_status = data[0]; ++replies; }
static volatile uint32_t B4_NpiUartTxFinishedEvents;
static unsigned b1_eot;
static void b1_startup_uart_event(UART2_Handle h, uint32_t event, uint32_t data, void *arg)
{ (void)h; (void)data; (void)arg; assert(event & UART2_EVENT_TX_FINISHED); ++b1_eot; }
"""

MAIN = r"""
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void disc(uint16_t dst, ZStatus_t status, unsigned occupy)
{
    uint8_t frame[3 + 4] = { 4u, 0x25u, 0x45u, (uint8_t)dst, (uint8_t)(dst >> 8), 0x00u, 30u };
    unsigned before = replies;
    answer = status; add = occupy;
    MT_ZdoExtRouteDisc(frame);
    /* Request and reply are exactly TI's. */
    assert(replies == before + 1u && reply_status == status && reply_len == 1u);
    assert(reply_cmd0 == (MT_RPC_CMD_SRSP | MT_RPC_SYS_ZDO) && reply_cmd1 == MT_ZDO_EXT_ROUTE_DISC);
    assert(nlme_dst == dst && nlme_opt == 0u && nlme_radius == 30u);
}
int main(void)
{
    static uint8_t page[248];
    unsigned i;
    memset(rtDiscTable, 0, sizeof rtDiscTable);
    B4_V58_RouteUartSnapshot(page);
    assert(memcmp(page, "B1E9", 4) == 0 && page[4] == 1u && page[5] == 248u && page[6] == 0u);
    assert(page[44] == 0u && page[46] == 40u && page[47] == (uint8_t)sizeof(rtDiscEntry_t));
    assert(cs_depth == 0u);

    ticks = 2000u; disc(0x1234u, ZSuccess, 40u);         /* 0 live before, 40 after */
    ticks = 3000u; disc(0x0cddu, ZNwkTableFull, 0u);     /* 40 live before: refused */
    for (i = 10u; i < 40u; ++i) rtDiscTable[i].expiryTime = 0u; /* 30 expire */
    ticks = 4000u; disc(0x9cebu, ZNwkTableFull, 5u);     /* 10 before, 15 after */
    ticks = 5000u; disc(0x0001u, 0xC2u, 0u);             /* other status */
    B4_V58_RouteUartSnapshot(page);
    assert(get32(page + 16) == 4u && get32(page + 20) == 1u && get32(page + 24) == 2u && get32(page + 28) == 1u);
    assert(get32(page + 32) == 3000u && get32(page + 36) == 4000u);
    assert(page[40] == 0xC2u && page[41] == 10u && page[42] == 40u && page[43] == 40u);
    assert(page[44] == 15u && page[45] == 15u && page[48] == 0xebu && page[49] == 0x9cu);
    assert((page[6] & 3u) == 3u && (page[6] & 12u) == 0u);

    /* Entries freed with stale bytes: live drops, non-zero count stays. */
    for (i = 0u; i < 40u; ++i) { rtDiscTable[i].expiryTime = 0u; rtDiscTable[i].rreqId = 1u; }
    B4_V58_RouteUartSnapshot(page);
    assert(page[44] == 0u && page[45] == 40u && page[42] == 40u);

    /* UART: RX errors are counted and never reach the TX/B1 path. */
    ticks = 7000u; B4_NpiUartTxFinishedCallback(NULL, UART2_EVENT_OVERRUN, 5u, NULL);
    ticks = 8000u; B4_NpiUartTxFinishedCallback(NULL, UART2_EVENT_OVERRUN | UART2_EVENT_FRAMING, 6u, NULL);
    B4_NpiUartTxFinishedCallback(NULL, UART2_EVENT_BREAK | UART2_EVENT_PARITY, 6u, NULL);
    assert(B4_NpiUartTxFinishedEvents == 0u && b1_eot == 0u);
    B4_NpiUartTxFinishedCallback(NULL, UART2_EVENT_TX_FINISHED, 0u, NULL);
    assert(B4_NpiUartTxFinishedEvents == 1u && b1_eot == 1u);
    B4_V58_RouteUartSnapshot(page);
    assert(get32(page + 52) == 2u && get32(page + 56) == 6u && get32(page + 60) == 1u);
    assert(get32(page + 64) == 1u && get32(page + 68) == 1u);
    assert(get32(page + 72) == 7000u && get32(page + 76) == 8000u);
    assert((page[6] & 12u) == 12u && cs_depth == 0u);
    printf("V58_ROUTE_UART_EVIDENCE_REAL_C_PASS\n");
    return 0;
}
"""

MUTANTS = {
    "status_forced_success": ("  B4_V58_RouteDiscAfter(dstAddr, status);\n",
                              "  B4_V58_RouteDiscAfter(dstAddr, status); status = ZSuccess;\n"),
    "refusal_not_counted": ("        B4_V58_Inc(&B4_V58_Rd.tableFull);\n", ""),
    "occupancy_sampled_after_request": ("        B4_V58_Rd.liveAtLastFull = B4_V58_Rd.liveBefore;\n",
                                        "        B4_V58_Rd.liveAtLastFull = live;\n"),
    "live_counts_stale_bytes": ("        if (rtDiscTable[i].expiryTime != 0u) ++live;\n",
                                "        if (rtDiscTable[i].rreqId != 0u || rtDiscTable[i].expiryTime != 0u) ++live;\n"),
    "first_tick_overwritten": ("        if (B4_V58_Rd.tableFull == 0u) B4_V58_Rd.firstFullTick = now;\n",
                               "        B4_V58_Rd.firstFullTick = now;\n"),
    "other_status_not_recorded": ("        B4_V58_Rd.lastOther = (uint8_t)status;\n", ""),
    "snapshot_offset_swapped": ("    B4_V58_Put32(out + 20u, rd.ok);\n    B4_V58_Put32(out + 24u, rd.tableFull);\n",
                                "    B4_V58_Put32(out + 24u, rd.ok);\n    B4_V58_Put32(out + 20u, rd.tableFull);\n"),
    "snapshot_leaves_cs_open": ("    live = B4_V58_RreqLive(&nonzero);\n    OsalPort_leaveCS(key);\n",
                                "    live = B4_V58_RreqLive(&nonzero);\n    (void)key;\n"),
    "uart_rx_event_not_counted": ("    B4_V58_UartRxEvent(event, data);\n", ""),
    "rx_error_reaches_b1_eot": ("    B4_V58_UartRxEvent(event, data);\n    if ((event & UART2_EVENT_TX_FINISHED) != 0u)\n",
                                "    B4_V58_UartRxEvent(event, data);\n    if ((event & (UART2_EVENT_TX_FINISHED | UART2_EVENT_OVERRUN)) != 0u)\n"),
    "driver_overrun_count_ignored": ("        B4_V58_Uart[1] = data; /* UART2: accumulated overrun count */\n", ""),
    "framing_not_counted": ("    if ((event & UART2_EVENT_FRAMING) != 0u && B4_V58_Uart[2] != 0xFFFFFFFFu) ++B4_V58_Uart[2];\n", ""),
}


def _block(text, start, end_after, label):
    a = text.find(start)
    if a < 0 or text.count(start) != 1:
        raise ValueError("V58_HARNESS_BLOCK_" + label)
    b = text.find(end_after, a)
    if b < 0:
        raise ValueError("V58_HARNESS_BLOCK_END_" + label)
    return text[a:b + len(end_after)]


def compose(sdk):
    sdk = Path(sdk)
    zdo, uart = (sdk / MTZDO).read_text(), (sdk / UART).read_text()
    if MARKER_ZDO not in zdo or MARKER_UART not in uart:
        raise ValueError("V58_HARNESS_REQUIRES_APPLIED_STAGE")
    zdo_block = _block(zdo, "/* B4_V58_ROUTE_DISCOVERY_EVIDENCE: RAM-only",
                       "MT_ZDO_EXT_ROUTE_DISC, 1, &status );\n}\n", "ZDO")
    uart_state = _block(uart, "/* B4_V58_UART_RX_ERROR_EVIDENCE: RX errors",
                        "    OsalPort_leaveCS(key);\n}\n", "UART_STATE")
    callback = _block(uart, "static void B4_NpiUartTxFinishedCallback(UART2_Handle handle, uint32_t event,",
                      "        b1_startup_uart_event(handle, event, data, userArg);\n    }\n}\n", "UART_CB")
    return PRELUDE + uart_state + callback + zdo_block + MAIN


def exercise(sdk):
    code = compose(sdk)
    uart = (Path(sdk) / UART).read_text()
    # The added mask keeps TI's TX_FINISHED subscription and the single owner.
    if ("    params.eventMask |= UART2_EVENT_TX_FINISHED;\n"
            "    /* B4_V58: also count RX errors; TX_FINISHED handling is unchanged. */\n"
            "    params.eventMask |= (UART2_EVENT_OVERRUN | UART2_EVENT_FRAMING |\n"
            "                         UART2_EVENT_BREAK | UART2_EVENT_PARITY);\n") not in uart:
        raise ValueError("V58_HARNESS_EVENT_MASK_NOT_EMITTED")
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        raise RuntimeError("V58_NATIVE_C_COMPILER_REQUIRED")

    def build(name, source, should_pass):
        with tempfile.TemporaryDirectory(prefix="p7u-v58-") as td:
            unit, exe = Path(td) / "t.c", Path(td) / "t"
            unit.write_text(source, encoding="utf-8")
            built = subprocess.run(
                [cc, "-std=c11", "-O0", "-g", "-Wall", "-Wextra", "-Werror",
                 "-Wno-unused-function", "-Wno-unused-parameter",
                 "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                 str(unit), "-o", str(exe)], capture_output=True, text=True, timeout=60)
            if built.returncode:
                raise RuntimeError("V58_C_COMPILE_" + name + ": " + built.stderr[-3000:])
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
            if (run.returncode == 0) != should_pass:
                raise RuntimeError("V58_MUTANT_NOT_REJECTED_" + name + ": " +
                                   run.stdout[-400:] + run.stderr[-800:])
            return run.stdout.strip()

    output = build("actual", code, True)
    rejected = []
    for label, (old, new) in MUTANTS.items():
        if code.count(old) != 1:
            raise ValueError("V58_MUTANT_PREIMAGE_" + label + " occurrences=" + str(code.count(old)))
        build(label, code.replace(old, new, 1), False)
        rejected.append("v58:" + label)
    return {"schema": "p7u-v58-route-uart-evidence-actual-c-v1", "status": "PASS",
            "mt_zdo_sha256": hashlib.sha256((Path(sdk) / MTZDO).read_bytes()).hexdigest(),
            "npi_tl_uart_sha256": hashlib.sha256((Path(sdk) / UART).read_bytes()).hexdigest(),
            "compiled_emitted_source": True, "negative_mutants_rejected": rejected,
            "hosted_model_only": True, "closed_nwk_semantics_proven": False, "output": output}
