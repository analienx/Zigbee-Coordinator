#!/usr/bin/env python3
"""V58: RAM-only evidence for route-discovery refusals and UART RX errors (B1E9).

Field evidence (R4 V57, 13-15 Nov 2026, official Zigbee2MQTT 2.14.2):
  * every 0xC7 NWK_TABLE_FULL in the host log (6 in 37.5 h) was the SRSP of
    `ZDO extRouteDisc`, which zigbee-herdsman sends only after a unicast has
    already failed, as its recovery step. Five of the six targeted two Innr
    bulbs that were reporting to the coordinator in the same minute;
  * the V57 native image links TI's default route-discovery table,
    rtDiscTable[8] (gMAX_RREQ_ENTRIES = 8); V58 raises it to 40 in the T6
    compiler-option stage (tools/r4_t6_full_capacity.py);
  * on 14 Nov the V57 parser resynced 5 times at runtime; the first in DATA
    state with 67 of 75 bytes collected, i.e. bytes of a host frame were lost
    inside the radio. The NPI UART runs at 115200 baud with no flow control,
    a 32-byte DMA read buffer and a 32-byte ring buffer. TI's UART2 driver
    counts overruns only when UART2_EVENT_OVERRUN is in the event mask; the
    ZNP's mask holds TX_FINISHED only, so overruns are currently silent.

Neither cause is proven. This stage only measures, so the next field read
tells the hypotheses apart:
  1. mt_zdo.c, MT_ZdoExtRouteDisc: calls and results (SUCCESS, 0xC7, other),
     the last refused short address, and the route-discovery table occupancy
     sampled just before each request, at the last refusal, and after it.
     A refusal with every entry live confirms a full discovery table; one with
     free entries points at another NWK table. The request, its status and the
     SRSP are unchanged.
  2. npi_tl_uart.c: the existing single UART2 event callback also receives
     OVERRUN, FRAMING, BREAK and PARITY events and counts them. TX_FINISHED
     handling (B4 counter, then B1 startup EOT) is untouched. Deliberate
     behaviour change: with the overrun event enabled, TI's driver drains the
     hardware FIFO after an overrun (UART2CC26X2_hwiIntFxn), dropping the
     bytes of the frame that already lost bytes. V57's parser resync then
     hunts for the next start-of-frame, as it does today.
  3. B1E9 (B1Q1 op4 page7), answered by the NPI owner like B1E2..B1E8.
     Counters and ticks only: no keys, no IEEE addresses, no NV data.

"Live" route-discovery entries are counted as expiryTime != 0 (TI rtg.h
rtDiscEntry_t). The closed TI NWK library owns the table, so that criterion
is reported next to the count of entries with any non-zero byte; field data
must confirm it before either number is called occupancy.
"""
import hashlib
from pathlib import Path

from r4_uart_tx_liveness import once

MTZDO = "source/ti/zstack/mt/mt_zdo.c"
UART = "source/ti/zstack/npi/npi_tl_uart.c"
# Exact composed pre-images: V57 eb59b677 composition (local
# tools/p7u_compose_source_locally.sh at 94cb1c16, patch b7dc5df7, 36 files).
PREIMAGE_SHA256 = {
    MTZDO: "f75ac2853f117538e63dbcddd696662da53f5ce40bf862c31143fc3c4a44e39d",
    UART: "abef0660b4a47bf40e84a1a53358542bd6e24f813f82610fd52fe22a44c36c0c",
}
MARKER_ZDO = "B4_V58_ROUTE_DISCOVERY_EVIDENCE"
MARKER_UART = "B4_V58_UART_RX_ERROR_EVIDENCE"
EVIDENCE_SIZE = 248

ZDO_INCLUDE = '#include "nwk_util.h"\n'
ZDO_INCLUDE_NEW = '#include "nwk_util.h"\n#include "rtg.h" /* ' + MARKER_ZDO + ' */\n'

ZDO_DEF = "static void MT_ZdoExtRouteDisc( uint8_t *pBuf )\n{"
ZDO_STATE = r"""/* B4_V58_ROUTE_DISCOVERY_EVIDENCE: RAM-only counters for ZDO extRouteDisc,
 * the request zigbee-herdsman sends after a failed unicast, and the route
 * discovery table occupancy around it. The request, its status and the SRSP
 * are unchanged. Answered as B1E9 (op4 page7) by the NPI owner. */
#define B4_V58_EVIDENCE_SIZE 248u
typedef struct
{
    uint32_t calls;
    uint32_t ok;
    uint32_t tableFull;
    uint32_t other;
    uint32_t firstFullTick;
    uint32_t lastFullTick;
    uint16_t lastFullDst;
    uint8_t lastOther;
    uint8_t liveBefore;
    uint8_t liveAtLastFull;
    uint8_t maxLiveBefore;
    uint8_t maxLiveAfter;
} B4_V58_RouteDisc_t;
static B4_V58_RouteDisc_t B4_V58_Rd;

static void B4_V58_Put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8u);
    p[2] = (uint8_t)(v >> 16u); p[3] = (uint8_t)(v >> 24u);
}

static void B4_V58_Inc(uint32_t *v)
{
    if (*v != 0xFFFFFFFFu) ++*v;
}

/* expiryTime != 0 is the live criterion; *nonzero counts entries with any
 * non-zero byte, reported beside it until field data confirms the first. */
static uint8_t B4_V58_RreqLive(uint8_t *nonzero)
{
    uint16_t i, j, live = 0u, any = 0u;
    uint16_t n = (uint16_t)gMAX_RREQ_ENTRIES;
    for (i = 0u; i < n; ++i)
    {
        const uint8_t *e = (const uint8_t *)&rtDiscTable[i];
        uint8_t used = 0u;
        if (rtDiscTable[i].expiryTime != 0u) ++live;
        for (j = 0u; j < (uint16_t)sizeof(rtDiscEntry_t); ++j) used |= e[j];
        if (used != 0u) ++any;
    }
    if (nonzero != NULL) *nonzero = (uint8_t)(any > 255u ? 255u : any);
    return (uint8_t)(live > 255u ? 255u : live);
}

static void B4_V58_RouteDiscBefore(void)
{
    uint8_t live = B4_V58_RreqLive(NULL);
    B4_V58_Rd.liveBefore = live;
    if (live > B4_V58_Rd.maxLiveBefore) B4_V58_Rd.maxLiveBefore = live;
}

static void B4_V58_RouteDiscAfter(uint16_t dstAddr, ZStatus_t status)
{
    uint8_t live = B4_V58_RreqLive(NULL);
    uint32_t now = Clock_getTicks();
    B4_V58_Inc(&B4_V58_Rd.calls);
    if (live > B4_V58_Rd.maxLiveAfter) B4_V58_Rd.maxLiveAfter = live;
    if (status == ZSuccess)
    {
        B4_V58_Inc(&B4_V58_Rd.ok);
    }
    else if (status == ZNwkTableFull)
    {
        if (B4_V58_Rd.tableFull == 0u) B4_V58_Rd.firstFullTick = now;
        B4_V58_Inc(&B4_V58_Rd.tableFull);
        B4_V58_Rd.lastFullTick = now;
        B4_V58_Rd.lastFullDst = dstAddr;
        B4_V58_Rd.liveAtLastFull = B4_V58_Rd.liveBefore;
    }
    else
    {
        B4_V58_Inc(&B4_V58_Rd.other);
        B4_V58_Rd.lastOther = (uint8_t)status;
    }
}

/* NPI-owner query; the UART counters are read from npi_tl_uart.c. */
extern void B4_V58_UartRead(uint32_t *out);
__attribute__((noinline)) void B4_V58_RouteUartSnapshot(uint8_t *out)
{
    B4_V58_RouteDisc_t rd;
    uint32_t uart[7];
    uint8_t live, nonzero = 0u;
    uint16_t j, cap = (uint16_t)gMAX_RREQ_ENTRIES;
    uint32_t key;
    for (j = 0u; j < B4_V58_EVIDENCE_SIZE; ++j) out[j] = 0u;
    key = OsalPort_enterCS();
    rd = B4_V58_Rd;
    live = B4_V58_RreqLive(&nonzero);
    OsalPort_leaveCS(key);
    B4_V58_UartRead(uart);
    out[0] = 'B'; out[1] = '1'; out[2] = 'E'; out[3] = '9';
    out[4] = 1u; out[5] = (uint8_t)B4_V58_EVIDENCE_SIZE;
    out[6] = (uint8_t)((rd.tableFull ? 1u : 0u) | (rd.other ? 2u : 0u) |
                       (uart[0] ? 4u : 0u) | ((uart[2] | uart[3] | uart[4]) ? 8u : 0u));
    B4_V58_Put32(out + 12u, Clock_getTicks());
    B4_V58_Put32(out + 16u, rd.calls);
    B4_V58_Put32(out + 20u, rd.ok);
    B4_V58_Put32(out + 24u, rd.tableFull);
    B4_V58_Put32(out + 28u, rd.other);
    B4_V58_Put32(out + 32u, rd.firstFullTick);
    B4_V58_Put32(out + 36u, rd.lastFullTick);
    out[40] = rd.lastOther;
    out[41] = rd.liveAtLastFull;
    out[42] = rd.maxLiveBefore;
    out[43] = rd.maxLiveAfter;
    out[44] = live;
    out[45] = nonzero;
    out[46] = (uint8_t)(cap > 255u ? 255u : cap);
    out[47] = (uint8_t)sizeof(rtDiscEntry_t);
    out[48] = (uint8_t)rd.lastFullDst; out[49] = (uint8_t)(rd.lastFullDst >> 8u);
    for (j = 0u; j < 7u; ++j) B4_V58_Put32(out + 52u + 4u * j, uart[j]);
}

"""

ZDO_CALL = "  status = NLME_RouteDiscoveryRequest( dstAddr, pBuf[2], pBuf[3] );\n"
ZDO_CALL_NEW = ("  B4_V58_RouteDiscBefore();\n" + ZDO_CALL +
                "  B4_V58_RouteDiscAfter(dstAddr, status);\n")

UART_INCLUDE = "#include <ti/sysbios/knl/Swi.h>\n"
UART_INCLUDE_NEW = UART_INCLUDE + "#include <ti/sysbios/knl/Clock.h> /* " + MARKER_UART + " */\n"

UART_ANCHOR = "volatile uint32_t B4_NpiUartTxFinishedEvents = 0;\n"
UART_STATE = r"""/* B4_V58_UART_RX_ERROR_EVIDENCE: RX errors reported by TI's UART2 driver
 * to the existing event callback, from HWI context. RAM only (B1E9). */
static volatile uint32_t B4_V58_Uart[7]; /* overrun events, driver overrun
    count, framing, break, parity, first and last overrun tick */
static void B4_V58_UartRxEvent(uint32_t event, uint32_t data)
{
    if ((event & UART2_EVENT_OVERRUN) != 0u)
    {
        uint32_t now = Clock_getTicks();
        if (B4_V58_Uart[0] == 0u) B4_V58_Uart[5] = now;
        if (B4_V58_Uart[0] != 0xFFFFFFFFu) ++B4_V58_Uart[0];
        B4_V58_Uart[1] = data; /* UART2: accumulated overrun count */
        B4_V58_Uart[6] = now;
    }
    if ((event & UART2_EVENT_FRAMING) != 0u && B4_V58_Uart[2] != 0xFFFFFFFFu) ++B4_V58_Uart[2];
    if ((event & UART2_EVENT_BREAK) != 0u && B4_V58_Uart[3] != 0xFFFFFFFFu) ++B4_V58_Uart[3];
    if ((event & UART2_EVENT_PARITY) != 0u && B4_V58_Uart[4] != 0xFFFFFFFFu) ++B4_V58_Uart[4];
}

void B4_V58_UartRead(uint32_t *out)
{
    uint32_t key = OsalPort_enterCS();
    uint8_t j;
    for (j = 0u; j < 7u; ++j) out[j] = B4_V58_Uart[j];
    OsalPort_leaveCS(key);
}

"""

UART_CB = ("    (void)handle;\n    (void)data;\n    (void)userArg;\n"
           "    if ((event & UART2_EVENT_TX_FINISHED) != 0u)\n")
UART_CB_NEW = ("    (void)handle;\n    (void)data;\n    (void)userArg;\n"
               "    B4_V58_UartRxEvent(event, data);\n"
               "    if ((event & UART2_EVENT_TX_FINISHED) != 0u)\n")

UART_MASK = "    params.eventMask |= UART2_EVENT_TX_FINISHED;\n"
UART_MASK_NEW = (UART_MASK +
                 "    /* B4_V58: also count RX errors; TX_FINISHED handling is unchanged. */\n"
                 "    params.eventMask |= (UART2_EVENT_OVERRUN | UART2_EVENT_FRAMING |\n"
                 "                         UART2_EVENT_BREAK | UART2_EVENT_PARITY);\n")


def apply(sdk):
    sdk = Path(sdk)
    paths = {name: sdk / name for name in (MTZDO, UART)}
    if any(p.is_symlink() or not p.is_file() for p in paths.values()):
        raise ValueError("V58_FILES_REQUIRED")
    before = {name: p.read_text() for name, p in paths.items()}
    if MARKER_ZDO in before[MTZDO] or MARKER_UART in before[UART]:
        raise ValueError("V58_ALREADY_APPLIED")
    for name, text in before.items():
        if hashlib.sha256(text.encode()).hexdigest() != PREIMAGE_SHA256[name]:
            raise ValueError("V58_REQUIRES_V57_COMPOSED_PREIMAGE_" + name.rsplit("/", 1)[1])
    zdo = once(before[MTZDO], ZDO_INCLUDE, ZDO_INCLUDE_NEW, "V58_ZDO_INCLUDE")
    zdo = once(zdo, ZDO_DEF, ZDO_STATE + ZDO_DEF, "V58_ZDO_STATE")
    zdo = once(zdo, ZDO_CALL, ZDO_CALL_NEW, "V58_ZDO_ROUTE_DISC_HOOKS")
    uart = once(before[UART], UART_INCLUDE, UART_INCLUDE_NEW, "V58_UART_INCLUDE")
    uart = once(uart, UART_ANCHOR, UART_STATE + UART_ANCHOR, "V58_UART_STATE")
    uart = once(uart, UART_CB, UART_CB_NEW, "V58_UART_CALLBACK")
    uart = once(uart, UART_MASK, UART_MASK_NEW, "V58_UART_EVENT_MASK")
    if (zdo.count("NLME_RouteDiscoveryRequest(") != 1 or
            zdo.count("MT_ZDO_EXT_ROUTE_DISC, 1, &status );") != 1 or
            zdo.count("#define B4_V58_EVIDENCE_SIZE %du" % EVIDENCE_SIZE) != 1 or
            uart.count("params.eventCallback = B4_NpiUartTxFinishedCallback;") != 1 or
            uart.count("params.eventMask = UART2_EVENT_TX_FINISHED;") != 1 or
            uart.count("params.eventMask |= UART2_EVENT_TX_FINISHED;") != 1 or
            uart.count("b1_startup_uart_event(handle, event, data, userArg);") != 1 or
            uart.count("B4_V58_UartRxEvent(event, data);") != 1):
        raise ValueError("V58_SCOPE_DRIFT")
    paths[MTZDO].write_text(zdo, encoding="utf-8", newline="")
    paths[UART].write_text(uart, encoding="utf-8", newline="")
    return {
        "schema": "p7u-v58-route-uart-evidence-v1",
        "files": [MTZDO, UART],
        "b1e9_query": "B1Q1 v1/8 op4 page7",
        "b1e9_size": EVIDENCE_SIZE,
        "route_discovery_request_status_or_reply_changed": False,
        "route_discovery_live_criterion": "EXPIRY_TIME_NONZERO_UNVERIFIED_AGAINST_CLOSED_NWK",
        "uart_event_mask_added": ["OVERRUN", "FRAMING", "BREAK", "PARITY"],
        "uart_tx_finished_handling_changed": False,
        "behaviour_change": "TI_UART2_DRAINS_HW_FIFO_AFTER_AN_OVERRUN",
        "changes_network_nv_or_security": False,
        "root_cause_proven": False,
        "flash_authorized": False,
        "before_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in before.items()},
        "modified_sha256": {MTZDO: hashlib.sha256(zdo.encode()).hexdigest(),
                            UART: hashlib.sha256(uart.encode()).hexdigest()},
    }
