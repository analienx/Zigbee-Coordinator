#!/usr/bin/env python3
"""V50: keep the coordinator serviceable while the Stack task is saturated.

Supersedes the unflashed V49 READY-only NPI retention. Hardware B1E1 decode:
  * V47 polls 30-100: the Stack task was inside an NWK (service 2) dispatch on
    EVERY sample, ~57 dispatches per 0.76 s poll, input 0x2070 (broadcast,
    broadcast-timer, data-buffer-send, route-timer), returned 0, while the
    posted ZDApp INIT stayed pending behind it.
  * V48 READY frame: dev_state 9, Stack again inside NWK 0x2070. After the
    V47 window dropped NPI to its native priority 4, B1P1 got ZERO bytes.
A priority-5 Stack that never blocks starves every lower task (the NPI UART
owner: the historical "SRSP AF register after 6000ms"/"ping unavailable"
hang signature) and, through TI's lowest-index-first selection, every
higher-index service (APS, ZDApp, ...). The NWK storm cause is NOT proven.

This stage changes no network/NV/security state and adds no UART owner:
  1. NPI service floor: once B1's genuine retained-start event armed V47, the
     SAME NPI owner stays at priority 6 for the boot. Any B1 HOLD deboosts.
  2. Stack aging: TI first-ready order, but a ready service passed over
     B4_V50_AGE_LIMIT consecutive selections is served next (bounded wait).
  3. B1E2 (op4) RAM-only evidence answered by the NPI owner: per-service
     dispatch count, busy ticks, input masks and longest dispatch, plus
     selection and MAC data request/confirm/indication counters.
  4. V51 B1E3 (op4 page1) onset record for the hours-later production hang:
     the first post-READY saturated 10 s window (top service, its inputs,
     NV time, MAC deltas, heap), first/worst post-READY >=1 s dispatches,
     the worst boot dispatch, OSAL heap free/low-water/largest block, and
     NV driver time per Stack service through transparent wrappers on the
     existing pZStackCfg->nvFps table (identical arguments and results).
  5. V51 B1E4/B1E5 (op4 page2/3) post-READY trend rings, 17 x 5 min and
     17 x 60 min: Stack busy, top service, longest dispatch, NV time, heap
     low, MAC requests and confirm failures per bucket.
  6. V52: the Stack task frees expired OSAL timers after EVERY dispatch
     (r4_v52_osal_timers.py: TI deferred them to the last, first-starved
     service); B1E2 busy ticks are modular (deltas stay valid past 11.9 h
     of busy time); every latch records its 32-bit tick-wrap epoch; and B1E6
     (op4 page4) gives the NPI->MT->UART progress counters, OSAL timer
     evidence and the LIVE in-flight dispatch, which no dispatch-end latch
     can report when a handler never returns.
  7. V53: RAM read cache in front of the NV table. Hardware V52 (31 Oct):
     ~72 received frames/s each cost one ~10 ms NVOCMP linear lookup
     (ZDSecMgrReadKeyFromNv reads the NWK active key per secured frame) and
     NWK spent 98% of its CPU inside NV. Successful reads of <=32 bytes are
     served from RAM; every write/create/delete/compact/doNext/erase through
     the same table invalidates the cache before and after the driver call,
     and a read inserts only when no invalidation raced it. B1E7 (op4 page5)
     reports hits/misses and per-item NV cost (item IDs only, never data).
  8. V54: the cache honours B1's fail-closed NV/security HOLD (no hit, no
     insert, cached bytes wiped; HOLD re-checked after the driver read),
     never stores the TCLK seed, and never sees a NULL buffer or zero length.
"""
import hashlib
import re
from pathlib import Path

from r4_uart_tx_liveness import extract, once

TASK = "source/ti/zstack/npi/npi_task.c"
STACK = "source/ti/zstack/startup/zstackstartup.c"
ZMAC = "source/ti/zstack/zmac/f8w/zmac.c"
ZMAC_CB = "source/ti/zstack/zmac/f8w/zmac_cb.c"
FILES = (TASK, STACK, ZMAC, ZMAC_CB)
MARKER = "B4_V50_STACK_SERVICE_AGING_AND_EVIDENCE"
NPI_MARKER = "B4_V50_ADMITTED_NPI_SERVICE_FLOOR"
QUERY_MARKER = "B4_V50_STACK_SERVICE_EVIDENCE_QUERY"
END_MARKER = "/* B4_V50_END_STACK_SERVICE_AGING_AND_EVIDENCE */"
ONSET_MARKER = "B4_V51_ONSET_RECORD_AND_NV_TIMING"
EVIDENCE_SIZE = 248
AGE_LIMIT = 4
MAX_SERVICES = 12
WINDOW_MS = 10000
LONG_MS = 1000
SAT_PCT = 90
CALM_PCT = 50

NPI_DECLARATIONS = r"""/* B4_V50_STACK_SERVICE_EVIDENCE: B1E2 op4 page0 and B1E3 op4 page1
 * layouts are owned by zstackstartup.c; the NPI owner adds the public
 * source digest bytes. */
#define B4_V50_EVIDENCE_SIZE 248u
extern void B4_V50_StackSnapshot(uint8_t *out, uint8_t npiArmed, uint32_t npiArmTick);
extern void B4_V51_OnsetSnapshot(uint8_t *out);
extern void B4_V51_TrendSnapshot(uint8_t *out, uint8_t level);
extern void B4_V52_TimerSnapshot(uint8_t *out);
extern void B4_V52_InflightSnapshot(uint8_t *page);
extern void B4_V53_NvCacheSnapshot(uint8_t *out);
/* B4_V52 B1E6: 16..95 B4_V43 NPI->MT->UART progress, 96..199 OSAL timers,
 * 200..247 live in-flight Stack dispatch (owners write their own ranges). */
static void B4_V52_PipelineSnapshot(uint8_t *out)
{
    uint16_t j;
    for (j = 0u; j < B4_V50_EVIDENCE_SIZE; ++j) out[j] = 0u;
    out[0] = 'B'; out[1] = '1'; out[2] = 'E'; out[3] = '6';
    out[4] = 1u; out[5] = (uint8_t)B4_V50_EVIDENCE_SIZE;
    B4_V43_Snapshot(out + 16u);
    B4_V52_TimerSnapshot(out + 96u);
    B4_V52_InflightSnapshot(out);
    out[6] = (uint8_t)((out[134] != 0xFFu ? 1u : 0u) | (out[200] != 0u ? 2u : 0u));
}
static const uint8_t B4_V50_BuildDigest[4] = { @DIGEST@ };

"""

V47_ACTIVE = """static uint8_t B4_V47_ActiveLocked(void)
{
    if (!B4_V47_Armed) return 0u;
    if ((uint32_t)(Clock_getTicks() - B4_V47_StartTick) <
        B4_V47_WindowTicks) return 1u;
    B4_V47_Armed = 0u;
    return 0u;
}"""

V50_ACTIVE = """static uint8_t B4_V47_ActiveLocked(void)
{
    /* B4_V50_ADMITTED_NPI_SERVICE_FLOOR
     * V47/V48 hardware: a CPU-saturated priority5 Stack starved the native
     * priority4 NPI owner completely (zero response bytes). Once genuinely
     * armed by B1's retained-start event, keep the SAME owner above the Stack
     * for this boot: no 90s expiry and no READY bookkeeping dependency.
     * Any B1 HOLD still returns it to its native priority (see refresh). */
    return B4_V47_Armed;
}"""

V47_DEBOOST = """    if (startup && (b1_startup_state() != B1_STARTUP_RUNNING ||
        b1_management_transport_unavailable()))
        startup = 0u;"""

V50_DEBOOST = """    /* B4_V50: NV/security/transport HOLD: NPI then executes MT itself or
     * the link is gone. RUNNING, READY and FAILED keep the host serviceable. */
    if (startup && b1_management_get_hold_active())
        startup = 0u;"""

QUERY_ANCHOR = """    B4_V43_Request(0u, pReq);
    /* Strict, RAM-only op3 B1E1 and op2 B1P1 share original NPI owner."""

QUERY = """    B4_V43_Request(0u, pReq);
    /* B4_V50_STACK_SERVICE_EVIDENCE_QUERY: op4 page0 -> B1E2, page1 -> B1E3,
     * page2/3 -> B1E4/B1E5 trend rings, page4 -> B1E6 on this NPI owner. Answered here,
     * never by the Stack task whose CPU use it reports. */
    if (pReq[0] == B1_STATUS_QUERY_SIZE && (pReq[1] & 0x1fu) == 1u &&
        pReq[2] == B1_STATUS_COMMAND && pReq[9] == 4u)
    {
        static uint8_t stackEvidence[B4_V50_EVIDENCE_SIZE]; /* static: bounded NPI stack */
        static const uint8_t prefix[6] = { 'B', '1', 'Q', '1', 1u, 8u };
        if (pReq[1] == 0x21u && memcmp(pReq + 3, prefix, sizeof(prefix)) == 0 &&
            pReq[10] <= 5u)
        {
            if (pReq[10] == 0u)
                B4_V50_StackSnapshot(stackEvidence, B4_V47_Armed, B4_V47_StartTick);
            else if (pReq[10] == 1u)
                B4_V51_OnsetSnapshot(stackEvidence);
            else if (pReq[10] == 4u)
                B4_V52_PipelineSnapshot(stackEvidence);
            else if (pReq[10] == 5u)
                B4_V53_NvCacheSnapshot(stackEvidence);
            else
                B4_V51_TrendSnapshot(stackEvidence, (uint8_t)(pReq[10] - 2u));
            memcpy(stackEvidence + 8, B4_V50_BuildDigest, sizeof(B4_V50_BuildDigest));
            MT_BuildAndSendZToolResponse(0x61u, B1_STATUS_COMMAND,
                                         B4_V50_EVIDENCE_SIZE, stackEvidence);
        }
        else if (pReq[1] == 0x21u)
        {
            uint8_t rejected[3] = { 3u, pReq[1], pReq[2] };
            MT_BuildAndSendZToolResponse(0x60u, 0u, 3u, rejected);
        }
        OsalPort_msgDeallocate(pMsg->pBuf);
        OsalPort_free(pMsg);
        return 0;
    }
    /* Strict, RAM-only op3 B1E1 and op2 B1P1 share original NPI owner."""

STACK_DECLARATION = "extern void B4_V6_StackPulse(uint32_t,uint32_t);\n"

STACK_BLOCK = r"""/* B4_V50_STACK_SERVICE_AGING_AND_EVIDENCE
 * TI selects the lowest-index ready service on every Stack wake. V47 hardware
 * captured NWK (service 2) dispatched ~75 times/s with ZDApp's posted INIT
 * pending behind it, and V48's READY frame showed the same NWK input. Keep the
 * TI first-ready order, but once a ready service has been passed over
 * B4_V50_AGE_LIMIT consecutive selections, serve it next, so every ready
 * service is dispatched within a bounded number of Stack wakes. Selection
 * only: the original CS/clear/call/merge and B1 credit code is unchanged.
 * Counters are RAM-only B1E2 evidence; nothing here posts or clears events.
 */
#include <ti/sysbios/knl/Clock.h>
#define B4_V50_MAX_SERVICES 12u
#define B4_V50_AGE_LIMIT 4u
#define B4_V50_EVIDENCE_SIZE 248u
typedef struct
{
    uint32_t dispatches, busy, inputs, longest;
} B4_V50_Service_t;
static B4_V50_Service_t B4_V50_Service[B4_V50_MAX_SERVICES];
static uint8_t B4_V50_Skipped[B4_V50_MAX_SERVICES];
static uint32_t B4_V50_Wakes, B4_V50_Empty, B4_V50_Aged, B4_V50_Returned, B4_V50_Busy;
static uint32_t B4_V50_Since;
static uint8_t B4_V50_Current, B4_V50_MaxSkip;
static uint32_t B4_V50_MacReq, B4_V50_MacReqOk, B4_V50_MacCnf, B4_V50_MacCnfFail;
static uint32_t B4_V50_MacInd, B4_V50_MacEvents;
static uint8_t B4_V50_MacReqLast, B4_V50_MacCnfLast;
/* B4_V52: 10 us ticks wrap every ~11.9 h, inside an hours-long collapse.
 * The Stack task counts wraps at each dispatch end; latches keep their
 * epoch. NWK storm bits (nwk.h) present at dispatch, modular counts. */
static uint32_t B4_V52_LastNow, B4_V52_NwkBits[4];
static uint8_t B4_V52_Wraps;
extern void OsalPortTimers_cleanUpTimers(void);
extern void B4_V52_TimerProbe(uint8_t taskId);

static void B4_V50_Sat(uint32_t *value, uint32_t add)
{
    *value = (0xFFFFFFFFu - *value < add) ? 0xFFFFFFFFu : *value + add;
}

/* Stack task only. Unlocked event-word reads match TI's own first-ready
 * scan; other contexts only ever set bits, and the dispatch below still
 * clears and merges the selected word inside the original OSAL CS. */
static uint8_t B4_V50_SelectService(void)
{
    uint8_t idx, first = zstackTasksCnt, aged = zstackTasksCnt;
    if (zstackTasksCnt > B4_V50_MAX_SERVICES)
    {
        /* Unsupported table size: exact original TI first-ready selection. */
        for (idx = 0u; idx < zstackTasksCnt; ++idx)
            if (*(pTasksEvents[idx])) break;
        return idx;
    }
    for (idx = 0u; idx < zstackTasksCnt; ++idx)
    {
        if (*(pTasksEvents[idx]) == 0u) continue;
        if (first == zstackTasksCnt) first = idx;
        if (aged == zstackTasksCnt && B4_V50_Skipped[idx] >= B4_V50_AGE_LIMIT)
            aged = idx;
    }
    idx = (aged < zstackTasksCnt) ? aged : first;
    if (idx < zstackTasksCnt)
    {
        uint8_t j;
        uint32_t key = OsalPort_enterCS();
        if (idx != first) B4_V50_Sat(&B4_V50_Aged, 1u);
        for (j = 0u; j < zstackTasksCnt; ++j)
        {
            if (j == idx || *(pTasksEvents[j]) == 0u)
                B4_V50_Skipped[j] = 0u;
            else if (B4_V50_Skipped[j] < 0xFFu)
            {
                ++B4_V50_Skipped[j];
                if (B4_V50_Skipped[j] > B4_V50_MaxSkip) B4_V50_MaxSkip = B4_V50_Skipped[j];
            }
        }
        OsalPort_leaveCS(key);
    }
    return idx;
}

static void B4_V50_NoteSelection(uint8_t idx)
{
    uint32_t key = OsalPort_enterCS();
    B4_V50_Sat(&B4_V50_Wakes, 1u);
    if (idx >= zstackTasksCnt) B4_V50_Sat(&B4_V50_Empty, 1u);
    OsalPort_leaveCS(key);
}

/* B4_V51_ONSET_RECORD_AND_NV_TIMING
 * Production hangs develop over hours (27-Oct F2: AF timeouts rising ~14 h
 * before the last reply), long after any startup observer closed. B1E3
 * latches in RAM what the Stack was doing when it FIRST saturated after
 * READY (devState DEV_ZB_COORD), the first and the worst post-READY >=1 s
 * dispatches, the worst boot dispatch, OSAL heap free/low-water/largest
 * block, and NV driver time per Stack service. NV timing wraps the existing
 * pZStackCfg->nvFps members: same arguments, same results, same order.
 * Nothing here posts, clears or reorders events or changes NV contents.
 */
#define B4_V51_WINDOW_MS 10000u
#define B4_V51_LONG_MS 1000u
#define B4_V51_SAT_PCT 90u
#define B4_V51_CALM_PCT 50u
#define B4_V51_NV_SERVICES 10u /* B1E3 room: this build has 10 services */
#define B4_V51_TREND_ENTRIES 17u
#define B4_V51_FINE_MS 300000u     /* B1E4: 17 x 5 min  */
#define B4_V51_COARSE_MS 3600000u  /* B1E5: 17 x 60 min */
#define B4_V51_READY 0x01u
#define B4_V51_SETTLED 0x02u
#define B4_V51_ONSET 0x04u
#define B4_V51_LONG 0x08u
#define B4_V51_NV_HOOKED 0x10u
#define B4_V51_AFTER_CALM 0x20u
#define B4_V51_HEAP 0x40u
typedef struct
{
    uint32_t tick, ticks, input, returned, nv;
    uint8_t service, nvOps;
} B4_V51_Dispatch_t;
typedef struct
{
    uint32_t tick, busy, elapsed, dispatches, svcBusy, svcInputs, nv, heap;
    uint16_t macReq, macCnfFail, macInd;
    uint8_t service;
} B4_V51_Onset_t;
typedef struct
{
    uint8_t flags, dispReady, dispNvOps, nvLongestKind, nvLongestSvc, nvLastFail, nvLastFailKind;
    uint8_t readyEpoch, settleEpoch, onsetEpoch, longEpoch, heapEpoch;
    uint16_t consec, maxConsec, nvDeletes, nvCompacts, nvFails;
    uint8_t winHeapSeen;
    uint32_t winStart, winBusy, winDispatches, winNv, winMacReq, winMacCnfFail, winMacInd;
    uint32_t winMaxDispatch, winHeapLow;
    uint32_t winSvcBusy[B4_V50_MAX_SERVICES], winSvcInputs[B4_V50_MAX_SERVICES];
    uint32_t windows, satWindows, busyWindows, peakBusy, peakElapsed, peakTick;
    uint32_t readyTick, settleTick, heapLow, heapLowTick;
    uint32_t nvReads, nvWrites, nvTicks, nvOther, nvLongest, dispNv, dispInput;
    uint32_t svcNv[B4_V50_MAX_SERVICES];
    B4_V51_Onset_t onset;
    B4_V51_Dispatch_t firstLong, runWorst, bootWorst;
} B4_V51_t;
/* Same untagged member list as osal_port.c's ICall_heapStats_t, hence a
 * compatible type across translation units (C11 6.2.7). */
typedef struct
{
    uint32_t totalSize;
    uint32_t totalFreeSize;
    uint32_t largestFreeSize;
} B4_V51_HeapStats_t;
/* OSAL heapmgr instance in osal_port.c (rtos_heaposal.h template). */
extern uint32_t heapmgrMemFreeTotal;
extern void OsalPort_heapGetStats(B4_V51_HeapStats_t *stats);
/* Post-READY trend rings, fed from every rated 10 s window: the firmware
 * keeps the hours-long history a host sampler could not (27-Oct F2 skipped
 * 1097 of 1177 samples while the adapter queue was busy). */
typedef struct
{
    uint16_t busyPermille, maxDispatchMs, nvMs, heapLow16, macReq;
    uint8_t service, macCnfFail;
} B4_V51_TrendEntry_t;
typedef struct
{
    uint32_t start, busy, nv, maxDispatch, heapLow, macReq, macCnfFail, pushed;
    uint32_t svcBusy[B4_V50_MAX_SERVICES];
    uint8_t head, count, heapSeen;
    B4_V51_TrendEntry_t ring[B4_V51_TREND_ENTRIES];
} B4_V51_Trend_t;
static B4_V51_t B4_V51;
static B4_V51_Trend_t B4_V51_Trend[2];
static NVINTF_nvFuncts_t B4_V51_Nv;

/* B4_V53_NV_READ_CACHE: see the stage docstring. This ZNP build has no NV
 * writer outside pZStackCfg->nvFps (main.c skips sampleApp_task under
 * ZNP_NPI), so table-level invalidation is complete. Cached bytes never
 * leave this file; B1E7 reports counts and item IDs only. */
#define B4_V53_CACHE_ENTRIES 8u
#define B4_V53_CACHE_BYTES 32u
#define B4_V53_HOT_ENTRIES 8u
typedef struct
{
    NVINTF_itemID_t id;
    uint16_t offset, length;
    uint8_t used;
    uint8_t data[B4_V53_CACHE_BYTES];
} B4_V53_Line_t;
typedef struct
{
    uint32_t count, ticks, maxTicks;
    uint16_t itemID, subID;
    uint8_t systemID, status, kind, used;
} B4_V53_Hot_t;
static B4_V53_Line_t B4_V53_Cache[B4_V53_CACHE_ENTRIES];
static B4_V53_Hot_t B4_V53_Hot[B4_V53_HOT_ENTRIES];
static uint32_t B4_V53_Gen, B4_V53_Hits, B4_V53_Misses, B4_V53_Inserts, B4_V53_Invalidations;
static uint8_t B4_V53_Next;

static uint8_t B4_V53_SameId(const NVINTF_itemID_t *a, const NVINTF_itemID_t *b)
{
    return a->systemID == b->systemID && a->itemID == b->itemID && a->subID == b->subID;
}

/* Any task. Before AND after every mutating driver call. */
static void B4_V53_Invalidate(void)
{
    uint32_t key = OsalPort_enterCS();
    uint8_t i, j;
    ++B4_V53_Gen;
    for (i = 0u; i < B4_V53_CACHE_ENTRIES; ++i)
    {
        if (!B4_V53_Cache[i].used) continue;
        B4_V53_Cache[i].used = 0u;
        for (j = 0u; j < B4_V53_CACHE_BYTES; ++j) B4_V53_Cache[i].data[j] = 0u;
    }
    B4_V50_Sat(&B4_V53_Invalidations, 1u);
    OsalPort_leaveCS(key);
}

static uint32_t B4_V53_Generation(void)
{
    uint32_t key = OsalPort_enterCS();
    uint32_t gen = B4_V53_Gen;
    OsalPort_leaveCS(key);
    return gen;
}

/* Exact (item, offset, length) match only; copies inside the CS. */
static uint8_t B4_V53_Lookup(NVINTF_itemID_t id, uint16_t offset, uint16_t length, void *buffer)
{
    uint32_t key = OsalPort_enterCS();
    uint8_t i, j, hit = 0u;
    for (i = 0u; i < B4_V53_CACHE_ENTRIES && !hit; ++i)
    {
        B4_V53_Line_t *line = &B4_V53_Cache[i];
        if (!line->used || !B4_V53_SameId(&line->id, &id) ||
            line->offset != offset || line->length != length) continue;
        for (j = 0u; j < length; ++j) ((uint8_t *)buffer)[j] = line->data[j];
        hit = 1u;
    }
    B4_V50_Sat(hit ? &B4_V53_Hits : &B4_V53_Misses, 1u);
    OsalPort_leaveCS(key);
    return hit;
}

/* Insert a successful driver read only if no invalidation raced it. */
static void B4_V53_Insert(NVINTF_itemID_t id, uint16_t offset, uint16_t length,
                          const void *buffer, uint32_t gen)
{
    uint32_t key;
    uint8_t j;
    if (length == 0u || length > B4_V53_CACHE_BYTES || buffer == NULL) return;
    key = OsalPort_enterCS();
    if (gen == B4_V53_Gen)
    {
        B4_V53_Line_t *line = &B4_V53_Cache[B4_V53_Next];
        B4_V53_Next = (uint8_t)((B4_V53_Next + 1u) % B4_V53_CACHE_ENTRIES);
        line->id = id;
        line->offset = offset;
        line->length = length;
        for (j = 0u; j < length; ++j) line->data[j] = ((const uint8_t *)buffer)[j];
        line->used = 1u;
        B4_V50_Sat(&B4_V53_Inserts, 1u);
    }
    OsalPort_leaveCS(key);
}

/* Per-item driver cost (cache hits excluded): the costliest items stay. */
static void B4_V53_NoteItem(NVINTF_itemID_t id, uint8_t kind, uint32_t start, uint8_t status)
{
    uint32_t key = OsalPort_enterCS();
    uint32_t spent = Clock_getTicks() - start;
    B4_V53_Hot_t *slot = NULL;
    uint8_t i;
    for (i = 0u; i < B4_V53_HOT_ENTRIES && slot == NULL; ++i)
        if (B4_V53_Hot[i].used && B4_V53_Hot[i].systemID == id.systemID &&
            B4_V53_Hot[i].itemID == id.itemID && B4_V53_Hot[i].subID == id.subID &&
            B4_V53_Hot[i].kind == kind)
            slot = &B4_V53_Hot[i];
    for (i = 0u; i < B4_V53_HOT_ENTRIES && slot == NULL; ++i)
        if (!B4_V53_Hot[i].used) slot = &B4_V53_Hot[i];
    if (slot == NULL)
    {
        B4_V53_Hot_t *least = &B4_V53_Hot[0];
        for (i = 1u; i < B4_V53_HOT_ENTRIES; ++i)
            if (B4_V53_Hot[i].ticks < least->ticks) least = &B4_V53_Hot[i];
        if (spent > least->ticks) { slot = least; slot->count = slot->ticks = slot->maxTicks = 0u; }
    }
    if (slot != NULL)
    {
        if (!slot->used || slot->itemID != id.itemID || slot->subID != id.subID ||
            slot->systemID != id.systemID || slot->kind != kind)
        {
            slot->count = slot->ticks = slot->maxTicks = 0u;
            slot->systemID = id.systemID; slot->itemID = id.itemID; slot->subID = id.subID;
            slot->kind = kind; slot->used = 1u;
        }
        B4_V50_Sat(&slot->count, 1u);
        B4_V50_Sat(&slot->ticks, spent);
        if (spent > slot->maxTicks) slot->maxTicks = spent;
        slot->status = status;
    }
    OsalPort_leaveCS(key);
}

static uint32_t B4_V51_MsTicks(uint32_t ms)
{
    uint32_t period = Clock_tickPeriod;
    return period == 0u ? 0xFFFFFFFFu : (uint32_t)(((uint64_t)ms * 1000u) / period);
}

static void B4_V51_Sat16(uint16_t *value)
{
    if (*value != 0xFFFFu) ++*value;
}

static uint16_t B4_V51_Delta16(uint32_t now, uint32_t then)
{
    uint32_t delta = now - then;
    return delta > 0xFFFFu ? 0xFFFFu : (uint16_t)delta;
}

/* Any task context. kind 1 read, 2 create/update/write, 3 delete, 4 compact.
 * Time inside a Stack dispatch is charged to that service. */
static void B4_V51_NvDone(uint8_t kind, uint32_t start, uint8_t status)
{
    B4_V51_t *v = &B4_V51;
    uint32_t key = OsalPort_enterCS();
    uint32_t spent = Clock_getTicks() - start;
    uint8_t service = (Task_self() == stackTaskHndl) ? B4_V50_Current : 0u;
    B4_V50_Sat(&v->nvTicks, spent);
    if (kind == 1u) B4_V50_Sat(&v->nvReads, 1u);
    else if (kind == 2u) B4_V50_Sat(&v->nvWrites, 1u);
    else if (kind == 3u) B4_V51_Sat16(&v->nvDeletes);
    else B4_V51_Sat16(&v->nvCompacts);
    /* A read of an absent item (NOTFOUND) is ordinary lookup traffic. */
    if (kind != 1u && status != 0u)
    {
        B4_V51_Sat16(&v->nvFails);
        v->nvLastFail = status;
        v->nvLastFailKind = kind;
    }
    if (spent > v->nvLongest)
    {
        v->nvLongest = spent;
        v->nvLongestKind = kind;
        v->nvLongestSvc = service;
    }
    if (service != 0u && service <= B4_V50_MAX_SERVICES)
    {
        B4_V50_Sat(&v->svcNv[service - 1u], spent);
        B4_V50_Sat(&v->dispNv, spent);
        B4_V50_Sat(&v->winNv, spent);
        if (v->dispNvOps != 0xFFu) ++v->dispNvOps;
    }
    else
        B4_V50_Sat(&v->nvOther, spent);
    OsalPort_leaveCS(key);
}

/* B4_V54_CACHE_HOLD_AND_SECRET_GUARD
 * 1. B1's fail-closed NV/security HOLD makes the driver refuse or zero every
 *    read. A cache hit must not outlive it: while held, every read goes to
 *    the driver, nothing is inserted, and any cached bytes are wiped.
 *    The HOLD is re-checked after the driver read too, because B1's
 *    NVOCMP_read zeroes the caller buffer when it latches a fault mid-read.
 * 2. The TCLK seed derives every TC link key and is read only for
 *    APS-secured traffic: it is never kept in this cache.
 * 3. Arguments the driver rejects (NULL buffer, zero length) never reach
 *    the cache; the driver returns its own BADPARAM. */
extern int b1_nv_runtime_hold_active(void);
#if !defined(NVINTF_SYSID_ZSTACK) || !defined(ZCD_NV_EX_LEGACY) || \
    !defined(ZCD_NV_TCLK_SEED) || NVINTF_SYSID_ZSTACK != 1 || \
    ZCD_NV_EX_LEGACY != 0x0000 || ZCD_NV_TCLK_SEED != 0x0101
#error B4_V54_PINNED_NV_ITEM_IDS_DRIFT
#endif
static uint8_t B4_V54_Cacheable(NVINTF_itemID_t id, uint16_t length, const void *buffer)
{
    if (buffer == NULL || length == 0u) return 0u;
    return !(id.systemID == NVINTF_SYSID_ZSTACK && id.itemID == ZCD_NV_EX_LEGACY &&
             id.subID == ZCD_NV_TCLK_SEED);
}

static void B4_V54_PurgeHeld(void)
{
    uint8_t i, any = 0u;
    uint32_t key = OsalPort_enterCS();
    for (i = 0u; i < B4_V53_CACHE_ENTRIES; ++i) any |= B4_V53_Cache[i].used;
    OsalPort_leaveCS(key);
    if (any) B4_V53_Invalidate();
}

static uint8_t B4_V51_NvReadItem(NVINTF_itemID_t id, uint16_t offset,
                                 uint16_t length, void *buffer)
{
    uint8_t cacheable = B4_V54_Cacheable(id, length, buffer);
    if (b1_nv_runtime_hold_active())
    {
        B4_V54_PurgeHeld();
        cacheable = 0u;
    }
    if (cacheable && B4_V53_Lookup(id, offset, length, buffer)) return NVINTF_SUCCESS;
    uint32_t gen = B4_V53_Generation();
    uint32_t start = Clock_getTicks();
    uint8_t status = B4_V51_Nv.readItem(id, offset, length, buffer);
    B4_V51_NvDone(1u, start, status);
    B4_V53_NoteItem(id, 1u, start, status);
    if (status == NVINTF_SUCCESS && cacheable && !b1_nv_runtime_hold_active())
        B4_V53_Insert(id, offset, length, buffer, gen);
    return status;
}

static uint8_t B4_V51_NvReadContItem(NVINTF_itemID_t id, uint16_t offset,
                                     uint16_t rlength, void *rbuffer,
                                     uint16_t clength, uint16_t coffset,
                                     void *cbuffer, uint16_t *pSubId)
{
    uint32_t start = Clock_getTicks();
    uint8_t status = B4_V51_Nv.readContItem(id, offset, rlength, rbuffer,
                                            clength, coffset, cbuffer, pSubId);
    B4_V51_NvDone(1u, start, status);
    return status;
}

static uint32_t B4_V51_NvGetItemLen(NVINTF_itemID_t id)
{
    uint32_t start = Clock_getTicks();
    uint32_t length = B4_V51_Nv.getItemLen(id);
    B4_V51_NvDone(1u, start, 0u);
    return length;
}

static uint8_t B4_V51_NvCreateItem(NVINTF_itemID_t id, uint32_t length, void *buffer)
{
    B4_V53_Invalidate();
    uint32_t start = Clock_getTicks();
    uint8_t created = B4_V51_Nv.createItem(id, length, buffer);
    B4_V51_NvDone(2u, start, created);
    B4_V53_Invalidate();
    B4_V53_NoteItem(id, 2u, start, created);
    return created;
}

static uint8_t B4_V51_NvUpdateItem(NVINTF_itemID_t id, uint32_t length, void *buffer)
{
    B4_V53_Invalidate();
    uint32_t start = Clock_getTicks();
    uint8_t updated = B4_V51_Nv.updateItem(id, length, buffer);
    B4_V51_NvDone(2u, start, updated);
    B4_V53_Invalidate();
    B4_V53_NoteItem(id, 2u, start, updated);
    return updated;
}

static uint8_t B4_V51_NvWriteItem(NVINTF_itemID_t id, uint16_t length, void *buffer)
{
    B4_V53_Invalidate();
    uint32_t start = Clock_getTicks();
    uint8_t written = B4_V51_Nv.writeItem(id, length, buffer);
    B4_V51_NvDone(2u, start, written);
    B4_V53_Invalidate();
    B4_V53_NoteItem(id, 2u, start, written);
    return written;
}

static uint8_t B4_V51_NvDeleteItem(NVINTF_itemID_t id)
{
    B4_V53_Invalidate();
    uint32_t start = Clock_getTicks();
    uint8_t deleted = B4_V51_Nv.deleteItem(id);
    B4_V51_NvDone(3u, start, deleted);
    B4_V53_Invalidate();
    B4_V53_NoteItem(id, 3u, start, deleted);
    return deleted;
}

static uint8_t B4_V51_NvCompact(uint16_t minBytes)
{
    B4_V53_Invalidate();
    uint32_t start = Clock_getTicks();
    uint8_t compacted = B4_V51_Nv.compactNV(minBytes);
    B4_V51_NvDone(4u, start, compacted);
    B4_V53_Invalidate();
    return compacted;
}

/* Iteration may delete (NVINTF_DODELETE); erase removes everything. */
static uint8_t B4_V53_NvDoNext(NVINTF_nvProxy_t *nvProxy)
{
    B4_V53_Invalidate();
    uint8_t done = B4_V51_Nv.doNext(nvProxy);
    B4_V53_Invalidate();
    return done;
}

static uint8_t B4_V53_NvErase(void)
{
    B4_V53_Invalidate();
    uint8_t erased = B4_V51_Nv.eraseNV();
    B4_V53_Invalidate();
    return erased;
}

/* Stack task entry, once, before its first NV use. Only populated members
 * are wrapped; each wrapper calls the saved original. The copy and the swap
 * share one CS, so no task can reach a wrapper before its original is saved;
 * later callers see either pointer, and both reach the same driver. */
static void B4_V51_InstallNvHooks(void)
{
    NVINTF_nvFuncts_t *fps;
    uint32_t key;
    if ((B4_V51.flags & B4_V51_NV_HOOKED) != 0u || pZStackCfg == NULL) return;
    key = OsalPort_enterCS();
    fps = &pZStackCfg->nvFps;
    B4_V51_Nv = *fps;
    if (fps->readItem != NULL) fps->readItem = B4_V51_NvReadItem;
    if (fps->readContItem != NULL) fps->readContItem = B4_V51_NvReadContItem;
    if (fps->getItemLen != NULL) fps->getItemLen = B4_V51_NvGetItemLen;
    if (fps->createItem != NULL) fps->createItem = B4_V51_NvCreateItem;
    if (fps->updateItem != NULL) fps->updateItem = B4_V51_NvUpdateItem;
    if (fps->writeItem != NULL) fps->writeItem = B4_V51_NvWriteItem;
    if (fps->deleteItem != NULL) fps->deleteItem = B4_V51_NvDeleteItem;
    if (fps->compactNV != NULL) fps->compactNV = B4_V51_NvCompact;
    if (fps->doNext != NULL) fps->doNext = B4_V53_NvDoNext;
    if (fps->eraseNV != NULL) fps->eraseNV = B4_V53_NvErase;
    B4_V51.flags |= B4_V51_NV_HOOKED;
    OsalPort_leaveCS(key);
}

static void B4_V51_Note(B4_V51_Dispatch_t *d, uint8_t idx, uint32_t now,
                        uint32_t spent, uint32_t returned)
{
    d->tick = now;
    d->ticks = spent;
    d->input = B4_V51.dispInput;
    d->returned = returned;
    d->nv = B4_V51.dispNv;
    d->service = (uint8_t)(idx + 1u);
    d->nvOps = B4_V51.dispNvOps;
}

static void B4_V51_WindowReset(uint32_t now)
{
    B4_V51_t *v = &B4_V51;
    uint8_t j;
    v->winStart = now;
    v->winBusy = 0u;
    v->winDispatches = 0u;
    v->winNv = 0u;
    v->winMaxDispatch = 0u;
    v->winHeapSeen = 0u;
    for (j = 0u; j < B4_V50_MAX_SERVICES; ++j)
    {
        v->winSvcBusy[j] = 0u;
        v->winSvcInputs[j] = 0u;
    }
    v->winMacReq = B4_V50_MacReq;
    v->winMacCnfFail = B4_V50_MacCnfFail;
    v->winMacInd = B4_V50_MacInd;
}

static uint16_t B4_V50_Ms(uint32_t ticks); /* defined with the snapshots */

static uint16_t B4_V51_Cap16(uint32_t value)
{
    return value > 0xFFFFu ? 0xFFFFu : (uint16_t)value;
}

/* One trend bucket from accumulated rated windows spanning `span` ticks. */
static void B4_V51_TrendEntry(const B4_V51_Trend_t *t, uint32_t span, B4_V51_TrendEntry_t *e)
{
    uint64_t permille = span ? ((uint64_t)t->busy * 1000u) / span : 0u;
    uint8_t top, j;
    for (top = 0u, j = 1u; j < B4_V50_MAX_SERVICES; ++j)
        if (t->svcBusy[j] > t->svcBusy[top]) top = j;
    e->busyPermille = permille > 1000u ? 1000u : (uint16_t)permille;
    e->service = t->busy ? (uint8_t)(top + 1u) : 0u;
    e->macCnfFail = t->macCnfFail > 0xFFu ? 0xFFu : (uint8_t)t->macCnfFail;
    e->maxDispatchMs = B4_V50_Ms(t->maxDispatch);
    e->nvMs = B4_V50_Ms(t->nv);
    e->heapLow16 = t->heapSeen ? B4_V51_Cap16(t->heapLow / 16u) : 0u;
    e->macReq = B4_V51_Cap16(t->macReq);
}

/* Stack task, inside DispatchEnd's CS, for each rated post-READY window. */
static void B4_V51_TrendFeed(B4_V51_Trend_t *t, uint32_t periodMs, uint32_t now)
{
    B4_V51_t *v = &B4_V51;
    uint32_t span;
    uint8_t j;
    B4_V50_Sat(&t->busy, v->winBusy);
    B4_V50_Sat(&t->nv, v->winNv);
    if (v->winMaxDispatch > t->maxDispatch) t->maxDispatch = v->winMaxDispatch;
    if (v->winHeapSeen != 0u && (t->heapSeen == 0u || v->winHeapLow < t->heapLow))
    {
        t->heapLow = v->winHeapLow;
        t->heapSeen = 1u;
    }
    B4_V50_Sat(&t->macReq, B4_V50_MacReq - v->winMacReq);
    B4_V50_Sat(&t->macCnfFail, B4_V50_MacCnfFail - v->winMacCnfFail);
    for (j = 0u; j < B4_V50_MAX_SERVICES; ++j) B4_V50_Sat(&t->svcBusy[j], v->winSvcBusy[j]);
    span = now - t->start;
    if (span < B4_V51_MsTicks(periodMs)) return;
    B4_V51_TrendEntry(t, span, &t->ring[t->head]);
    t->head = (uint8_t)((t->head + 1u) % B4_V51_TREND_ENTRIES);
    if (t->count < B4_V51_TREND_ENTRIES) ++t->count;
    B4_V50_Sat(&t->pushed, 1u);
    t->start = now;
    t->busy = t->nv = t->maxDispatch = t->heapLow = t->macReq = t->macCnfFail = 0u;
    t->heapSeen = 0u;
    for (j = 0u; j < B4_V50_MAX_SERVICES; ++j) t->svcBusy[j] = 0u;
}

/* Stack task, inside DispatchEnd's CS. Only post-READY windows are rated. */
static void B4_V51_WindowRoll(uint32_t now)
{
    B4_V51_t *v = &B4_V51;
    uint32_t elapsed = now - v->winStart;
    uint64_t busy;
    uint8_t sat, calm, top, j;
    if (elapsed < B4_V51_MsTicks(B4_V51_WINDOW_MS)) return;
    if ((v->flags & B4_V51_READY) != 0u)
    {
        busy = (uint64_t)v->winBusy * 100u;
        sat = busy >= (uint64_t)elapsed * B4_V51_SAT_PCT;
        calm = busy < (uint64_t)elapsed * B4_V51_CALM_PCT;
        B4_V50_Sat(&v->windows, 1u);
        if (!calm) B4_V50_Sat(&v->busyWindows, 1u);
        if (sat)
        {
            B4_V50_Sat(&v->satWindows, 1u);
            B4_V51_Sat16(&v->consec);
            if (v->consec > v->maxConsec) v->maxConsec = v->consec;
        }
        else
            v->consec = 0u;
        if (v->peakElapsed == 0u ||
            (uint64_t)v->winBusy * v->peakElapsed > (uint64_t)v->peakBusy * elapsed)
        {
            v->peakBusy = v->winBusy;
            v->peakElapsed = elapsed;
            v->peakTick = now;
        }
        if (calm && (v->flags & B4_V51_SETTLED) == 0u)
        {
            v->flags |= B4_V51_SETTLED;
            v->settleTick = now;
            v->settleEpoch = B4_V52_Wraps;
        }
        if (sat && (v->flags & B4_V51_ONSET) == 0u)
        {
            for (top = 0u, j = 1u; j < B4_V50_MAX_SERVICES; ++j)
                if (v->winSvcBusy[j] > v->winSvcBusy[top]) top = j;
            if ((v->flags & B4_V51_SETTLED) != 0u) v->flags |= B4_V51_AFTER_CALM;
            v->flags |= B4_V51_ONSET;
            v->onset.tick = now;
            v->onsetEpoch = B4_V52_Wraps;
            v->onset.busy = v->winBusy;
            v->onset.elapsed = elapsed;
            v->onset.dispatches = v->winDispatches;
            v->onset.service = (uint8_t)(top + 1u);
            v->onset.svcBusy = v->winSvcBusy[top];
            v->onset.svcInputs = v->winSvcInputs[top];
            v->onset.nv = v->winNv;
            v->onset.heap = heapmgrMemFreeTotal;
            v->onset.macReq = B4_V51_Delta16(B4_V50_MacReq, v->winMacReq);
            v->onset.macCnfFail = B4_V51_Delta16(B4_V50_MacCnfFail, v->winMacCnfFail);
            v->onset.macInd = B4_V51_Delta16(B4_V50_MacInd, v->winMacInd);
        }
        B4_V51_TrendFeed(&B4_V51_Trend[0], B4_V51_FINE_MS, now);
        B4_V51_TrendFeed(&B4_V51_Trend[1], B4_V51_COARSE_MS, now);
    }
    B4_V51_WindowReset(now);
}

/* Stack task, inside DispatchEnd's CS, with the dispatch's own phase. */
static void B4_V51_DispatchEnd(uint8_t idx, uint32_t returned, uint32_t now, uint32_t spent)
{
    B4_V51_t *v = &B4_V51;
    if (v->dispReady != 0u)
    {
        uint32_t heapFree = heapmgrMemFreeTotal;
        if ((v->flags & B4_V51_HEAP) == 0u || heapFree < v->heapLow)
        {
            v->heapLow = heapFree;
            v->heapLowTick = now;
            v->heapEpoch = B4_V52_Wraps;
            v->flags |= B4_V51_HEAP;
        }
        if (v->winHeapSeen == 0u || heapFree < v->winHeapLow)
        {
            v->winHeapLow = heapFree;
            v->winHeapSeen = 1u;
        }
        if (spent > v->runWorst.ticks) B4_V51_Note(&v->runWorst, idx, now, spent, returned);
        if ((v->flags & B4_V51_LONG) == 0u && spent >= B4_V51_MsTicks(B4_V51_LONG_MS))
        {
            B4_V51_Note(&v->firstLong, idx, now, spent, returned);
            v->longEpoch = B4_V52_Wraps;
            v->flags |= B4_V51_LONG;
        }
    }
    else if (spent > v->bootWorst.ticks)
        B4_V51_Note(&v->bootWorst, idx, now, spent, returned);
    B4_V50_Sat(&v->winBusy, spent);
    B4_V50_Sat(&v->winDispatches, 1u);
    if (spent > v->winMaxDispatch) v->winMaxDispatch = spent;
    if (idx < B4_V50_MAX_SERVICES)
    {
        B4_V50_Sat(&v->winSvcBusy[idx], spent);
        v->winSvcInputs[idx] |= v->dispInput;
    }
    if ((v->flags & B4_V51_READY) == 0u && devState == DEV_ZB_COORD)
    {
        /* Post-READY windows contain post-READY time only. */
        v->flags |= B4_V51_READY;
        v->readyTick = now;
        v->readyEpoch = B4_V52_Wraps;
        B4_V51_Trend[0].start = now;
        B4_V51_Trend[1].start = now;
        B4_V51_WindowReset(now);
    }
    else
        B4_V51_WindowRoll(now);
}

static void B4_V50_DispatchBegin(uint8_t idx, uint32_t events)
{
    uint32_t key = OsalPort_enterCS();
    B4_V50_Since = Clock_getTicks();
    B4_V50_Current = (uint8_t)(idx + 1u);
    if (idx < B4_V50_MAX_SERVICES)
    {
        B4_V50_Sat(&B4_V50_Service[idx].dispatches, 1u);
        B4_V50_Service[idx].inputs |= events;
    }
    /* B4_V51: per-dispatch NV attribution and boot/READY phase. */
    B4_V51.dispNv = 0u;
    B4_V51.dispNvOps = 0u;
    B4_V51.dispInput = events;
    B4_V51.dispReady = (uint8_t)(B4_V51.flags & B4_V51_READY);
    if (pTasksEvents[idx] == &nwkServiceEvents)
    {
        if (events & RTG_TIMER_EVENT) ++B4_V52_NwkBits[0];
        if (events & NWK_DATABUF_SEND) ++B4_V52_NwkBits[1];
        if (events & NWK_BCAST_TIMER_EVT) ++B4_V52_NwkBits[2];
        if (events & NWK_BROADCAST_MSG_EVT) ++B4_V52_NwkBits[3];
    }
    OsalPort_leaveCS(key);
}

static void B4_V50_DispatchEnd(uint8_t idx, uint32_t returned)
{
    uint32_t key = OsalPort_enterCS();
    uint32_t now = Clock_getTicks();
    uint32_t spent = now - B4_V50_Since;
    if (now < B4_V52_LastNow) ++B4_V52_Wraps;
    B4_V52_LastNow = now;
    B4_V50_Busy += spent; /* B4_V52: modular; every consumer takes deltas */
    if (idx < B4_V50_MAX_SERVICES)
    {
        B4_V50_Service[idx].busy += spent; /* B4_V52: modular */
        if (spent > B4_V50_Service[idx].longest) B4_V50_Service[idx].longest = spent;
    }
    if (returned != 0u) B4_V50_Sat(&B4_V50_Returned, 1u);
    B4_V51_DispatchEnd(idx, returned, now, spent);
    B4_V50_Current = 0u;
    OsalPort_leaveCS(key);
}

/* ZMacDataReqSec entry, before B1's HOLD refusal: any context. */
__attribute__((noinline)) void B4_V50_MacDataReqEnter(void)
{
    uint32_t key = OsalPort_enterCS();
    B4_V50_Sat(&B4_V50_MacReq, 1u);
    OsalPort_leaveCS(key);
}

/* Synchronous MAP_MAC_McpsDataReq result; 0 is MAC_SUCCESS. */
__attribute__((noinline)) void B4_V50_MacDataReqDone(uint8_t status)
{
    uint32_t key = OsalPort_enterCS();
    if (status == 0u) B4_V50_Sat(&B4_V50_MacReqOk, 1u);
    else B4_V50_MacReqLast = status;
    OsalPort_leaveCS(key);
}

/* MAC_CbackEvent: kind 1 data confirm, 2 data indication, 0 other. */
__attribute__((noinline)) void B4_V50_MacEvent(uint8_t kind, uint8_t status)
{
    uint32_t key = OsalPort_enterCS();
    B4_V50_Sat(&B4_V50_MacEvents, 1u);
    if (kind == 1u)
    {
        B4_V50_Sat(&B4_V50_MacCnf, 1u);
        if (status != 0u)
        {
            B4_V50_Sat(&B4_V50_MacCnfFail, 1u);
            B4_V50_MacCnfLast = status;
        }
    }
    else if (kind == 2u)
        B4_V50_Sat(&B4_V50_MacInd, 1u);
    OsalPort_leaveCS(key);
}

static void B4_V50_Put32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8u);
    out[2] = (uint8_t)(value >> 16u);
    out[3] = (uint8_t)(value >> 24u);
}

static uint16_t B4_V50_Ms(uint32_t ticks)
{
    uint32_t period = Clock_tickPeriod, ms;
    if (period == 0u) return 0u;
    if (period <= 1000u) ms = ticks / (1000u / period);
    else if (ticks > 0xFFFFFFFFu / (period / 1000u)) ms = 0xFFFFFFFFu;
    else ms = ticks * (period / 1000u);
    return ms > 0xFFFFu ? 0xFFFFu : (uint16_t)ms;
}

/* NPI owner context only (single, non-reentrant caller). One short CS copy;
 * the copy is static because the NPI task stack is only 1024 bytes. */
__attribute__((noinline)) void B4_V50_StackSnapshot(uint8_t *out, uint8_t npiArmed, uint32_t npiArmTick)
{
    static B4_V50_Service_t services[B4_V50_MAX_SERVICES];
    uint32_t wakes, empty, aged, returned, busy, age, now;
    uint32_t macReq, macReqOk, macCnf, macCnfFail, macInd, macEvents;
    uint8_t current, maxSkip, macReqLast, macCnfLast, count, j;
    uint32_t key = OsalPort_enterCS();
    for (j = 0u; j < B4_V50_MAX_SERVICES; ++j) services[j] = B4_V50_Service[j];
    wakes = B4_V50_Wakes; empty = B4_V50_Empty; aged = B4_V50_Aged;
    returned = B4_V50_Returned; busy = B4_V50_Busy; current = B4_V50_Current;
    maxSkip = B4_V50_MaxSkip; macReq = B4_V50_MacReq; macReqOk = B4_V50_MacReqOk;
    macCnf = B4_V50_MacCnf; macCnfFail = B4_V50_MacCnfFail; macInd = B4_V50_MacInd;
    macEvents = B4_V50_MacEvents; macReqLast = B4_V50_MacReqLast;
    macCnfLast = B4_V50_MacCnfLast;
    now = Clock_getTicks();
    age = current ? now - B4_V50_Since : 0u;
    OsalPort_leaveCS(key);
    count = zstackTasksCnt > B4_V50_MAX_SERVICES ? (uint8_t)B4_V50_MAX_SERVICES : zstackTasksCnt;
    for (j = 0u; j < B4_V50_EVIDENCE_SIZE; ++j) out[j] = 0u;
    out[0] = 'B'; out[1] = '1'; out[2] = 'E'; out[3] = '2';
    out[4] = 1u; out[5] = (uint8_t)B4_V50_EVIDENCE_SIZE; out[6] = count;
    out[7] = (uint8_t)((zstackTasksCnt <= B4_V50_MAX_SERVICES ? 1u : 2u) |
                       (npiArmed ? 0x80u : 0u));
    /* out[8..11]: public source digest, written by the NPI owner. */
    B4_V50_Put32(out + 12u, now);
    B4_V50_Put32(out + 16u, Clock_tickPeriod);
    B4_V50_Put32(out + 20u, wakes);
    B4_V50_Put32(out + 24u, empty);
    B4_V50_Put32(out + 28u, aged);
    B4_V50_Put32(out + 32u, returned);
    B4_V50_Put32(out + 36u, busy);
    B4_V50_Put32(out + 40u, age);
    out[44] = current;
    out[45] = maxSkip;
    out[46] = (uint8_t)Task_getPri(Task_self());
    out[47] = stackTaskHndl != NULL ? (uint8_t)Task_getPri(stackTaskHndl) : 0xFFu;
    B4_V50_Put32(out + 48u, macReq);
    B4_V50_Put32(out + 52u, macReqOk);
    B4_V50_Put32(out + 56u, macCnf);
    B4_V50_Put32(out + 60u, macCnfFail);
    B4_V50_Put32(out + 64u, macInd);
    B4_V50_Put32(out + 68u, macEvents);
    B4_V50_Put32(out + 72u, npiArmTick);
    out[76] = macReqLast;
    out[77] = macCnfLast;
    for (j = 0u; j < count; ++j)
    {
        uint16_t longest = B4_V50_Ms(services[j].longest);
        B4_V50_Put32(out + 80u + 4u * j, services[j].dispatches);
        B4_V50_Put32(out + 128u + 4u * j, services[j].busy);
        B4_V50_Put32(out + 176u + 4u * j, services[j].inputs);
        out[224u + 2u * j] = (uint8_t)longest;
        out[225u + 2u * j] = (uint8_t)(longest >> 8u);
    }
}

static void B4_V51_Put16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8u);
}

static void B4_V51_PutDispatch(uint8_t *out, const B4_V51_Dispatch_t *d)
{
    B4_V50_Put32(out, d->tick);
    B4_V51_Put16(out + 4u, B4_V50_Ms(d->ticks));
    out[6] = d->service;
    out[7] = d->nvOps;
    B4_V50_Put32(out + 8u, d->input);
    B4_V50_Put32(out + 12u, d->returned);
    B4_V50_Put32(out + 16u, d->nv);
}

static uint16_t B4_V51_Clamp16(size_t value)
{
    return value > 0xFFFFu ? 0xFFFFu : (uint16_t)value;
}

/* NPI owner context only (single, non-reentrant caller), like B1E2. The heap
 * walk runs under the heap manager's own lock BEFORE the one short CS copy;
 * copies are static because the NPI task stack is only 1024 bytes. Task
 * stack high-water needs TI-RTOS Task.initStackFlag (0 when unavailable). */
__attribute__((noinline)) void B4_V51_OnsetSnapshot(uint8_t *out)
{
    static B4_V51_t s;
    static Task_Stat stackStat, npiStat;
    B4_V51_HeapStats_t heap = { 0u, 0u, 0u };
    uint32_t key, now;
    uint8_t j;
    stackStat.used = 0u; stackStat.stackSize = 0u;
    if (stackTaskHndl != NULL) Task_stat(stackTaskHndl, &stackStat);
    Task_stat(Task_self(), &npiStat);
    OsalPort_heapGetStats(&heap);
    key = OsalPort_enterCS();
    s = B4_V51;
    now = Clock_getTicks();
    OsalPort_leaveCS(key);
    for (j = 0u; j < B4_V50_EVIDENCE_SIZE; ++j) out[j] = 0u;
    out[0] = 'B'; out[1] = '1'; out[2] = 'E'; out[3] = '3';
    out[4] = 1u; out[5] = (uint8_t)B4_V50_EVIDENCE_SIZE; out[6] = s.flags;
    out[7] = (uint8_t)(B4_V51_WINDOW_MS / 1000u);
    /* out[8..11]: public source digest, written by the NPI owner. */
    B4_V50_Put32(out + 12u, now);
    B4_V50_Put32(out + 16u, s.windows);
    B4_V50_Put32(out + 20u, s.satWindows);
    B4_V50_Put32(out + 24u, s.busyWindows);
    B4_V51_Put16(out + 28u, s.consec);
    B4_V51_Put16(out + 30u, s.maxConsec);
    B4_V50_Put32(out + 32u, s.peakBusy);
    B4_V50_Put32(out + 36u, s.peakElapsed);
    B4_V50_Put32(out + 40u, s.peakTick);
    B4_V50_Put32(out + 44u, s.readyTick);
    B4_V50_Put32(out + 48u, s.settleTick);
    B4_V50_Put32(out + 52u, s.nvReads);
    B4_V50_Put32(out + 56u, s.nvWrites);
    B4_V51_Put16(out + 60u, s.nvDeletes);
    B4_V51_Put16(out + 62u, s.nvCompacts);
    B4_V51_Put16(out + 64u, s.nvFails);
    out[66] = s.nvLastFail;
    out[67] = s.nvLastFailKind;
    B4_V50_Put32(out + 68u, s.nvTicks);
    B4_V50_Put32(out + 72u, s.nvOther);
    B4_V51_Put16(out + 76u, B4_V50_Ms(s.nvLongest));
    out[78] = s.nvLongestKind;
    out[79] = s.nvLongestSvc;
    B4_V50_Put32(out + 80u, heap.totalSize);
    B4_V50_Put32(out + 84u, heap.totalFreeSize);
    B4_V50_Put32(out + 88u, heap.largestFreeSize);
    B4_V50_Put32(out + 92u, s.heapLow);
    B4_V50_Put32(out + 96u, s.heapLowTick);
    B4_V50_Put32(out + 100u, s.onset.tick);
    B4_V50_Put32(out + 104u, s.onset.busy);
    B4_V50_Put32(out + 108u, s.onset.elapsed);
    B4_V50_Put32(out + 112u, s.onset.dispatches);
    out[116] = s.onset.service;
    B4_V51_Put16(out + 118u, s.onset.macCnfFail);
    B4_V50_Put32(out + 120u, s.onset.svcBusy);
    B4_V50_Put32(out + 124u, s.onset.svcInputs);
    B4_V50_Put32(out + 128u, s.onset.nv);
    B4_V51_Put16(out + 132u, s.onset.macReq);
    B4_V51_Put16(out + 134u, s.onset.macInd);
    B4_V50_Put32(out + 136u, s.onset.heap);
    B4_V51_PutDispatch(out + 140u, &s.firstLong);
    B4_V51_PutDispatch(out + 160u, &s.runWorst);
    B4_V51_PutDispatch(out + 180u, &s.bootWorst);
    for (j = 0u; j < B4_V51_NV_SERVICES && j < B4_V50_MAX_SERVICES; ++j)
        B4_V50_Put32(out + 200u + 4u * j, s.svcNv[j]);
    B4_V51_Put16(out + 240u, B4_V51_Clamp16(stackStat.used));
    B4_V51_Put16(out + 242u, B4_V51_Clamp16(stackStat.stackSize));
    B4_V51_Put16(out + 244u, B4_V51_Clamp16(npiStat.used));
    B4_V51_Put16(out + 246u, B4_V51_Clamp16(npiStat.stackSize));
}

static void B4_V51_PutTrend(uint8_t *out, const B4_V51_TrendEntry_t *e)
{
    B4_V51_Put16(out, e->busyPermille);
    out[2] = e->service;
    out[3] = e->macCnfFail;
    B4_V51_Put16(out + 4u, e->maxDispatchMs);
    B4_V51_Put16(out + 6u, e->nvMs);
    B4_V51_Put16(out + 8u, e->heapLow16);
    B4_V51_Put16(out + 10u, e->macReq);
}

/* NPI owner context only. level 0: B1E4 (5 min), 1: B1E5 (60 min). The
 * partial bucket covers completed windows since the last push; entries are
 * oldest first. One short CS copy into static storage (1024 B NPI stack). */
__attribute__((noinline)) void B4_V51_TrendSnapshot(uint8_t *out, uint8_t level)
{
    static B4_V51_Trend_t t;
    B4_V51_TrendEntry_t partial;
    uint32_t key, now, rolled, span;
    uint8_t ready, i, j;
    key = OsalPort_enterCS();
    t = B4_V51_Trend[level != 0u ? 1u : 0u];
    rolled = B4_V51.winStart;
    ready = (uint8_t)(B4_V51.flags & B4_V51_READY);
    now = Clock_getTicks();
    OsalPort_leaveCS(key);
    for (j = 0u; j < B4_V50_EVIDENCE_SIZE; ++j) out[j] = 0u;
    out[0] = 'B'; out[1] = '1'; out[2] = 'E'; out[3] = level != 0u ? '5' : '4';
    out[4] = 1u; out[5] = (uint8_t)B4_V50_EVIDENCE_SIZE; out[6] = t.count;
    out[7] = (uint8_t)((level != 0u ? B4_V51_COARSE_MS : B4_V51_FINE_MS) / 60000u);
    /* out[8..11]: public source digest, written by the NPI owner. */
    B4_V50_Put32(out + 12u, now);
    B4_V50_Put32(out + 16u, t.pushed);
    span = ready ? rolled - t.start : 0u;
    B4_V50_Put32(out + 20u, span);
    B4_V51_TrendEntry(&t, span, &partial);
    B4_V51_PutTrend(out + 24u, &partial);
    for (i = 0u; i < t.count; ++i)
        B4_V51_PutTrend(out + 36u + 12u * i,
                        &t.ring[(t.head + B4_V51_TREND_ENTRIES - t.count + i) %
                                B4_V51_TREND_ENTRIES]);
}

/* NPI owner context only: B1E6 now (12..15) and the live dispatch
 * (200..247). It shows a handler that has NOT returned, which no
 * dispatch-end latch (B1E3 windows, long dispatches) can ever finalize. */
__attribute__((noinline)) void B4_V52_InflightSnapshot(uint8_t *page)
{
    uint32_t key, now, since, input, nv, winStart, winBusy, winDispatches, bits[4];
    uint8_t current, nvOps, wraps, epochs[5], j;
    key = OsalPort_enterCS();
    now = Clock_getTicks();
    current = B4_V50_Current;
    since = B4_V50_Since;
    input = B4_V51.dispInput;
    nv = B4_V51.dispNv;
    nvOps = B4_V51.dispNvOps;
    winStart = B4_V51.winStart;
    winBusy = B4_V51.winBusy;
    winDispatches = B4_V51.winDispatches;
    wraps = (uint8_t)(B4_V52_Wraps + (now < B4_V52_LastNow ? 1u : 0u));
    epochs[0] = B4_V51.readyEpoch;
    epochs[1] = B4_V51.onsetEpoch;
    epochs[2] = B4_V51.longEpoch;
    epochs[3] = B4_V51.heapEpoch;
    epochs[4] = B4_V51.settleEpoch;
    for (j = 0u; j < 4u; ++j) bits[j] = B4_V52_NwkBits[j];
    OsalPort_leaveCS(key);
    B4_V50_Put32(page + 12u, now);
    page[200] = current;
    page[201] = current ? nvOps : 0u;
    page[202] = wraps;
    page[203] = epochs[0];
    B4_V50_Put32(page + 204u, current ? input : 0u);
    B4_V50_Put32(page + 208u, current ? now - since : 0u);
    B4_V50_Put32(page + 212u, current ? nv : 0u);
    B4_V50_Put32(page + 216u, winBusy);
    B4_V50_Put32(page + 220u, now - winStart);
    B4_V50_Put32(page + 224u, winDispatches);
    for (j = 0u; j < 4u; ++j) B4_V50_Put32(page + 228u + 4u * j, bits[j]);
    for (j = 1u; j < 5u; ++j) page[243u + j] = epochs[j];
}

/* NPI owner context only: B1E7 = read-cache counters and the costliest NV
 * items (system/item/sub IDs, kind, count, driver ticks); never data. */
__attribute__((noinline)) void B4_V53_NvCacheSnapshot(uint8_t *out)
{
    static B4_V53_Hot_t hot[B4_V53_HOT_ENTRIES];
    uint32_t key, now, hits, misses, inserts, invalidations;
    uint8_t i, lines = 0u;
    key = OsalPort_enterCS();
    for (i = 0u; i < B4_V53_HOT_ENTRIES; ++i) hot[i] = B4_V53_Hot[i];
    for (i = 0u; i < B4_V53_CACHE_ENTRIES; ++i) lines = (uint8_t)(lines + B4_V53_Cache[i].used);
    hits = B4_V53_Hits; misses = B4_V53_Misses; inserts = B4_V53_Inserts;
    invalidations = B4_V53_Invalidations;
    now = Clock_getTicks();
    OsalPort_leaveCS(key);
    for (i = 0u; i < B4_V50_EVIDENCE_SIZE; ++i) out[i] = 0u;
    out[0] = 'B'; out[1] = '1'; out[2] = 'E'; out[3] = '7';
    out[4] = 1u; out[5] = (uint8_t)B4_V50_EVIDENCE_SIZE; out[6] = lines;
    out[7] = (uint8_t)B4_V53_CACHE_ENTRIES;
    /* out[8..11]: public source digest, written by the NPI owner. */
    B4_V50_Put32(out + 12u, now);
    B4_V50_Put32(out + 16u, hits);
    B4_V50_Put32(out + 20u, misses);
    B4_V50_Put32(out + 24u, inserts);
    B4_V50_Put32(out + 28u, invalidations);
    for (i = 0u; i < B4_V53_HOT_ENTRIES; ++i)
    {
        uint8_t *e = out + 32u + 24u * i;
        if (!hot[i].used) continue;
        e[0] = hot[i].systemID;
        e[1] = hot[i].status;
        B4_V51_Put16(e + 2u, hot[i].itemID);
        B4_V51_Put16(e + 4u, hot[i].subID);
        e[6] = hot[i].kind;
        e[7] = 1u;
        B4_V50_Put32(e + 8u, hot[i].count);
        B4_V50_Put32(e + 12u, hot[i].ticks);
        B4_V50_Put32(e + 16u, hot[i].maxTicks);
    }
}
/* B4_V50_END_STACK_SERVICE_AGING_AND_EVIDENCE */
"""

V48_ELSE = """      else
      {
        // Original priority-based first-ready selection for all other work.
        do {
          if (*(pTasksEvents[idx]))
          {
            break;
          }
        } while (++idx < zstackTasksCnt);
      }

      if (idx < zstackTasksCnt)
      {"""

V50_ELSE = """      else
      {
        /* B4_V50: TI first-ready order with bounded aging (see above). */
        idx = B4_V50_SelectService();
      }
      B4_V50_NoteSelection(idx);

      if (idx < zstackTasksCnt)
      {"""

DISPATCH = """        B4_V6_StackPulse((uint32_t)idx+1u,0u);
        events = (zstackTasksArr[idx])( 0U, events );
        B4_V6_StackPulse((uint32_t)idx+1u,1u);"""

V50_DISPATCH = """        B4_V6_StackPulse((uint32_t)idx+1u,0u);
        B4_V50_DispatchBegin(idx, events);
        events = (zstackTasksArr[idx])( 0U, events );
        B4_V50_DispatchEnd(idx, events);
        OsalPortTimers_cleanUpTimers(); /* B4_V52: never wait for service 9 */
        B4_V6_StackPulse((uint32_t)idx+1u,1u);"""

NWK_INIT = "    nwk_init( tmpServiceId );\n"
V52_NWK_INIT = ("    nwk_init( tmpServiceId );\n"
                "    B4_V52_TimerProbe( tmpServiceId ); /* B4_V52: NWK timer evidence */\n")

TASK_ENTRY = """static void stackTaskFxn(UArg a0, UArg a1)
{
    /* Task context: pZStackCfg is bound; NV mutex is initialized."""

V51_TASK_ENTRY = """static void stackTaskFxn(UArg a0, UArg a1)
{
    /* B4_V51: transparent RAM-only NV timing, before the first Stack NV use. */
    B4_V51_InstallNvHooks();
    /* Task context: pZStackCfg is bound; NV mutex is initialized."""

ZMAC_DECL = '#include "mac_api.h"\nextern int b1_nv_runtime_hold_active(void);'
ZMAC_SIGNATURE = "uint8_t ZMacDataReqSec( ZMacDataReq_t *pData, applySecCB_t secCB )"
ZMAC_ENTRY = "{\n  if (b1_nv_runtime_hold_active()) return MAC_NO_RESOURCES;\n  ApiMac_mcpsDataReq_t dataReq;"
ZMAC_CALL = "  /* Call Mac Data Request */\n  stat = MAP_MAC_McpsDataReq( &dataReq );\n"
CB_ENTRY = "void MAC_CbackEvent(macCbackEvent_t *pData)\n{\n  uint8_t event = pData->hdr.event;\n"


def digest_bytes(source_sha):
    if not isinstance(source_sha, str) or re.fullmatch("[0-9a-f]{40}", source_sha) is None:
        raise ValueError("V50_EXACT_SOURCE_SHA_REQUIRED")
    return ", ".join("0x" + source_sha[i:i + 2] for i in range(0, 8, 2))


def apply(sdk, source_sha):
    sdk = Path(sdk)
    paths = {name: sdk / name for name in FILES}
    if any(p.is_symlink() or not p.is_file() for p in paths.values()):
        raise ValueError("V50_EXACT_COMPOSITE_FILES_REQUIRED")
    before = {name: paths[name].read_text() for name in FILES}
    if any(MARKER in text or NPI_MARKER in text for text in before.values()):
        raise ValueError("V50_ALREADY_APPLIED")
    task, stack = before[TASK], before[STACK]
    if ("B4_V47_BOUNDED_B1_STARTUP_NPI" not in task or
            "B4_V46_PENDING_SRSP_TASK_PRIORITY" not in task or
            "B4_V49_RETAINED_READY_NPI_OWNER" in task or
            "B4_V48_RETAINED_ZDAPP_DISPATCH_FAIRNESS" not in stack or
            "if (events != 0u) Semaphore_post(stackSemHandle);" not in stack):
        raise ValueError("V50_REQUIRES_EXACT_V47_NPI_AND_V48_STACK")

    task = once(task, "/* B4_V47_BOUNDED_B1_STARTUP_NPI",
                NPI_DECLARATIONS.replace("@DIGEST@", digest_bytes(source_sha)) +
                "/* B4_V47_BOUNDED_B1_STARTUP_NPI", "V50_NPI_DECLARATIONS")
    task = once(task, V47_ACTIVE, V50_ACTIVE, "V50_STICKY_ARMED_NPI_FLOOR")
    task = once(task, V47_DEBOOST, V50_DEBOOST, "V50_ANY_B1_HOLD_DEBOOSTS")
    task = once(task, QUERY_ANCHOR, QUERY, "V50_B1E2_NPI_QUERY")

    stack = once(stack, STACK_DECLARATION, STACK_DECLARATION + STACK_BLOCK,
                 "V50_STACK_HELPERS_BEFORE_TASK")
    stack = once(stack, V48_ELSE, V50_ELSE, "V50_AGED_SELECTION_AFTER_V48")
    stack = once(stack, DISPATCH, V50_DISPATCH, "V50_DISPATCH_EVIDENCE")
    stack = once(stack, TASK_ENTRY, V51_TASK_ENTRY, "V51_NV_HOOKS_AT_STACK_TASK_ENTRY")
    stack = once(stack, NWK_INIT, V52_NWK_INIT, "V52_NWK_TIMER_PROBE")

    zmac = once(before[ZMAC], ZMAC_DECL, ZMAC_DECL +
                "\nextern void B4_V50_MacDataReqEnter(void);"
                "\nextern void B4_V50_MacDataReqDone(uint8_t status);",
                "V50_ZMAC_DECLARATIONS")
    body = extract(zmac, ZMAC_SIGNATURE)
    new_body = once(body, ZMAC_SIGNATURE + "\n" + ZMAC_ENTRY,
                    ZMAC_SIGNATURE + "\n{\n"
                    "  B4_V50_MacDataReqEnter(); /* B4_V50: counted before B1 HOLD refusal */\n"
                    + ZMAC_ENTRY[2:], "V50_ZMAC_REQUEST_ENTRY")
    new_body = once(new_body, ZMAC_CALL,
                    ZMAC_CALL + "  B4_V50_MacDataReqDone(stat);\n",
                    "V50_ZMAC_SYNCHRONOUS_RESULT")
    zmac = once(zmac, body, new_body, "V50_ZMAC_FUNCTION")

    cb = once(before[ZMAC_CB], CB_ENTRY,
              "extern void B4_V50_MacEvent(uint8_t kind, uint8_t status);\n" + CB_ENTRY +
              "  B4_V50_MacEvent(event == MAC_MCPS_DATA_CNF ? 1u :\n"
              "                  (event == MAC_MCPS_DATA_IND ? 2u : 0u),\n"
              "                  (uint8_t)pData->hdr.status);\n",
              "V50_MAC_CALLBACK_COUNTERS")

    after = {TASK: task, STACK: stack, ZMAC: zmac, ZMAC_CB: cb}
    if (task.count(NPI_MARKER) != 1 or task.count(QUERY_MARKER) != 1 or
            stack.count(MARKER) != 1 or stack.count(END_MARKER) != 1 or
            stack.count("idx = B4_V50_SelectService();") != 1 or
            stack.count("B4_V50_DispatchBegin(idx, events);") != 1 or
            stack.count("Semaphore_post(stackSemHandle);") != 1 or
            stack.count(ONSET_MARKER) != 1 or
            stack.count("    B4_V51_InstallNvHooks();") != 1 or
            not (stack.index("    B4_V51_InstallNvHooks();") <
                 stack.index("if (!b1_sec_validate_restored()) return;") <
                 stack.index("    stackInit();")) or
            task.count("B4_V51_OnsetSnapshot(stackEvidence);") != 1 or
            task.count("B4_V51_TrendSnapshot(stackEvidence, (uint8_t)(pReq[10] - 2u));") != 1 or
            task.count("B4_V52_PipelineSnapshot(stackEvidence);") != 1 or
            task.count("B4_V53_NvCacheSnapshot(stackEvidence);") != 1 or
            stack.count("B4_V53_Invalidate();") != 15 or
            stack.count("B4_V54_CACHE_HOLD_AND_SECRET_GUARD") != 1 or
            stack.count("if (b1_nv_runtime_hold_active())\n    {\n        B4_V54_PurgeHeld();") != 1 or
            stack.count("cacheable && !b1_nv_runtime_hold_active())") != 1 or
            stack.count("OsalPortTimers_cleanUpTimers(); /* B4_V52") != 1 or
            stack.count("B4_V52_TimerProbe( tmpServiceId );") != 1 or
            "B4_V50_Sat(&B4_V50_Busy" in stack or
            V47_DEBOOST in task or "B4_V47_Armed = 0u;" in task):
        raise ValueError("V50_SOURCE_SCOPE_DRIFT")
    for name in FILES:
        paths[name].write_text(after[name], encoding="utf-8", newline="")
    return {
        "schema": "p7u-v50-stack-service-v5",
        "supersedes_unflashed": "V49_READY_NPI_RETENTION",
        "root_cause_proven": False,
        "npi_priority_after_retained_arm": 6,
        "npi_deboost": "ANY_B1_HOLD",
        "npi_time_window": None,
        "stack_selection": "TI_FIRST_READY_WITH_AGING",
        "stack_age_limit": AGE_LIMIT,
        "stack_evidence_services": MAX_SERVICES,
        "b1e2_size": EVIDENCE_SIZE,
        "b1e2_query": "B1Q1 v1/8 op4",
        "b1e3_query": "B1Q1 v1/8 op4 page1",
        "b1e3_size": EVIDENCE_SIZE,
        "onset_window_ms": WINDOW_MS,
        "onset_saturated_pct": SAT_PCT,
        "onset_calm_pct": CALM_PCT,
        "long_dispatch_ms": LONG_MS,
        "trend_queries": {"B1E4": "op4 page2 17x5min", "B1E5": "op4 page3 17x60min"},
        "b1e6_query": "B1Q1 v1/8 op4 page4",
        "expired_timer_free": "STACK_TASK_AFTER_EVERY_DISPATCH",
        "busy_ticks": "MODULAR_DELTA_SAFE",
        "tick_wrap_epochs": True,
        "nv_read_cache": {"entries": 8, "max_bytes": 32, "invalidation": "EVERY_TABLE_MUTATION_BEFORE_AND_AFTER",
                          "evidence": "B1E7 op4 page5",
                          "b1_hold": "NO_HIT_NO_INSERT_WIPE_AND_RECHECK_AFTER_READ",
                          "never_cached": ["ZCD_NV_TCLK_SEED"],
                          "argument_guard": "NULL_BUFFER_OR_ZERO_LENGTH_BYPASS"},
        "onset_phase_boundary": "devState == DEV_ZB_COORD",
        "nv_timing": "TRANSPARENT_NVFPS_WRAPPERS_SAME_ARGUMENTS_AND_RESULTS",
        "heap_source": "OSAL_HEAPMGR_TOTAL_FREE_AND_GETSTATS",
        "source_digest_prefix": source_sha[:8],
        "changes_network_nv_or_security": False,
        "posts_or_clears_events": False,
        "flash_authorized": False,
        "before_sha256": {n: hashlib.sha256(before[n].encode()).hexdigest() for n in FILES},
        "modified_sha256": {n: hashlib.sha256(after[n].encode()).hexdigest() for n in FILES},
    }
