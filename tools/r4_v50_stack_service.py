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
EVIDENCE_SIZE = 248
AGE_LIMIT = 4
MAX_SERVICES = 12

NPI_DECLARATIONS = r"""/* B4_V50_STACK_SERVICE_EVIDENCE: B1E2 op4 reply layout is owned by
 * zstackstartup.c; the NPI owner adds the public source digest bytes. */
#define B4_V50_EVIDENCE_SIZE 248u
extern void B4_V50_StackSnapshot(uint8_t *out, uint8_t npiArmed, uint32_t npiArmTick);
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
    /* B4_V50_STACK_SERVICE_EVIDENCE_QUERY: op4 -> B1E2 on this NPI owner.
     * Answered here, never by the Stack task whose CPU use it reports. */
    if (pReq[0] == B1_STATUS_QUERY_SIZE && (pReq[1] & 0x1fu) == 1u &&
        pReq[2] == B1_STATUS_COMMAND && pReq[9] == 4u)
    {
        static uint8_t stackEvidence[B4_V50_EVIDENCE_SIZE]; /* static: bounded NPI stack */
        static const uint8_t prefix[6] = { 'B', '1', 'Q', '1', 1u, 8u };
        if (pReq[1] == 0x21u && memcmp(pReq + 3, prefix, sizeof(prefix)) == 0 &&
            pReq[10] == 0u)
        {
            B4_V50_StackSnapshot(stackEvidence, B4_V47_Armed, B4_V47_StartTick);
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
    OsalPort_leaveCS(key);
}

static void B4_V50_DispatchEnd(uint8_t idx, uint32_t returned)
{
    uint32_t key = OsalPort_enterCS();
    uint32_t spent = Clock_getTicks() - B4_V50_Since;
    B4_V50_Sat(&B4_V50_Busy, spent);
    if (idx < B4_V50_MAX_SERVICES)
    {
        B4_V50_Sat(&B4_V50_Service[idx].busy, spent);
        if (spent > B4_V50_Service[idx].longest) B4_V50_Service[idx].longest = spent;
    }
    if (returned != 0u) B4_V50_Sat(&B4_V50_Returned, 1u);
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
        B4_V6_StackPulse((uint32_t)idx+1u,1u);"""

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
            V47_DEBOOST in task or "B4_V47_Armed = 0u;" in task):
        raise ValueError("V50_SOURCE_SCOPE_DRIFT")
    for name in FILES:
        paths[name].write_text(after[name], encoding="utf-8", newline="")
    return {
        "schema": "p7u-v50-stack-service-v1",
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
        "source_digest_prefix": source_sha[:8],
        "changes_network_nv_or_security": False,
        "posts_or_clears_events": False,
        "flash_authorized": False,
        "before_sha256": {n: hashlib.sha256(before[n].encode()).hexdigest() for n in FILES},
        "modified_sha256": {n: hashlib.sha256(after[n].encode()).hexdigest() for n in FILES},
    }
