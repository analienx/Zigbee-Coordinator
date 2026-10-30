#!/usr/bin/env python3
"""Compile the EMITTED V50/V51 C from the composed SDK and reject behavior mutants.

Three hosted programs, each built from exact composed source text:
  A. V47/V50 NPI priority helpers + V46 refresh (scheduler/clock stubs).
  B. The real composed stackTaskFxn loop (V48 branch, V50 aging, original
     CS/clear/call/merge/B1 credit) with ten deterministic service handlers,
     plus the V50 evidence, MAC counters and B1E2 snapshot layout, and the
     V51 NV wrappers, boot/READY phases, onset windows and B1E3 layout.
  C. The NPI B1E2/B1E3 op4 query branch of NPITask_sendBufToStack.
Every mutant below changes an asserted outcome; none is equivalent. This is a
hosted functional model only: NOT hardware state9 or NWK root-cause evidence.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

from r4_startup_ingress_priority_harness import PREFIX as V47_PREFIX, function
from r4_v50_stack_service import (TASK, STACK, MARKER, END_MARKER, QUERY_MARKER,
                                  NPI_MARKER, ONSET_MARKER, EVIDENCE_SIZE, AGE_LIMIT)

NPI_STUB = V47_PREFIX + r"""
static uint8_t hold_active;
static int b1_management_get_hold_active(void) { return hold_active || transport_hold; }
"""

NPI_MAIN = r"""
int main(void)
{
    B4_V46_RefreshNpiPriority(); assert(npiTaskStruct.priority == 4);
    /* Only B1's genuine retained-start event (state RUNNING) can arm. */
    startup_state = 2; B4_V47_ArmStartupNpi(); assert(npiTaskStruct.priority == 4);
    startup_state = 3; B4_V47_ArmStartupNpi(); assert(npiTaskStruct.priority == 6);
    /* Far beyond V47's 90s window: the service floor remains. */
    tick += 1000000u; B4_V46_RefreshNpiPriority(); assert(npiTaskStruct.priority == 6);
    /* READY and FAILED do not hide the host link either. */
    startup_state = 4; B4_V46_RefreshNpiPriority(); assert(npiTaskStruct.priority == 6);
    startup_state = 5; B4_V46_RefreshNpiPriority(); assert(npiTaskStruct.priority == 6);
    /* NV/security HOLD: NPI executes MT itself, so return to native 4. */
    startup_state = 4; hold_active = 1u;
    B4_V46_RefreshNpiPriority(); assert(npiTaskStruct.priority == 4);
    hold_active = 0u; transport_hold = 1u;
    B4_V46_RefreshNpiPriority(); assert(npiTaskStruct.priority == 4);
    transport_hold = 0u;
    B4_V46_RefreshNpiPriority(); assert(npiTaskStruct.priority == 6);
    /* Unarmed boots keep V46's pending-SRSP behavior unchanged. */
    B4_V47_Armed = 0u; startup_state = 0;
    B4_V46_RefreshNpiPriority(); assert(npiTaskStruct.priority == 4);
    queue_record.count = 1; B4_V46_RefreshNpiPriority(); assert(npiTaskStruct.priority == 6);
    queue_record.count = 0; B4_V46_RefreshNpiPriority(); assert(npiTaskStruct.priority == 4);
    /* Arming is refused under transport HOLD and on narrow RTOS configs. */
    transport_hold = 1u; startup_state = 3;
    B4_V47_ArmStartupNpi(); assert(npiTaskStruct.priority == 4 && !B4_V47_Armed);
    transport_hold = 0u; Task_numPriorities = 6;
    B4_V47_ArmStartupNpi(); assert(npiTaskStruct.priority == 4 && !B4_V47_Armed);
    Task_numPriorities = 8;
    assert(!cs_depth && !scheduler_depth);
    printf("V50_NPI_FLOOR_REAL_C_PASS changes=%u\n", priority_changes);
    return 0;
}
"""

NPI_MUTANTS = {
    "window_expiry_restored": (
        "    return B4_V47_Armed;\n}",
        "    if (!B4_V47_Armed) return 0u;\n"
        "    if ((uint32_t)(Clock_getTicks() - B4_V47_StartTick) <\n"
        "        B4_V47_WindowTicks) return 1u;\n"
        "    B4_V47_Armed = 0u;\n    return 0u;\n}"),
    "running_state_only": (
        "    if (startup && b1_management_get_hold_active())",
        "    if (startup && (b1_startup_state() != B1_STARTUP_RUNNING ||\n"
        "        b1_management_get_hold_active()))"),
    "hold_ignored": (
        "    if (startup && b1_management_get_hold_active())",
        "    if (startup && 0)"),
    "transport_hold_only": (
        "    if (startup && b1_management_get_hold_active())",
        "    if (startup && b1_management_transport_unavailable())"),
    "no_npi_floor": (
        "int priority = (urgent || startup) &&",
        "int priority = urgent &&"),
}

STACK_STUB = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define ZDO_NETWORK_INIT 0x0001u
#define ZDO_NETWORK_START 0x0002u
#define BIOS_WAIT_FOREVER (~0u)
#define NSERV 10u
typedef uint32_t (*pZTaskEventHandlerFn)(uint8_t, uint32_t);
typedef struct { int priority; } Task_Struct;
typedef Task_Struct *Task_Handle;
static Task_Struct stack_task = {5}, npi_task = {6};
static Task_Handle stackTaskHndl = &stack_task, current_task = &npi_task;
static Task_Handle Task_self(void) { return current_task; }
static int Task_getPri(Task_Handle t) { return t->priority; }
typedef struct { int priority; void *stack; size_t stackSize; size_t used; } Task_Stat;
static void Task_stat(Task_Handle t, Task_Stat *st)
{ st->stackSize = t == stackTaskHndl ? 3072u : 1024u; st->used = t == stackTaskHndl ? 1500u : 600u; }
static uint32_t Clock_tickPeriod = 10u, now_tick;
static uint32_t Clock_getTicks(void) { return now_tick; }
static unsigned cs_depth;
static uint32_t OsalPort_enterCS(void) { return ++cs_depth; }
static void OsalPort_leaveCS(uint32_t key) { assert(key == cs_depth); --cs_depth; }
static int credits;
static void *stackSemHandle = &credits;
static int harness_running(void) { return credits > 0; }
static void Semaphore_pend(void *s, unsigned timeout)
{ (void)timeout; assert(s == stackSemHandle && credits > 0); --credits; }
static void Semaphore_post(void *s) { assert(s == stackSemHandle); ++credits; }
static int retained_active;
static int b1_retained_attempt_active(void) { return retained_active; }
static void b1_evidence_dispatch(uint8_t i, uint32_t e) { (void)i; (void)e; }
static void b1_evidence_dispatch_end(uint32_t e) { (void)e; }
static void B4_V6_StackPulse(uint32_t a, uint32_t b) { (void)a; (void)b; }
static uint32_t ev[NSERV];
static uint32_t *ev_ptr[NSERV];
static uint32_t **pTasksEvents = ev_ptr;
#define zdAppServiceEvents ev[5]
static const uint8_t zstackTasksCnt = NSERV;
/* nvintf.h / zstackconfig.h / zd_app.h shapes used by the V51 block. */
typedef struct { uint8_t systemID; uint16_t itemID; uint16_t subID; } NVINTF_itemID_t;
typedef uint8_t (*NVINTF_initNV)(void *param);
typedef uint8_t (*NVINTF_compactNV)(uint16_t minBytes);
typedef uint8_t (*NVINTF_createItem)(NVINTF_itemID_t id, uint32_t length, void *buffer);
typedef uint8_t (*NVINTF_updateItem)(NVINTF_itemID_t id, uint32_t length, void *buffer);
typedef uint8_t (*NVINTF_deleteItem)(NVINTF_itemID_t id);
typedef uint8_t (*NVINTF_readItem)(NVINTF_itemID_t id, uint16_t offset, uint16_t length, void *buffer);
typedef uint8_t (*NVINTF_readContItem)(NVINTF_itemID_t id, uint16_t offset, uint16_t rlength,
                                       void *rbuffer, uint16_t clength, uint16_t coffset,
                                       void *cbuffer, uint16_t *pSubId);
typedef uint8_t (*NVINTF_writeItem)(NVINTF_itemID_t id, uint16_t length, void *buffer);
typedef uint32_t (*NVINTF_getItemLen)(NVINTF_itemID_t id);
typedef struct
{
    NVINTF_initNV initNV; NVINTF_compactNV compactNV; NVINTF_createItem createItem;
    NVINTF_updateItem updateItem; NVINTF_deleteItem deleteItem; NVINTF_readItem readItem;
    NVINTF_readContItem readContItem; NVINTF_writeItem writeItem; NVINTF_getItemLen getItemLen;
} NVINTF_nvFuncts_t;
typedef struct { NVINTF_nvFuncts_t nvFps; } zstack_Config_t;
static zstack_Config_t stack_cfg;
static zstack_Config_t *pZStackCfg = &stack_cfg;
typedef enum { DEV_HOLD = 0, DEV_INIT = 1, DEV_ZB_COORD = 9 } devStates_t;
static devStates_t devState = DEV_HOLD;
static uint32_t heapmgrMemFreeTotal = 50000u;
"""

STACK_HANDLERS = r"""
static unsigned order[4096], n_order, calls[NSERV], storm_budget;
static uint32_t leftover[NSERV], extra[NSERV], heap_step[NSERV];
static uint8_t nv_in[NSERV];
/* Fake NV driver behind the V51 wrappers: records exact arguments. */
static unsigned nv_calls;
static NVINTF_itemID_t nv_id;
static uint32_t nv_len, nv_cost;
static void *nv_buf;
static uint16_t nv_off, nv_min;
static uint8_t nv_status;
static void nv_note(NVINTF_itemID_t id, uint32_t len, void *buf)
{ ++nv_calls; nv_id = id; nv_len = len; nv_buf = buf; now_tick += nv_cost; }
static uint8_t fake_init(void *p) { (void)p; return 0u; }
static uint8_t fake_update(NVINTF_itemID_t id, uint32_t length, void *buffer)
{ nv_note(id, length, buffer); return nv_status; }
static uint8_t fake_read(NVINTF_itemID_t id, uint16_t offset, uint16_t length, void *buffer)
{ nv_off = offset; nv_note(id, length, buffer); return nv_status; }
static uint32_t fake_len(NVINTF_itemID_t id) { nv_note(id, 0u, NULL); return 42u; }
static uint8_t fake_delete(NVINTF_itemID_t id) { nv_note(id, 0u, NULL); return nv_status; }
static uint8_t fake_compact(uint16_t minBytes)
{ NVINTF_itemID_t none = {0u, 0u, 0u}; nv_min = minBytes; nv_note(none, 0u, NULL); return nv_status; }
void OsalPort_heapGetStats(B4_V51_HeapStats_t *stats)
{
    assert(cs_depth == 0u); /* the heap walk takes its own lock, never inside ours */
    stats->totalSize = 90000u; stats->totalFreeSize = heapmgrMemFreeTotal; stats->largestFreeSize = 1234u;
}
static void set_event(unsigned s, uint32_t bits) { ev[s] |= bits; Semaphore_post(stackSemHandle); }
static uint32_t handle(uint8_t s, uint32_t events)
{
    (void)events;
    assert(n_order < 4096u && cs_depth == 0u);
    order[n_order++] = s; ++calls[s];
    now_tick += (s == 2u) ? 1300u : 10u;
    now_tick += extra[s];
    heapmgrMemFreeTotal -= heap_step[s];
    if (nv_in[s])
    {
        uint8_t row[4] = {0u, 0u, 0u, 0u};
        NVINTF_itemID_t id = {1u, 0x50u, s};
        Task_Handle saved = current_task;
        current_task = stackTaskHndl;
        assert(pZStackCfg->nvFps.updateItem(id, sizeof(row), row) == nv_status);
        current_task = saved;
    }
    if (s == 2u && storm_budget) { --storm_budget; set_event(2u, 0x2070u); }
    if (leftover[s]) { uint32_t r = leftover[s]; leftover[s] = 0u; return r; }
    return 0u;
}
#define H(n) static uint32_t h##n(uint8_t t, uint32_t e) { (void)t; return handle(n, e); }
H(0) H(1) H(2) H(3) H(4) H(5) H(6) H(7) H(8) H(9)
static const pZTaskEventHandlerFn zstackTasksArr[NSERV] = {h0,h1,h2,h3,h4,h5,h6,h7,h8,h9};
"""

STACK_MAIN = r"""
static uint32_t get32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static int position(unsigned s) { unsigned i; for (i = 0; i < n_order; ++i) if (order[i] == s) return (int)i; return -1; }
static void reset_all(void)
{
    unsigned i;
    for (i = 0; i < NSERV; ++i) { ev[i] = 0u; ev_ptr[i] = &ev[i]; calls[i] = 0u; leftover[i] = 0u; }
    n_order = 0u; credits = 0; storm_budget = 0u; retained_active = 0; now_tick = 1000u;
    memset(B4_V50_Service, 0, sizeof(B4_V50_Service));
    memset(B4_V50_Skipped, 0, sizeof(B4_V50_Skipped));
    B4_V50_Wakes = B4_V50_Empty = B4_V50_Aged = B4_V50_Returned = B4_V50_Busy = 0u;
    B4_V50_Since = 0u; B4_V50_Current = B4_V50_MaxSkip = 0u;
    B4_V50_MacReq = B4_V50_MacReqOk = B4_V50_MacCnf = B4_V50_MacCnfFail = 0u;
    B4_V50_MacInd = B4_V50_MacEvents = 0u; B4_V50_MacReqLast = B4_V50_MacCnfLast = 0u;
    memset(&B4_V51, 0, sizeof(B4_V51));
    for (i = 0; i < NSERV; ++i) { extra[i] = 0u; heap_step[i] = 0u; nv_in[i] = 0u; }
    devState = DEV_HOLD; heapmgrMemFreeTotal = 50000u; nv_cost = 0u; nv_status = 0u;
}
static void run_loop(void) { STACK_LOOP }
int main(void)
{
    uint8_t out[B4_V50_EVIDENCE_SIZE + 8u];
    unsigned j;
    uint32_t first_long_tick;
    /* 1. No starvation: exact TI lowest-index-first order, no aging. */
    reset_all(); set_event(4u, 1u); set_event(0u, 1u); set_event(2u, 1u); run_loop();
    assert(n_order == 3u && order[0] == 0u && order[1] == 2u && order[2] == 4u);
    assert(B4_V50_Aged == 0u && B4_V50_Empty == 0u && B4_V50_Wakes == 3u);
    /* 2. Self-rearming NWK storm (hardware: input 0x2070, ~75/s): APS and
     * ZDApp are served after exactly AGE_LIMIT and AGE_LIMIT+1 wakes. */
    reset_all(); storm_budget = 200u;
    set_event(2u, 0x2070u); set_event(3u, 1u); set_event(5u, 0x10u); run_loop();
    assert(calls[2] == 201u && calls[3] == 1u && calls[5] == 1u);
    assert(position(3u) == (int)B4_V50_AGE_LIMIT && position(5u) == (int)B4_V50_AGE_LIMIT + 1);
    assert(B4_V50_Aged == 2u && B4_V50_MaxSkip == B4_V50_AGE_LIMIT + 1u);
    assert(B4_V50_Wakes == 203u && B4_V50_Empty == 0u && B4_V50_Returned == 0u);
    assert(B4_V50_Service[2].dispatches == 201u && B4_V50_Service[2].busy == 201u * 1300u);
    assert(B4_V50_Service[2].longest == 1300u && (B4_V50_Service[2].inputs & 0x2070u) == 0x2070u);
    assert(B4_V50_Service[3].dispatches == 1u && B4_V50_Service[5].inputs == 0x10u);
    assert(B4_V50_Busy == 201u * 1300u + 20u);
    /* B1E2 layout from the same run, plus MAC counters. */
    B4_V50_MacDataReqEnter(); B4_V50_MacDataReqEnter(); B4_V50_MacDataReqEnter();
    B4_V50_MacDataReqDone(0u); B4_V50_MacDataReqDone(0xE1u);
    B4_V50_MacEvent(1u, 0u); B4_V50_MacEvent(1u, 0xE9u); B4_V50_MacEvent(2u, 0u); B4_V50_MacEvent(0u, 7u);
    memset(out, 0xA5, sizeof(out));
    B4_V50_StackSnapshot(out, 1u, 0x1234u);
    assert(!memcmp(out, "B1E2", 4) && out[4] == 1u && out[5] == 248u && out[6] == 10u && out[7] == 0x81u);
    assert(get32(out + 8) == 0u && get32(out + 12) == now_tick && get32(out + 16) == 10u);
    assert(get32(out + 20) == 203u && get32(out + 24) == 0u && get32(out + 28) == 2u);
    assert(get32(out + 32) == 0u && get32(out + 36) == 201u * 1300u + 20u && get32(out + 40) == 0u);
    assert(out[44] == 0u && out[45] == B4_V50_AGE_LIMIT + 1u && out[46] == 6u && out[47] == 5u);
    assert(get32(out + 48) == 3u && get32(out + 52) == 1u && get32(out + 56) == 2u);
    assert(get32(out + 60) == 1u && get32(out + 64) == 1u && get32(out + 68) == 4u);
    assert(get32(out + 72) == 0x1234u && out[76] == 0xE1u && out[77] == 0xE9u);
    assert(get32(out + 80 + 4 * 2) == 201u && get32(out + 80 + 4 * 3) == 1u && get32(out + 80 + 4 * 5) == 1u);
    assert(get32(out + 128 + 4 * 2) == 201u * 1300u && get32(out + 176 + 4 * 2) == 0x2070u);
    assert(get16(out + 224 + 2 * 2) == 13u && get16(out + 224 + 2 * 3) == 0u);
    for (j = 10u; j < 12u; ++j)
        assert(get32(out + 80 + 4 * j) == 0u && get32(out + 128 + 4 * j) == 0u && get16(out + 224 + 2 * j) == 0u);
    for (j = B4_V50_EVIDENCE_SIZE; j < sizeof(out); ++j) assert(out[j] == 0xA5u);
    /* An in-flight dispatch reports its service and age. */
    B4_V50_DispatchBegin(2u, 0x40u); now_tick += 500u;
    B4_V50_StackSnapshot(out, 0u, 0u);
    assert(out[44] == 3u && get32(out + 40) == 500u && out[7] == 0x01u);
    B4_V50_DispatchEnd(2u, 0u);
    B4_V50_Service[4].longest = 0xFFFFFFFFu; B4_V50_StackSnapshot(out, 0u, 0u);
    assert(get16(out + 224 + 2 * 4) == 0xFFFFu);
    /* 3. V48 retained INIT/START selection still runs before aging. */
    reset_all(); retained_active = 1; storm_budget = 10u;
    set_event(2u, 0x2070u); set_event(5u, ZDO_NETWORK_INIT); run_loop();
    assert(order[0] == 5u && calls[5] == 1u && calls[2] == 11u);
    /* 4. Returned bits keep B1's semaphore credit and are counted. */
    reset_all(); leftover[4] = 2u; set_event(4u, 1u); run_loop();
    assert(calls[4] == 2u && B4_V50_Returned == 1u && B4_V50_Wakes == 2u);
    /* 5. A spurious credit is an empty selection, not a dispatch. */
    reset_all(); Semaphore_post(stackSemHandle); run_loop();
    assert(n_order == 0u && B4_V50_Empty == 1u && B4_V50_Wakes == 1u);
    assert(cs_depth == 0u && credits == 0);
    /* 6. V51 NV wrappers: same arguments and results; NULL members kept;
     * a second install never wraps the wrappers. */
    reset_all();
    memset(&stack_cfg, 0, sizeof(stack_cfg));
    stack_cfg.nvFps.initNV = fake_init; stack_cfg.nvFps.updateItem = fake_update;
    stack_cfg.nvFps.readItem = fake_read; stack_cfg.nvFps.getItemLen = fake_len;
    stack_cfg.nvFps.deleteItem = fake_delete; stack_cfg.nvFps.compactNV = fake_compact;
    B4_V51_InstallNvHooks(); B4_V51_InstallNvHooks();
    assert((B4_V51.flags & B4_V51_NV_HOOKED) != 0u && stack_cfg.nvFps.initNV == fake_init);
    assert(stack_cfg.nvFps.updateItem != fake_update && stack_cfg.nvFps.readItem != fake_read);
    assert(stack_cfg.nvFps.getItemLen != fake_len && stack_cfg.nvFps.deleteItem != fake_delete);
    assert(stack_cfg.nvFps.compactNV != fake_compact && stack_cfg.nvFps.createItem == NULL);
    assert(stack_cfg.nvFps.readContItem == NULL && stack_cfg.nvFps.writeItem == NULL);
    {
        NVINTF_itemID_t id = {1u, 0x22u, 0x33u};
        uint8_t buf[4];
        nv_status = 7u; nv_cost = 30u;
        assert(stack_cfg.nvFps.updateItem(id, 4u, buf) == 7u);
        assert(nv_calls == 1u && nv_id.itemID == 0x22u && nv_id.subID == 0x33u && nv_len == 4u && nv_buf == buf);
        assert(B4_V51.nvWrites == 1u && B4_V51.nvTicks == 30u && B4_V51.nvOther == 30u);
        assert(B4_V51.nvFails == 1u && B4_V51.nvLastFail == 7u && B4_V51.nvLastFailKind == 2u);
        assert(B4_V51.nvLongest == 30u && B4_V51.nvLongestKind == 2u && B4_V51.nvLongestSvc == 0u);
        nv_status = 10u; /* NVINTF_NOTFOUND: ordinary lookup, not a failure */
        assert(stack_cfg.nvFps.readItem(id, 5u, 2u, buf) == 10u && nv_calls == 2u && nv_off == 5u && nv_len == 2u);
        assert(stack_cfg.nvFps.getItemLen(id) == 42u && nv_calls == 3u);
        assert(B4_V51.nvReads == 2u && B4_V51.nvFails == 1u);
        nv_status = 0u;
        assert(stack_cfg.nvFps.deleteItem(id) == 0u && stack_cfg.nvFps.compactNV(300u) == 0u && nv_min == 300u);
        assert(B4_V51.nvDeletes == 1u && B4_V51.nvCompacts == 1u && nv_calls == 5u);
        assert(B4_V51.nvTicks == 150u && B4_V51.nvOther == 150u);
    }
    /* 7. NV time inside a Stack dispatch is charged to that service. */
    reset_all(); nv_cost = 400u; nv_in[5] = 1u;
    set_event(5u, 1u); run_loop();
    assert(B4_V51.svcNv[5] == 400u && B4_V51.nvOther == 0u && B4_V51.nvWrites == 1u);
    assert(B4_V51.nvLongestSvc == 6u && B4_V51.bootWorst.service == 6u);
    assert(B4_V51.bootWorst.nvOps == 1u && B4_V51.bootWorst.nv == 400u && B4_V51.bootWorst.ticks == 410u);
    /* 8. Boot vs READY, the first saturated window after calm, long
     * dispatches and heap. Window 10 s = 1e6 ticks, long 1 s = 1e5 ticks. */
    reset_all();
    extra[5] = 150000u; set_event(5u, 1u); run_loop(); extra[5] = 0u;
    storm_budget = 599u; set_event(2u, 0x2070u); run_loop();
    assert(B4_V51.bootWorst.service == 6u && B4_V51.bootWorst.ticks == 150010u);
    assert((B4_V51.flags & B4_V51_READY) == 0u && B4_V51.windows == 0u);
    /* READY is seen at the next dispatch end; that dispatch is boot phase and
     * the boot-heavy window is discarded, never rated as a READY onset. */
    devState = DEV_ZB_COORD; set_event(4u, 1u); run_loop();
    assert((B4_V51.flags & B4_V51_READY) != 0u && B4_V51.readyTick == now_tick);
    assert(B4_V51.runWorst.ticks == 0u && (B4_V51.flags & B4_V51_HEAP) == 0u);
    B4_V50_MacDataReqEnter(); B4_V50_MacDataReqEnter(); B4_V50_MacDataReqEnter();
    now_tick += 200000u; set_event(4u, 1u); run_loop();
    assert(B4_V51.windows == 0u && (B4_V51.flags & B4_V51_ONSET) == 0u);
    assert((B4_V51.flags & B4_V51_HEAP) != 0u && B4_V51.heapLow == 50000u && B4_V51.runWorst.service == 5u);
    now_tick += 900000u; set_event(4u, 1u); run_loop();
    assert(B4_V51.windows == 1u && B4_V51.busyWindows == 0u && B4_V51.satWindows == 0u);
    assert((B4_V51.flags & B4_V51_SETTLED) != 0u && B4_V51.settleTick == now_tick);
    /* NWK storm with NV inside every dispatch: 17 x 623 ms > one window. */
    for (j = 0u; j < 5u; ++j) B4_V50_MacDataReqEnter();
    B4_V50_MacEvent(1u, 0xE9u); B4_V50_MacEvent(1u, 0xF0u);
    for (j = 0u; j < 4u; ++j) B4_V50_MacEvent(2u, 0u);
    extra[2] = 60000u; nv_in[2] = 1u; nv_cost = 1000u; heap_step[2] = 10u;
    storm_budget = 16u; set_event(2u, 0x2070u); run_loop();
    assert(calls[2] == 600u + 17u && (B4_V51.flags & B4_V51_LONG) == 0u);
    assert(B4_V51.runWorst.service == 3u && B4_V51.runWorst.ticks == 62300u && B4_V51.runWorst.nvOps == 1u);
    assert(B4_V51.runWorst.nv == 1000u && B4_V51.runWorst.input == 0x2070u && B4_V51.svcNv[2] == 17000u);
    extra[2] = 0u; nv_in[2] = 0u; nv_cost = 0u; heap_step[2] = 0u;
    extra[7] = 150000u; set_event(7u, 0x8u); run_loop();
    first_long_tick = now_tick;
    extra[7] = 200000u; set_event(7u, 0x8u); run_loop(); extra[7] = 0u;
    assert((B4_V51.flags & B4_V51_LONG) != 0u && B4_V51.firstLong.tick == first_long_tick);
    assert(B4_V51.firstLong.service == 8u && B4_V51.firstLong.ticks == 150010u && B4_V51.firstLong.input == 0x8u);
    assert(B4_V51.runWorst.service == 8u && B4_V51.runWorst.ticks == 200010u);
    assert(B4_V51.bootWorst.service == 6u && B4_V51.bootWorst.ticks == 150010u);
    memset(out, 0xA5, sizeof(out));
    B4_V51_OnsetSnapshot(out);
    assert(!memcmp(out, "B1E3", 4) && out[4] == 1u && out[5] == 248u && out[7] == 10u);
    assert(out[6] == (B4_V51_READY | B4_V51_SETTLED | B4_V51_ONSET | B4_V51_LONG |
                      B4_V51_AFTER_CALM | B4_V51_HEAP));
    assert(get32(out + 8) == 0u && get32(out + 12) == now_tick);
    assert(get32(out + 16) == 2u && get32(out + 20) == 1u && get32(out + 24) == 1u);
    assert(get16(out + 28) == 1u && get16(out + 30) == 1u);
    assert(get32(out + 32) == 1059100u && get32(out + 36) == 1059100u && get32(out + 40) == 3090140u);
    assert(get32(out + 44) == 931020u && get32(out + 48) == 2031040u);
    assert(get32(out + 52) == 0u && get32(out + 56) == 17u);
    assert(get16(out + 60) == 0u && get16(out + 62) == 0u && get16(out + 64) == 0u);
    assert(get32(out + 68) == 17000u && get32(out + 72) == 0u);
    assert(get16(out + 76) == 10u && out[78] == 2u && out[79] == 3u);
    assert(get32(out + 80) == 90000u && get32(out + 84) == 49830u && get32(out + 88) == 1234u);
    assert(get32(out + 92) == 49830u && get32(out + 96) == 3090140u);
    assert(get32(out + 100) == 3090140u && get32(out + 104) == 1059100u && get32(out + 108) == 1059100u);
    assert(get32(out + 112) == 17u && out[116] == 3u && get16(out + 118) == 2u);
    assert(get32(out + 120) == 1059100u && get32(out + 124) == 0x2070u && get32(out + 128) == 17000u);
    assert(get16(out + 132) == 5u && get16(out + 134) == 4u && get32(out + 136) == 49830u);
    assert(get32(out + 140) == first_long_tick && get16(out + 144) == 1500u && out[146] == 8u && out[147] == 0u);
    assert(get32(out + 148) == 0x8u && get32(out + 152) == 0u && get32(out + 156) == 0u);
    assert(get16(out + 164) == 2000u && out[166] == 8u);
    assert(get16(out + 184) == 1500u && out[186] == 6u && get32(out + 188) == 1u);
    assert(get32(out + 200 + 4 * 2) == 17000u && get32(out + 200 + 4 * 5) == 0u);
    /* Task stack high-water: Stack 1500/3072, caller (NPI owner) 600/1024. */
    assert(get16(out + 240) == 1500u && get16(out + 242) == 3072u);
    assert(get16(out + 244) == 600u && get16(out + 246) == 1024u);
    for (j = B4_V50_EVIDENCE_SIZE; j < sizeof(out); ++j) assert(out[j] == 0xA5u);
    assert(cs_depth == 0u && credits == 0);
    printf("V50_STACK_AGING_EVIDENCE_REAL_C_PASS\n");
    printf("V51_ONSET_RECORD_NV_TIMING_REAL_C_PASS\n");
    return 0;
}
"""

FALLBACK_MAIN = STACK_MAIN.split("int main(void)")[0] + r"""
int main(void)
{
    uint8_t out[B4_V50_EVIDENCE_SIZE];
    /* Table larger than the evidence capacity: exact TI selection. */
    reset_all(); storm_budget = 50u;
    set_event(2u, 0x2070u); set_event(3u, 1u); run_loop();
    assert(position(3u) == 51 && B4_V50_Aged == 0u);
    B4_V50_StackSnapshot(out, 0u, 0u);
    assert(out[6] == 8u && (out[7] & 3u) == 2u && get32(out + 80 + 4 * 2) == 51u);
    printf("V50_OVERSIZED_TABLE_TI_FALLBACK_PASS\n");
    return 0;
}
"""

STACK_MUTANTS = {
    "aging_disabled": (
        "B4_V50_Skipped[idx] >= B4_V50_AGE_LIMIT", "0u"),
    "selection_bypassed": (
        "        idx = B4_V50_SelectService();",
        "        while (idx < zstackTasksCnt && !*(pTasksEvents[idx])) ++idx;"),
    "skip_never_incremented": (
        "                ++B4_V50_Skipped[j];", "                (void)B4_V50_Skipped[j];"),
    "service_busy_not_accumulated": (
        "        B4_V50_Sat(&B4_V50_Service[idx].busy, spent);", "        (void)spent;"),
    "returned_bits_not_counted": (
        "    if (returned != 0u) B4_V50_Sat(&B4_V50_Returned, 1u);", "    (void)returned;"),
    "empty_selection_not_counted": (
        "    if (idx >= zstackTasksCnt) B4_V50_Sat(&B4_V50_Empty, 1u);", "    (void)idx;"),
    "mac_confirm_failure_not_counted": (
        "            B4_V50_Sat(&B4_V50_MacCnfFail, 1u);", "            (void)0;"),
    "snapshot_dispatch_offset_shifted": (
        "B4_V50_Put32(out + 80u + 4u * j, services[j].dispatches);",
        "B4_V50_Put32(out + 84u + 4u * j, services[j].dispatches);"),
    "dispatch_begin_hook_removed": (
        "        B4_V50_DispatchBegin(idx, events);\n", ""),
    # V51 onset record and NV timing.
    "nv_update_not_wrapped": (
        "    if (fps->updateItem != NULL) fps->updateItem = B4_V51_NvUpdateItem;\n", ""),
    "nv_update_status_dropped": (
        "    uint8_t updated = B4_V51_Nv.updateItem(id, length, buffer);",
        "    uint8_t updated = (B4_V51_Nv.updateItem(id, length, buffer), 0u);"),
    "nv_second_install_wraps_wrappers": (
        "    if ((B4_V51.flags & B4_V51_NV_HOOKED) != 0u || pZStackCfg == NULL) return;",
        "    if (pZStackCfg == NULL) return;"),
    "nv_time_not_charged_to_service": (
        "    uint8_t service = (Task_self() == stackTaskHndl) ? B4_V50_Current : 0u;",
        "    uint8_t service = 0u;"),
    "nv_notfound_read_counted_as_failure": (
        "    if (kind != 1u && status != 0u)", "    if (status != 0u)"),
    "ready_window_not_reset": (
        "        v->readyTick = now;\n        B4_V51_WindowReset(now);", "        v->readyTick = now;"),
    "saturation_never_detected": (
        "        sat = busy >= (uint64_t)elapsed * B4_V51_SAT_PCT;", "        sat = 0u;"),
    "calm_never_detected": (
        "        calm = busy < (uint64_t)elapsed * B4_V51_CALM_PCT;", "        calm = 0u;"),
    "onset_top_service_not_searched": (
        "                if (v->winSvcBusy[j] > v->winSvcBusy[top]) top = j;", "                (void)j;"),
    "first_long_overwritten": (
        "            v->flags |= B4_V51_LONG;\n", ""),
    "boot_worst_includes_run_phase": (
        "    else if (spent > v->bootWorst.ticks)", "    if (spent > v->bootWorst.ticks)"),
    "heap_low_water_not_tracked": (
        "            v->heapLow = heapFree;", "            (void)heapFree;"),
    "onset_mac_delta_absolute": (
        "            v->onset.macReq = B4_V51_Delta16(B4_V50_MacReq, v->winMacReq);",
        "            v->onset.macReq = B4_V51_Delta16(B4_V50_MacReq, 0u);"),
    "heap_walk_inside_cs": (
        "    OsalPort_heapGetStats(&heap);\n    key = OsalPort_enterCS();\n",
        "    key = OsalPort_enterCS();\n    OsalPort_heapGetStats(&heap);\n"),
    "b1e3_stack_task_high_water_not_reported": (
        "    if (stackTaskHndl != NULL) Task_stat(stackTaskHndl, &stackStat);\n", ""),
    "b1e3_service_nv_offset_shifted": (
        "        B4_V50_Put32(out + 200u + 4u * j, s.svcNv[j]);",
        "        B4_V50_Put32(out + 204u + 4u * j, s.svcNv[j]);"),
}

QUERY_STUB = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define B1_STATUS_QUERY_SIZE 8u
#define B1_STATUS_COMMAND 0xF1u
typedef struct { uint8_t *pBuf; } NPIMSG_msg_t;
static unsigned replies, deallocs, frees, snaps, onsets;
static uint8_t last_c0, last_c1, last_len, last_payload[256], armed_seen;
static uint32_t tick_seen;
static void MT_BuildAndSendZToolResponse(uint8_t c0, uint8_t c1, uint8_t len, uint8_t *p)
{ ++replies; last_c0 = c0; last_c1 = c1; last_len = len; memcpy(last_payload, p, len); }
static void OsalPort_msgDeallocate(uint8_t *p) { (void)p; ++deallocs; }
static void OsalPort_free(void *p) { (void)p; ++frees; }
static volatile uint8_t B4_V47_Armed = 1u;
static uint32_t B4_V47_StartTick = 77u;
"""

QUERY_MAIN = r"""
void B4_V50_StackSnapshot(uint8_t *out, uint8_t npiArmed, uint32_t npiArmTick)
{
    ++snaps; memset(out, 0, B4_V50_EVIDENCE_SIZE); memcpy(out, "B1E2", 4);
    out[4] = 1u; out[5] = (uint8_t)B4_V50_EVIDENCE_SIZE; armed_seen = npiArmed; tick_seen = npiArmTick;
}
void B4_V51_OnsetSnapshot(uint8_t *out)
{
    ++onsets; memset(out, 0, B4_V50_EVIDENCE_SIZE); memcpy(out, "B1E3", 4);
    out[4] = 1u; out[5] = (uint8_t)B4_V50_EVIDENCE_SIZE;
}
static int consume(uint8_t *pReq)
{
    NPIMSG_msg_t message = { pReq };
    NPIMSG_msg_t *pMsg = &message;
QUERY_BLOCK
    return 99;
}
static void clear(void) { replies = deallocs = frees = snaps = onsets = 0u; last_len = 0u; }
int main(void)
{
    static const uint8_t digest[4] = { DIGEST };
    uint8_t ok[16] = {8u, 0x21u, 0xF1u, 'B', '1', 'Q', '1', 1u, 8u, 4u, 0u};
    uint8_t frame[16];
    clear(); assert(consume(ok) == 0 && snaps == 1u && onsets == 0u && replies == 1u && deallocs == 1u && frees == 1u);
    assert(last_c0 == 0x61u && last_c1 == 0xF1u && last_len == 248u && !memcmp(last_payload, "B1E2", 4));
    assert(!memcmp(last_payload + 8, digest, 4) && armed_seen == 1u && tick_seen == 77u);
    /* Exact prefix/version required: SREQ rejection, no snapshot. */
    memcpy(frame, ok, 16); frame[7] = 2u;
    clear(); assert(consume(frame) == 0 && snaps == 0u && replies == 1u && last_c0 == 0x60u);
    assert(last_len == 3u && last_payload[0] == 3u && last_payload[1] == 0x21u && last_payload[2] == 0xF1u);
    /* Page 1 is the V51 B1E3 onset record, with the same digest. */
    memcpy(frame, ok, 16); frame[10] = 1u;
    clear(); assert(consume(frame) == 0 && snaps == 0u && onsets == 1u && replies == 1u);
    assert(last_c0 == 0x61u && last_c1 == 0xF1u && last_len == 248u && !memcmp(last_payload, "B1E3", 4));
    assert(!memcmp(last_payload + 8, digest, 4) && deallocs == 1u && frees == 1u);
    memcpy(frame, ok, 16); frame[10] = 2u;
    clear(); assert(consume(frame) == 0 && snaps == 0u && onsets == 0u && replies == 1u && last_c0 == 0x60u);
    /* AREQ form is dropped without any reply, like B1E1. */
    memcpy(frame, ok, 16); frame[1] = 0x41u;
    clear(); assert(consume(frame) == 0 && replies == 0u && snaps == 0u && deallocs == 1u);
    /* op3 B1E1, op2 B1P1 and wrong lengths continue to the original paths. */
    memcpy(frame, ok, 16); frame[9] = 3u; clear(); assert(consume(frame) == 99 && replies == 0u && deallocs == 0u);
    memcpy(frame, ok, 16); frame[9] = 2u; clear(); assert(consume(frame) == 99 && replies == 0u);
    memcpy(frame, ok, 16); frame[0] = 9u; clear(); assert(consume(frame) == 99 && replies == 0u);
    printf("V50_B1E2_B1E3_NPI_QUERY_REAL_C_PASS\n");
    return 0;
}
"""

QUERY_MUTANTS = {
    "digest_not_written": (
        "            memcpy(stackEvidence + 8, B4_V50_BuildDigest, sizeof(B4_V50_BuildDigest));\n", ""),
    "areq_answered": ("        else if (pReq[1] == 0x21u)\n", "        else\n"),
    "wrong_opcode": ("pReq[2] == B1_STATUS_COMMAND && pReq[9] == 4u)",
                     "pReq[2] == B1_STATUS_COMMAND && pReq[9] == 3u)"),
    "length_unchecked": ("    if (pReq[0] == B1_STATUS_QUERY_SIZE && (pReq[1] & 0x1fu) == 1u &&",
                         "    if ((pReq[1] & 0x1fu) == 1u &&"),
    "b1e3_page_rejected": ("            pReq[10] <= 1u)", "            pReq[10] == 0u)"),
    "pages_swapped": ("            if (pReq[10] == 0u)\n", "            if (pReq[10] == 1u)\n"),
}


def between(text, start, end, label):
    if text.count(start) != 1:
        raise ValueError("V50_HARNESS_ANCHOR_" + label)
    a = text.index(start)
    b = text.index(end, a)
    return text[a:b]


def compose(sdk, source_sha):
    sdk = Path(sdk)
    task = (sdk / TASK).read_text()
    stack = (sdk / STACK).read_text()
    if (task.count(NPI_MARKER) != 1 or task.count(QUERY_MARKER) != 1 or
            stack.count(MARKER) != 1 or stack.count(END_MARKER) != 1):
        raise ValueError("V50_HARNESS_COMPOSED_MARKERS")
    digest = ", ".join("0x" + source_sha[i:i + 2] for i in range(0, 8, 2))
    declarations = between(task, "/* B4_V50_STACK_SERVICE_EVIDENCE: B1E2 op4 page0",
                           "/* B4_V47_BOUNDED_B1_STARTUP_NPI", "NPI_DECLARATIONS")
    if ("#define B4_V50_EVIDENCE_SIZE %du" % EVIDENCE_SIZE not in declarations or
            "{ " + digest + " }" not in declarations or
            "#define B4_V50_EVIDENCE_SIZE %du" % EVIDENCE_SIZE not in stack or
            "#define B4_V50_AGE_LIMIT %du" % AGE_LIMIT not in stack):
        raise ValueError("V50_HARNESS_SIZE_OR_DIGEST_DRIFT")
    helpers = between(task, "/* B4_V47_BOUNDED_B1_STARTUP_NPI",
                      "__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)\n{", "V47_HELPERS")
    refresh = function(task, "__attribute__((noinline)) void B4_V46_RefreshNpiPriority(void)")
    npi = NPI_STUB + helpers + "\n" + refresh + "\n" + NPI_MAIN

    send = function(task, "static uint8_t NPITask_sendBufToStack( NPIMSG_msg_t *pMsg )")
    query = between(send, "    /* B4_V50_STACK_SERVICE_EVIDENCE_QUERY",
                    "    /* Strict, RAM-only op3 B1E1", "QUERY")
    if not (send.index("B4_V43_Request(0u, pReq);") < send.index(QUERY_MARKER) <
            send.index("b1_evidence_query(pReq, evidence, &error)")):
        raise ValueError("V50_HARNESS_QUERY_ORDER")
    query_code = (QUERY_STUB + declarations + QUERY_MAIN
                  .replace("QUERY_BLOCK", query).replace("DIGEST", digest))

    block = between(stack, "/* " + MARKER, END_MARKER, "STACK_BLOCK")
    if block.count(ONSET_MARKER) != 1:
        raise ValueError("V50_HARNESS_V51_ONSET_BLOCK")
    include = "#include <ti/sysbios/knl/Clock.h>\n"
    if block.count(include) != 1:
        raise ValueError("V50_HARNESS_CLOCK_INCLUDE")
    block = block.replace(include, "/* hosted: Clock stubs above */\n", 1)
    task_fn = function(stack, "static void stackTaskFxn(UArg a0, UArg a1)")
    if not (task_fn.index("    B4_V51_InstallNvHooks();") <
            task_fn.index("if (!b1_sec_validate_restored()) return;") <
            task_fn.index("    stackInit();")):
        raise ValueError("V50_HARNESS_V51_NV_HOOK_ORDER")
    loop = task_fn[task_fn.index("    while(1)\n    {"):task_fn.rindex("}")]
    for item in ("B4_V48_RETAINED_ZDAPP_DISPATCH_FAIRNESS", "idx = B4_V50_SelectService();",
                 "B4_V50_NoteSelection(idx);", "B4_V50_DispatchBegin(idx, events);",
                 "B4_V50_DispatchEnd(idx, events);",
                 "if (events != 0u) Semaphore_post(stackSemHandle);"):
        if loop.count(item) != 1:
            raise ValueError("V50_HARNESS_LOOP_" + item)
    loop = loop.replace("    while(1)\n", "    while (harness_running())\n", 1)
    stack_code = (STACK_STUB + block + STACK_HANDLERS +
                  STACK_MAIN.replace("STACK_LOOP", loop))
    fallback_code = (STACK_STUB + block.replace("#define B4_V50_MAX_SERVICES 12u",
                                                "#define B4_V50_MAX_SERVICES 8u", 1) +
                     STACK_HANDLERS + FALLBACK_MAIN.replace("STACK_LOOP", loop))
    return {"npi": npi, "stack": stack_code, "fallback": fallback_code, "query": query_code}


def exercise(sdk, source_sha):
    programs = compose(sdk, source_sha)
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        raise RuntimeError("V50_NATIVE_C_COMPILER_REQUIRED")

    def build(name, code, should_pass):
        with tempfile.TemporaryDirectory(prefix="p7u-v50-c-") as td:
            root = Path(td)
            unit, exe = root / "v50.c", root / "v50"
            unit.write_text(code, encoding="utf-8")
            built = subprocess.run(
                [cc, "-std=c11", "-O0", "-g", "-Wall", "-Wextra", "-Werror",
                 "-Wno-unused-variable", "-Wno-unused-function",
                 "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                 str(unit), "-o", str(exe)],
                capture_output=True, text=True, timeout=60)
            if built.returncode:
                raise RuntimeError("V50_C_COMPILE_" + name + ": " + built.stderr[-3000:])
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
            if (run.returncode == 0) != should_pass:
                raise RuntimeError("V50_MUTANT_NOT_REJECTED_" + name + ": " +
                                   run.stdout[-500:] + run.stderr[-800:])
            return run.stdout.strip()

    outputs = {name: build(name, programs[name], True) for name in programs}
    rejected = []
    for program, mutants in (("npi", NPI_MUTANTS), ("stack", STACK_MUTANTS),
                             ("query", QUERY_MUTANTS)):
        code = programs[program]
        for label, (old, new) in mutants.items():
            if code.count(old) != 1:
                raise ValueError("V50_MUTANT_PREIMAGE_" + label + " occurrences=" + str(code.count(old)))
            build(program + "_" + label, code.replace(old, new, 1), False)
            rejected.append(program + ":" + label)
    task_text = (Path(sdk) / TASK).read_bytes()
    stack_text = (Path(sdk) / STACK).read_bytes()
    return {
        "schema": "p7u-v50-emitted-stack-service-actual-c-v2",
        "status": "PASS",
        "task_sha256": hashlib.sha256(task_text).hexdigest(),
        "stack_sha256": hashlib.sha256(stack_text).hexdigest(),
        "compiled_actual_npi_refresh": True,
        "compiled_actual_stack_loop": True,
        "compiled_actual_b1e2_query": True,
        "compiled_actual_b1e3_onset_record": True,
        "compiled_actual_nv_timing_wrappers": True,
        "negative_mutants_rejected": rejected,
        "hosted_model_only": True,
        "hardware_state9_proven": False,
        "nwk_storm_root_cause_proven": False,
        "outputs": outputs,
    }
