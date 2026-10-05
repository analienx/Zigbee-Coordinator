/* R5 fixed RAM snapshots. Included only by the real recorder.
 * Snapshot ages are uint32 RAM values; wire current/max pairs saturate at
 * 65535 ms. SWD retains full ages. No history accumulates during a stall. */
#define T832_R5_VALUES 13u
#define T832_R5_NWK 17u
#define T832_R5_EXPORTS (T832_R5_VALUES + 12u + 8u + T832_R5_NWK + 4u)
typedef struct {
    uint32_t sampled_ms, blocked_since, blocked_mask, blocked_sticky;
    uint32_t current[T832_R5_VALUES], maximum[T832_R5_VALUES];
    uint32_t rx_ms, stage_ms, stage_max[10], stage_seen;
    uint32_t uart_count[6], uart_last[6], accepted_ms, accepted_age_max;
    uint32_t nwk_ms, task_ms;
    uintptr_t task_handle[2];
    uint16_t nwk[T832_R5_NWK], nwk_max[T832_R5_NWK], nwk_limit[T832_R5_NWK];
    uint16_t task_used[2], task_size[2], task_mode[2];
    uint16_t generation, command, dispatch_gen;
    int16_t rx_status, write_status;
    uint8_t stage, uart_accepted, resource_cursor, boot_seen, rpc_ok;
} T832R5State;
static T832R5State t832R5;
volatile T832FatalLatch t832DiagFatal;
_Static_assert(sizeof(T832DiagState) + sizeof(T832R5State) +
               sizeof(T832FatalLatch) + 8u <= 4096u,
               "ALL diagnostic state including fatal latch must fit 4 KiB");

static uint16_t T832R5_sat(uint32_t value)
{
    return value > 0xFFFFu ? 0xFFFFu : (uint16_t)value;
}

static void T832Diag_record(uint8_t kind, uint16_t a, uint16_t b, uint16_t c);
static void T832Diag_bootTiming(uint8_t milestone)
{
    uint32_t now;
    uint8_t bit = (uint8_t)(1u << (milestone - 1u));
    if (t832R5.boot_seen & bit) return;
    t832R5.boot_seen |= bit;
    now = (uint32_t)T832Diag_nowMs();
    T832Diag_record(T832_DIAG_EV_BOOT_TIMING, milestone,
                    (uint16_t)now, (uint16_t)(now >> 16));
}

/* Fatal functions deliberately call NO functions, including clock/locks.
 * First writer sets writing before touching fields; nested faults return.
 * Volatile stores commit the validity marker last. Invalid/partial latches
 * are evidence of an interrupted capture, never a complete fault record. */
void T832Diag_fatalError(uintptr_t id, uintptr_t a0, uintptr_t a1)
{
    if (t832DiagFatal.magic || t832DiagFatal.writing) return;
    t832DiagFatal.writing = 1u;
    t832DiagFatal.kind = 1u;
    t832DiagFatal.build_id = T832_BUILD_ID;
    t832DiagFatal.error_id = (uint32_t)id;
    t832DiagFatal.a0 = (uint32_t)a0;
    t832DiagFatal.a1 = (uint32_t)a1;
    t832DiagFatal.sampled_ms = t832R5.sampled_ms;
    t832DiagFatal.command = t832R5.command;
    t832DiagFatal.generation = t832R5.generation;
    t832DiagFatal.stage = t832R5.stage;
    t832DiagFatal.mt_age = t832R5.current[5];
    t832DiagFatal.npi_age = t832R5.current[6];
    t832DiagFatal.zstack_age = t832R5.current[8];
    /* Thread identity intentionally unavailable for Error: do not inspect
     * potentially corrupt kernel objects. Exception captures thread type. */
    t832DiagFatal.thread_type = 0xFFFFFFFFu;
    t832DiagFatal.magic = T832_FATAL_MAGIC;
}

void T832Diag_fatalException(const unsigned int *stack, unsigned int lr,
    uint32_t thread_type, uint32_t icsr, uint32_t mmfsr, uint32_t bfsr,
    uint32_t ufsr, uint32_t hfsr, uint32_t dfsr, uint32_t mmar,
    uint32_t bfar, uint32_t afsr)
{
    uint8_t i;
    if (t832DiagFatal.magic || t832DiagFatal.writing) return;
    t832DiagFatal.writing = 1u;
    t832DiagFatal.kind = 2u;
    t832DiagFatal.build_id = T832_BUILD_ID;
    /* Exact v8m ASM saved r4-r11 then the basic hardware frame. Its
     * pre-existing handler consumes this same 16-word layout. No FPU or
     * security-state reinterpretation is invented here. */
    for (i = 0u; i < 4u; i++) t832DiagFatal.registers[i] = stack[8u + i];
    for (i = 4u; i < 12u; i++) t832DiagFatal.registers[i] = stack[i - 4u];
    t832DiagFatal.registers[12] = stack[12];
    t832DiagFatal.registers[13] = (uint32_t)(uintptr_t)(stack + 16);
    t832DiagFatal.registers[14] = stack[13];
    t832DiagFatal.registers[15] = stack[14];
    t832DiagFatal.registers[16] = stack[15];
    t832DiagFatal.exc_return = lr;
    t832DiagFatal.thread_type = thread_type;
    t832DiagFatal.status[0] = icsr;
    t832DiagFatal.status[1] = mmfsr;
    t832DiagFatal.status[2] = bfsr;
    t832DiagFatal.status[3] = ufsr;
    t832DiagFatal.status[4] = hfsr;
    t832DiagFatal.status[5] = dfsr;
    t832DiagFatal.status[6] = mmar;
    t832DiagFatal.status[7] = bfar;
    t832DiagFatal.status[8] = afsr;
    t832DiagFatal.sampled_ms = t832R5.sampled_ms;
    t832DiagFatal.command = t832R5.command;
    t832DiagFatal.generation = t832R5.generation;
    t832DiagFatal.stage = t832R5.stage;
    t832DiagFatal.mt_age = t832R5.current[5];
    t832DiagFatal.npi_age = t832R5.current[6];
    t832DiagFatal.zstack_age = t832R5.current[8];
    t832DiagFatal.magic = T832_FATAL_MAGIC;
}

static void T832Diag_pipelineStage(uint8_t stage, uint16_t gen)
{
    uint32_t now, age;
    if (!gen || gen != t832R5.generation || stage < 1u || stage > 10u) return;
    if (t832R5.stage_seen & (1u << (stage - 1u))) return;
    now = (uint32_t)T832Diag_nowMs();
    age = now - t832R5.rx_ms;
    if (age > t832R5.stage_max[stage - 1u]) t832R5.stage_max[stage - 1u] = age;
    t832R5.stage_seen |= 1u << (stage - 1u);
    /* Driver callbacks / TX_BEGIN may run before UART2_write returns.
     * Preserve observed mask and furthest progress; never move backward. */
    if (stage > t832R5.stage) {
        t832R5.stage = stage;
        t832R5.stage_ms = now;
    }
}

static void T832Diag_pipelineNew(uint8_t cmd0, uint8_t cmd1)
{
    t832R5.generation = t832Diag.sync_gen;
    t832R5.command = (uint16_t)(((uint16_t)cmd0 << 8) | cmd1);
    /* Scope begins at MT_ProcessIncoming entry, so invalid-command error
     * SRSPs can still bind before any handler is dispatched. */
    t832R5.dispatch_gen = t832R5.generation;
    t832R5.stage = 1u;
    t832R5.stage_ms = (uint32_t)T832Diag_nowMs();
    t832R5.rx_ms = t832R5.stage_ms;
    t832R5.stage_seen = 1u;
    t832R5.rpc_ok = 0u;
}

static void T832Diag_pipelineDispatch(uint8_t cmd0, uint8_t cmd1)
{
    if (((uint16_t)cmd0 << 8 | cmd1) == t832R5.command) {
        t832R5.dispatch_gen = t832R5.generation;
        T832Diag_pipelineStage(2u, t832R5.dispatch_gen);
    }
}

static void T832Diag_pipelineReturn(uint8_t cmd0, uint8_t cmd1, uint8_t status)
{
    if (((uint16_t)cmd0 << 8 | cmd1) == t832R5.command) {
        T832Diag_pipelineStage(3u, t832R5.dispatch_gen);
        t832R5.rpc_ok = (uint8_t)(status == 0u);
    }
}

static uint16_t T832Diag_pipelineResponse(uint8_t cmd0, uint8_t cmd1)
{
    uint16_t gen = 0u;
    /* Normalize SRSP type to SREQ while retaining subsystem and command. */
    if ((((uint16_t)((cmd0 & MT_RPC_SUBSYSTEM_MASK) | MT_RPC_CMD_SREQ) << 8) | cmd1)
        == t832R5.command) gen = t832R5.dispatch_gen;
    T832Diag_pipelineStage(4u, gen);
    return gen;
}

void T832Diag_npiQueueAccepted(uint8_t cmd0, uint8_t cmd1, uint8_t len)
{
    uint16_t i;
    uint32_t key = OsalPort_enterCS();
    /* Match the oldest not-yet-enqueued descriptor, preserving FIFO order
     * for repeated commands. An unknown/overflowed frame advances nothing. */
    for (i = 0u; i < t832Diag.txq_count; i++) {
        uint16_t slot = (uint16_t)((t832Diag.txq_head + i) % T832_DIAG_TXQ_DEPTH);
        T832DiagTxSlot *s = &t832Diag.txq[slot];
        if (!s->queue_accepted && s->cmd0 == cmd0 && s->cmd1 == cmd1 && s->len == len) {
            s->queue_accepted = 1u;
            if (s->cls == T832_DIAG_TXCLS_SYNC_SRSP) T832Diag_pipelineStage(5u, s->gen);
            break;
        }
    }
    OsalPort_leaveCS(key);
}

void T832Diag_commandEnd(void)
{
    t832R5.dispatch_gen = 0u;
}

static void T832Diag_pipelineInflight(uint8_t stage)
{
    if (t832Diag.inflight_valid && t832Diag.inflight.cls == T832_DIAG_TXCLS_SYNC_SRSP)
        T832Diag_pipelineStage(stage, t832Diag.inflight.gen);
}

void T832Diag_uartEvent(uint8_t event, uint16_t size, int16_t status)
{
    uint32_t now = (uint32_t)T832Diag_nowMs();
    uint8_t index;
    if (event < 1u || event > 6u) return;
    index = event - 1u;
    if (t832R5.uart_count[index] != 0xFFFFFFFFu) t832R5.uart_count[index]++;
    t832R5.uart_last[index] = now;
    if (event == 1u) {
        /* Completion can pre-empt the return from UART2_write. Do not
         * re-arm accepted-no-FINISHED after that completion. */
        t832R5.uart_accepted = t832Diag.transport_active;
        t832R5.accepted_ms = t832Diag.tx_start_ms;
        t832R5.write_status = status;
        T832Diag_pipelineInflight(7u);
    } else if (event == 2u) {
        t832R5.write_status = status;
        T832Diag_pipelineInflight(8u);
    } else if (event == 3u) {
        T832Diag_pipelineInflight(9u);
    } else if (event == 4u || event == 6u) {
        uint32_t age = t832R5.uart_accepted ? now - t832R5.accepted_ms : 0u;
        if (age > t832R5.accepted_age_max) t832R5.accepted_age_max = age;
        t832R5.uart_accepted = 0u;
        if (event == 4u) T832Diag_pipelineInflight(10u);
        else t832R5.write_status = status;
    } else {
        t832R5.rx_status = status;
    }
    (void)size; /* accepted bytes are counted ONLY after readIsrBuf copy */
}

void T832Diag_registerTask(uint8_t which, uintptr_t handle)
{
    if (which >= 1u && which <= 2u && handle) t832R5.task_handle[which - 1u] = handle;
}

uint8_t T832Diag_nwkDue(void)
{
    uint32_t now = (uint32_t)T832Diag_nowMs();
    if (t832R5.nwk_ms && (uint32_t)(now - t832R5.nwk_ms) < 60000u) return 0u;
    t832R5.nwk_ms = now ? now : 1u;
    return 1u;
}

void T832Diag_nwkPressure(uint8_t selector, uint16_t current, uint16_t limit)
{
    if (selector >= T832_R5_NWK) return;
    if (!t832R5.nwk_limit[selector] && limit)
        T832Diag_record(T832_DIAG_EV_NWK_LIMIT, selector, limit, 0u);
    t832R5.nwk[selector] = current;
    if (current > t832R5.nwk_max[selector]) t832R5.nwk_max[selector] = current;
    t832R5.nwk_limit[selector] = limit;
}

static void T832Diag_sampleR5(uint32_t now)
{
    uint32_t key = OsalPort_enterCS();
    uint32_t mask = (t832Diag.sync_outstanding ? 1u : 0u) |
        (t832Diag.transport_active ? 2u : 0u) | (t832Diag.diag_pending ? 4u : 0u) |
        (t832Diag.normal_pending ? 8u : 0u) |
        (t832Diag.txq_count >= T832_DIAG_TXQ_DEPTH ? 16u : 0u);
    uint8_t i;
    if (mask && !t832R5.blocked_mask) t832R5.blocked_since = now;
    if (!mask && t832R5.blocked_mask) {
        uint32_t age = now - t832R5.blocked_since;
        if (age > t832R5.maximum[1]) t832R5.maximum[1] = age;
        if (age >= 5000u) t832R5.resource_cursor = 0u;
    }
    t832R5.blocked_mask = mask;
    t832R5.blocked_sticky |= mask;
    t832R5.current[0] = mask;
    t832R5.current[1] = mask ? now - t832R5.blocked_since : 0u;
    t832R5.current[2] = t832Diag.normal_pending;
    t832R5.current[3] = t832Diag.normal_pending ? now - t832Diag.oldest_pending_ms : 0u;
    t832R5.current[4] = t832Diag.transport_active ? now - t832Diag.tx_start_ms : 0u;
    t832R5.current[5] = now - t832Diag.mt_work_ms;
    t832R5.current[6] = now - t832Diag.npi_work_ms;
    t832R5.current[7] = now - t832Diag.npi_task_ms;
    t832R5.current[8] = t832Diag.zstack_work_valid ? now - t832Diag.zstack_work_ms : 0xFFFFFFFFu;
    t832R5.current[9] = t832Diag.af_outstanding;
    t832R5.current[10] = t832Diag.af_outstanding ? now - t832Diag.af_oldest_ms : 0u;
    t832R5.current[11] = t832R5.stage && t832R5.stage != 10u ? now - t832R5.stage_ms : 0u;
    t832R5.current[12] = now - t832Diag.mt_sched_ms;
    for (i = 0u; i < T832_R5_VALUES; i++) {
        /* Unknown ZStack progress must not poison lifetime maxima. */
        if (t832R5.current[i] != 0xFFFFFFFFu && t832R5.current[i] > t832R5.maximum[i])
            t832R5.maximum[i] = t832R5.current[i];
    }
    if (t832R5.uart_accepted && now - t832R5.accepted_ms > t832R5.accepted_age_max)
        t832R5.accepted_age_max = now - t832R5.accepted_ms;
    t832R5.sampled_ms = now;
    OsalPort_leaveCS(key);
#ifndef T832_DIAG_HOST
    /* Task_stat scans only fixed NPI / shared OSAL stacks in task context,
     * without disabling interrupts. It is an approximate watermark, and
     * cost still requires hardware measurement. Global stack flags stay off. */
    if ((uint32_t)(now - t832R5.task_ms) >= 60000u) {
        t832R5.task_ms = now;
        for (i = 0u; i < 2u; i++) {
            if (t832R5.task_handle[i]) {
                Task_Stat stat;
                Task_stat((Task_Handle)t832R5.task_handle[i], &stat);
                t832R5.task_mode[i] = (uint16_t)stat.mode;
                t832R5.task_used[i] = T832R5_sat((uint32_t)stat.used);
                t832R5.task_size[i] = T832R5_sat((uint32_t)stat.stackSize);
            }
        }
    }
#endif
}

static T832DiagRecord T832Diag_liveR5(uint8_t index, uint32_t now)
{
    T832DiagRecord r = {0};
    r.first_ms = t832R5.sampled_ms;
    r.last_ms = r.first_ms;
    r.flags = T832_DIAG_FLAG_SNAPSHOT;
    r.repeat_count = 1u;
    if (index < T832_R5_VALUES) {
        r.kind = T832_DIAG_EV_BLOCK_SNAPSHOT;
        r.a = index;
        r.b = T832R5_sat(t832R5.current[index]);
        r.c = index == 0u ? (uint16_t)t832R5.blocked_sticky : T832R5_sat(t832R5.maximum[index]);
    } else if ((index -= T832_R5_VALUES) < 12u) {
        r.kind = T832_DIAG_EV_PIPELINE;
        r.a = index;
        if (!index) { r.b = t832R5.generation; r.c = t832R5.command; }
        else if (index == 1u) { r.b = t832R5.stage; r.c = (uint16_t)t832R5.stage_seen; }
        else { r.b = T832R5_sat(t832R5.stage_max[index - 2u]); r.c = t832R5.generation; }
    } else if ((index -= 12u) < 8u) {
        r.kind = T832_DIAG_EV_UART_EVENT;
        r.a = index;
        if (index < 6u) {
            r.b = T832R5_sat(t832R5.uart_count[index]);
            r.c = t832R5.uart_count[index] ? T832R5_sat(now - t832R5.uart_last[index]) : 0xFFFFu;
        } else if (index == 6u) {
            r.b = (uint16_t)t832R5.rx_status; r.c = (uint16_t)t832R5.write_status;
        } else {
            r.b = t832R5.uart_accepted ? T832R5_sat(now - t832R5.accepted_ms) : 0u;
            r.c = T832R5_sat(t832R5.accepted_age_max);
        }
    } else if ((index -= 8u) < T832_R5_NWK) {
        r.kind = T832_DIAG_EV_NWK_PRESSURE;
        r.a = index;
        r.b = t832R5.nwk_ms ? t832R5.nwk[index] : 0xFFFFu;
        r.c = t832R5.nwk_max[index];
        /* Capacities are immutable and included in the pinned manifest. */
        r.first_ms = t832R5.nwk_ms;
        r.last_ms = r.first_ms;
    } else {
        index -= T832_R5_NWK;
        r.kind = T832_DIAG_EV_TASK_STAT;
        r.a = index;
        if (index < 2u) { r.b = t832R5.task_mode[index]; r.c = t832R5.task_size[index]; }
        else { r.b = t832R5.task_used[index - 2u]; r.c = t832R5.task_handle[index - 2u] ? 1u : 0u; }
        r.first_ms = t832R5.task_ms;
        r.last_ms = r.first_ms;
    }
    return r;
}
