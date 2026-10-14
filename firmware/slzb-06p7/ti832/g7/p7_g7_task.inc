/* Included in the pinned NPI task AFTER its declarations. One task services
 * both queues; producers enqueue under the same OSAL critical section.
 * No live delivery, reset or hardware qualification is implied. */
#include "npi_config.h"
#include "p7_g7_transport.h"
#include "p7_tx_policy.h"
#define P7_G7_LANE_CAPACITY 8u
#define P7_G7_WAKE_EVENT 0x0100u
typedef struct {
    Queue_Struct queue;
    Queue_Handle handle;
    NPI_QueueRec *head;
    p7_tx_budget_t budget;
    uint32_t head_tick;
    uint8_t count; /* includes retained head */
} p7_g7_lane_t;
typedef struct {
    uint32_t queued[2], submitted[2], ambiguous, rejected, dropped;
    uint32_t invalid, full, timer_fault, transport_fault, unexpected_outcome, completion_fault;
    uint8_t high_water[2];
} p7_g7_counters_t;
/* RAM counters only: submission is not host reception or physical TX idle. */
volatile p7_g7_counters_t p7_g7_counters;
static p7_g7_lane_t p7_g7_lanes[2]; /* 0 SRSP, 1 AREQ */
static ClockP_Struct p7_g7_clock_struct;
static ClockP_Handle p7_g7_clock;
static volatile uint16_t p7_g7_isr_event;
static uint8_t p7_g7_burst, p7_g7_fault;
static uint8_t p7_g7_busy_seen;
static uint32_t p7_g7_busy_tick;

static void p7_g7_clock_cb(uintptr_t arg)
{
    uint32_t key = OsalPort_enterCS();
    (void)arg;
    p7_g7_isr_event = P7_G7_WAKE_EVENT;
    Semaphore_post(npiSemHandle);
    OsalPort_leaveCS(key);
}

static void p7_g7_init(void)
{
    ClockP_Params params;
    unsigned i;
    for (i = 0; i < 2; ++i)
        p7_g7_lanes[i].handle = Queue_construct(&p7_g7_lanes[i].queue, NULL);
    ClockP_Params_init(&params);
    params.period = 0;
    params.startFlag = false;
    params.arg = 0;
    p7_g7_clock = ClockP_construct(&p7_g7_clock_struct, p7_g7_clock_cb, 1, &params);
    if (!p7_g7_clock || !p7_g6_period_us()) {
        p7_g7_fault = 1;
        p7_g7_counters.timer_fault++;
    }
}

static void p7_g7_free(NPI_QueueRec *rec)
{
    if (rec) {
        OsalPort_msgDeallocate(rec->npiMsg->pBuf);
        OsalPort_free(rec->npiMsg);
        OsalPort_free(rec);
    }
}

/* The MT wrapper's msgType is ASYNC even for MT SRSP. Validate the complete
 * framed bytes before classifying CMD0; never classify raw unframed messages. */
static int p7_g7_classify(const NPIMSG_msg_t *msg)
{
    uint16_t i;
    uint8_t fcs = 0, type;
    if (!msg || msg->msgType != NPIMSG_Type_ASYNC || !msg->pBuf ||
        msg->pBufSize < 5 || msg->pBufSize > NPI_TL_BUF_SIZE ||
        msg->pBuf[0] != 0xfe || msg->pBufSize != (uint16_t)msg->pBuf[1] + 5u)
        return -1;
    for (i = 1; i < msg->pBufSize; ++i) fcs ^= msg->pBuf[i];
    if (fcs) return -1;
    type = msg->pBuf[2] & 0xe0u;
    return type == 0x60u ? 0 : type == 0x40u ? 1 : -1;
}

/* Consumes msg on every path, including allocation failure and saturation. */
static void __attribute__((noinline)) p7_g7_enqueue(NPIMSG_msg_t *msg)
{
    NPI_QueueRec *rec;
    int lane;
    uint32_t key = OsalPort_enterCS();
    lane = p7_g7_classify(msg);
    if (!msg) { OsalPort_leaveCS(key); return; }
    if (lane < 0 || p7_g7_fault || p7_g7_lanes[lane].count >= P7_G7_LANE_CAPACITY) {
        if (lane < 0) p7_g7_counters.invalid++;
        else if (!p7_g7_fault) p7_g7_counters.full++;
        p7_g7_counters.dropped++;
        p7_g6_record(P7D_NPI_Q_REJECT, (uint16_t)(lane < 0 ? 3 : 5));
        OsalPort_msgDeallocate(msg->pBuf);
        OsalPort_free(msg);
        OsalPort_leaveCS(key);
        return;
    }
    rec = OsalPort_malloc(sizeof(*rec));
    if (!rec) {
        p7_g7_counters.dropped++;
        p7_g6_record(P7D_NPI_Q_REJECT, 4);
        OsalPort_msgDeallocate(msg->pBuf);
        OsalPort_free(msg);
        OsalPort_leaveCS(key);
        return;
    }
    rec->npiMsg = msg;
    Queue_enqueue(p7_g7_lanes[lane].handle, &rec->_elem);
    ++p7_g7_lanes[lane].count;
    ++p7_g7_counters.queued[lane];
    if (p7_g7_lanes[lane].count > p7_g7_counters.high_water[lane])
        p7_g7_counters.high_water[lane] = p7_g7_lanes[lane].count;
    p7_g6_record(P7D_NPI_Q_ACCEPT, (uint16_t)(lane + 1));
    npiServiceTaskEvents |= NPITASK_TX_READY_EVENT;
    Semaphore_post(npiSemHandle);
    OsalPort_leaveCS(key);
}

static void p7_g7_release_head(unsigned lane, int dropped)
{
    p7_g7_free(p7_g7_lanes[lane].head);
    p7_g7_lanes[lane].head = NULL;
    --p7_g7_lanes[lane].count;
    if (dropped) ++p7_g7_counters.dropped;
}

static int p7_g7_elapsed(uint32_t start, uint32_t now, uint32_t period)
{
    uint32_t age = now - start;
    return !period || age >= 0x80000000u ||
        (uint64_t)age * period >= P7_TX_DEADLINE_US;
}

/* Remaining ticks to an absolute budget. Retry includes an extra tick for
 * unknown tick phase; expiry has tick quantization and task scheduling delay. */
static uint32_t p7_g7_remaining(uint32_t start, uint32_t now,
                               uint32_t period, uint64_t interval)
{
    uint32_t age = now - start;
    uint64_t used = (uint64_t)age * period;
    if (!period || age >= 0x80000000u || used >= interval) return 1;
    return (uint32_t)(((uint64_t)interval - used + period - 1u) / period);
}

static void p7_g7_latch_transport_fault(void)
{
    unsigned i;
    p7_g7_fault = 1;
    ++p7_g7_counters.transport_fault;
    /* Do not cancel UART, clear its busy bit, overwrite the DMA buffer, reset
     * the radio or retransmit uncertain bytes. RX remains in the TI task. */
    for (i = 0; i < 2; ++i) {
        if (p7_g7_lanes[i].head) p7_g7_release_head(i, 1);
        while (!Queue_empty(p7_g7_lanes[i].handle)) {
            p7_g7_free((NPI_QueueRec *)Queue_dequeue(p7_g7_lanes[i].handle));
            --p7_g7_lanes[i].count;
            ++p7_g7_counters.dropped;
        }
    }
}

/* One bounded service pass, not a semaphore repost loop. Called on enqueue,
 * completion and timer events. All absolute timestamps survive unrelated wakes. */
static void __attribute__((noinline)) p7_g7_service(void)
{
    uint32_t key = OsalPort_enterCS();
    uint32_t now = p7_g6_now(), period = p7_g6_period_us(), wait = 0xffffffffu;
    unsigned i;
    int ready[2] = {0, 0};
    enum p7_tx_lane selected;
    p7_submit_result_t result;
    npiServiceTaskEvents &= ~(NPITASK_TX_READY_EVENT | NPITASK_TRANSPORT_TX_DONE_EVENT | P7_G7_WAKE_EVENT);
    if (p7_g7_clock) ClockP_stop(p7_g7_clock);
    if (p7_g7_fault) { OsalPort_leaveCS(key); return; }
    if (p7_g7_uart_completion_error()) {
        /* A failed/short DMA callback is not successful delivery; never
         * retransmit uncertain bytes. Retire task queues, keep RX alive. */
        ++p7_g7_counters.completion_fault;
        p7_g7_latch_transport_fault();
        OsalPort_leaveCS(key);
        return;
    }
    if (NPITL_checkNpiBusy()) {
        if (!p7_g7_busy_seen) { p7_g7_busy_seen = 1; p7_g7_busy_tick = now; }
        if (p7_g7_elapsed(p7_g7_busy_tick, now, period)) {
            p7_g7_latch_transport_fault();
            OsalPort_leaveCS(key);
            return;
        }
        wait = p7_g7_remaining(p7_g7_busy_tick, now, period, P7_TX_DEADLINE_US);
    } else p7_g7_busy_seen = 0;
    for (i = 0; i < 2; ++i) {
        p7_g7_lane_t *lane = &p7_g7_lanes[i];
        if (!lane->head && !Queue_empty(lane->handle)) {
            lane->head = (NPI_QueueRec *)Queue_dequeue(lane->handle);
            lane->head_tick = now;
            p7_tx_budget_init(&lane->budget);
        }
        if (lane->head) {
            enum p7_tx_ready state = p7_tx_budget_ready(&lane->budget, now, period);
            if (p7_g7_elapsed(lane->head_tick, now, period) || state == P7_TX_EXPIRED) {
                p7_g7_release_head(i, 1);
                /* Continue the next FIFO entry on a scheduled pass, at most 2 drops. */
            } else {
                uint32_t remaining = p7_g7_remaining(lane->head_tick, now, period, P7_TX_DEADLINE_US);
                if (remaining < wait) wait = remaining;
                ready[i] = state == P7_TX_NOW;
                if (state == P7_TX_WAIT) {
                    remaining = p7_g7_remaining(lane->budget.rejected_tick, now, period,
                        (uint64_t)p7_tx_retry_ticks(period) * period);
                    if (remaining < wait) wait = remaining;
                }
            }
        }
    }
    selected = NPITL_checkNpiBusy() ? P7_TX_NONE : p7_tx_choose(ready[0], ready[1], p7_g7_burst);
    if (selected != P7_TX_NONE) {
        i = selected == P7_TX_SRSP ? 0 : 1;
        p7_g7_lane_t *lane = &p7_g7_lanes[i];
        NPITL_writeTL(lane->head->npiMsg->pBuf, lane->head->npiMsg->pBufSize);
        result = p7_g7_tl_outcome();
        if (result == P7_SUBMIT_REJECTED || result == P7_SUBMIT_ACCEPTED || result == P7_SUBMIT_AMBIGUOUS)
            p7_tx_budget_attempt(&lane->budget, now);
        now = p7_g6_now(); /* backoff begins after the actual driver result */
        if (result == P7_SUBMIT_REJECTED) {
            ++p7_g7_counters.rejected;
            p7_g6_record(P7D_UART_REJECTED, 0);
            p7_tx_budget_rejected(&lane->budget, now);
            if (lane->budget.attempts >= P7_TX_MAX_ATTEMPTS) p7_g7_release_head(i, 1);
        } else if (result == P7_SUBMIT_ACCEPTED || result == P7_SUBMIT_AMBIGUOUS) {
            ++p7_g7_counters.submitted[i];
            if (result == P7_SUBMIT_AMBIGUOUS) ++p7_g7_counters.ambiguous;
            if (result == P7_SUBMIT_ACCEPTED)
                p7_g6_record(P7D_UART_ACCEPTED, lane->head->npiMsg->pBufSize);
            p7_g7_burst = p7_tx_accepted_burst(selected, p7_g7_burst);
            p7_g7_release_head(i, 0); /* transport owns its independent copy */
            if (NPITL_checkNpiBusy()) { p7_g7_busy_seen = 1; p7_g7_busy_tick = now; }
        } else {
            /* Service selected while TL was idle under the SAME OSAL CS.
             * BUSY, INVALID and unrecognized result values violate the
             * transport contract. Do not retry, or silently discard and
             * continue: an accepted DMA write may already own the TL copy.
             * Freeze TX, preserve that copy, and keep RX operational. */
            ++p7_g7_counters.unexpected_outcome;
            p7_g7_latch_transport_fault();
        }
    }
    if (p7_g7_fault) {
        /* The one-shot was stopped at entry. A fault must not rearm it. */
        OsalPort_leaveCS(key);
        return;
    }
    /* Compute the next wake from absolute budgets, never from enqueue time.
     * With a pending UART copy monitor even when both task queues are empty. */
    wait = 0xffffffffu;
    if (p7_g7_busy_seen)
        wait = p7_g7_remaining(p7_g7_busy_tick, now, period, P7_TX_DEADLINE_US);
    for (i = 0; i < 2; ++i) if (p7_g7_lanes[i].head) {
        p7_g7_lane_t *lane = &p7_g7_lanes[i];
        uint32_t next = p7_g7_remaining(lane->head_tick, now, period, P7_TX_DEADLINE_US);
        if (lane->budget.attempts && lane->budget.attempts < P7_TX_MAX_ATTEMPTS &&
            p7_tx_budget_ready(&lane->budget, now, period) == P7_TX_WAIT) {
            uint32_t retry = p7_g7_remaining(lane->budget.rejected_tick, now, period,
                (uint64_t)p7_tx_retry_ticks(period) * period);
            if (retry < next) next = retry;
        }
        if (next < wait) wait = next;
    }
    /* A rejected SRSP must not prevent a ready AREQ from being serviced.
     * A one-tick one-shot schedules progress without task busy spinning. */
    if (!NPITL_checkNpiBusy()) for (i = 0; i < 2; ++i)
        if (p7_g7_lanes[i].count && (!p7_g7_lanes[i].head ||
            p7_tx_budget_ready(&p7_g7_lanes[i].budget, now, period) == P7_TX_NOW))
            wait = 1;
    if (wait != 0xffffffffu) {
        ClockP_setTimeout(p7_g7_clock, wait);
        ClockP_start(p7_g7_clock);
    }
    OsalPort_leaveCS(key);
}
