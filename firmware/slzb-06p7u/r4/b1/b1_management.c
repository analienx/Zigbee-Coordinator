#include "b1_management.h"
#include <stddef.h>
#include <string.h>

#ifdef B1_MANAGEMENT_HOST
/* Hosted tests simulate only interrupt masking, never a UART or RF device. */
extern uintptr_t b1_management_test_disable(void);
extern void b1_management_test_restore(uintptr_t key);
#define B1_CS_ENTER() b1_management_test_disable()
#define B1_CS_LEAVE(key) b1_management_test_restore(key)
/* Standalone legacy harnesses do not extract the native ZDApp scheduler. */
__attribute__((weak)) void b1_startup_post_run(void) {}
__attribute__((weak)) void b1_startup_trace_tx_done(void) {}
#else
#include <ti/drivers/dpl/HwiP.h>
#define B1_CS_ENTER() HwiP_disable()
#define B1_CS_LEAVE(key) HwiP_restore(key)
#endif

/* No reset/clear API: only a true C runtime reboot reinitializes this RAM. */
static uint8_t b1_management_flags;
static uint8_t b1_management_first_error;
static uint8_t b1_management_current_error;
static uint8_t b1_management_stage;
static uint8_t b1_management_nv_probe;
static uint8_t b1_network_ready_attested;
static uint8_t b1_network_needs_fresh_validation;
static uint8_t b1_nv4_measured;
static uint32_t b1_nv4_result[7];
static uint8_t b1_boot_startup_state;
static uint8_t b1_startup_response_subsystem, b1_startup_response_command;
static uint8_t b1_startup_phase, b1_startup_status, b1_startup_first_failure;
static uint8_t b1_startup_trace, b1_startup_trace_consumed, b1_startup_srsp_eot;
static uint8_t b1_startup_nv_stage, b1_startup_nv_op;
static uint16_t b1_startup_index, b1_startup_nv_item, b1_startup_nv_sub;
static uint32_t b1_startup_sequence, b1_startup_nv_sequence;
/* A numeric cookie survives freeing the original NPI queue record. */
static uint8_t b1_tx_kind, b1_tx_complete, b1_tx_accepted, b1_tx_eot;
/* Every UART2 TX_FINISHED belongs to an ordered physical write, not merely
 * whichever SRSP is currently awaiting transmission. No pointer survives. */
static uint32_t b1_uart_submit_generation, b1_uart_eot_generation;
static uint32_t b1_tx_target_generation;
static uint16_t b1_tx_length, b1_trace_expected_sequence;
static uint8_t b1_trace_expected;
static uint8_t b1_retained_admitted, b1_retained_network_started;
static uint8_t b1_retained_attempt_completed;

typedef struct {
    uint32_t mask, activity, stack_wakes, zdapp_loops, last_zdapp_input;
    uint32_t npi_wakes, dispatch_entry, dispatch_exit, last_dispatch_input;
    uint32_t last_dispatch_returned;
    uint16_t counts[7];
    uint8_t order[B1_MILESTONES], first_status[B1_MILESTONES];
    uint8_t first_order_next, last_milestone, current_service;
    uint8_t bdb_branch, restore_result, dev_state, confirmation, nlme_result;
    uint32_t *zdapp_pending;
} b1_evidence_ram_t;
static b1_evidence_ram_t b1_ev; /* BSS: not NV, never cleared by requests. */

static void b1_ev_sat32(uint32_t *value)
{
    if (*value != UINT32_MAX) ++*value;
}
static void b1_ev_note_locked(uint8_t milestone, uint8_t status)
{
    if (milestone >= B1_MILESTONES) return;
    b1_ev_sat32(&b1_ev.activity);
    b1_ev.last_milestone = milestone;
    if (!(b1_ev.mask & ((uint32_t)1u << milestone)))
    {
        b1_ev.mask |= ((uint32_t)1u << milestone);
        if (b1_ev.first_order_next < 24u)
            b1_ev.order[milestone] = ++b1_ev.first_order_next;
        b1_ev.first_status[milestone] = status;
    }
}
void b1_evidence_milestone(uint8_t milestone, uint8_t status)
{
    uintptr_t key = B1_CS_ENTER();
    b1_ev_note_locked(milestone, status);
    B1_CS_LEAVE(key);
}
void b1_evidence_count(uint8_t slot)
{
    uintptr_t key = B1_CS_ENTER();
    if (slot < 7u && b1_ev.counts[slot] != UINT16_MAX)
        ++b1_ev.counts[slot];
    B1_CS_LEAVE(key);
}
void b1_evidence_bind_pending(uint32_t *events)
{
    uintptr_t key = B1_CS_ENTER();
    if (!b1_ev.zdapp_pending) b1_ev.zdapp_pending = events;
    B1_CS_LEAVE(key);
}
void b1_evidence_dispatch(uint8_t service, uint32_t input)
{
    uintptr_t key = B1_CS_ENTER();
    b1_ev_sat32(&b1_ev.stack_wakes);
    b1_ev_sat32(&b1_ev.dispatch_entry);
    b1_ev.current_service = service;
    b1_ev.last_dispatch_input = input;
    B1_CS_LEAVE(key);
}
void b1_evidence_dispatch_end(uint32_t returned)
{
    uintptr_t key = B1_CS_ENTER();
    b1_ev.last_dispatch_returned = returned;
    b1_ev_sat32(&b1_ev.dispatch_exit);
    B1_CS_LEAVE(key);
}
void b1_evidence_note_npi_wake(void)
{
    uintptr_t key = B1_CS_ENTER();
    b1_ev_sat32(&b1_ev.npi_wakes);
    B1_CS_LEAVE(key);
}
void b1_evidence_note_zdapp_loop(uint32_t events)
{
    uintptr_t key=B1_CS_ENTER();
    b1_ev_sat32(&b1_ev.zdapp_loops);
    b1_ev.last_zdapp_input=events;
    B1_CS_LEAVE(key);
}
void b1_evidence_set_status(uint8_t slot, uint8_t value)
{
    uintptr_t key = B1_CS_ENTER();
    if (slot == 1u) b1_ev.bdb_branch = value;
    else if (slot == 2u) b1_ev.restore_result = value;
    else if (slot == 3u) b1_ev.dev_state = value;
    else if (slot == 4u) b1_ev.confirmation = value;
    else if (slot == 5u) b1_ev.nlme_result = value;
    B1_CS_LEAVE(key);
}
static void b1_ev_pack32(uint8_t *out, uint32_t val)
{
    unsigned j;
    for (j = 0u; j < 4u; ++j) out[j] = (uint8_t)(val >> (8u*j));
}
static void b1_ev_pack16(uint8_t *out, uint16_t val)
{
    out[0] = (uint8_t)val;
    out[1] = (uint8_t)(val >> 8u);
}
void b1_evidence_snapshot(uint8_t out[B1_EVIDENCE_REPLY_SIZE])
{
    b1_evidence_ram_t local;
    uint32_t pending = 0u;
    uint8_t first_error, state, flags;
    unsigned j;
    uintptr_t key = B1_CS_ENTER();
    memcpy(&local, &b1_ev, sizeof(local));
    if (b1_ev.zdapp_pending) pending = *b1_ev.zdapp_pending;
    state = b1_boot_startup_state;
    first_error = b1_startup_first_failure;
    flags = (uint8_t)((b1_retained_admitted ? 1u : 0u) |
                      (b1_retained_network_started ? 2u : 0u) |
                      (b1_retained_attempt_completed ? 4u : 0u));
    B1_CS_LEAVE(key);
    memset(out, 0, B1_EVIDENCE_REPLY_SIZE);
    memset(out+40, 0xff, 8u);
    memset(out+88, 0xff, 24u);
    memcpy(out, "B1E1", 4u);
    out[4]=1u;out[5]=B1_EVIDENCE_REPLY_SIZE;
    out[6]=state;out[7]=flags;
#ifdef B1_BUILD_DIGEST_BYTES
    { static const uint8_t digest[4] = { B1_BUILD_DIGEST_BYTES };
      memcpy(out+8, digest, 4u); }
#endif
    b1_ev_pack32(out+12,local.mask);
    b1_ev_pack32(out+16,local.activity);
    b1_ev_pack32(out+20,local.stack_wakes);
    b1_ev_pack32(out+24,local.zdapp_loops);
    b1_ev_pack32(out+28,local.last_zdapp_input);
    b1_ev_pack32(out+32,pending);
    b1_ev_pack32(out+36,local.npi_wakes);
    out[40]=first_error;
    out[41]=local.bdb_branch;out[42]=local.restore_result;
    out[43]=local.dev_state;out[44]=local.confirmation;
    out[45]=local.nlme_result;out[46]=5u;out[47]=4u;
    for (j=0u;j<7u;++j) b1_ev_pack16(out+48+2*j,local.counts[j]);
    out[62]=local.last_milestone;out[63]=local.current_service;
    for (j=0u;j<B1_MILESTONES;++j)
    {
        out[64+j]=local.order[j];
        if (local.mask & ((uint32_t)1u << j))
            out[88+j]=local.first_status[j];
    }
    b1_ev_pack32(out+112,local.dispatch_entry);
    b1_ev_pack32(out+116,local.dispatch_exit);
    b1_ev_pack32(out+120,local.last_dispatch_input);
    b1_ev_pack32(out+124,local.last_dispatch_returned);
}
uint8_t b1_evidence_query(const uint8_t *frame,
                          uint8_t out[B1_EVIDENCE_REPLY_SIZE],
                          uint8_t *error)
{
    static const uint8_t prefix[6] = {'B','1','Q','1',1u,8u};
    if (!frame || !out || !error) return B1_MT_DROP;
    if ((frame[1] & 0x1fu) != 1u || frame[2] != B1_STATUS_COMMAND ||
        frame[0] != B1_STATUS_QUERY_SIZE || frame[9] != 3u)
        return B1_MT_CONTINUE;
    *error = 3u;
    if (frame[1] != 0x21u) return B1_MT_DROP;
    if (memcmp(frame+3,prefix,6u) != 0 || frame[10] != 0u)
        return B1_MT_REJECT;
    b1_evidence_snapshot(out);
    return B1_MT_STATUS;
}
int b1_retained_attempt_active(void)
{
    uintptr_t key=B1_CS_ENTER();
    int result=b1_retained_admitted && !b1_retained_attempt_completed;
    B1_CS_LEAVE(key);
    return result;
}
/* The caller must validate native MODE_RESUME, coordinator logical type and
 * restored key/HOLD before invoking; tokens are set before NLME calls. */
int b1_retained_start_gate(uint8_t mode_ok,uint8_t security_ok)
{
    uintptr_t key=B1_CS_ENTER();
    int active=b1_retained_admitted && !b1_retained_attempt_completed;
    int okay=active && b1_boot_startup_state==B1_STARTUP_RUNNING &&
             !b1_retained_network_started && mode_ok && security_ok &&
             b1_management_first_error==0u;
    if(okay)b1_retained_network_started=1u;
    B1_CS_LEAVE(key);
    if(active && !okay && !b1_retained_network_started)
        b1_startup_fail(B1_ERROR_RESUME_MODE);
    return okay;
}

static void b1_management_latch(uint8_t flag, uint8_t stage, uint8_t reason)
{
    uintptr_t key = B1_CS_ENTER();
    if (b1_management_first_error == 0u)
    {
        b1_management_first_error = reason;
    }
    b1_management_current_error = reason;
    b1_management_stage = stage;
    b1_network_ready_attested = 0u; /* irreversible fault revokes ready */
    b1_management_flags |= flag;
    if (b1_boot_startup_state != B1_STARTUP_IDLE)
    {
        b1_boot_startup_state = B1_STARTUP_FAILED;
        if (b1_startup_first_failure == 0u) b1_startup_first_failure = reason;
    }
    B1_CS_LEAVE(key);
}

void b1_management_hold_nv(uint8_t reason)
{
    b1_management_latch(B1_FLAG_HOLD_NV, B1_STAGE_HOLD_NV,
                       reason != 0u ? reason : B1_ERROR_NV_BACKEND);
}

void b1_security_runtime_hold_latch(void)
{
    b1_management_latch(B1_FLAG_HOLD_SECURITY, B1_STAGE_HOLD_SECURITY,
                       B1_ERROR_SECURITY_RESTORE);
}

int b1_management_get_hold_active(void)
{
    uintptr_t key = B1_CS_ENTER();
    int held = (b1_management_flags &
                (B1_FLAG_HOLD_NV | B1_FLAG_HOLD_SECURITY |
                 B1_FLAG_HOLD_TRANSPORT)) != 0u;
    B1_CS_LEAVE(key);
    return held;
}

int b1_management_nv_security_hold_active(void)
{
    uintptr_t key = B1_CS_ENTER();
    int held = (b1_management_flags & (B1_FLAG_HOLD_NV | B1_FLAG_HOLD_SECURITY)) != 0u;
    B1_CS_LEAVE(key);
    return held;
}

void b1_management_transport_failed(uint8_t reason)
{
    b1_management_latch(B1_FLAG_HOLD_TRANSPORT, B1_STAGE_HOLD_TRANSPORT,
                       reason != 0u ? reason : B1_ERROR_UART_OPEN);
}

int b1_management_transport_unavailable(void)
{
    uintptr_t key = B1_CS_ENTER();
    int unavailable = (b1_management_flags & B1_FLAG_HOLD_TRANSPORT) != 0u;
    B1_CS_LEAVE(key);
    return unavailable;
}

void b1_management_note_uart_opened(void)
{
    uintptr_t key = B1_CS_ENTER();
    b1_management_flags |= B1_FLAG_UART_OPENED;
    B1_CS_LEAVE(key);
}

void b1_management_note_npi_initialized(void)
{
    uintptr_t key = B1_CS_ENTER();
    if ((b1_management_flags & (B1_FLAG_UART_OPENED | B1_FLAG_HOLD_TRANSPORT))
        == B1_FLAG_UART_OPENED)
        b1_management_flags |= B1_FLAG_NPI_INITIALIZED;
    B1_CS_LEAVE(key);
}

int b1_management_npi_initialized(void)
{
    uintptr_t key = B1_CS_ENTER();
    int ready = (b1_management_flags &
                 (B1_FLAG_NPI_INITIALIZED | B1_FLAG_HOLD_TRANSPORT))
                == B1_FLAG_NPI_INITIALIZED;
    B1_CS_LEAVE(key);
    return ready;
}

void b1_management_note_mt_registered(void)
{
    uintptr_t key = B1_CS_ENTER();
    b1_management_flags |= B1_FLAG_MT_REGISTERED;
    B1_CS_LEAVE(key);
}

int b1_management_mt_registered(void)
{
    uintptr_t key = B1_CS_ENTER();
    int registered = (b1_management_flags & B1_FLAG_MT_REGISTERED) != 0u;
    B1_CS_LEAVE(key);
    return registered;
}

/* The authority is monotonic against faults but not against leaving ZDO coordinator. */
void b1_management_note_zdo_state(uint8_t coordinator, uint8_t persisted_restore_ok)
{
    uintptr_t key = B1_CS_ENTER();
    if (!coordinator)
    {
        /* Once an attested restored coordinator leaves the role, a later
         * ZDO callback cannot reuse stale boot-time security/counter proof. */
        if (b1_network_ready_attested) b1_network_needs_fresh_validation = 1u;
        b1_network_ready_attested = 0u;
        if ((b1_management_flags & (B1_FLAG_HOLD_NV | B1_FLAG_HOLD_SECURITY |
                                   B1_FLAG_HOLD_TRANSPORT)) == 0u)
            b1_management_stage = (b1_management_flags & B1_FLAG_NV_HEADER_CANDIDATE)
                ? B1_STAGE_NV_HEADER_CANDIDATE : B1_STAGE_PRE_BOOT;
    }
    else if (persisted_restore_ok && !b1_network_needs_fresh_validation &&
             b1_management_first_error == 0u &&
             (b1_management_flags & (B1_FLAG_NV_HEADER_CANDIDATE | B1_FLAG_MT_REGISTERED)) ==
             (B1_FLAG_NV_HEADER_CANDIDATE | B1_FLAG_MT_REGISTERED) &&
             (b1_management_flags & (B1_FLAG_HOLD_NV | B1_FLAG_HOLD_SECURITY |
                                    B1_FLAG_HOLD_TRANSPORT)) == 0u)
    {
        b1_network_ready_attested = 1u;
        b1_management_stage = B1_STAGE_NETWORK_READY;
        b1_boot_startup_state = B1_STARTUP_READY;
        b1_retained_attempt_completed = 1u;
        b1_ev_note_locked(B1_M_READY, 0u);
    }
    B1_CS_LEAVE(key);
}

int b1_management_network_ready(void)
{
    uintptr_t key = B1_CS_ENTER();
    int ready = b1_network_ready_attested != 0u &&
                (b1_management_flags & (B1_FLAG_HOLD_NV | B1_FLAG_HOLD_SECURITY |
                                       B1_FLAG_HOLD_TRANSPORT)) == 0u;
    B1_CS_LEAVE(key);
    return ready;
}

void b1_management_note_nv_candidate(void)
{
    uintptr_t key = B1_CS_ENTER();
    b1_management_flags |= B1_FLAG_NV_HEADER_CANDIDATE;
    b1_management_nv_probe = 7u; /* source b1_nv_probe_code HEADER_CANDIDATE */
    if (b1_management_first_error == 0u)
        b1_management_stage = B1_STAGE_NV_HEADER_CANDIDATE;
    B1_CS_LEAVE(key);
}

void b1_management_note_nv_probe(uint8_t code)
{
    uintptr_t key = B1_CS_ENTER();
    b1_management_nv_probe = code;
    B1_CS_LEAVE(key);
}

__attribute__((noinline))
void b1_management_note_nv4(uint32_t code, uint32_t semantic, uint32_t reads,
                           uint32_t records, uint32_t active, uint32_t fault,
                           uint32_t semantic_flags)
{
    uintptr_t key = B1_CS_ENTER();
    b1_nv4_result[0] = code;
    b1_nv4_result[1] = semantic;
    b1_nv4_result[2] = reads;
    b1_nv4_result[3] = records;
    b1_nv4_result[4] = active;
    b1_nv4_result[5] = fault;
    b1_nv4_result[6] = semantic_flags;
    b1_nv4_measured = 1u;
    B1_CS_LEAVE(key);
}

static void b1_nv4_pack16(uint8_t *out, uint32_t value)
{
    if (value > 0xffffu) value = 0xffffu;
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8u);
}

uint8_t b1_startup_state(void)
{
    uintptr_t key = B1_CS_ENTER();
    uint8_t state = b1_boot_startup_state;
    B1_CS_LEAVE(key);
    return state;
}

int b1_startup_admit(uint8_t subsystem, uint8_t command)
{
    uintptr_t key = B1_CS_ENTER();
    int okay = 0;
    if (b1_network_ready_attested && b1_management_first_error == 0u)
        okay = 1; /* Ready requests are idempotent: no second BDB call. */
    else if (b1_boot_startup_state == B1_STARTUP_IDLE &&
             b1_management_first_error == 0u)
    {
        b1_startup_response_subsystem = subsystem;
        b1_startup_response_command = command;
        b1_boot_startup_state = B1_STARTUP_WAIT_SRSP_TX;
        b1_retained_admitted = 1u;
        b1_startup_phase = B1_PHASE_ADMITTED;
        ++b1_startup_sequence;
        okay = 1;
    }
    B1_CS_LEAVE(key);
    return okay;
}

int b1_startup_begin(void)
{
    uintptr_t key = B1_CS_ENTER();
    int okay = b1_boot_startup_state == B1_STARTUP_QUEUED &&
               b1_management_first_error == 0u;
    if (okay) b1_boot_startup_state = B1_STARTUP_RUNNING;
    B1_CS_LEAVE(key);
    return okay;
}

void b1_startup_fail(uint8_t reason)
{
    uintptr_t key = B1_CS_ENTER();
    b1_boot_startup_state = B1_STARTUP_FAILED;
    b1_ev_note_locked(B1_M_FAILED, reason);
    if (b1_startup_first_failure == 0u) b1_startup_first_failure = reason;
    B1_CS_LEAVE(key);
}

void b1_startup_expire(void)
{
    if (b1_startup_state() == B1_STARTUP_WAIT_SRSP_TX)
    {
        b1_startup_fail(B1_ERROR_STARTUP_TX_TIMEOUT);
        b1_management_transport_failed(B1_ERROR_STARTUP_TX_TIMEOUT);
    }
}

int b1_startup_trace_armed(void) { return b1_startup_trace != 0u; }

void b1_startup_note_phase(uint8_t phase, uint8_t status, uint16_t index)
{
    uintptr_t key = B1_CS_ENTER();
    if (b1_boot_startup_state == B1_STARTUP_RUNNING)
    {
        b1_startup_phase = phase;
        b1_startup_status = status;
        b1_startup_index = index;
        ++b1_startup_sequence;
    }
    B1_CS_LEAVE(key);
}

void b1_startup_note_nv(uint8_t stage, uint8_t op, uint16_t item,
                        uint16_t sub, uint8_t status)
{
    uintptr_t key = B1_CS_ENTER();
    if (b1_boot_startup_state == B1_STARTUP_RUNNING)
    {
        b1_startup_nv_stage = stage;
        b1_startup_nv_op = op;
        b1_startup_nv_item = item;
        b1_startup_nv_sub = sub;
        b1_startup_status = status;
        ++b1_startup_nv_sequence;
    }
    B1_CS_LEAVE(key);
}

static void b1_startup_pack32(uint8_t *out, uint32_t value)
{
    uint8_t i;
    for (i = 0u; i < 4u; ++i) out[i] = (uint8_t)(value >> (i * 8u));
}

void b1_startup_snapshot(uint8_t reply[B1_STARTUP_REPLY_SIZE])
{
    uintptr_t key = B1_CS_ENTER();
    memset(reply, 0, B1_STARTUP_REPLY_SIZE);
    memcpy(reply, "B1P1", 4u);
    reply[4] = 1u; reply[5] = B1_STARTUP_REPLY_SIZE;
    reply[6] = b1_boot_startup_state; reply[7] = b1_startup_phase;
    reply[8] = b1_startup_status; reply[9] = b1_startup_first_failure;
    reply[10] = (uint8_t)((b1_startup_trace ? 1u : 0u) |
                         (b1_startup_srsp_eot ? 2u : 0u) |
                         (b1_trace_expected ? 4u : 0u));
    reply[11] = b1_startup_nv_stage;
#ifdef B1_BUILD_DIGEST_BYTES
    {
        static const uint8_t digest[4] = { B1_BUILD_DIGEST_BYTES };
        memcpy(reply + 12, digest, sizeof(digest));
    }
#endif
    b1_startup_pack32(reply + 16, b1_startup_sequence);
    b1_nv4_pack16(reply + 20, b1_startup_index);
    reply[22] = b1_startup_nv_op;
    b1_startup_pack32(reply + 24, b1_startup_nv_sequence);
    b1_nv4_pack16(reply + 28, b1_startup_nv_item);
    b1_nv4_pack16(reply + 30, b1_startup_nv_sub);
    B1_CS_LEAVE(key);
}

uint8_t b1_startup_query(const uint8_t *frame,
                        uint8_t reply[B1_STARTUP_REPLY_SIZE], uint8_t *error)
{
    static const uint8_t prefix[6] = { 'B','1','Q','1',1u,8u };
    uintptr_t key;
    if (frame == NULL || reply == NULL || error == NULL) return B1_MT_DROP;
    if ((frame[1] & 0x1fu) != 1u || frame[2] != B1_STATUS_COMMAND)
        return B1_MT_CONTINUE;
    if (frame[0] != B1_STATUS_QUERY_SIZE) return B1_MT_CONTINUE;
    if (frame[9] != 2u) return B1_MT_CONTINUE; /* op0/op1 ABI is unchanged. */
    *error = 3u;
    if (frame[1] != 0x21u) return B1_MT_DROP;
    if (memcmp(frame + 3, prefix, sizeof(prefix)) != 0 || frame[10] > 1u)
        return B1_MT_REJECT;
    key = B1_CS_ENTER();
    if (frame[10] == 1u)
    {
        if (b1_boot_startup_state != B1_STARTUP_IDLE ||
            b1_startup_trace_consumed || b1_management_first_error != 0u)
        { B1_CS_LEAVE(key); return B1_MT_REJECT; }
        b1_startup_trace = b1_startup_trace_consumed = 1u;
    }
    B1_CS_LEAVE(key);
    b1_startup_snapshot(reply);
    return B1_MT_STATUS;
}

void b1_startup_trace_expect(uint16_t sequence)
{
    uintptr_t key = B1_CS_ENTER();
    b1_trace_expected_sequence = sequence;
    b1_trace_expected = 1u;
    B1_CS_LEAVE(key);
}

/* Called by the original UART owner under its existing submission CS. */
void b1_startup_tx_submit(const uint8_t *frame, uint16_t length)
{
    uint8_t check = 0u;
    uint16_t i;
    uintptr_t key = B1_CS_ENTER();
    uint8_t kind = 0u;
    if (frame != NULL && length >= 5u && frame[0] == 0xfeu &&
        length == (uint16_t)(frame[1] + 5u))
    {
        for (i = 1u; i < length; ++i) check ^= frame[i];
        if (check == 0u && length == 6u && frame[1] == 1u && frame[4] == 0u &&
            b1_boot_startup_state == B1_STARTUP_WAIT_SRSP_TX &&
            frame[2] == b1_startup_response_subsystem &&
            frame[3] == b1_startup_response_command) kind = 1u;
        if (check == 0u && length == B1_STARTUP_REPLY_SIZE + 5u &&
            frame[2] == 0x41u && frame[3] == B1_STARTUP_TRACE_COMMAND &&
            b1_trace_expected && frame[20] == (uint8_t)b1_trace_expected_sequence &&
            frame[21] == (uint8_t)(b1_trace_expected_sequence >> 8u)) kind = 2u;
    }
    /* Reservation occurs before UART2_write so a synchronous callback cannot
     * overtake the generation. A failed write latches transport HOLD; it must
     * never be followed by another submission in the same boot. */
    ++b1_uart_submit_generation;
    /* Later ordinary messages cannot rebind a pending startup SRSP. */
    if (kind != 0u && b1_tx_kind == 0u)
    {
        b1_tx_kind = kind; b1_tx_length = length;
        b1_tx_target_generation = b1_uart_submit_generation;
        b1_tx_complete = b1_tx_accepted = b1_tx_eot = 0u;
    }
    B1_CS_LEAVE(key);
}

static void b1_startup_tx_publish(void)
{
    uint8_t action = 0u;
    uintptr_t key = B1_CS_ENTER();
    if (b1_tx_kind && b1_tx_complete && b1_tx_accepted && b1_tx_eot)
    {
        action = b1_tx_kind;
        b1_tx_kind = 0u;
        if (action == 1u && b1_boot_startup_state == B1_STARTUP_WAIT_SRSP_TX)
        {
            b1_startup_srsp_eot = 1u;
            b1_boot_startup_state = B1_STARTUP_QUEUED;
        }
        else if (action == 1u) action = 0u;
        if (action == 2u) b1_trace_expected = 0u;
    }
    B1_CS_LEAVE(key);
    if (action == 1u) b1_startup_post_run();
    else if (action == 2u) b1_startup_trace_tx_done();
}

void b1_startup_tx_result(uint16_t length, int success)
{
    uintptr_t key = B1_CS_ENTER();
    uint8_t bad = b1_tx_kind && (!success || length != b1_tx_length);
    if (!bad && b1_tx_kind && !b1_tx_complete)
        b1_tx_complete = 1u;
    B1_CS_LEAVE(key);
    if (bad)
    {
        b1_startup_fail(B1_ERROR_UART_WRITE);
        b1_management_transport_failed(B1_ERROR_UART_WRITE);
        return;
    }
    b1_startup_tx_publish();
}

void b1_startup_tx_accepted(uint16_t length, int success)
{
    uintptr_t key = B1_CS_ENTER();
    uint8_t bad = b1_tx_kind && (!success || length != b1_tx_length);
    if (!bad && b1_tx_kind) b1_tx_accepted = 1u;
    B1_CS_LEAVE(key);
    if (bad)
    {
        b1_startup_fail(B1_ERROR_UART_WRITE);
        b1_management_transport_failed(B1_ERROR_UART_WRITE);
        return;
    }
    b1_startup_tx_publish();
}

void b1_startup_tx_eot(void)
{
    uintptr_t key = B1_CS_ENTER();
    if (b1_uart_eot_generation < b1_uart_submit_generation)
        ++b1_uart_eot_generation;
    if (b1_tx_kind && b1_uart_eot_generation == b1_tx_target_generation)
        b1_tx_eot = 1u;
    B1_CS_LEAVE(key);
    b1_startup_tx_publish();
}

uint8_t b1_management_mt_filter(const uint8_t *frame,
                              uint8_t reply[B1_STATUS_REPLY_SIZE],
                              uint8_t *rpc_error)
{
    static const uint8_t query[B1_STATUS_QUERY_SIZE] =
        { 'B', '1', 'Q', '1', 1u, B1_STATUS_QUERY_SIZE, 0u, 0u };
    uintptr_t key;
    uint8_t flags, stage, first_error, current_error, nv_probe, network_ready;
    int held;
    if (frame == NULL || reply == NULL || rpc_error == NULL)
        return B1_MT_DROP;

    key = B1_CS_ENTER();
    b1_management_flags |= B1_FLAG_MT_HANDLER_REACHED;
    flags = b1_management_flags;
    stage = b1_management_stage;
    first_error = b1_management_first_error;
    current_error = b1_management_current_error;
    nv_probe = b1_management_nv_probe;
    network_ready = b1_network_ready_attested;
    B1_CS_LEAVE(key);
    held = (flags & (B1_FLAG_HOLD_NV | B1_FLAG_HOLD_SECURITY |
                     B1_FLAG_HOLD_TRANSPORT)) != 0u;
    *rpc_error = 3u; /* donor MT_RPC_ERR_PARAMETER, bounded HOLD rejection */

    if ((frame[1] & 0x1Fu) == 1u && frame[2] == B1_STATUS_COMMAND)
    {
        if (frame[1] != 0x21u) return B1_MT_DROP; /* SREQ SYS only */
        if (frame[0] != B1_STATUS_QUERY_SIZE)
        {
            *rpc_error = 4u; /* donor MT_RPC_ERR_LENGTH */
            return B1_MT_REJECT;
        }
        if (memcmp(frame + 3, query, 6u) != 0 || frame[9] > 1u || frame[10] != 0u)
            return B1_MT_REJECT;
        memset(reply, 0, B1_STATUS_REPLY_SIZE);
        if (frame[9] == 1u)
        {
            /* B1Q1 v1/8 op1 -> B1N1 v1/24. Counts and offsets only;
             * no item identities, NIB contents, network keys or counters.
             * The original op0 B1S1 response remains byte compatible. */
            memcpy(reply, "B1N1", 4u);
            reply[4] = 1u;
            reply[5] = B1_STATUS_REPLY_SIZE;
            key = B1_CS_ENTER();
            reply[6] = b1_nv4_measured ? (uint8_t)b1_nv4_result[0] : 0xffu;
            reply[7] = b1_nv4_measured ? (uint8_t)b1_nv4_result[1] : 0xffu;
            b1_nv4_pack16(reply + 8, b1_nv4_result[3]);
            b1_nv4_pack16(reply + 10, b1_nv4_result[4]);
            b1_nv4_pack16(reply + 12, b1_nv4_result[2]);
            b1_nv4_pack16(reply + 14, b1_nv4_result[5]);
            reply[20] = b1_nv4_measured;
            reply[21] = (uint8_t)b1_nv4_result[6];
            B1_CS_LEAVE(key);
#ifdef B1_BUILD_DIGEST_BYTES
            {
                static const uint8_t build_digest[4] = { B1_BUILD_DIGEST_BYTES };
                memcpy(reply + 16, build_digest, sizeof(build_digest));
            }
#endif
            return B1_MT_STATUS;
        }
        memcpy(reply, "B1S1", 4u);
        reply[4] = 1u;
        reply[5] = B1_STATUS_REPLY_SIZE;
        reply[6] = stage;
        reply[7] = first_error;
        reply[8] = flags;
        reply[9] = 3u; /* bit0 snapshot; bit1 MT HOLD command admission */
        if (network_ready && !held) reply[9] |= 8u; /* bit3 N30 attested restored ZDO coordinator */
        reply[10] = current_error;
        reply[11] = nv_probe; /* zero = not measured; otherwise probe enum */
#ifdef B1_BUILD_DIGEST_BYTES
        {
            static const uint8_t build_digest[4] = { B1_BUILD_DIGEST_BYTES };
            memcpy(reply + 12, build_digest, sizeof(build_digest));
            reply[9] |= 4u; /* public source commit prefix, not a radio ID */
        }
#endif
        return B1_MT_STATUS;
    }
    {
        uint8_t subsystem = frame[1] & 0x1fu;
        /* This retained-network image has NO authenticated one-shot restore
         * or virgin-new grant. A reported UNCOMMISSIONED candidate is not
         * proof of erased security/keys, so it must not open destructive
         * raw-MT paths. Explicit provisioning must introduce a separate
         * fail-closed authorization boundary before relaxing this rule. */
        /* Alternate raw host paths must not bypass the SYS NV backstop:
         * SAPI writeConfiguration and ZNP basicCfg can rewrite network NV. */
        if ((subsystem == 1u && frame[2] == 3u) || /* SYS setExtAddr */
            (subsystem == 6u && frame[2] == 5u) ||
            (subsystem == 11u && frame[2] == 0u))
            return (frame[1] & 0xe0u) == 0x20u ? B1_MT_REJECT : B1_MT_DROP;
        if (subsystem == 15u && frame[2] == 5u)
        {
            /* TI bdb_StartCommissioning: formation=04, steering=02,
             * initialization=10. Resume/permit joining remain available. */
            if (frame[1] != 0x2fu) return B1_MT_DROP;
            if (frame[0] != 1u) { *rpc_error = 4u; return B1_MT_REJECT; }
            if (frame[3] & 4u) return B1_MT_REJECT;
            if (frame[3] != 0u && !network_ready) return B1_MT_REJECT;
        }
    }
    if (!held) return B1_MT_CONTINUE;
#if defined(B1_B4_F2_HOLD_DIAGNOSTIC_REVIEWED)
    /* Compile-time opt-in ONLY after the exact B4 SYS F2 8-byte read-only
     * handler and single-owner dispatcher have been composition-reviewed.
     * No broad SYS pass-through and no F2 request processing in this module.
     * B4 itself validates/echoes the nonce; B1 grants only the narrow SREQ.
     * MT admission cannot cancel already queued/in-flight RF operations. */
    if (frame[1] == 0x21u && frame[2] == 0xF2u)
    {
        if (frame[0] != 8u)
        {
            *rpc_error = 4u;
            return B1_MT_REJECT;
        }
        return B1_MT_CONTINUE;
    }
#endif
    if (frame[1] == 0x21u && (frame[2] == 1u || frame[2] == 2u))
    {
        if (frame[0] == 0u) return B1_MT_CONTINUE; /* exact donor PING/VERSION */
        *rpc_error = 4u;
        return B1_MT_REJECT;
    }
    if ((frame[1] & 0xE0u) == 0x20u) return B1_MT_REJECT;
    return B1_MT_DROP; /* no arbitrary AREQ/SRSP emission in HOLD */
}
