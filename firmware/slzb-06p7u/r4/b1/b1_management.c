#include "b1_management.h"
#include <stddef.h>
#include <string.h>

#ifdef B1_MANAGEMENT_HOST
/* Hosted tests simulate only interrupt masking, never a UART or RF device. */
extern uintptr_t b1_management_test_disable(void);
extern void b1_management_test_restore(uintptr_t key);
#define B1_CS_ENTER() b1_management_test_disable()
#define B1_CS_LEAVE(key) b1_management_test_restore(key)
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
        if (memcmp(frame + 3, query, sizeof(query)) != 0)
            return B1_MT_REJECT;
        memset(reply, 0, B1_STATUS_REPLY_SIZE);
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
