/*
 * R12 retention journal: pure implementation, no physical AUX connection.
 * Intended as a small embeddable C11 unit only AFTER independent source,
 * power-domain, SCE ownership and same-radio-reset qualification.
 */
#include "r12_aux_trace.h"

enum {
    R12_MAGIC = 0,
    R12_VERSION_SIZE = 1,
    R12_BUILD = 2,
    R12_ATTEMPT = 3,
    R12_BOOT = 4,
    R12_SEQUENCE = 5,
    R12_MARK = 6,
    R12_CONTEXT = 7,
    R12_CHECKSUM = 8,
    R12_COMMITTED = 9
};

static uint32_t crc_word(uint32_t crc, uint32_t word)
{
    unsigned int byte_no;
    for (byte_no = 0u; byte_no != 4u; ++byte_no) {
        unsigned int bit;
        crc ^= (word >> (byte_no * 8u)) & 0xffu;
        for (bit = 0u; bit != 8u; ++bit) {
            const uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1u) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return crc;
}

uint32_t R12Aux_checksumWords(const uint32_t *words, size_t count)
{
    uint32_t crc = UINT32_C(0xffffffff);
    size_t i;
    if (words == NULL || count > (size_t)R12_CONTEXT + 1u) {
        return 0u;
    }
    for (i = 0u; i != count; ++i) {
        crc = crc_word(crc, words[i]);
    }
    return ~crc;
}

static uint32_t crc_volatile_slot(const volatile uint32_t *words)
{
    uint32_t crc = UINT32_C(0xffffffff);
    unsigned int i;
    for (i = 0u; i < (unsigned int)R12_CHECKSUM; ++i) {
        crc = crc_word(crc, words[i]);
    }
    return ~crc;
}

static int populated(const volatile uint32_t *p)
{
    unsigned int i;
    for (i = 0; i < R12_AUX_SLOT_WORDS; i++) {
        if (p[i] != 0u && p[i] != UINT32_C(0xffffffff)) {
            return 1;
        }
    }
    return 0;
}

static int valid_slot(const volatile uint32_t *p)
{
    return p[R12_COMMITTED] == R12_AUX_COMMIT
        && p[R12_MAGIC] == R12_AUX_MAGIC
        && p[R12_VERSION_SIZE] == R12_AUX_VERSION_SIZE
        && p[R12_BUILD] != 0u
        && p[R12_ATTEMPT] != 0u
        && p[R12_BOOT] != 0u
        && p[R12_SEQUENCE] != 0u
        && p[R12_CHECKSUM] == crc_volatile_slot(p);
}

static R12AuxRecord get_record(const volatile uint32_t *p, uint8_t slot)
{
    R12AuxRecord r;
    uint32_t mark = p[R12_MARK];
    r.build = p[R12_BUILD];
    r.attempt = p[R12_ATTEMPT];
    r.boot_epoch = p[R12_BOOT];
    r.sequence = p[R12_SEQUENCE];
    r.milestone = (uint16_t)(mark & 0xffffu);
    r.phase = (uint8_t)((mark >> 16u) & 0xffu);
    r.flags = (uint8_t)((mark >> 24u) & 0xffu);
    r.context = p[R12_CONTEXT];
    r.slot = slot;
    return r;
}

R12AuxStatus R12Aux_readLatest(const volatile uint32_t *window,
                               uint32_t expected_build,
                               R12AuxRecord *out)
{
    const volatile uint32_t *s0;
    const volatile uint32_t *s1;
    int a, b;
    uint8_t best;
    uint32_t delta;
    if (window == NULL || out == NULL || expected_build == 0u) {
        return R12_AUX_BAD_ARGUMENT;
    }
    s0 = window;
    s1 = window + R12_AUX_SLOT_WORDS;
    a = valid_slot(s0);
    b = valid_slot(s1);
    if ((a && s0[R12_BUILD] != expected_build)
            || (b && s1[R12_BUILD] != expected_build)) {
        return R12_AUX_FOREIGN_BUILD;
    }
    if (!a && !b) {
        return populated(s0) || populated(s1) ? R12_AUX_TORN : R12_AUX_EMPTY;
    }
    if (a && b) {
        delta = s1[R12_SEQUENCE] - s0[R12_SEQUENCE];
        if (delta == 0u || delta == UINT32_C(0x80000000)) {
            return R12_AUX_AMBIGUOUS_SEQUENCE;
        }
        best = (delta < UINT32_C(0x80000000)) ? 1u : 0u;
    } else {
        best = b ? 1u : 0u;
    }
    *out = get_record(best ? s1 : s0, best);
    return R12_AUX_OK;
}

static void store_word(volatile uint32_t *p, uint32_t value)
{
    p[0] = value;
    /* A volatile read drains the peripheral bridge write buffer. */
    (void)p[0];
}

R12AuxStatus R12Aux_commit(volatile uint32_t *window,
                           uint32_t expected_build,
                           uint32_t attempt,
                           uint32_t boot_epoch,
                           uint16_t milestone,
                           uint8_t phase,
                           uint8_t flags,
                           uint32_t context,
                           R12AuxRecord *committed_out)
{
    R12AuxRecord previous, now;
    R12AuxStatus status;
    volatile uint32_t *p;
    uint8_t slot;
    uint32_t seq;
    unsigned int j;
    const uint32_t payload[8] = {
        R12_AUX_MAGIC, R12_AUX_VERSION_SIZE, expected_build,
        attempt, boot_epoch, 0u, /* seq assigned below */
        ((uint32_t)milestone | ((uint32_t)phase << 16u)
            | ((uint32_t)flags << 24u)),
        context
    };
    uint32_t data[8];

    if (window == NULL || committed_out == NULL || expected_build == 0u
            || attempt == 0u || boot_epoch == 0u || milestone == 0u
            || phase > 2u) {
        return R12_AUX_BAD_ARGUMENT;
    }
    status = R12Aux_readLatest(window, expected_build, &previous);
    if (status == R12_AUX_EMPTY) {
        slot = 0u;
        seq = 1u;
    } else if (status == R12_AUX_OK) {
        slot = previous.slot ^ 1u;
        seq = previous.sequence + 1u;
        if (seq == 0u) {
            /* skip 0; do not reuse an old "empty" serial */
            seq = 1u;
        }
    } else {
        return status;
    }
    p = window + ((size_t)slot * R12_AUX_SLOT_WORDS);
    for (j = 0u; j < 8u; ++j) {
        data[j] = payload[j];
    }
    data[R12_SEQUENCE] = seq;
    /* Invalidate only the alternate slot, preserving the previous good one. */
    store_word(&p[R12_COMMITTED], 0u);
    for (j = 0u; j < 8u; ++j) {
        store_word(&p[j], data[j]);
    }
    store_word(&p[R12_CHECKSUM], R12Aux_checksumWords(data, 8u));
    /* Publish the commit marker LAST. No writes after this commit. */
    store_word(&p[R12_COMMITTED], R12_AUX_COMMIT);
    status = R12Aux_readLatest(window, expected_build, &now);
    if (status != R12_AUX_OK || now.slot != slot || now.sequence != seq
            || now.build != expected_build || now.attempt != attempt
            || now.boot_epoch != boot_epoch || now.milestone != milestone
            || now.phase != phase || now.flags != flags
            || now.context != context) {
        return R12_AUX_VERIFY_FAILED;
    }
    *committed_out = now;
    return R12_AUX_OK;
}
