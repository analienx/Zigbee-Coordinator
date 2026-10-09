/* Native C regression checks for the offline-only 80-byte AUX recorder. */
#include "r12_aux_trace.h"
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define BUILD UINT32_C(8320062)
#define ATTEMPT UINT32_C(0x12345678)
#define EPOCH UINT32_C(0xAABBCCDD)

static volatile uint32_t aux[R12_AUX_WINDOW_WORDS];
static unsigned int checks;

static void reset_blank(void)
{
    unsigned int i;
    for (i = 0u; i < R12_AUX_WINDOW_WORDS; ++i) {
        aux[i] = 0u;
    }
}

static R12AuxRecord record(uint16_t site, uint8_t phase)
{
    R12AuxRecord got = {0};
    assert(R12Aux_commit(aux, BUILD, ATTEMPT, EPOCH,
                         site, phase, 0u, 0u, &got) == R12_AUX_OK);
    checks++;
    return got;
}

static void check(const R12AuxRecord *expect)
{
    R12AuxRecord copy = {0};
    assert(R12Aux_readLatest(aux, BUILD, &copy) == R12_AUX_OK);
    assert(copy.build == BUILD);
    assert(copy.attempt == ATTEMPT);
    assert(copy.sequence == expect->sequence);
    assert(copy.slot == expect->slot);
    assert(copy.milestone == expect->milestone);
    assert(copy.phase == expect->phase);
    checks++;
}

int main(void)
{
    R12AuxRecord a, b, c, view;
    uint32_t saved[R12_AUX_WINDOW_WORDS];
    uint32_t invalid_slot;
    unsigned int i;
    assert(sizeof(uint32_t) == 4u);
    assert(R12_AUX_NUM_SLOTS * R12_AUX_SLOT_BYTES == 80u);
    assert(R12_AUX_SLOT_WORDS == 10u);

    reset_blank();
    assert(R12Aux_readLatest(aux, BUILD, &view) == R12_AUX_EMPTY);
    a = record(2u, 0u); /* synchronous BDB call entry */
    assert(a.sequence == 1u && a.slot == 0u);
    check(&a);
    b = record(3u, 1u); /* restored ZDO init exit */
    assert(b.sequence == 2u && b.slot == 1u);
    check(&b);
    c = record(4u, 0u);
    assert(c.sequence == 3u && c.slot == 0u);
    check(&c);
    /* Simulated PIN_RESET: arrays are retained, C global locals reboot. */
    memcpy(saved, (const void *)aux, sizeof(saved));
    assert(R12Aux_readLatest(aux, BUILD, &view) == R12_AUX_OK);
    assert(view.milestone == 4u && view.sequence == 3u);
    checks++;
    /* Interrupt an overwrite of the *alternate* slot: good record remains. */
    invalid_slot = 1u * R12_AUX_SLOT_WORDS;
    aux[invalid_slot + 9u] = 0u; /* mark uncommitted */
    aux[invalid_slot + 0u] = UINT32_C(0xdeadbeef);
    assert(R12Aux_readLatest(aux, BUILD, &view) == R12_AUX_OK);
    assert(view.sequence == 3u && view.slot == 0u);
    checks++;
    /* We can recover a slot after a torn alternate update. */
    b = record(5u, 0u);
    assert(b.sequence == 4u && b.slot == 1u);
    check(&b);
    /* First of two good slots corrupts; second still reconstructs. */
    aux[0u + 8u] ^= 1u;
    assert(R12Aux_readLatest(aux, BUILD, &view) == R12_AUX_OK);
    assert(view.sequence == 4u);
    checks++;
    /* Both slots corrupted -> no false diagnosis. */
    aux[10u + 8u] ^= 1u;
    assert(R12Aux_readLatest(aux, BUILD, &view) == R12_AUX_TORN);
    checks++;

    /* A full power loss erases the simulation; classify as no evidence. */
    reset_blank();
    assert(R12Aux_readLatest(aux, BUILD, &view) == R12_AUX_EMPTY);
    checks++;

    /* An old valid image is not silently attributed to the new firmware. */
    memcpy((void *)aux, saved, sizeof(saved));
    assert(R12Aux_readLatest(aux, BUILD + 1u, &view) == R12_AUX_FOREIGN_BUILD);
    assert(R12Aux_commit(aux, BUILD + 1u, ATTEMPT, EPOCH, 1u, 0u, 0u,
                         0u, &view) == R12_AUX_FOREIGN_BUILD);
    checks++;

    /* Fail closed on caller null/zero IDs and invalid phase. */
    assert(R12Aux_commit(NULL, BUILD, ATTEMPT, EPOCH, 2u, 0u, 0u,
                         0u, &view) == R12_AUX_BAD_ARGUMENT);
    assert(R12Aux_commit(aux, BUILD, 0u, EPOCH, 2u, 0u, 0u,
                         0u, &view) == R12_AUX_BAD_ARGUMENT);
    assert(R12Aux_commit(aux, BUILD, ATTEMPT, EPOCH, 2u, 3u, 0u,
                         0u, &view) == R12_AUX_BAD_ARGUMENT);
    checks++;

    /* Check true wrap semantics: newer seq 1 after seq 0xFFFFFFFF. */
    reset_blank();
    (void)record(2u, 0u);
    aux[5u] = UINT32_C(0xffffffff);
    {
        uint32_t words[8];
        for (i = 0u; i != 8u; ++i) {
            words[i] = aux[i];
        }
        aux[8u] = R12Aux_checksumWords(words, 8u);
    }
    b = record(3u, 0u);
    assert(b.sequence == 1u && b.slot == 1u);
    check(&b);

    /* Ambiguous exactly-half-circle and same sequence are not ordered. */
    aux[10u + 5u] = UINT32_C(0x7fffffff);
    {
        uint32_t words[8];
        for (i = 0u; i != 8u; ++i) {
            words[i] = aux[10u + i];
        }
        aux[10u + 8u] = R12Aux_checksumWords(words, 8u);
    }
    /* delta=0x80000000 between seq=0xffffffff and 0x7fffffff. */
    assert(R12Aux_readLatest(aux, BUILD, &view)
           == R12_AUX_AMBIGUOUS_SEQUENCE);
    checks++;
    printf("{\"ok\":true,\"checks\":%u,\"window_bytes\":80,"
           "\"writes_to_nv\":0,\"hardware_operations\":0}\n", checks);
    return 0;
}
