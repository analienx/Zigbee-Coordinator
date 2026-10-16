/* Source-linked NV2 admission for TI SDK 8.33 CC2652P7.
 * Deliberately read only; no NVS_open/write/erase, no identity/keys in result.
 * Two valid page headers are CANDIDATES, NOT full NV/security validation.
 * Fails closed on mixed/unknown headers and on every backend read failure.
 */
#include "b1_admission.h"

/* A monotonically asserted word store is atomic on this Cortex-M4 target.
 * In-flight or ROM-originated transmissions are NOT covered by this gate. */
static volatile uint32_t b1_nv_runtime_held;
static volatile uint32_t b1_nv_existing_pair;

int b1_nv_existing_header_candidate(void)
{
    return b1_nv_existing_pair != 0u;
}

void b1_nv_runtime_hold_latch(void)
{
    b1_nv_runtime_held = 1u;
}

int b1_nv_runtime_hold_active(void)
{
    return b1_nv_runtime_held != 0u;
}

static int b1_nv2_known_header(const uint8_t h[4])
{
    const uint8_t state = h[0];
    const uint8_t cycle = h[1];
    const uint8_t version = (uint8_t)(h[2] >> 2);
    if (h[3] != 0x96u || version != 3u ||
        cycle == 0u || cycle == 0xFFu) return 0;
    switch (state) {
    case 0xFFu: /* NACT, valid only with version/signature */
    case 0xFEu: /* XDST */
    case 0x7Eu: /* RDY */
    case 0x7Cu: /* ACT */
    case 0x78u: /* FULL */
    case 0x70u: /* XSRC */
        return 1;
    default:
        return 0;
    }
}

b1_nv_probe_result b1_nv_probe(b1_nv_read_fn reader, void *ctx,
                               bool factory_new_authorized)
{
    b1_nv_probe_result result = {B1_NV_HOLD_NO_READER, 0, 0, 0, 0};
    uint8_t chunk[32];
    uint8_t hdr[4];
    uint8_t page_states[B1_NV2_PAGE_COUNT] = {0xFFu, 0xFFu};
    uint32_t page;
    if (reader == NULL) return result;
    for (page = 0; page < B1_NV2_PAGE_COUNT; ++page) {
        uint32_t offset;
        int all_ff = 1;
        for (offset = 0; offset < B1_NV2_PAGE_SIZE;
             offset += (uint32_t)sizeof(chunk)) {
            uint32_t i;
            const uint32_t absolute = page * B1_NV2_PAGE_SIZE + offset;
            if (reader(ctx, absolute, chunk, (uint32_t)sizeof(chunk)) != 0) {
                result.code = B1_NV_HOLD_READ_FAILED;
                result.first_fault_offset = absolute;
                return result;
            }
            ++result.reads;
            if (offset == 0u) {
                for (i = 0; i < sizeof(hdr); ++i) hdr[i] = chunk[i];
            }
            for (i = 0; i < sizeof(chunk); ++i) {
                if (chunk[i] != 0xFFu) all_ff = 0;
            }
        }
        if (all_ff) {
            ++result.blank_pages;
        } else if (b1_nv2_known_header(hdr)) {
            page_states[page] = hdr[0];
            ++result.candidate_pages;
        } else {
            result.code = B1_NV_HOLD_UNKNOWN_LAYOUT;
            result.first_fault_offset = page * B1_NV2_PAGE_SIZE;
            return result;
        }
    }
    if (result.blank_pages == B1_NV2_PAGE_COUNT) {
        result.code = factory_new_authorized
            ? B1_NV_FACTORY_AUTHORIZED : B1_NV_HOLD_FACTORY_NOT_AUTHORIZED;
    } else if (result.candidate_pages == B1_NV2_PAGE_COUNT) {
        /* The actual two-page NVOCMP_initNv donor erases the tail when
         * there is no PGXDST and may compact a PGXSRC pair. Only a
         * source-supported active+destination pair passes this gate.
         * An interrupted compaction is not silently repaired. */
        const int active0 = page_states[0] == 0x7Cu || page_states[0] == 0x78u;
        const int active1 = page_states[1] == 0x7Cu || page_states[1] == 0x78u;
        const int dest0 = page_states[0] == 0xFEu;
        const int dest1 = page_states[1] == 0xFEu;
        result.code = ((active0 && dest1) || (active1 && dest0))
            ? B1_NV2_HEADER_CANDIDATE : B1_NV_HOLD_MIXED_LAYOUT;
        if (result.code == B1_NV2_HEADER_CANDIDATE) b1_nv_existing_pair = 1u;
    } else {
        /* Formatted+erased may be a legitimate interrupted compaction,
         * but we have no source-proven safe recovery yet: do not mutate it. */
        result.code = B1_NV_HOLD_MIXED_LAYOUT;
    }
    return result;
}
