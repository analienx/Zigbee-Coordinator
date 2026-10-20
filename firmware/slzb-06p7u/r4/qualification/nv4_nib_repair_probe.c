/* Exact-stock P7U NVOCMP v3 / pinned 8.33 legacy-item layout.
 *
 * No NVS_write(), NVS_erase(), TI NVOCMP mutator, or Zigbee API here.
 * A structural admission failure, odd status, ambiguous NIB, mismatched
 * extended PAN ID, missing live key/TC record or torn read all return HOLD.
 */
#include "nv4_nib_repair_probe.h"
#include <string.h>

#define R4_REPAIR_DATA 16u
#define R4_REPAIR_TRAILER 7u
#define R4_REPAIR_SYSID 1u
#define R4_REPAIR_ITEMID 0u
#define R4_RECOVER_EPID 0x002Du
#define R4_RECOVER_ACTIVE_KEY 0x003Au
#define R4_RECOVER_ALTERN_KEY 0x003Bu
#define R4_RECOVER_BDB 0x0055u
#define R4_RECOVER_TC 0x0071u
#define R4_RECOVER_ROLE 0x0087u
#define R4_RECOVER_SEED 0x0101u

static int r4_rread(r4_nv4_read read, void *ctx, uint32_t off,
                   uint8_t *dst, uint32_t n)
{
    if (n == 0u || off > R4_NV4_REGION_SIZE ||
        n > R4_NV4_REGION_SIZE - off) return 0;
    return read(ctx, off, dst, n) == 0;
}

static uint32_t r4_rid(const uint8_t h[7])
{
    return (((uint32_t)h[0] >> 2u) << 20u) |
           (((uint32_t)(h[0] & 3u) << 8u | h[1]) << 10u) |
           ((uint32_t)h[2] << 2u) | ((uint32_t)h[3] >> 6u);
}

#define R4_RID(x) ((R4_REPAIR_SYSID << 20u) | (R4_REPAIR_ITEMID << 10u) | (x))

int r4_nv4_probe_nib(r4_nv4_read read, void *ctx,
                     r4_nv4_nib_candidate *result,
                     uint8_t nib_out[R4_RECOVER_NIB_LENGTH])
{
    r4_nv4_result admission;
    uint8_t prefix[16], block[64], h[7], epid[8];
    uint8_t has_bdb = 0u, has_role = 0u, has_option = 0u;
    uint8_t has_epid = 0u, has_active_key = 0u, has_alt_key = 0u;
    uint8_t has_tc = 0u, has_seed = 0u, active_nib = 0u;
    uint8_t old_nib_count = 0u, startup = 0xffu;
    uint32_t nib_offset = 0u, p;
    int success = 0;

    if (result == NULL || nib_out == NULL || read == NULL) return 0;
    memset(result, 0, sizeof(*result));
    memset(nib_out, 0, R4_RECOVER_NIB_LENGTH);
    memset(epid, 0, sizeof(epid));

    /* Existing B1 observer verifies all records' CRC, header chain, page
     * journal, active-ID uniqueness and settles the four-page ring. */
    admission = r4_nv4_admit(read, ctx);
    if (admission.code != R4_NV4_READONLY_STRUCTURE_ACCEPTED ||
        admission.semantic_state != R4_NV4_STATE_UNKNOWN_HOLD)
        return 0;

    for (p = 0u; p < R4_NV4_PAGES; ++p) {
        uint32_t base = p * R4_NV4_PAGE_SIZE;
        uint32_t end = R4_REPAIR_DATA, off, nitems = 0u;
        uint16_t logical;
        if (!r4_rread(read, ctx, base, prefix, sizeof(prefix))) goto done;
        if (prefix[0] == 0xfeu || prefix[0] == 0xffu) continue;
        logical = (uint16_t)((uint16_t)prefix[4] |
                             ((uint16_t)prefix[5] << 8u));
        if (logical != 0xffffu) {
            end = logical;
        } else {
            for (off = R4_REPAIR_DATA; off < R4_NV4_PAGE_SIZE; off += 64u) {
                uint32_t i, count = R4_NV4_PAGE_SIZE - off;
                if (count > sizeof(block)) count = sizeof(block);
                if (!r4_rread(read, ctx, base + off, block, count)) goto done;
                for (i = 0u; i < count; ++i)
                    if (block[i] != 0xffu) end = off + i + 1u;
            }
        }
        while (end > R4_REPAIR_DATA) {
            uint32_t len, start, id, status;
            uint8_t b;
            if (++nitems > 2000u || end < R4_REPAIR_DATA + R4_REPAIR_TRAILER)
                goto done;
            if (!r4_rread(read, ctx, base + end - 7u, h, sizeof(h)))
                goto done;
            len = ((uint32_t)(h[3] & 63u) << 6u) | ((uint32_t)h[4] >> 2u);
            if (h[6] != 0x96u || len == 0u ||
                len > end - R4_REPAIR_DATA - R4_REPAIR_TRAILER)
                goto done;
            start = end - R4_REPAIR_TRAILER - len;
            status = h[5] & 3u;
            id = r4_rid(h);
            if (id == R4_RID(R4_RECOVER_NIB_ID)) {
                if (status == 2u) {
                    active_nib = 1u;
                } else if (status == 0u && len == R4_RECOVER_NIB_LENGTH) {
                    ++old_nib_count;
                    nib_offset = base + start;
                }
            }
            if (status == 2u) {
                if (id == R4_RID(R4_RECOVER_BDB) ||
                    id == R4_RID(R4_RECOVER_ROLE) ||
                    id == R4_RID(R4_RECOVER_STARTUP_OPTION)) {
                    if (len != 1u ||
                        !r4_rread(read, ctx, base + start, &b, 1u)) goto done;
                    if (id == R4_RID(R4_RECOVER_BDB)) has_bdb = b == 1u;
                    if (id == R4_RID(R4_RECOVER_ROLE)) has_role = b == 0u;
                    if (id == R4_RID(R4_RECOVER_STARTUP_OPTION)) {
                        has_option = 1u; startup = b;
                    }
                } else if (id == R4_RID(R4_RECOVER_EPID)) {
                    if (len != sizeof(epid) ||
                        !r4_rread(read, ctx, base + start, epid, sizeof(epid)))
                        goto done;
                    has_epid = 1u;
                } else if (id == R4_RID(R4_RECOVER_ACTIVE_KEY)) {
                    has_active_key = len == 17u;
                } else if (id == R4_RID(R4_RECOVER_ALTERN_KEY)) {
                    has_alt_key = len == 17u;
                } else if (id == R4_RID(R4_RECOVER_TC)) {
                    has_tc = len == 8u;
                } else if (id == R4_RID(R4_RECOVER_SEED)) {
                    has_seed = len == 16u;
                }
            }
            end = start;
        }
    }
    if (!has_bdb || !has_role || !has_option || !has_epid ||
        !has_active_key || !has_alt_key || !has_tc || !has_seed ||
        active_nib || old_nib_count != 1u ||
        (startup != 0x03u && startup != 0x00u)) goto done;
    if (!r4_rread(read, ctx, nib_offset, nib_out, R4_RECOVER_NIB_LENGTH))
        goto done;
    /* Exact pinned ARM nwkIB_t layout confirmed against retained unit.
     * Require the candidate NIB's E-PAN to equal the currently active
     * OSAL extended-PAN record; not merely a CRC-valid arbitrary NIB. */
    if (memcmp(nib_out + R4_RECOVER_NIB_EPAN_OFFSET, epid,
               sizeof(epid)) != 0) goto done;
    result->nib_payload_offset = nib_offset;
    result->startup_value = startup;
    result->eligible = 1u;
    success = 1;
done:
    if (!success) memset(nib_out, 0, R4_RECOVER_NIB_LENGTH);
    memset(epid, 0, sizeof(epid));
    return success;
}
