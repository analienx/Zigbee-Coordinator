/* Independent bounded observer for the settled stock four-page NVOCMP v3.
 * A pending compaction/power loss, unreadable page, or changed format HOLDS.
 * It NEVER has NVS_write/NVS_erase/compaction or Zigbee/RF entry points.
 * This does not prove TI native parser compatibility or security semantics.
 */
#include "nv4_readonly_admission.h"
#include <stddef.h>

#define R4_DATA_START 16u
#define R4_TRAILER 7u
#define R4_MAX_READS 30000u
#define R4_MAX_RECORDS 2000u
#define R4_MAX_ACTIVE_IDENTITIES 512u

/* Pinned TI 3615ad5: NVOCMP_HDRLE=0, NVOCMP_FASTITEM=0. */
static uint32_t compressed_id(const uint8_t header[R4_TRAILER])
{
    uint32_t sysid = (header[0] >> 2u) & 0x3fu;
    uint32_t itemid = ((uint32_t)(header[0] & 3u) << 8u) | header[1];
    uint32_t subid = ((uint32_t)header[2] << 2u) | (header[3] >> 6u);
    return (sysid << 20u) | (itemid << 10u) | subid;
}

static int bounded_read(r4_nv4_read reader, void *ctx, r4_nv4_result *r,
                        uint32_t offset, uint8_t *to, uint32_t length)
{
    if (length == 0u || length > R4_NV4_REGION_SIZE ||
        offset > R4_NV4_REGION_SIZE - length ||
        r->reads >= R4_MAX_READS) {
        r->code = R4_NV4_SCAN_LIMIT;
        r->fault_offset = offset;
        return 0;
    }
    ++r->reads;
    if (reader(ctx, offset, to, length) != 0) {
        r->code = R4_NV4_READ_FAILURE;
        r->fault_offset = offset;
        return 0;
    }
    return 1;
}

static uint8_t crc8(uint8_t crc, const uint8_t *data, uint32_t length)
{
    uint32_t i;
    for (i = 0u; i < length; ++i) {
        unsigned bit;
        crc ^= data[i];
        for (bit = 0u; bit < 8u; ++bit) {
            crc = (uint8_t)((crc & 0x80u) ? (((uint32_t)crc << 1) ^ 0x97u)
                                         : ((uint32_t)crc << 1));
        }
    }
    return crc;
}

static int inspect_items(r4_nv4_read reader, void *ctx, r4_nv4_result *r,
                         uint32_t page_base, uint32_t end,
                         uint32_t *live_ids, uint32_t *live_count)
{
    uint8_t header[R4_TRAILER], block[64];
    while (end > R4_DATA_START) {
        uint32_t header_offset, length, offset;
        uint8_t crc = 0u, saved_crc, last;
        if (end < R4_DATA_START + R4_TRAILER ||
            r->records >= R4_MAX_RECORDS) {
            r->code = R4_NV4_BAD_ITEM;
            r->fault_offset = page_base + end;
            return 0;
        }
        header_offset = end - R4_TRAILER;
        if (!bounded_read(reader, ctx, r, page_base + header_offset,
                          header, sizeof(header))) return 0;
        length = ((uint32_t)(header[3] & 0x3fu) << 6) | (header[4] >> 2);
        if (header[6] != 0x96u || length == 0u ||
            length > header_offset - R4_DATA_START) {
            r->code = R4_NV4_BAD_ITEM;
            r->fault_offset = page_base + header_offset;
            return 0;
        }
        saved_crc = (uint8_t)(((header[4] & 3u) << 6) | (header[5] >> 2));
        for (offset = header_offset - length; offset < header_offset;) {
            uint32_t count = header_offset - offset;
            if (count > sizeof(block)) count = sizeof(block);
            if (!bounded_read(reader, ctx, r, page_base + offset,
                              block, count)) return 0;
            crc = crc8(crc, block, count);
            offset += count;
        }
        crc = crc8(crc, header, 4u);
        last = (uint8_t)(header[4] & 0xfcu);
        crc = crc8(crc, &last, 1u);
        if (crc != saved_crc) {
            r->code = R4_NV4_BAD_CRC;
            r->fault_offset = page_base + header_offset;
            return 0;
        }
        ++r->records;
        /* NVOCMP_VALIDIDBIT=1 marks corruption. Refuse before TI's
         * parser can attempt write-backed recovery of this record. */
        if (header[5] & 1u) {
            r->code = R4_NV4_INVALID_STATUS;
            r->fault_offset = page_base + header_offset + 5u;
            return 0;
        }
        if ((header[5] & 3u) == 2u) {
            uint32_t identity = compressed_id(header), i;
            if (*live_count >= R4_MAX_ACTIVE_IDENTITIES) {
                r->code = R4_NV4_SCAN_LIMIT;
                r->fault_offset = page_base + header_offset;
                return 0;
            }
            for (i = 0u; i < *live_count; ++i) {
                if (live_ids[i] == identity) {
                    r->code = R4_NV4_DUPLICATE_ACTIVE_ID;
                    r->fault_offset = page_base + header_offset;
                    return 0;
                }
            }
            live_ids[(*live_count)++] = identity;
            ++r->active_records;
        }
        end = header_offset - length;
    }
    return 1;
}

r4_nv4_result r4_nv4_admit(r4_nv4_read reader, void *ctx)
{
    r4_nv4_result r = {R4_NV4_BAD_READER, 0u, 0u, 0u, 0u};
    uint32_t page, active = 0u, full = 0u, destination = 0u;
    uint32_t live_count = 0u;
    /* Pre-init bounded scratch: do not consume half the 4 KiB C/IRQ stack.
     * Admission is a single-threaded boot preflight, not a runtime service. */
    static uint32_t live_ids[R4_MAX_ACTIVE_IDENTITIES];
    if (reader == NULL) return r;
    for (page = 0u; page < R4_NV4_PAGES; ++page) {
        uint8_t header[16], block[64];
        uint32_t base = page * R4_NV4_PAGE_SIZE, end = R4_DATA_START;
        uint32_t off;
        uint16_t logical;
        uint8_t mode;
        if (!bounded_read(reader, ctx, &r, base, header, sizeof(header))) return r;
        if (header[3] != 0x96u || header[7] != 0x96u ||
            header[11] != 0x96u || header[15] != 0x96u ||
            (header[2] >> 2) != 3u ||
            header[1] == 0u || header[1] == 0xffu) {
            r.code = R4_NV4_BAD_PAGE_HEADER;
            r.fault_offset = base;
            return r;
        }
        /* NVOCMP_scanPage uses THIS.pageOffset if cleanPage committed it.
         * Retired bytes beyond that end do not belong to the logical store. */
        logical = (uint16_t)((uint16_t)header[4] |
                             ((uint16_t)header[5] << 8u));
        mode = header[6];
        if ((logical != 0xffffu &&
             (logical < R4_DATA_START || logical > R4_NV4_PAGE_SIZE)) ||
            (mode != 0xffu && mode != 0xfcu) ||
            (mode == 0xffu &&
             (header[8] != 0xffu || header[9] != 0xffu ||
              header[10] != 0xffu || header[12] != 0xffu ||
              header[13] != 0xffu || header[14] != 0xffu)) ||
            (mode == 0xfcu &&
             ((uint16_t)(header[8] | ((uint16_t)header[9] << 8u)) < R4_DATA_START ||
              (uint16_t)(header[8] | ((uint16_t)header[9] << 8u)) > R4_NV4_PAGE_SIZE ||
              ((uint16_t)(header[12] | ((uint16_t)header[13] << 8u)) < R4_DATA_START) ||
              ((uint16_t)(header[12] | ((uint16_t)header[13] << 8u)) > R4_NV4_PAGE_SIZE) ||
              header[10] >= R4_NV4_PAGES || header[14] >= R4_NV4_PAGES))) {
            r.code = R4_NV4_UNSAFE_PAGE_STATES;
            r.fault_offset = base + 4u;
            return r;
        }
        switch (header[0]) {
        case 0x7cu: ++active; break;
        case 0x78u: ++full; break;
        case 0xfeu: ++destination; break;
        default:
            r.code = R4_NV4_UNSAFE_PAGE_STATES;
            r.fault_offset = base;
            return r;
        }
        for (off = R4_DATA_START; off < R4_NV4_PAGE_SIZE; off += sizeof(block)) {
            uint32_t i, count = R4_NV4_PAGE_SIZE - off;
            if (count > sizeof(block)) count = sizeof(block);
            if (!bounded_read(reader, ctx, &r, base + off,
                              block, count)) return r;
            for (i = 0u; i < count; ++i) {
                if (block[i] != 0xffu) end = off + i + 1u;
            }
        }
        if (header[0] != 0xfeu && logical != 0xffffu) {
            end = logical;
        }
        if (header[0] == 0xfeu) {
            if (end != R4_DATA_START || logical != 0xffffu ||
                mode != 0xffu) {
                r.code = R4_NV4_UNSAFE_PAGE_STATES;
                r.fault_offset = base + end;
                return r;
            }
        } else if (!inspect_items(reader, ctx, &r, base, end,
                                  live_ids, &live_count)) return r;
    }
    if (active != 1u || full != 2u || destination != 1u || r.active_records == 0u) {
        r.code = R4_NV4_UNSAFE_PAGE_STATES;
        return r;
    }
    r.code = R4_NV4_READONLY_STRUCTURE_ACCEPTED;
    return r;
}
