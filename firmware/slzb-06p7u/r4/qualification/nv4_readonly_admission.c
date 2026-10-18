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
                         uint32_t page_base, uint32_t end)
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
        if ((header[5] & 3u) == 2u) ++r->active_records;
        end = header_offset - length;
    }
    return 1;
}

r4_nv4_result r4_nv4_admit(r4_nv4_read reader, void *ctx)
{
    r4_nv4_result r = {R4_NV4_BAD_READER, 0u, 0u, 0u, 0u};
    uint32_t page, active = 0u, full = 0u, destination = 0u;
    if (reader == NULL) return r;
    for (page = 0u; page < R4_NV4_PAGES; ++page) {
        uint8_t header[16], block[64];
        uint32_t base = page * R4_NV4_PAGE_SIZE, end = R4_DATA_START;
        uint32_t off;
        if (!bounded_read(reader, ctx, &r, base, header, sizeof(header))) return r;
        if (header[3] != 0x96u || header[7] != 0x96u ||
            header[11] != 0x96u || header[15] != 0x96u ||
            (header[2] >> 2) != 3u ||
            header[1] == 0u || header[1] == 0xffu) {
            r.code = R4_NV4_BAD_PAGE_HEADER;
            r.fault_offset = base;
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
        if (header[0] == 0xfeu) {
            if (end != R4_DATA_START) {
                r.code = R4_NV4_UNSAFE_PAGE_STATES;
                r.fault_offset = base + end;
                return r;
            }
        } else if (!inspect_items(reader, ctx, &r, base, end)) return r;
    }
    if (active != 1u || full != 2u || destination != 1u || r.active_records == 0u) {
        r.code = R4_NV4_UNSAFE_PAGE_STATES;
        return r;
    }
    r.code = R4_NV4_READONLY_STRUCTURE_ACCEPTED;
    return r;
}
