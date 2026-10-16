/* Read-only admission for pinned TI SDK 8.33 NVOCMP version 3, HDRLE=0.
 * This proves a bounded, internally consistent two-page candidate only.
 * Keys, NIB, counter continuity and physical flash behavior need other gates.
 * Item packing/CRC comes from NVOCMP_writeItem/readHeader/verifyCRC. */
#include "b1_admission.h"
#ifdef B1_MANAGEMENT_ENABLED
#include "b1_management.h"
#endif

static volatile uint32_t b1_nv_runtime_held;
static volatile uint32_t b1_nv_existing_pair;

int b1_nv_existing_header_candidate(void)
{
    return b1_nv_existing_pair != 0u;
}

void b1_nv_runtime_hold_latch(void)
{
    b1_nv_runtime_held = 1u;
#ifdef B1_MANAGEMENT_ENABLED
    b1_management_hold_nv(B1_ERROR_NV_BACKEND);
#endif
}

int b1_nv_runtime_hold_active(void)
{
#ifdef B1_MANAGEMENT_ENABLED
    return b1_nv_runtime_held != 0u || b1_management_get_hold_active();
#else
    return b1_nv_runtime_held != 0u;
#endif
}

static int b1_nv2_read(b1_nv_read_fn reader, void *ctx,
                       b1_nv_probe_result *result, uint32_t offset,
                       uint8_t *dst, uint32_t length)
{
    if (length > B1_NV2_REGION_SIZE ||
        offset > B1_NV2_REGION_SIZE - length ||
        result->reads >= B1_NV2_MAX_READS) {
        result->code = B1_NV_HOLD_SCAN_LIMIT;
        result->first_fault_offset = offset;
        return 0;
    }
    ++result->reads;
    if (reader(ctx, offset, dst, length) != 0) {
        result->code = B1_NV_HOLD_READ_FAILED;
        result->first_fault_offset = offset;
        return 0;
    }
    return 1;
}

/* Same non-reflected CRC-8 polynomial (0x97), initial 0, as TI crc.c.
 * Host tests also check fixtures against TI's real crc_update body. */
static uint8_t b1_nv2_crc(uint8_t crc, const uint8_t *data, uint32_t length)
{
    uint32_t i;
    for (i = 0; i < length; ++i) {
        uint8_t bit;
        crc ^= data[i];
        for (bit = 0; bit < 8u; ++bit) {
            crc = (uint8_t)((crc & 0x80u) != 0u
                ? ((uint32_t)crc << 1) ^ 0x97u : (uint32_t)crc << 1);
        }
    }
    return crc;
}

static int b1_nv2_known_header(const uint8_t h[16])
{
    const uint8_t all_active = (uint8_t)(h[2] & 3u);
    if (h[3] != 0x96u || (h[2] >> 2) != 3u ||
        h[1] == 0u || h[1] == 0xFFu ||
        (all_active != 0u && all_active != 3u)) return 0;
    switch (h[0]) {
    case 0xFFu: case 0xFEu: case 0x7Eu:
    case 0x7Cu: case 0x78u: case 0x70u:
        return 1;
    default:
        return 0;
    }
}

/* Every formatted donor page has three four-byte compaction headers.
 * Admit normal/completed modes, never pending source/destination repair.
 * NV2 ignores completed offsets on normal resume; references must still name
 * an NV2 page/boundary or the erased sentinel. */
static int b1_nv2_compaction_headers(const uint8_t h[16], int destination)
{
    uint32_t i;
    for (i = 4u; i < 16u; i += 4u) {
        const uint32_t offset = (uint32_t)h[i] | ((uint32_t)h[i + 1u] << 8);
        const uint8_t page = h[i + 2u];
        if (h[i + 3u] != 0x96u) return 0;
        if (i == 4u) {
            if (page != 0xFFu && (!destination && page != 0xFCu)) return 0;
        } else if (page != 0xFFu && page >= B1_NV2_PAGE_COUNT) return 0;
        if (offset != 0xFFFFu &&
            (offset < B1_NV2_DATA_OFFSET || offset > B1_NV2_PAGE_SIZE)) return 0;
        if (destination && (page != 0xFFu || offset != 0xFFFFu)) return 0;
    }
    return 1;
}

static int b1_nv2_items(b1_nv_read_fn reader, void *ctx,
                        b1_nv_probe_result *result, uint32_t page,
                        uint32_t end)
{
    uint8_t header[B1_NV2_ITEM_HEADER_SIZE];
    uint8_t chunk[32];
    const uint32_t base = page * B1_NV2_PAGE_SIZE;
    uint32_t remaining = (B1_NV2_PAGE_SIZE - B1_NV2_DATA_OFFSET) /
                         B1_NV2_ITEM_HEADER_SIZE;
    while (end > B1_NV2_DATA_OFFSET) {
        uint32_t header_offset, length, start, offset;
        uint8_t crc = 0u, saved_crc, final_byte;
        if (remaining-- == 0u || end < B1_NV2_DATA_OFFSET + sizeof(header)) {
            result->code = B1_NV_HOLD_ITEM_HEADER;
            result->first_fault_offset = base + end;
            return 0;
        }
        header_offset = end - (uint32_t)sizeof(header);
        if (!b1_nv2_read(reader, ctx, result, base + header_offset,
                         header, (uint32_t)sizeof(header))) return 0;
        /* Pinned HDRLE=0, valid bit0=0; active bit1 may be zero for an
         * obsolete row. CRC omits both status bits. */
        length = ((uint32_t)(header[3] & 0x3Fu) << 6) |
                 ((uint32_t)header[4] >> 2);
        if (header[6] != 0x96u || (header[5] & 1u) != 0u ||
            length == 0u || length > header_offset - B1_NV2_DATA_OFFSET) {
            result->code = B1_NV_HOLD_ITEM_HEADER;
            result->first_fault_offset = base + header_offset;
            return 0;
        }
        start = header_offset - length;
        saved_crc = (uint8_t)(((header[4] & 3u) << 6) | (header[5] >> 2));
        for (offset = start; offset < header_offset;) {
            const uint32_t size = header_offset - offset > sizeof(chunk)
                ? (uint32_t)sizeof(chunk) : header_offset - offset;
            if (!b1_nv2_read(reader, ctx, result, base + offset,
                             chunk, size)) return 0;
            crc = b1_nv2_crc(crc, chunk, size);
            offset += size;
        }
        crc = b1_nv2_crc(crc, header, 4u);
        final_byte = (uint8_t)(header[4] & 0xFCu);
        crc = b1_nv2_crc(crc, &final_byte, 1u);
        if (crc != saved_crc) {
            result->code = B1_NV_HOLD_ITEM_CRC;
            result->first_fault_offset = base + header_offset;
            return 0;
        }
        end = start; /* strictly decreases; never hunts for a signature */
    }
    return 1;
}

b1_nv_probe_result b1_nv_probe(b1_nv_read_fn reader, void *ctx,
                               bool factory_new_authorized)
{
    b1_nv_probe_result result = {B1_NV_HOLD_NO_READER, 0, 0, 0, 0};
    uint8_t chunk[32];
    uint8_t headers[B1_NV2_PAGE_COUNT][16];
    uint32_t ends[B1_NV2_PAGE_COUNT] = {0u, 0u};
    uint32_t page;
    /* Failed revalidation must never retain an earlier candidate grant. */
    b1_nv_existing_pair = 0u;
    if (reader == NULL) return result;
    for (page = 0; page < B1_NV2_PAGE_COUNT; ++page) {
        uint32_t offset;
        int all_ff = 1;
        for (offset = 0; offset < B1_NV2_PAGE_SIZE; offset += sizeof(chunk)) {
            uint32_t i;
            if (!b1_nv2_read(reader, ctx, &result,
                page * B1_NV2_PAGE_SIZE + offset, chunk, sizeof(chunk))) return result;
            if (offset == 0u) {
                for (i = 0u; i < 16u; ++i) headers[page][i] = chunk[i];
            }
            for (i = 0; i < sizeof(chunk); ++i) {
                if (chunk[i] != 0xFFu) {
                    all_ff = 0;
                    if (offset + i >= B1_NV2_DATA_OFFSET) ends[page] = offset + i + 1u;
                }
            }
        }
        if (all_ff) ++result.blank_pages;
        else if (b1_nv2_known_header(headers[page])) ++result.candidate_pages;
        else {
            result.code = B1_NV_HOLD_UNKNOWN_LAYOUT;
            result.first_fault_offset = page * B1_NV2_PAGE_SIZE;
            return result;
        }
    }
    if (result.blank_pages == B1_NV2_PAGE_COUNT) {
        result.code = factory_new_authorized ? B1_NV_FACTORY_AUTHORIZED
            : B1_NV_HOLD_FACTORY_NOT_AUTHORIZED;
    } else if (result.candidate_pages == B1_NV2_PAGE_COUNT) {
        const int active0 = headers[0][0] == 0x7Cu || headers[0][0] == 0x78u;
        const int active1 = headers[1][0] == 0x7Cu || headers[1][0] == 0x78u;
        const int dest0 = headers[0][0] == 0xFEu;
        const int dest1 = headers[1][0] == 0xFEu;
        if (!((active0 && dest1) || (active1 && dest0))) {
            result.code = B1_NV_HOLD_MIXED_LAYOUT;
            return result;
        }
        for (page = 0u; page < B1_NV2_PAGE_COUNT; ++page) {
            const int destination = headers[page][0] == 0xFEu;
            if (!b1_nv2_compaction_headers(headers[page], destination) ||
                (destination && ends[page] != 0u)) {
                result.code = B1_NV_HOLD_COMPACTION_HEADER;
                result.first_fault_offset = page * B1_NV2_PAGE_SIZE + 4u;
                return result;
            }
            if (!destination && ends[page] != 0u &&
                !b1_nv2_items(reader, ctx, &result, page, ends[page])) return result;
        }
        result.code = B1_NV2_HEADER_CANDIDATE;
        b1_nv_existing_pair = 1u;
    } else {
        result.code = B1_NV_HOLD_MIXED_LAYOUT;
    }
    return result;
}
