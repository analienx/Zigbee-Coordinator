/* R4-B1 native-source admission harness. Synthetic flash ONLY.
 * Build with -fsanitize=address,undefined -fno-omit-frame-pointer -Werror.
 * No Python implementation of admission; links production b1_admission.c.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "b1_admission.h"

static uint8_t nv[B1_NV2_REGION_SIZE];
static uint32_t rd_count;
static uint32_t write_count;
static uint32_t erase_count;
static uint32_t fail_at;
static uint32_t bad_geometry;
static uint32_t max_read_end;

static int_fast16_t sim_read(void *context, uint32_t offset, uint8_t *dst,
                             uint32_t length)
{
    (void)context;
    ++rd_count;
    if (offset + length < offset ||
        offset + length > sizeof(nv) || bad_geometry) return -1;
    if (fail_at == offset) return -5;
    memcpy(dst, nv + offset, length);
    if (offset + length > max_read_end) max_read_end = offset + length;
    return 0;
}

static void reset(void)
{
    memset(nv, 0xFF, sizeof(nv));
    rd_count = write_count = erase_count = bad_geometry = max_read_end = 0;
    fail_at = UINT32_MAX;
}

static void set_header(uint32_t page, uint8_t state)
{
    const uint32_t p = page * B1_NV2_PAGE_SIZE;
    nv[p] = state;
    nv[p+1] = 1u + (uint8_t)page;
    nv[p+2] = 0x0Fu; /* version 3 (6 bits), allActive 3 (2 bits) */
    nv[p+3] = 0x96u;
    nv[p+7] = nv[p+11] = nv[p+15] = 0x96u;
}

/* Independently packed NVOCMP_HDRLE=0 fixture. The backend source harness
 * additionally verifies this against the pinned donor CRC implementation. */
static uint8_t fixture_crc(const uint8_t *data, uint32_t length)
{
    uint16_t crc = 0u;
    uint32_t i;
    for (i = 0u; i < length; ++i) {
        uint8_t bit;
        crc ^= data[i];
        for (bit = 0u; bit < 8u; ++bit) {
            crc <<= 1;
            if (crc > 255u) crc ^= 0x197u;
        }
    }
    return (uint8_t)crc;
}

static uint32_t item(uint32_t page, uint32_t start, uint16_t id,
                     uint16_t length, int active)
{
    uint32_t i;
    uint8_t *p = nv + page * B1_NV2_PAGE_SIZE + start;
    uint8_t *h = p + length;
    uint8_t crc;
    assert(length != 0u && length <= 4095u);
    assert(start + length + 7u <= B1_NV2_PAGE_SIZE);
    for (i = 0u; i < length; ++i) p[i] = (uint8_t)(i * 19u + id);
    h[0] = (uint8_t)((1u << 2) | ((id >> 8) & 3u));
    h[1] = (uint8_t)id;
    h[2] = 0u;
    h[3] = (uint8_t)((length >> 6) & 0x3Fu);
    h[4] = (uint8_t)((length & 0x3Fu) << 2);
    crc = fixture_crc(p, length + 5u);
    h[4] |= (uint8_t)(crc >> 6);
    h[5] = (uint8_t)((uint32_t)(crc & 0x3Fu) << 2) | (active ? 2u : 0u);
    h[6] = 0x96u;
    return start + length + 7u;
}

static void verify_silent(void)
{
    assert(write_count == 0u);
    assert(erase_count == 0u);
    assert(max_read_end <= sizeof(nv));
    /* rd_count is cumulative within a fixture; bound each probe below. */
}

static b1_nv_probe_result probe(int factory_approved)
{
    return b1_nv_probe(sim_read, NULL, factory_approved != 0);
}

static void check(uint32_t index, b1_nv_probe_code expected, int approved)
{
    uint32_t before_reads = rd_count;
    b1_nv_probe_result r = probe(approved);
    if (r.code != expected) {
        fprintf(stderr, "case %u: got %d expected %d\n",
                index, (int)r.code, (int)expected);
        assert(r.code == expected);
    }
    assert(rd_count - before_reads <= B1_NV2_MAX_READS);
    verify_silent();
}

int main(void)
{
    b1_nv_probe_result r;
    reset();
    /* N01: blank device is NOT permission to initialize silently */
    check(1u, B1_NV_HOLD_FACTORY_NOT_AUTHORIZED, 0);
    assert(rd_count == 512u);
    /* N19 positive: explicit test-only factory authorization */
    check(19u, B1_NV_FACTORY_AUTHORIZED, 1);

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    /* N02 partial: structurally recognizable; NOT security validation */
    check(2u, B1_NV2_HEADER_CANDIDATE, 0);
    assert(rd_count == 512u);

    /* N02 real packed positive, including obsolete row and full-length row. */
    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    nv[2] &= 0xFCu; /* donor marks page as having inactive rows */
    {
        uint32_t end = item(0u, 16u, 1u, 1u, 0);
        end = item(0u, end, 2u, 4095u, 1);
        (void)item(0u, end, 3u, 63u, 1);
    }
    check(201u, B1_NV2_HEADER_CANDIDATE, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    (void)item(0u, 16u, 1u, 8u, 1);
    nv[16u] ^= 1u; /* intact header but corrupted value reaches CRC gate */
    check(901u, B1_NV_HOLD_ITEM_CRC, 0);
    assert(!b1_nv_existing_header_candidate());

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    (void)item(0u, 16u, 1u, 8u, 1);
    nv[30u] = 0u; /* exact header signature offset */
    check(902u, B1_NV_HOLD_ITEM_HEADER, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    (void)item(0u, 16u, 1u, 8u, 1);
    nv[27u] |= 0x3Fu; /* declared length exceeds data prefix */
    check(1101u, B1_NV_HOLD_ITEM_HEADER, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    (void)item(0u, 16u, 1u, 8u, 1);
    nv[29u] |= 1u; /* donor invalid-row flag */
    check(1102u, B1_NV_HOLD_ITEM_HEADER, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    (void)item(0u, 17u, 1u, 8u, 1); /* gap before oldest row */
    check(1103u, B1_NV_HOLD_ITEM_HEADER, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    nv[6u] = 0xFEu; /* interrupted compaction mode */
    check(1001u, B1_NV_HOLD_COMPACTION_HEADER, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    nv[B1_NV2_PAGE_SIZE + 100u] = 0u; /* populated destination never erased */
    check(1002u, B1_NV_HOLD_COMPACTION_HEADER, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    nv[6u] = 0xFCu; /* completed-compaction mode positive */
    (void)item(0u, 16u, 1u, 31u, 1);
    check(202u, B1_NV2_HEADER_CANDIDATE, 0);

    /* N29 synthetic roster, bounded rows; no RF/device capacity claim. */
    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    {
        uint32_t end = 16u, i;
        for (i = 1u; i <= 128u; ++i) end = item(0u, end, (uint16_t)i, 32u, 1);
    }
    check(2901u, B1_NV2_HEADER_CANDIDATE, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    (void)item(0u, 16u, 1u, 8u, 1);
    fail_at = 24u; /* initial linear read passes; item-header read fails */
    check(1104u, B1_NV_HOLD_READ_FAILED, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0xFEu);
    (void)item(0u, 16u, 1u, 8u, 1);
    fail_at = 16u; /* fail specifically in item CRC payload read */
    check(1105u, B1_NV_HOLD_READ_FAILED, 0);

    reset(); set_header(0, 0x78u); set_header(1, 0xFEu);
    check(27u, B1_NV2_HEADER_CANDIDATE, 0); /* FULL + XDST */

    reset(); set_header(0, 0xFEu); set_header(1, 0x7Cu);
    check(28u, B1_NV2_HEADER_CANDIDATE, 0); /* reverse page roles */

    reset(); set_header(0, 0x7Cu); set_header(1, 0x7Eu);
    check(29u, B1_NV_HOLD_MIXED_LAYOUT, 0); /* donor would erase RDY */

    reset(); set_header(0, 0x7Cu); set_header(1, 0x7Cu);
    check(30u, B1_NV_HOLD_MIXED_LAYOUT, 0); /* ambiguous two actives */

    reset(); set_header(0, 0x70u); set_header(1, 0xFEu);
    check(31u, B1_NV_HOLD_MIXED_LAYOUT, 0); /* interrupted compaction */

    reset(); set_header(0, 0xFEu); set_header(1, 0xFEu);
    check(32u, B1_NV_HOLD_MIXED_LAYOUT, 0); /* ambiguous two destinations */

    reset(); set_header(0, 0x7Cu);
    /* N10: mixed blank/formatted: no unsafe implicit compaction */
    check(10u, B1_NV_HOLD_MIXED_LAYOUT, 0);

    reset(); nv[5000] = 0x00; /* blank first header but populated body */
    check(9u, B1_NV_HOLD_UNKNOWN_LAYOUT, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0x7Cu);
    nv[B1_NV2_PAGE_SIZE + 3u] = 0x00; /* bad signature */
    check(20u, B1_NV_HOLD_UNKNOWN_LAYOUT, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0x7Cu);
    nv[2] = 0x13u; /* format version 4 not NVOCMP 3 */
    check(21u, B1_NV_HOLD_UNKNOWN_LAYOUT, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0x7Cu);
    nv[1] = 0xFFu; /* invalid cycle */
    check(22u, B1_NV_HOLD_UNKNOWN_LAYOUT, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0x7Cu);
    nv[0] = 0x22u; /* unknown page state */
    check(23u, B1_NV_HOLD_UNKNOWN_LAYOUT, 0);

    reset(); set_header(0, 0x7Cu); set_header(1, 0x7Cu);
    fail_at = 320u; /* N05 backend read error, NOT all-FF */
    r = probe(0);
    assert(r.code == B1_NV_HOLD_READ_FAILED);
    assert(r.first_fault_offset == 320u);
    verify_silent();

    reset(); fail_at = 0u;
    check(24u, B1_NV_HOLD_READ_FAILED, 0);
    assert(rd_count == 1u);

    reset(); fail_at = B1_NV2_PAGE_SIZE;
    check(25u, B1_NV_HOLD_READ_FAILED, 1); /* permission never masks I/O error */

    reset(); bad_geometry = 1;
    check(3u, B1_NV_HOLD_READ_FAILED, 0);
    assert(rd_count == 1u);

    reset();
    r = b1_nv_probe(NULL, NULL, false);
    assert(r.code == B1_NV_HOLD_NO_READER);
    assert(rd_count == 0u);
    verify_silent();

    /* Linked sticky NV fault latch (host C control, not a MAC RF proof). */
    assert(b1_nv_runtime_hold_active() == 0);
    b1_nv_runtime_hold_latch();
    assert(b1_nv_runtime_hold_active() == 1);
    b1_nv_runtime_hold_latch();
    assert(b1_nv_runtime_hold_active() == 1);
    puts("B1_NATIVE_ADMISSION_SYNTHETIC_PASS: bounded/zero-write; no RF, no stock NV assertion");
    return 0;
}
