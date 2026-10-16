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
    nv[p+20] = 0x12u; /* synthetic data, not a key */
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
    assert(rd_count - before_reads <= (B1_NV2_REGION_SIZE / 32u));
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
