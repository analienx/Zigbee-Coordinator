/* R11-DIAG hosted test on the real sources (hosted CI only, never on HA).
 * Uses the REAL nv_r6_probe.inc behind stub TI driver globals, the REAL
 * recorder (t832_diag_host_test.c) with the R11 extension export, and the
 * REAL r11_startup.h inline captures. No mirrors. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
/* Stub TI NV driver surface exactly as nv_r6_probe.inc observes it. */
#define NVOCMP_NVPAGES 15
#define NVINTF_SUCCESS 0
#define NVINTF_FAILURE 1
#define NVINTF_BADPARAM 4
#define NVINTF_NOTFOUND 10
#define NVINTF_EXIST 13
#define NVINTF_SYSID_ZSTACK 1
#define NVOCMP_COMPACT_FAILURE 0x10
typedef struct { uint16_t offset; uint8_t state; } T832TestPage;
typedef struct {
    uint16_t nvSize, headPage, tailPage, actPage, actOffset;
    T832TestPage pageInfo[15];
} T832TestHandle;
static T832TestHandle NVOCMP_nvHandle;
static uint8_t NVOCMP_failF, NVOCMP_failW;
static struct { uint8_t status, page, site, raw; } t832R10Reject;
#include "nv_r6_probe.h"
#include "nv_r6_probe.inc"
#define T832Diag_uartTxFinished T832Diag_uartWriteComplete
#define main r11_recorder_main
#include "t832_diag_host_test.c"
#undef main
static void r11_fresh(void)
{
    fresh(9u);
    memset((void *)&t832R6Nv, 0, sizeof(t832R6Nv));
    memset((void *)&t832R11Startup, 0, sizeof(t832R11Startup));
    t832R11Startup.last_status = 0xFFFFu;
    t832R11Startup.dev_state = 0xFFu;
    t832R11Startup.nwk_state = 0xFFu;
    memset(&t832R11Ext, 0, sizeof(t832R11Ext));
    t832R11Ext.last_startup_hash = 0xFFFFFFFFu;
    memset(&NVOCMP_nvHandle, 0, sizeof(NVOCMP_nvHandle));
    NVOCMP_failF = 0u;
    NVOCMP_failW = 0u;
    memset(&t832R10Reject, 0, sizeof(t832R10Reject));
    NVOCMP_nvHandle.nvSize = 15;
}
static void test_f1_compact_domain(void)
{
    uint32_t f;
    r11_fresh();
    T832R6Nv_capture(3u, 27u, 0u);
    CHECK(t832R6Nv.first.fault_id == 0u);
    T832R6Nv_capture(3u, 27u, 1u);
    CHECK(t832R6Nv.first.fault_id == 0u);
    T832R6Nv_capture(3u, 27u, 2u);
    CHECK(t832R6Nv.first.fault_id == 0u);
    T832R6Nv_capture(3u, 27u, 3u);
    CHECK(t832R6Nv.first.fault_id == 0u);
    CHECK(t832R6Nv.compact_failures == 0u);
    T832R6Nv_capture(3u, 27u, 0x10u);
    CHECK(t832R6Nv.first.fault_id != 0u);
    CHECK(t832R6Nv.compact_failures == 1u);
    CHECK(t832R6Nv.first.status == 0x10u);
    CHECK(t832R6Nv.first.requested == 27u);
    CHECK(t832R6Nv.first.site == T832R6NV_SITE_COMPACT_INNER);
    /* Explicit compaction must not borrow the previous successful write item. */
    r11_fresh();
    T832R6Nv_captureCtx(8u, T832R6NV_API_WRITE, T832R6NV_SITE_API_BOUNDARY,
        9u, 2u, 1u, 27u, 0u, 8u, 0x7Fu);
    T832R6Nv_captureCtx(0u, T832R6NV_API_COMPACT, T832R6NV_SITE_UNKNOWN,
        0u, 0u, 0u, 100u, 0u, 0u,
        T832R6NV_KNOWN_API | T832R6NV_KNOWN_REQUESTED);
    T832R6Nv_capture(1u, 27u, 0u);
    T832R6Nv_capture(3u, 27u, 0x10u);
    CHECK(t832R6Nv.first.api == T832R6NV_API_COMPACT);
    CHECK(t832R6Nv.first.item_id == 0u && t832R6Nv.first.sub_id == 0u);
    CHECK((t832R6Nv.first.known_flags & (T832R6NV_KNOWN_ITEM |
        T832R6NV_KNOWN_SYS | T832R6NV_KNOWN_SUB)) == 0u);
    CHECK(t832R6Nv.first.requested == 27u);
    CHECK(t832R6Nv.first.phase_domain == ((T832R6NV_DOMAIN_COMPACT << 4) | 3u));
    f = t832R6Nv.first.fault_id;
    T832R6Nv_captureCtx(8u, T832R6NV_API_WRITE, T832R6NV_SITE_API_BOUNDARY,
                        9u, 9u, 1u, 20u, NVINTF_FAILURE,
                        (T832R6NV_DOMAIN_NVINTF << 4) | 8u, 0x7Fu);
    CHECK(t832R6Nv.first.fault_id == f);
    CHECK(t832R6Nv.first.status == 0x10u);
    puts("R11 F1 PASS: compact 0..3 benign, 0x10 faults, first immutable");
}
static void test_f2_pod(void)
{
    r11_fresh();
    CHECK(sizeof(T832R6NvFirst) == 16u);
    CHECK(sizeof(T832R6NvCurrent) == 12u);
    CHECK(sizeof(T832R6NvSnapshot) == 116u);
    CHECK(offsetof(T832R6NvFirst, fault_id) == 0u);
    CHECK(offsetof(T832R6NvFirst, requested) == 4u);
    CHECK(offsetof(T832R6NvFirst, item_id) == 6u);
    CHECK(offsetof(T832R6NvFirst, sub_id) == 8u);
    CHECK(offsetof(T832R6NvFirst, api) == 10u);
    CHECK(offsetof(T832R6NvFirst, system_id) == 11u);
    CHECK(offsetof(T832R6NvFirst, site) == 12u);
    CHECK(offsetof(T832R6NvFirst, status) == 13u);
    CHECK(offsetof(T832R6NvFirst, phase_domain) == 14u);
    CHECK(offsetof(T832R6NvFirst, known_flags) == 15u);
    CHECK(offsetof(T832R6NvCurrent, generation) == 0u);
    CHECK(offsetof(T832R6NvCurrent, item_id) == 4u);
    CHECK(offsetof(T832R6NvCurrent, sub_id) == 6u);
    CHECK(offsetof(T832R6NvCurrent, api) == 8u);
    CHECK(offsetof(T832R6NvCurrent, system_id) == 9u);
    CHECK(offsetof(T832R6NvCurrent, site) == 10u);
    CHECK(offsetof(T832R6NvCurrent, known_flags) == 11u);
    T832R6Nv_captureCtx(8u, T832R6NV_API_COMPACT, T832R6NV_SITE_API_BOUNDARY,
                        0u, 0u, 0u, 27u, NVINTF_BADPARAM,
                        (T832R6NV_DOMAIN_NVINTF << 4) | 8u,
                        T832R6NV_KNOWN_API | T832R6NV_KNOWN_SITE |
                        T832R6NV_KNOWN_STATUS | T832R6NV_KNOWN_REQUESTED);
    CHECK(t832R6Nv.first.fault_id == 0u);
    T832R6Nv_captureCtx(8u, T832R6NV_API_CREATE, T832R6NV_SITE_API_BOUNDARY,
                        4u, 0u, NVINTF_SYSID_ZSTACK, 20u, NVINTF_EXIST,
                        (T832R6NV_DOMAIN_NVINTF << 4) | 8u, 0x7Fu);
    CHECK(t832R6Nv.first.fault_id == 0u);
    T832R6Nv_captureCtx(8u, T832R6NV_API_DELETE, T832R6NV_SITE_API_BOUNDARY,
                        12u, 0u, NVINTF_SYSID_ZSTACK, 0u, NVINTF_NOTFOUND,
                        (T832R6NV_DOMAIN_NVINTF << 4) | 8u, 0x7Fu);
    CHECK(t832R6Nv.first.fault_id == 0u);
    T832R6Nv_captureCtx(6u, T832R6NV_API_WRITE, T832R6NV_SITE_ADD_INNER,
                        9u, 2u, NVINTF_SYSID_ZSTACK, 27u, NVINTF_FAILURE,
                        (T832R6NV_DOMAIN_NVINTF << 4) | 6u, 0x7Fu);
    CHECK(t832R6Nv.first.fault_id != 0u);
    CHECK(t832R6Nv.first.api == T832R6NV_API_WRITE);
    CHECK(t832R6Nv.first.item_id == 9u);
    CHECK(t832R6Nv.first.sub_id == 2u);
    CHECK(t832R6Nv.first.system_id == NVINTF_SYSID_ZSTACK);
    CHECK(t832R6Nv.first.status == NVINTF_FAILURE);
    CHECK((t832R6Nv.first.known_flags & 0x80u) == 0u);
    T832R6Nv_captureCtx(8u, T832R6NV_API_WRITE, T832R6NV_SITE_API_BOUNDARY,
                        9u, 2u, NVINTF_SYSID_ZSTACK, 27u, NVINTF_BADPARAM,
                        (T832R6NV_DOMAIN_NVINTF << 4) | 8u, 0x7Fu);
    CHECK(t832R6Nv.first.status == NVINTF_FAILURE);
    CHECK(t832R6Nv.current.site == T832R6NV_SITE_API_BOUNDARY);
    CHECK(t832R6Nv.status == NVINTF_BADPARAM);
    r11_fresh();
    T832R6Nv_captureCtx(5u, T832R6NV_API_CREATE, T832R6NV_SITE_ADD_INNER,
                        5u, 6u, NVINTF_SYSID_ZSTACK, 20u, 0u,
                        (T832R6NV_DOMAIN_NVINTF << 4) | 5u, 0x7Eu);
    T832R6Nv_capture(1u, 27u, 0u);
    T832R6Nv_capture(3u, 27u, 0x10u);
    CHECK(t832R6Nv.first.fault_id != 0u);
    CHECK(t832R6Nv.first.api == T832R6NV_API_CREATE);
    CHECK(t832R6Nv.first.item_id == 5u);
    CHECK(t832R6Nv.first.sub_id == 6u);
    CHECK(t832R6Nv.first.site == T832R6NV_SITE_COMPACT_INNER);
    puts("R11 F2 PASS: sticky 16B/12B context, benign exclusions, inheritance");
}
static void test_f3_startup(void)
{
    T832DiagRecord recs[4];
    uint32_t hash;
    r11_fresh();
    CHECK(t832R11Startup.last_status == 0xFFFFu);
    CHECK(t832R11Startup.dev_state == 0xFFu);
    T832R11_enter(1u);
    CHECK(t832R11Startup.generation == 1u);
    T832R11_exit(1u, 0u, 0xFFu, 0xFFu, T832R11_VALID_STATUS);
    T832R11_enter(2u);
    T832R11_exit(2u, 1u, 0xFFu, 0xFFu, T832R11_VALID_STATUS);
    T832R11_enter(3u);
    T832R11_exit(3u, 0u, 0xFFu, 0xFFu, T832R11_VALID_STATUS);
    T832R11_enter(4u);
    T832R11_nlme(1u);
    T832R11_exit(4u, 0u, 0xFFu, 0xFFu,
                 T832R11_VALID_STATUS | T832R11_VALID_NLME | T832R11_NLME_RESTORED);
    T832R11_enter(5u);
    CHECK(t832R11Startup.last_status == T832R11_STATUS_UNKNOWN);
    CHECK((t832R11Startup.valid & T832R11_VALID_STATUS) == 0u);
    T832R11_exit(5u, 0xFFFFu, 0xFFu, 0xFFu, 0u);
    T832R11_enter(6u);
    T832R11_exit(6u, 0xFFFFu, 0xFFu, 0xFFu, 0u);
    T832R11_confirm(0u);
    T832R11_enter(8u);
    T832R11_exit(8u, 0xFFFFu, 9u, 8u,
                 T832R11_VALID_DEV | T832R11_VALID_NWK);
    CHECK(t832R11Startup.entry_mask == 0xFFu);
    CHECK(t832R11Startup.exit_mask == 0xFFu);
    CHECK(t832R11Startup.last_site == 8u);
    CHECK(t832R11Startup.last_phase == T832R11_PHASE_EXIT);
    CHECK(t832R11Startup.dev_state == 9u);
    CHECK(t832R11Startup.nwk_state == 8u);
    CHECK(t832R11Startup.valid ==
          (T832R11_VALID_DEV | T832R11_VALID_NWK |
           T832R11_VALID_NLME | T832R11_NLME_RESTORED));
    r11_fresh();
    CHECK(T832R11_buildStartup(recs, &hash) == 0u);
    T832R11_enter(1u);
    /* A reached boundary with no return is evidence, even with unknown fields. */
    CHECK(T832R11_buildStartup(recs, &hash) == 1u);
    CHECK(recs[1].b == 1u && recs[1].c == 0u);
    CHECK(recs[3].c == 0u);
    t832R11Startup.sequence++;
    CHECK(T832R11_buildStartup(recs, &hash) == 0u);
    CHECK(host_cs_depth == 0);
    t832R11Startup.sequence++;
    T832R11_enter(5u);
    CHECK((t832R11Startup.exit_mask & (1u << 4)) == 0u);
    CHECK((t832Diag.capabilities & (1u << 30)) != 0u);
    puts("R11 F3 PASS: eight boundaries with masks and validity");
}
/* Minimal T832D2 frame check on host-captured MT payloads. */
static int frame_kind_part(const uint8_t *data, uint8_t len, uint8_t want,
                           uint8_t idx)
{
    uint8_t tmp[256];
    uint8_t bin[160];
    size_t hexlen;
    size_t blen;
    size_t i;
    uint8_t count;
    size_t off;
    (void)idx;
    if (len < 9u) return 0;
    if (memcmp(data + 1, "T832D2:", 7) != 0) return 0;
    memcpy(tmp, data + 8, len - 8u);
    tmp[len - 8u] = 0;
    hexlen = strlen((const char *)tmp);
    if (hexlen & 1u) return 0;
    blen = hexlen / 2u;
    for (i = 0; i < blen; i++) {
        unsigned v;
        if (sscanf((const char *)tmp + 2 * i, "%2x", &v) != 1) return 0;
        bin[i] = (uint8_t)v;
    }
    if (blen < 34u) return 0;
    if (memcmp(bin, "T8D1", 4) != 0 || bin[4] != 2u) return 0;
    count = bin[32];
    if (count != 4u) return 0;
    for (i = 0; i < 4u; i++) {
        size_t base = 33u + 20u * i;
        uint8_t kind = bin[base + 10u];
        uint16_t a = (uint16_t)(bin[base + 12u] | (bin[base + 13u] << 8));
        if (kind != want) return 0;
        if ((a & 0x3u) != i) return 0;
        if ((a >> 12) != 1u) return 0;
        if (a & 0x0800u) return 0;
    }
    off = 33u;
    (void)off;
    return 1;
}
static void r11_wire_complete_diag(void)
{
    T832Diag_npiTxDequeue(0xFEu, 0x48u, 0x80u, 234u);
    T832Diag_uartTxStart(234u);
    T832Diag_uartWriteComplete(234u);
    CHECK(t832Diag.diag_pending == 0u);
}
static void test_f4_groups(void)
{
    T832DiagRecord recs[4];
    uint8_t sat = 0u;
    uint8_t unk = 0u;
    r11_fresh();
    CHECK(T832R11_buildNv(recs) == 0u);
    t832R6Nv.sequence = 2u;
    CHECK(T832R11_buildNv(recs) == 0u);
    t832R6Nv.sequence = 3u;
    CHECK(T832R11_buildNv(recs) == 0u);
    r11_fresh();
    T832R6Nv_captureCtx(8u, T832R6NV_API_WRITE, T832R6NV_SITE_API_BOUNDARY,
                        0x0102u, 3u, 1u, 27u, NVINTF_FAILURE,
                        (T832R6NV_DOMAIN_NVINTF << 4) | 8u, 0x7Fu);
    CHECK(T832R11_buildNv(recs) == 1u);
    CHECK(recs[0].a == 0x1000u);
    CHECK(recs[1].a == 0x1001u && recs[1].b == 0x0102u && recs[1].c == 3u);
    CHECK(recs[2].b == 27u && recs[2].c == ((1u << 8) | 4u));
    CHECK(T832R11_delta16(21u, 0xFFFFFFF0u, &sat) == 37u && sat == 0u);
    sat = 0u;
    CHECK(T832R11_delta16(0xFFFFFFFFu, 0u, &sat) == 0xFFFEu && sat == 1u);
    unk = 0u;
    sat = 0u;
    CHECK(T832R11_age10(1000u, 0u, 0u, &unk, &sat) == 0xFFFFu && unk == 1u);
    unk = 0u;
    sat = 0u;
    CHECK(T832R11_age10(0xFFFFFFFFu, 0u, 1u, &unk, &sat) == 0xFFFEu &&
          unk == 0u && sat == 1u);
    /* Fairness reserve holds when nothing is overdue; overdue runtime
     * breaks through (liveness on legacy-idle). NV already exported and
     * startup unbuildable (generation 0) so only the streak gate decides. */
    t832R11Ext.ext_streak = 2u;
    t832R11Ext.last_nv_fault = t832R6Nv.first.fault_id;
    t832R11Ext.last_nv_ms = 100000u;
    t832R11Ext.last_startup_ms = 100000u;
    t832R11Ext.last_runtime_ms = 100000u;
    CHECK(T832R11Ext_tryExport(100000u, 100000u) == 0u);
    t832R11Ext.last_runtime_ms = 0u;
    CHECK(T832R11Ext_tryExport(100000u, 100000u) == 1u);
    t832R11Ext.ext_streak = 0u;
    t832Diag.sync_outstanding = 1u;
    t832Diag.transport_active = 1u;
    t832Diag.normal_pending = 3u;
    T832R11Ext_sample(2000u);
    CHECK((t832R11Ext.seen & (1u << 2)) != 0u);
    CHECK((t832R11Ext.seen & (1u << 3)) != 0u);
    CHECK((t832R11Ext.seen & (1u << 5)) != 0u);
    t832Diag.sync_outstanding = 0u;
    t832Diag.transport_active = 0u;
    t832Diag.normal_pending = 0u;
    puts("R11 F4 PASS: atomic packing, wrap, saturation, fairness reserve");
}
static void r11_scenario(void)
{
    r11_fresh();
    T832R11_enter(1u);
    T832R11_exit(1u, 0u, 0xFFu, 0xFFu, T832R11_VALID_STATUS);
    T832R11_enter(2u);
    T832R11_exit(2u, 1u, 0xFFu, 0xFFu, T832R11_VALID_STATUS);
    T832R11_enter(3u);
    T832R11_exit(3u, 0u, 0xFFu, 0xFFu, T832R11_VALID_STATUS);
    T832R11_enter(4u);
    T832R11_nlme(1u);
    T832R11_exit(4u, 0u, 0xFFu, 0xFFu,
                 T832R11_VALID_STATUS | T832R11_VALID_NLME | T832R11_NLME_RESTORED);
    T832R11_confirm(0u);
    T832R11_enter(8u);
    T832R11_exit(8u, 0xFFFFu, 9u, 8u,
                 T832R11_VALID_DEV | T832R11_VALID_NWK);
    T832R6Nv_captureCtx(8u, T832R6NV_API_WRITE, T832R6NV_SITE_API_BOUNDARY,
                        0x0102u, 3u, 1u, 27u, NVINTF_FAILURE,
                        (T832R6NV_DOMAIN_NVINTF << 4) | 8u, 0x7Fu);
    T832Diag_taskScheduled(9u, 0x03u);
    T832Diag_taskWork(1u, 0x8000u);
    T832Diag_npiTaskWake();
    T832Diag_uartRx(100u, 10u);
    advance_ms(6000u);
    T832Diag_exportPoll();
    CHECK(host_frame_count == 1u);
    CHECK(frame_kind_part(host_frame_data[0], host_frame_len[0], 51u, 0));
    r11_wire_complete_diag();
    advance_ms(6000u);
    T832Diag_exportPoll();
    CHECK(host_frame_count == 2u);
    CHECK(frame_kind_part(host_frame_data[1], host_frame_len[1], 52u, 1));
    r11_wire_complete_diag();
    advance_ms(30000u);
    T832Diag_exportPoll();
    CHECK(host_frame_count == 3u);
    CHECK(frame_kind_part(host_frame_data[2], host_frame_len[2], 53u, 2));
    r11_wire_complete_diag();
    host_fail_alloc = 1;
    advance_ms(60000u);
    {
        uint32_t lost_before = t832Diag.export_lost;
        uint32_t sched_before = t832R11Ext.base_sched;
        T832Diag_exportPoll();
        CHECK(host_frame_count == 3u);
        CHECK(t832Diag.export_lost == lost_before + 4u);
        CHECK(t832R11Ext.base_sched == sched_before);
        CHECK(t832Diag.last_export_ms == host_tick);
        T832Diag_exportPoll();
        CHECK(t832Diag.export_lost == lost_before + 4u);
        advance_ms(T832_DIAG_EXPORT_MIN_MS - 1u);
        T832Diag_exportPoll();
        CHECK(t832Diag.export_lost == lost_before + 4u);
        advance_ms(1u);
        host_fail_alloc = 1;
        T832Diag_exportPoll();
        CHECK(t832Diag.export_lost == lost_before + 8u);
    }
    host_fail_alloc = 0;
}
static void r11_dump(const char *path)
{
    FILE *fh;
    uint32_t i;
    uint32_t k;
    r11_scenario();
    if (failures) return;
    fh = fopen(path, "w");
    if (!fh) {
        printf("FAIL: cannot open dump path\n");
        failures++;
        return;
    }
    for (i = 0; i < host_frame_count; i++) {
        for (k = 0; k < host_frame_len[i]; k++) {
            fprintf(fh, "%02X", host_frame_data[i][k]);
        }
        fprintf(fh, "\n");
    }
    fclose(fh);
    printf("R11 DUMP-OK %u frames -> %s\n", (unsigned)host_frame_count, path);
}
int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "dump") == 0) {
        r11_dump(argv[2]);
        if (failures) {
            printf("R11 HARNESS RESULT: FAIL (%d)\n", failures);
            return 1;
        }
        return 0;
    }
    test_f1_compact_domain();
    test_f2_pod();
    test_f3_startup();
    test_f4_groups();
    r11_scenario();
    if (failures) {
        printf("R11 HARNESS RESULT: FAIL (%d)\n", failures);
        return 1;
    }
    puts("R11 HOST PASS: F1/F2/F3/F4 on real sources with atomic groups");
    return 0;
}
