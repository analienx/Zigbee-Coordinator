/* HOST ONLY. Never link this file or generated trace code into radio firmware.
 * Stdin stays in RAM; stdout contains only source provenance, structural
 * metadata and counts. No record ID, payload, key, counter or capture path.
 */
#include "nv4_readonly_admission.h"
#include "oracle_build.h"
#include <stdio.h>
#include <string.h>

#define FULL_SIZE 0xB0000u
#define CURRENT_NV_BASE 0xA4000u
#define MAX_CALLS 30000u

extern r4_nv4_result r4_nv4_admit_traced(r4_nv4_read, void *);
extern unsigned r4_nv4_host_bridge_reason(r4_nv4_result);

typedef struct { uint32_t offset, length, status; } read_call;
typedef struct {
    const uint8_t *media;
    read_call calls[MAX_CALLS];
    uint32_t count;
    unsigned overflow;
} read_context;
typedef struct {
    const char *reason;
    unsigned line;
    uint32_t value[8];
} trace_event;

static uint8_t private_input[FULL_SIZE], frozen_nv[R4_NV4_REGION_SIZE];
static read_context original_reads, traced_reads;
static trace_event terminal, pages[R4_NV4_PAGES], ends[R4_NV4_PAGES];
static trace_event aggregate, markers;

void r4_nv4_host_trace_event(const char *reason, unsigned line,
                            uint32_t a, uint32_t b, uint32_t c, uint32_t d,
                            uint32_t e, uint32_t f, uint32_t g, uint32_t h)
{
    trace_event *event = &terminal;
    if (strcmp(reason, "page_header") == 0) {
        if (a >= R4_NV4_PAGES) return;
        event = &pages[a];
    } else if (strcmp(reason, "page_end") == 0) {
        if (a >= R4_NV4_PAGES) return;
        event = &ends[a];
    } else if (strcmp(reason, "aggregate") == 0) event = &aggregate;
    else if (strcmp(reason, "semantic_markers") == 0) event = &markers;
    event->reason = reason;
    event->line = line;
    event->value[0] = a; event->value[1] = b;
    event->value[2] = c; event->value[3] = d;
    event->value[4] = e; event->value[5] = f;
    event->value[6] = g; event->value[7] = h;
}

static int immutable_read(void *opaque, uint32_t offset,
                          uint8_t *to, uint32_t length)
{
    read_context *context = opaque;
    uint32_t bad = offset > R4_NV4_REGION_SIZE ||
                   length > R4_NV4_REGION_SIZE - offset;
    if (context->count >= MAX_CALLS) {
        context->overflow = 1u;
        return -1;
    }
    context->calls[context->count++] = (read_call){offset, length, bad};
    if (bad) return -1;
    memcpy(to, context->media + offset, length);
    return 0;
}

static int same_result(r4_nv4_result a, r4_nv4_result b)
{
    return a.code == b.code && a.reads == b.reads &&
           a.records == b.records && a.active_records == b.active_records &&
           a.fault_offset == b.fault_offset && a.semantic_state == b.semantic_state;
}

static int same_reads(void)
{
    uint32_t i;
    if (original_reads.overflow || traced_reads.overflow ||
        original_reads.count != traced_reads.count) return 0;
    for (i = 0u; i < original_reads.count; ++i) {
        read_call a = original_reads.calls[i], b = traced_reads.calls[i];
        if (a.offset != b.offset || a.length != b.length || a.status != b.status)
            return 0;
    }
    return 1;
}

static void clear_private_input(void)
{
    /* Volatile stores prevent optimization from discarding the final wipe. */
    volatile uint8_t *p = private_input;
    size_t i;
    for (i = 0u; i < sizeof(private_input); ++i) p[i] = 0u;
    p = frozen_nv;
    for (i = 0u; i < sizeof(frozen_nv); ++i) p[i] = 0u;
}

static int error(const char *reason, int status)
{
    clear_private_input();
    printf("{\"oracle_error\":\"%s\",\"flash_authorized\":false}\n", reason);
    return status;
}

int main(int argc, char **argv)
{
    size_t expected;
    const uint8_t *nv;
    r4_nv4_result original, traced;
    unsigned i, probe, has_fault;
    if (argc != 2) return error("explicit_stdin_mode_required", 2);
    if (strcmp(argv[1], "--stdin-full-a4000") == 0) {
        expected = FULL_SIZE;
        nv = private_input + CURRENT_NV_BASE;
    } else if (strcmp(argv[1], "--stdin-nv4-a4000") == 0) {
        expected = R4_NV4_REGION_SIZE;
        nv = private_input;
    } else return error("explicit_stdin_mode_required", 2);
    if (fread(private_input, 1u, expected, stdin) != expected || getchar() != EOF)
        return error("exact_input_length_required", 2);
    memcpy(frozen_nv, nv, sizeof(frozen_nv));
    original_reads.media = nv;
    traced_reads.media = nv;
    original = r4_nv4_admit(immutable_read, &original_reads);
    if (memcmp(nv, frozen_nv, sizeof(frozen_nv)) != 0)
        return error("original_input_mutated", 3);
    traced = r4_nv4_admit_traced(immutable_read, &traced_reads);
    if (!same_result(original, traced) || !same_reads() || terminal.reason == NULL ||
        memcmp(nv, frozen_nv, sizeof(frozen_nv)) != 0)
        return error("original_traced_parity_failed", 3);
    probe = r4_nv4_host_bridge_reason(original);
    has_fault = original.code != R4_NV4_READONLY_STRUCTURE_ACCEPTED &&
                strcmp(terminal.reason, "page_counts") != 0 &&
                strcmp(terminal.reason, "no_zstack_records") != 0 &&
                strcmp(terminal.reason, "no_reader") != 0;
    printf("{\"schema\":\"p7u-nv4-host-admission-trace-v1\","
           "\"oracle_source_sha\":\"%s\",\"source_compatible_live_firmware_sha\":\"%s\","
           "\"observer_c_sha256_normalized_lf\":\"%s\","
           "\"original_traced_result_equal\":true,\"read_sequence_equal\":true,"
           "\"code\":%u,\"semantic_state\":%u,\"bridge_probe\":%u,"
           "\"bridge_hold_nv_expected\":%s,\"reason\":\"%s\","
           "\"source_file\":\"nv4_readonly_admission.c\",\"line\":%u,"
           "\"fault_offset\":%u,\"page\":",
           ORACLE_SOURCE_SHA, ORACLE_LIVE_FIRMWARE_SHA, ORACLE_OBSERVER_SHA,
           (unsigned)original.code, (unsigned)original.semantic_state, probe,
           probe == 7u ? "false" : "true", terminal.reason, terminal.line,
           (unsigned)original.fault_offset);
    if (has_fault) printf("%u", (unsigned)(original.fault_offset / R4_NV4_PAGE_SIZE));
    else printf("null");
    printf(",\"page_offset\":");
    if (has_fault) printf("%u", (unsigned)(original.fault_offset % R4_NV4_PAGE_SIZE));
    else printf("null");
    printf(",\"records\":%u,\"active_records\":%u,\"reads\":%u,\"pages\":[",
           (unsigned)original.records, (unsigned)original.active_records,
           (unsigned)original.reads);
    for (i = 0u; i < R4_NV4_PAGES; ++i) {
        if (i != 0u) putchar(',');
        if (pages[i].reason == NULL) { printf("null"); continue; }
        printf("{\"index\":%u,\"state\":%u,\"logical_end\":%u,\"mode\":%u,"
               "\"erased_journal\":%u,\"completed_journal_valid\":%u,\"scan_end\":",
               i, (unsigned)pages[i].value[1], (unsigned)pages[i].value[2],
               (unsigned)pages[i].value[3], (unsigned)pages[i].value[4],
               (unsigned)pages[i].value[5]);
        if (ends[i].reason == NULL) printf("null");
        else printf("%u", (unsigned)ends[i].value[1]);
        putchar('}');
    }
    printf("],\"page_counts\":");
    if (aggregate.reason == NULL) printf("null");
    else printf("{\"active\":%u,\"full\":%u,\"destination\":%u,\"inactive\":%u,"
                "\"live_identities\":%u,\"zstack_active_records\":%u}",
                (unsigned)aggregate.value[0], (unsigned)aggregate.value[1],
                (unsigned)aggregate.value[2], (unsigned)aggregate.value[3],
                (unsigned)aggregate.value[4], (unsigned)aggregate.value[5]);
    printf(",\"markers\":");
    if (markers.reason == NULL) printf("null");
    else printf("{\"bdb_seen\":%u,\"bdb_class_zero_one_other\":%u,\"role_seen\":%u,"
                "\"role_is_coordinator\":%u,\"nib_seen\":%u,\"malformed\":%u}",
                (unsigned)markers.value[0], (unsigned)markers.value[1],
                (unsigned)markers.value[2], (unsigned)markers.value[3],
                (unsigned)markers.value[4], (unsigned)markers.value[5]);
    printf(",\"writes\":0,\"erases\":0,\"firmware_modified\":false,"
           "\"runtime_equivalence_proven\":false,\"native_ti_recovery_validated\":false,"
           "\"flash_authorized\":false}\n");
    clear_private_input();
    return 0; /* Oracle executed; admission outcome is in code/bridge_probe. */
}
