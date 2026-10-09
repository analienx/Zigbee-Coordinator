#ifndef T832_R6_NV_PROBE_H
#define T832_R6_NV_PROBE_H
#include <stdint.h>
/* T832 R11-DIAG NV first-fault observer. Fixed public metadata only.
 * Never contains item values, payloads or keys: only numeric API, system,
 * item, sub identifiers, lengths, statuses, sites and phases.
 *
 * Status domains (M0b): the inner NVOCMP_compact result lives in the
 * NVOCMP_compactStatus_t domain (SUCCESS=0, SRCDONE=1, DSTDONE=2,
 * BOTHDOE=3, FAILURE=0x10; TI's own failure test is
 * `status == NVOCMP_COMPACT_FAILURE`, nvocmp.c:4145/:4319). Values 1/2/3
 * are successful progress, never a storage fault. Completed NV API
 * results live in the NVINTF domain (nvintf.h:107-122). The two domains
 * are preserved distinctly; the latch records which domain each status
 * belongs to. Historical NV_FAULT(a8,b1,c27) is therefore AMBIGUOUS
 * (healthy drained compaction vs genuine item-write failure vs API
 * failure) and must never be claimed as storage-failure proof.
 *
 * Prelock exits (parameter validation, checkItem, voltage/FLASHACCESS
 * before NVOCMP_LOCK) return before any capture site and are explicitly
 * unobservable: no POD field ever claims them.
 *
 * Operation-aware sticky context (F2): the first meaningful failure per
 * boot is immutable; later failures cannot overwrite it. Automatic
 * (get-destination) compaction inherits its caller's API/item context:
 * inner compact captures never overwrite api/item, only stage counters.
 * INIT captures serialized POD only.
 */

/* NV API classes observed (explicit COMPACT = compactNvApi; automatic
 * compaction inherits the caller, never reports its own class). */
#define T832R6NV_API_UNKNOWN 0u
#define T832R6NV_API_INIT    1u
#define T832R6NV_API_CREATE  2u
#define T832R6NV_API_UPDATE  3u
#define T832R6NV_API_WRITE   4u
#define T832R6NV_API_DELETE  5u
#define T832R6NV_API_COMPACT 6u

/* NV capture sites. */
#define T832R6NV_SITE_UNKNOWN      0u
#define T832R6NV_SITE_COMPACT_INNER 1u
#define T832R6NV_SITE_ADD_INNER    2u
#define T832R6NV_SITE_API_BOUNDARY 3u
#define T832R6NV_SITE_INIT_ACTION  4u

/* Status domains for phase_domain high nibble. */
#define T832R6NV_DOMAIN_NVINTF  0u
#define T832R6NV_DOMAIN_COMPACT 1u
#define T832R6NV_DOMAIN_INIT    2u
#define T832R6NV_DOMAIN_UNKNOWN 15u
/* phase_domain packs 4-bit domain (high) + 4-bit stage phase (low).
 * The low nibble carries the capture stage number (1,2,3,5,6,7,8). */

/* known_flags bits: which First/Current fields carry observed values.
 * Bit7 is reserved and always 0. */
#define T832R6NV_KNOWN_API       0x01u
#define T832R6NV_KNOWN_ITEM      0x02u
#define T832R6NV_KNOWN_SITE      0x04u
#define T832R6NV_KNOWN_STATUS    0x08u
#define T832R6NV_KNOWN_REQUESTED 0x10u
#define T832R6NV_KNOWN_SYS       0x20u
#define T832R6NV_KNOWN_SUB       0x40u

/* First meaningful failure per boot. fault_id 0 means invalid (no failure
 * latched yet); the latch commits fault_id last from the current
 * generation counter. Exactly 16 bytes. */
typedef struct {
    uint32_t fault_id;
    uint16_t requested, item_id, sub_id;
    uint8_t api, system_id, site, status, phase_domain, known_flags;
} T832R6NvFirst;
/* Latest installed NV operation context. generation is a per-boot
 * monotonic capture counter. Exactly 12 bytes. */
typedef struct {
    uint32_t generation;
    uint16_t item_id, sub_id;
    uint8_t api, system_id, site, known_flags;
} T832R6NvCurrent;
typedef struct {
    uint32_t sequence, requests, compactions, compact_failures;
    uint16_t requested, status, stage, init_action;
    uint16_t pages, head, tail, active, active_offset, ready;
    T832R6NvFirst first;
    T832R6NvCurrent current;
    uint16_t offsets[NVOCMP_NVPAGES];
    uint8_t states[NVOCMP_NVPAGES];
    uint8_t rej_status, rej_page, rej_site, rej_raw;
} T832R6NvSnapshot;
extern volatile T832R6NvSnapshot t832R6Nv;
/* Legacy stage capture: preserves the installed api/item context (used by
 * compact-inner stages 1/2/3 and init-action stage 7, which inherit their
 * caller). */
void T832R6Nv_capture(uint16_t stage,uint16_t requested,uint16_t status);
/* Operation-aware capture: installs api/site/item context (used by
 * add-item stages 5/6 and completed-API stage 8, after NVOCMP_LOCK).
 * phase_domain packs domain+stage; known_flags marks observed fields. */
void T832R6Nv_captureCtx(uint16_t stage,uint8_t api,uint8_t site,
                         uint16_t item_id,uint16_t sub_id,uint8_t system_id,
                         uint16_t requested,uint16_t status,
                         uint8_t phase_domain,uint8_t known_flags);
#endif
