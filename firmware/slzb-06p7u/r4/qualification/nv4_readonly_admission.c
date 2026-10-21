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
/* A physical NVOCMP record occupies at least one payload byte plus the
 * seven-byte item trailer. 4 NV pages reserve one full page for compaction,
 * so the physical data-page maximum, not an arbitrary lifetime-churn limit,
 * bounds legitimate records. A stale 2000-record scan ceiling could HOLD an
 * otherwise healthy retained network after repeated normal counter writes. */
#define R4_MAX_RECORDS (((R4_NV4_PAGES - 1u) * \
                         (R4_NV4_PAGE_SIZE - R4_DATA_START)) / \
                        (R4_TRAILER + 1u))
/* The restored 20260311 P7U capture has 779 active identities across 892
 * CRC-valid NVOCMP records. The active-identity index has a separate 1024
 * RAM safety cap; never silently conflate it with total journal records. */
#define R4_MAX_ACTIVE_IDENTITIES 1024u

/* Exact TI SDK 3615ad5: osal_nv.c maps legacy OSAL item IDs to
 * (NVINTF_SYSID_ZSTACK=1, ZCD_NV_EX_LEGACY=0, subID=original ID).
 * zcomdef.h: STARTUP_OPTION=0x03, NIB=0x21,
 * bdbNodeIsOnANetwork=0x55, logicalType=0x87.
 * These are the only Z-Stack payload values read for classification.
 * NIB/security/key contents are NEVER copied into semantic scratch. */
#define R4_ZSTACK_SYSID 1u
#define R4_OSAL_LEGACY_ITEMID 0u
#define R4_OSAL_STARTUP_OPTION 0x03u
/* Pinned zcomdef.h: CLEAR_CONFIG=0x01, CLEAR_STATE=0x02 and
 * CLEAR_NWK_FRAME_COUNTER=0x80. AUTO_START=0x04 does not clear NV. */
#define R4_DESTRUCTIVE_STARTUP_OPTIONS 0x83u
#define R4_OSAL_NIB 0x21u
#define R4_OSAL_BDB_ON_NETWORK 0x55u
#define R4_OSAL_LOGICAL_TYPE 0x87u

typedef struct {
    uint8_t bdb_seen, bdb_on_network;
    uint8_t role_seen, logical_type;
    uint8_t startup_seen, startup_options;
    uint8_t nib_seen, malformed;
} r4_nv4_markers;

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

static int erased_compaction_journal(const uint8_t header[16])
{
    return header[8] == 0xffu && header[9] == 0xffu &&
           header[10] == 0xffu && header[12] == 0xffu &&
           header[13] == 0xffu && header[14] == 0xffu;
}

static int valid_completed_journal(const uint8_t header[16], uint32_t page)
{
    uint16_t start = (uint16_t)(header[8] | ((uint16_t)header[9] << 8u));
    uint16_t end = (uint16_t)(header[12] | ((uint16_t)header[13] << 8u));
    uint32_t start_page = header[10], end_page = header[14];

    /* A retained completed journal is permitted on FC and F8 pages. TI
     * leaves historical journal bytes in FULL/ACTIVE pages when it marks
     * them PGCSRC=0xF8 before deciding to abort an all-active compaction. */
    if (start < R4_DATA_START || start > R4_NV4_PAGE_SIZE ||
        end < R4_DATA_START || end > R4_NV4_PAGE_SIZE ||
        start_page >= R4_NV4_PAGES || end_page >= R4_NV4_PAGES ||
        start_page == page || end_page == page) return 0;
    if ((end_page + R4_NV4_PAGES - start_page) % R4_NV4_PAGES >=
        (page + R4_NV4_PAGES - start_page) % R4_NV4_PAGES) return 0;
    if (start_page == end_page && end > start) return 0;
    return 1;
}

static int inspect_items(r4_nv4_read reader, void *ctx, r4_nv4_result *r,
                         uint32_t page_base, uint32_t end,
                         uint32_t *live_ids, uint32_t *live_count,
                         uint32_t *zstack_live_count,
                         r4_nv4_markers *markers)
{
    uint8_t header[R4_TRAILER], block[64];
    while (end > R4_DATA_START) {
        uint32_t header_offset, length, offset;
        uint8_t crc = 0u, saved_crc, last, first_payload_byte = 0xffu;
        if (r->records >= R4_MAX_RECORDS) {
            r->code = R4_NV4_SCAN_LIMIT;
            r->fault_offset = page_base + end;
            return 0;
        }
        if (end < R4_DATA_START + R4_TRAILER) {
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
            /* Capture only the first byte of this item in the *same* read
             * whose bytes are authenticated by the CRC. A second read of a
             * security-state marker after CRC would create a TOCTOU gap. */
            if (offset == header_offset - length)
                first_payload_byte = block[0];
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
            /* The fitted stock P7U's active records are Z-Stack sysid 1.
             * A CRC-valid unrelated NV namespace alone must not be used
             * to grant the B1 existing-network admission path. This still
             * does NOT prove BDB/NIB, key or counter semantics. */
            if ((header[0] >> 2u) == R4_ZSTACK_SYSID) {
                ++*zstack_live_count;
                if ((header[0] & 3u) == R4_OSAL_LEGACY_ITEMID &&
                    header[1] == 0u) {
                    uint32_t subid = ((uint32_t)header[2] << 2u) |
                                     (header[3] >> 6u);
                    if (subid == R4_OSAL_STARTUP_OPTION ||
                        subid == R4_OSAL_BDB_ON_NETWORK ||
                        subid == R4_OSAL_LOGICAL_TYPE) {
                        /* Use the verified payload byte, not an unverified
                         * second flash read after CRC validation. */
                        if (length != 1u) {
                            markers->malformed = 1u;
                        } else {
                            if (subid == R4_OSAL_STARTUP_OPTION) {
                                markers->startup_seen = 1u;
                                markers->startup_options = first_payload_byte;
                            } else if (subid == R4_OSAL_BDB_ON_NETWORK) {
                                markers->bdb_seen = 1u;
                                markers->bdb_on_network = first_payload_byte;
                            } else {
                                markers->role_seen = 1u;
                                markers->logical_type = first_payload_byte;
                            }
                        }
                    } else if (subid == R4_OSAL_NIB) {
                        /* Presence only; actual ABI and content are checked
                         * by the later compiled Z-Stack security precheck. */
                        markers->nib_seen = 1u;
                    }
                }
            }
        }
        end = header_offset - length;
    }
    return 1;
}

/* Preserve a distinct live ELF function for the exact-source NV4 role seal. */
__attribute__((noinline))
r4_nv4_result r4_nv4_admit(r4_nv4_read reader, void *ctx)
{
    r4_nv4_result r = {R4_NV4_BAD_READER, 0u, 0u, 0u, 0u,
                      R4_NV4_STATE_UNKNOWN_HOLD, 0u};
    uint32_t page, active = 0u, full = 0u, destination = 0u, inactive = 0u;
    uint32_t xsource = 0u, compact_dest = 0u;
    uint8_t inactive_page = 0xffu, completed_source_page = 0xffu;
    uint8_t completed_source_erased = 0u;
    uint8_t candidate_action = 0u; /* TI RECOVER_COMPACT=1, RECOVER_ERASE=2 */
    uint8_t partial_destination = 0u;
    uint32_t live_count = 0u, zstack_live_count = 0u;
    r4_nv4_markers markers = {0};
    /* Pre-init bounded scratch: do not consume half the 4 KiB C/IRQ stack.
     * Admission is a single-threaded boot preflight, not a runtime service. */
    static uint32_t live_ids[R4_MAX_ACTIVE_IDENTITIES];
    if (reader == NULL) return r;
    for (page = 0u; page < R4_NV4_PAGES; ++page) {
        uint8_t header[16], block[64];
        uint32_t base = page * R4_NV4_PAGE_SIZE, end = R4_DATA_START;
        uint32_t off;
        uint16_t logical;
        uint8_t mode, is_discarded_destination;
        if (!bounded_read(reader, ctx, &r, base, header, sizeof(header))) return r;
        /* Real TI NVOCMP_cleanPage can recycle the source to PGNACT=0xFF:
         * the *valid header* is reprogrammed, but data remain erased. It is
         * NOT an all-0xFF factory blank page. Unformatted erase, stale data
         * and torn page metadata still HOLD. */
        if (header[3] != 0x96u || header[7] != 0x96u ||
            header[11] != 0x96u || header[15] != 0x96u ||
            (header[2] >> 2) != 3u ||
            ((header[2] & 3u) != 0u && (header[2] & 3u) != 3u) ||
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
        /* TI >2-page NVOCMP first marks sources PGCSRC/PGXSRC, then
         * writes destination PGCDST, and marks the copied destination
         * PGACT/PGFULL before erasing the old source. The in-progress
         * XDST bytes are uncommitted and get erased by RECOVER_COMPACT;
         * NEVER authenticate them as source or require a valid item CRC. */
        is_discarded_destination = (header[0] == 0xfeu && mode == 0xfeu);
        if ((logical != 0xffffu &&
             (logical < R4_DATA_START || logical > R4_NV4_PAGE_SIZE)) ||
            /* TI NVOCMP PGCSRC=0xF8 is a page MODE, not PGXSRC=0x70.
             * The vendor marks all PGACT/PGFULL pages F8 before checking
             * the all-active early return. With one XDST and no PGXSRC,
             * TI init selects NORMAL_RESUME rather than compaction repair.
             * Such settled pages may retain a completed journal or an
             * erased journal, but a partial journal still must HOLD. */
            !((mode == 0xffu && erased_compaction_journal(header)) ||
              (mode == 0xfcu && valid_completed_journal(header, page)) ||
              (mode == 0xf8u &&
               (header[0] == 0x7cu || header[0] == 0x78u ||
                header[0] == 0x70u) &&
               (erased_compaction_journal(header) ||
                valid_completed_journal(header, page))) ||
              (is_discarded_destination) ||
              /* Destination's final records and source range must already
               * be fully committed before allowing RECOVER_ERASE. */
              (mode == 0xfeu &&
               (header[0] == 0x7cu || header[0] == 0x78u) &&
               valid_completed_journal(header, page)))) {
            r.code = R4_NV4_UNSAFE_PAGE_STATES;
            r.fault_offset = base + 4u;
            return r;
        }
        switch (header[0]) {
        case 0x7cu: ++active; break;
        case 0x78u: ++full; break;
        case 0xfeu: ++destination; break;
        case 0xffu: ++inactive; inactive_page = (uint8_t)page; break;
        case 0x70u: ++xsource; break;
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
        if (header[0] == 0xfeu || header[0] == 0xffu) {
            if (logical != 0xffffu ||
                (header[0] == 0xffu && (end != R4_DATA_START || mode != 0xffu)) ||
                (header[0] == 0xfeu &&
                 !(is_discarded_destination || (end == R4_DATA_START && mode == 0xffu)))) {
                r.code = R4_NV4_UNSAFE_PAGE_STATES;
                r.fault_offset = base + end;
                return r;
            }
            if (is_discarded_destination) partial_destination = 1u;
        } else if (!inspect_items(reader, ctx, &r, base, end,
                                  live_ids, &live_count,
                                  &zstack_live_count, &markers)) return r;
        if (mode == 0xfeu && header[0] != 0xfeu) {
            ++compact_dest;
            /* This conservative RECOVER_ERASE gate allows only a SINGLE
             * source page that has ALREADY BEEN ERASED by TI cleanPage.
             * A still-live source may contain records not yet copied;
             * permitting source erasure based on journal metadata alone
             * could irrevocably lose NIB or monotonic TC counters. */
            if (header[10] == header[14] &&
                header[12] == R4_DATA_START && header[13] == 0u) {
                completed_source_page = header[10];
                completed_source_erased = 1u;
            }
        }
    }
    /* Replicate ONLY deterministic TI 8.33 init dispatch. An in-progress
     * source plus XDST is RECOVER_COMPACT; the tentative destination gets
     * erased and the surviving CRC-valid source is copied again. A source
     * plus one blank NACT also chooses RECOVER_COMPACT. An already-complete
     * destination with committed source-range headers chooses RECOVER_ERASE.
     * Every other layout HOLDS instead of reaching TI FORCE_CLEAN. */
    if (xsource == 1u && destination == 1u && !compact_dest &&
        active + full + inactive + xsource + destination == R4_NV4_PAGES) {
        candidate_action = 1u;
    } else if (xsource == 1u && destination == 0u &&
               inactive == 1u && !compact_dest &&
               active + full + inactive + xsource == R4_NV4_PAGES) {
        candidate_action = 1u;
    } else if (xsource == 0u && destination == 0u &&
               inactive == 1u && compact_dest == 1u &&
               completed_source_erased &&
               completed_source_page == inactive_page &&
               active + full + inactive == R4_NV4_PAGES) {
        /* TI has already formatted the source NACT page (no live records).
         * RECOVER_ERASE will only re-erase that proven-empty page, while
         * the fully CRC-validated destination owns the active records. */
        candidate_action = 2u;
    }
    if (partial_destination && candidate_action != 1u) {
        r.code = R4_NV4_UNSAFE_PAGE_STATES;
        return r;
    }
    /* TI's >2-page normal ring can retain either, both or neither of the
     * other data pages as FULL after cleanPage. A formatted empty NACT page
     * is already authenticated above; FULL1/NACT1 is not a torn topology. */
    if ((!candidate_action &&
         (active != 1u || destination != 1u ||
          full + inactive != R4_NV4_PAGES - 2u)) ||
        r.active_records == 0u ||
        (candidate_action == 1u && xsource != 1u) ||
        (candidate_action == 2u && !completed_source_erased)) {
        r.code = R4_NV4_UNSAFE_PAGE_STATES;
        return r;
    }
    if (zstack_live_count == 0u) {
        r.code = R4_NV4_NO_ZSTACK_RECORDS;
        return r;
    }
    /* This is a *candidate* state, never a validated security decision.
     * Missing, malformed and incoherent markers remain UNKNOWN_HOLD even
     * when the media's CRC and four-page structure are valid. */
    r.semantic_flags = (markers.bdb_seen ? 1u : 0u) |
        (markers.bdb_on_network == 1u ? 2u : 0u) |
        (markers.role_seen ? 4u : 0u) |
        (markers.role_seen && markers.logical_type == 0u ? 8u : 0u) |
        (markers.nib_seen ? 16u : 0u) | (markers.startup_seen ? 32u : 0u) |
        (markers.startup_seen && !(markers.startup_options & R4_DESTRUCTIVE_STARTUP_OPTIONS) ? 64u : 0u) |
        (markers.malformed ? 128u : 0u);
    if (!markers.malformed && markers.bdb_seen && markers.role_seen &&
        markers.startup_seen &&
        !(markers.startup_options & R4_DESTRUCTIVE_STARTUP_OPTIONS) &&
        markers.logical_type == 0u) { /* coordinator, pinned zglobals.h */
        if (markers.bdb_on_network == 0u && !markers.nib_seen) {
            r.semantic_state = R4_NV4_STATE_UNCOMMISSIONED_CANDIDATE;
        } else if (markers.bdb_on_network == 1u && markers.nib_seen) {
            r.semantic_state = R4_NV4_STATE_FORMED_CANDIDATE;
        }
    }
    /* Recover ONLY a formed coordinator. Automatic commissioning and a
     * blank/newly provisioned network must never inherit this authority. */
    if (candidate_action) {
        if (r.semantic_state != R4_NV4_STATE_FORMED_CANDIDATE) {
            r.code = R4_NV4_UNSAFE_PAGE_STATES;
            r.semantic_state = R4_NV4_STATE_UNKNOWN_HOLD;
            return r;
        }
        r.code = candidate_action == 1u ?
            R4_NV4_RECOVER_COMPACT_CANDIDATE :
            R4_NV4_RECOVER_ERASE_CANDIDATE;
    } else {
        r.code = R4_NV4_READONLY_STRUCTURE_ACCEPTED;
    }
    return r;
}
