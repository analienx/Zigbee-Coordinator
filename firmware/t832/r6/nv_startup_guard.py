"""Preserve nonblank incompatible NV before any startup mutation.

Only the pinned fifteen-page candidate is qualified. This guard does not
repair unfamiliar headers or grant permission to format a commissioned store.
"""
import re
from apply_diag import Exact

HELPER=r'''/* T832-R10: classify every page before the first erase/program.
   F1 compact preflight: every compact-header field able to influence a
   startup erase/program (destination mode, source range pages and end
   offset, page data-end cursor) is structurally and topologically admitted
   here, read-only, before scanPage/recovery can mutate. Anything else
   preserves the image and rejects. F2: legacy generations fail closed;
   migration is not qualified. F6: multi-page RECOVER_ERASE ranges fail
   closed (non-end pages erase unconditionally: blank or all-live-twinned).
   F7: duplicate PGCDST
   metadata fails closed. F8: ACT/FULL/XSRC live IDs must agree pairwise
   (verbatim twins incl. both CRCs) or fail closed, except divergent
   pairs on the valid tail ID of a resume topology with at most one
   older copy and no older twin alongside (resume dedups the single
   nearest copy; mixed sets leave order-dependent survivors). F9:
   reserved page-header cycle/allActive values fail closed. RDY pages
   must be data-free (the driver never writes data to RDY). Erase
   admission also requires the XDST tail-mark to land on an erased
   page, or init fails every boot. */
static uint16_t NVOCMP_findOffset(uint8_t pg, uint16_t ofs);
static void NVOCMP_readHeader(uint8_t pg, uint16_t ofs, NVOCMP_itemHdr_t *iHdr, bool flag);
/* R8 provides the definition below (apply_fix always applies R8 first); the
   F8 proof reuses its verbatim-copy semantics so the gate and the recovery
   settle agree on what a safe duplicate is. */
static bool NVOCMP_recoverCopiesEqual(const NVOCMP_itemHdr_t *a, const NVOCMP_itemHdr_t *b);
static bool NVOCMP_startupErased(uint8_t pg, uint16_t start)
{
  uint8_t bytes[32];
  while(start < FLASH_PAGE_SIZE)
  {
    uint16_t count = FLASH_PAGE_SIZE - start;
    if(count > sizeof(bytes)) count = sizeof(bytes);
    memset(bytes, 0, sizeof(bytes)); /* a failed read must never look erased */
    NVOCMP_read(pg, start, bytes, count);
    for(uint16_t i = 0; i < count; i++) if(bytes[i] != 0xFF) return false;
    start += count;
  }
  return true;
}

static uint16_t NVOCMP_startupCmpOff(const uint8_t *b)
{
  return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

/* Read-only item-boundary walk: NV items pack data-first from
   NVOCMP_PGDATAOFS with each 7-byte header last (len uses the HDRLE=0
   branch of NVOCMP_readHeader). Walk downward from the true data end;
   true only when cursor lands exactly on an item boundary. */
static bool NVOCMP_startupOnBoundary(uint8_t pg, uint16_t cursor, uint16_t endTrue)
{
  uint16_t pos = endTrue;
  uint16_t steps = 0;
  uint8_t hdr[NVOCMP_ITEMHDRLEN];
  uint16_t len;
  if(cursor < NVOCMP_PGDATAOFS || cursor > endTrue) return false;
  if(cursor == endTrue) return true;
  while(pos > cursor)
  {
    if(pos < NVOCMP_PGDATAOFS + NVOCMP_ITEMHDRLEN) return false;
    NVOCMP_read(pg, (uint16_t)(pos - NVOCMP_ITEMHDRLEN), hdr, NVOCMP_ITEMHDRLEN);
    len = (uint16_t)(((uint16_t)(hdr[3] & 0x3Fu) << 6) | ((uint16_t)(hdr[4] >> 2) & 0x3Fu));
    if(len > (uint16_t)(pos - NVOCMP_ITEMHDRLEN - NVOCMP_PGDATAOFS)) return false;
    pos -= NVOCMP_ITEMHDRLEN + len;
    steps++;
    if(steps > 512u) return false;
  }
  return pos == cursor;
}

/* Read-only item walk state for the F8 agreement proof. */
typedef struct
{
  uint8_t pg;
  uint16_t pos;
  uint16_t steps;
  uint16_t slides;
} NVOCMP_startupWalk_t;

static void NVOCMP_startupWalkInit(NVOCMP_startupWalk_t *w, uint8_t pg)
{
  w->pg = pg;
  w->pos = NVOCMP_findOffset(pg, FLASH_PAGE_SIZE);
  w->steps = 0;
  w->slides = 0;
}

/* Next live header at or below the cursor: 1 fills *out, 0 at a clean chain
   end, -1 on anything unparseable (the caller fails closed). Unrecognized
   tail bytes (erased gaps, torn writes) slide past bounded; every valid
   header steps down exactly, so the walk always terminates. Torn bytes are
   1->0 prefixes of the true bytes being programmed, so forging a valid
   window that skips a live header needs a bit-precise tear (adversarial
   fault injection, which this NOR guard is not built to resist); random
   power-cut tears cannot forge one. The driver's own walks share this. */
static int8_t NVOCMP_startupWalkNext(NVOCMP_startupWalk_t *w, NVOCMP_itemHdr_t *out)
{
  for(;;)
  {
    if(w->pos <= NVOCMP_PGDATAOFS) return 0;
    if(w->pos < NVOCMP_PGDATAOFS + NVOCMP_ITEMHDRLEN) return -1;
    NVOCMP_readHeader(w->pg, (uint16_t)(w->pos - NVOCMP_ITEMHDRLEN), out, false);
    if(out->stats & NVOCMP_FOLLOWBIT)
    {
      if(out->len > (uint16_t)(w->pos - NVOCMP_ITEMHDRLEN - NVOCMP_PGDATAOFS)) return -1;
      w->pos -= NVOCMP_ITEMHDRLEN + out->len;
      if(++w->steps > 512u) return -1;
      if((out->stats & NVOCMP_ACTIVEIDBIT) && !(out->stats & NVOCMP_VALIDIDBIT)) return 1;
    }
    else
    {
      w->pos -= 1;
      if(++w->slides > 64u) return -1;
    }
  }
}

/* Q3 rejection latch: classify returns before scanPage populates
   pageInfo or gAction, so a bare status cannot say which page, field,
   or check rejected. Every reject path below latches status/page/site
   plus the offending raw byte when one is at hand (header bytes only:
   never item IDs, payloads, or keys). Site 0 means no rejection;
   page 0xFF means the check is not page-scoped. The latch clears on
   every classify entry so a re-init never reads a stale cause. */
typedef struct
{
  uint8_t status;
  uint8_t page;
  uint8_t site;
  uint8_t raw;
} NVOCMP_startupReject_t;
static NVOCMP_startupReject_t t832R10Reject;
enum
{
  NVOCMP_REJ_NONE = 0,
  NVOCMP_REJ_LEGACY, NVOCMP_REJ_HDR_SIGVER, NVOCMP_REJ_HDR_STATE,
  NVOCMP_REJ_HDR_ALLACTIVE, NVOCMP_REJ_HDR_CYCLE, NVOCMP_REJ_NACT_DATA,
  NVOCMP_REJ_RDY_DATA, NVOCMP_REJ_CMP_SIG, NVOCMP_REJ_CMP_MODE,
  NVOCMP_REJ_XSRC_PAGE, NVOCMP_REJ_XSRC_PAIR, NVOCMP_REJ_XSRC_SIG,
  NVOCMP_REJ_XSRC_OFF, NVOCMP_REJ_CURSOR_RANGE, NVOCMP_REJ_NACT_RDY_MODE,
  NVOCMP_REJ_RDY_CURSOR, NVOCMP_REJ_NACT_CURSOR, NVOCMP_REJ_SLOT_ERASE,
  NVOCMP_REJ_XDST_MODE, NVOCMP_REJ_XDST_CURSOR, NVOCMP_REJ_CDST_STATE,
  NVOCMP_REJ_CDST_CURSOR, NVOCMP_REJ_CURSOR_ABOVE_END,
  NVOCMP_REJ_CURSOR_OFF_BOUNDARY, NVOCMP_REJ_TOPO_COUNTS,
  NVOCMP_REJ_DUP_PGCDST, NVOCMP_REJ_CENSUS_WALK, NVOCMP_REJ_TAIL_MIXED,
  NVOCMP_REJ_TAIL_MULTI, NVOCMP_REJ_PAIR_WALK, NVOCMP_REJ_PAIR_CONFLICT,
  NVOCMP_REJ_ERASE_NULL_RANGE, NVOCMP_REJ_ERASE_SPAN,
  NVOCMP_REJ_ERASE_DST_IN_RANGE, NVOCMP_REJ_ERASE_NONTWINNED,
  NVOCMP_REJ_ERASE_END_NONTWINNED, NVOCMP_REJ_ERASE_EOFF_ABOVE,
  NVOCMP_REJ_ERASE_SUFFIX_NONTWINNED, NVOCMP_REJ_ERASE_TAIL_MARK
};
static uint8_t NVOCMP_startupReject(uint8_t st, uint8_t pg, uint8_t site, uint8_t raw)
{
  t832R10Reject.status = st;
  t832R10Reject.page = pg;
  t832R10Reject.site = site;
  t832R10Reject.raw = raw;
  return st;
}

/* Suffix proof: true only when every live item strictly above eoff on page
   epg has a verbatim twin on page fpg and both pages walk to a clean end.
   Below-end erase offsets are fresh partial-consumption frontiers (dst-full
   rounds stop mid-page) or stale/torn values; cleanPage hides everything
   above eoff, which is safe only when each hidden live item survives
   verbatim on dst. Anything unparseable fails closed. */
static bool NVOCMP_startupSuffixTwinned(uint8_t epg, uint16_t eoff, uint16_t endTrue, uint8_t fpg)
{
  NVOCMP_startupWalk_t w;
  NVOCMP_itemHdr_t h;
  int8_t r;
  if(!NVOCMP_startupOnBoundary(epg, eoff, endTrue)) return false;
  NVOCMP_startupWalkInit(&w, epg);
  for(;;)
  {
    r = NVOCMP_startupWalkNext(&w, &h);
    if(r < 0) return false;
    if(r == 0) return true;
    if(h.hofs > eoff)
    {
      NVOCMP_startupWalk_t v;
      NVOCMP_itemHdr_t g;
      int8_t s;
      bool twinned = false;
      NVOCMP_startupWalkInit(&v, fpg);
      for(;;)
      {
        s = NVOCMP_startupWalkNext(&v, &g);
        if(s < 0) return false;
        if(s == 0) break;
        if(g.cmpid == h.cmpid && NVOCMP_recoverCopiesEqual(&h, &g)) { twinned = true; break; }
      }
      if(!twinned) return false;
    }
  }
}
/* Whole-page twin proof: true only when every live item on page pg
   has a verbatim twin on page fpg and both pages walk to a clean end.
   Non-end erase pages erase unconditionally, which is safe only when
   each erased live item survives verbatim on dst. Anything
   unparseable fails closed. */
static bool NVOCMP_startupPageTwinned(uint8_t pg, uint8_t fpg)
{
  NVOCMP_startupWalk_t w;
  NVOCMP_itemHdr_t h;
  int8_t r;
  NVOCMP_startupWalkInit(&w, pg);
  for(;;)
  {
    r = NVOCMP_startupWalkNext(&w, &h);
    if(r < 0) return false;
    if(r == 0) return true;
    {
      NVOCMP_startupWalk_t v;
      NVOCMP_itemHdr_t g;
      int8_t s;
      bool twinned = false;
      NVOCMP_startupWalkInit(&v, fpg);
      for(;;)
      {
        s = NVOCMP_startupWalkNext(&v, &g);
        if(s < 0) return false;
        if(s == 0) break;
        if(g.cmpid == h.cmpid && NVOCMP_recoverCopiesEqual(&h, &g)) { twinned = true; break; }
      }
      if(!twinned) return false;
    }
  }
}
/* True when page pg holds a live copy of ref->cmpid that is neither a
   verbatim twin of ref nor covered by the tail-convergence exception, or
   when the page cannot be walked to a clean end. */
static bool NVOCMP_startupActConflict(uint8_t pg, const NVOCMP_itemHdr_t *ref, bool tailOk, uint32_t tailCmpid)
{
  NVOCMP_startupWalk_t w;
  NVOCMP_itemHdr_t g;
  int8_t r;
  NVOCMP_startupWalkInit(&w, pg);
  for(;;)
  {
    r = NVOCMP_startupWalkNext(&w, &g);
    if(r < 0) return true;
    if(r == 0) return false;
    if(g.cmpid == ref->cmpid && (g.hpage != ref->hpage || g.hofs != ref->hofs) &&
       !NVOCMP_recoverCopiesEqual(ref, &g) && !(tailOk && ref->cmpid == tailCmpid)) return true;
  }
}

static uint8_t NVOCMP_startupClassify(void)
{
  uint8_t inactive = 0, destinations = 0, sources = 0, ready = 0, dataPages = 0, cdst = 0;
  uint8_t actN = 0, chkN = 0;
  uint8_t actPgs[NVOCMP_NVPAGES];
  uint8_t chkPgs[NVOCMP_NVPAGES];
  uint8_t modes[NVOCMP_NVPAGES];
  uint8_t spages[NVOCMP_NVPAGES];
  uint8_t epages[NVOCMP_NVPAGES];
  uint16_t eoffs[NVOCMP_NVPAGES];
  uint8_t pg;
  t832R10Reject.status = t832R10Reject.page = t832R10Reject.site = t832R10Reject.raw = 0;
  for(pg = 0; pg < NVOCMP_NVSIZE; pg++)
  {
    uint32_t raw = 0;
    uint8_t cmp[12];
    uint8_t mode;
    uint16_t cursor;
    uint8_t s;
    NVOCMP_pageHdr_t *hdr = (NVOCMP_pageHdr_t *)&raw;
    NVOCMP_read(pg, NVOCMP_PGHDROFS, (uint8_t *)hdr, NVOCMP_PGHDRLEN);
    if(raw == 0xFFFFFFFF && NVOCMP_startupErased(pg, 0))
    {
      inactive++;
      modes[pg] = NVOCMP_PGNORMAL;
      spages[pg] = NVOCMP_NULLPAGE;
      epages[pg] = NVOCMP_NULLPAGE;
      eoffs[pg] = NVOCMP_NULLOFFSET;
      continue;
    }
    /* F2: any legacy generation fails closed. Migration is not qualified;
       this stays put even if NVOCMP_MIGRATE_DISABLED is ever lifted. */
    {
      uint8_t legacy = (hdr->version << 2) | hdr->allActive;
      if(hdr->signature == NVOCTP_SIGNATURE && legacy == NVOCTP_VERSION &&
         (hdr->state == NVOCTP_PGACTIVE || hdr->state == NVOCTP_PGXFER)) return NVOCMP_startupReject(NVINTF_FAILURE, pg, NVOCMP_REJ_LEGACY, hdr->state);
    }
    if(hdr->signature != NVOCMP_SIGNATURE || hdr->version != NVOCMP_VERSION)
      return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_HDR_SIGVER, hdr->signature);
    if(hdr->state != NVOCMP_PGNACT && hdr->state != NVOCMP_PGXDST &&
       hdr->state != NVOCMP_PGRDY && hdr->state != NVOCMP_PGACT &&
       hdr->state != NVOCMP_PGFULL && hdr->state != NVOCMP_PGXSRC)
      return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_HDR_STATE, hdr->state);
    /* F9: TI reserves allActive 1/2 (only SOMEINACTIVE=0/ALLACTIVE=3 exist)
       and cycle 0x00/0xFF (valid 0x01..0xFE). allActive steers compaction
       and inactive marking; a reserved value fails closed. */
    if(hdr->allActive != 0 && hdr->allActive != 3) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_HDR_ALLACTIVE, hdr->allActive);
    if(((raw >> 8) & 0xFF) == 0x00 || ((raw >> 8) & 0xFF) == 0xFF) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_HDR_CYCLE, (uint8_t)((raw >> 8) & 0xFF));
    if(hdr->state == NVOCMP_PGNACT && !NVOCMP_startupErased(pg, NVOCMP_PGDATAOFS))
      return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_NACT_DATA, 0);
    /* L0-F7/CH-F2: a RDY page carrying data is a flash-fault shape.
       Mark-before-write lands data on ACT only, never RDY, so RDY
       data fails closed here instead of admitting an end page the
       driver would cursor-write and then strand. */
    if(hdr->state == NVOCMP_PGRDY && !NVOCMP_startupErased(pg, NVOCMP_PGDATAOFS))
      return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_RDY_DATA, 0);
    /* F1: admit the compact metadata before it can steer recovery. */
    NVOCMP_read(pg, NVOCMP_PGHDRLEN, cmp, sizeof(cmp));
    mode = cmp[2];
    cursor = NVOCMP_startupCmpOff(cmp);
    if(cmp[3] != 0xFF && cmp[3] != NVOCMP_SIGNATURE) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_CMP_SIG, 3);
    if(cmp[7] != 0xFF && cmp[7] != NVOCMP_SIGNATURE) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_CMP_SIG, 7);
    if(cmp[11] != 0xFF && cmp[11] != NVOCMP_SIGNATURE) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_CMP_SIG, 11);
    if(mode != NVOCMP_PGNORMAL && mode != NVOCMP_PGCDST &&
       mode != NVOCMP_PGCDONE && mode != NVOCMP_PGCSRC) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_CMP_MODE, mode);
    for(s = 0; s < 2; s++)
    {
      const uint8_t *h = &cmp[4 + s * 4];
      uint8_t hpg = h[2];
      uint16_t hoff = NVOCMP_startupCmpOff(h);
      if(hpg != NVOCMP_NULLPAGE && hpg >= NVOCMP_NVSIZE) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_XSRC_PAGE, hpg);
      if((hpg == NVOCMP_NULLPAGE) != (hoff == NVOCMP_NULLOFFSET)) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_XSRC_PAIR, s);
      if(hpg != NVOCMP_NULLPAGE && h[3] != NVOCMP_SIGNATURE) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_XSRC_SIG, h[3]);
      if(hpg != NVOCMP_NULLPAGE && hoff > FLASH_PAGE_SIZE) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_XSRC_OFF, (uint8_t)(hoff & 0xFF));
    }
    if(hdr->state == NVOCMP_PGACT || hdr->state == NVOCMP_PGFULL || hdr->state == NVOCMP_PGXSRC)
    {
      if(cursor != NVOCMP_NULLOFFSET &&
         (cursor < NVOCMP_PGDATAOFS || cursor > FLASH_PAGE_SIZE)) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_CURSOR_RANGE, (uint8_t)(cursor & 0xFF));
    }
    if(hdr->state == NVOCMP_PGNACT || hdr->state == NVOCMP_PGRDY)
    {
      /* Never compact writers: mode stays normal and XSRC slots stay in an
         erase form. NACT offsets are forced to PGDATAOFS by scanPage, so
         the NACT cursor slot tolerates quirk values (a fully-drained end
         offset cursor-written onto an empty end page). RDY cursors are
         CONSUMED as data-end offsets (scanPage, getDstPage, RESUME), so
         only the null and drained forms are admitted: any other value,
         including a torn 16->0, could steer a later write into the page
         header region. */
      uint8_t s2;
      if(mode != NVOCMP_PGNORMAL) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_NACT_RDY_MODE, mode);
      if(hdr->state == NVOCMP_PGRDY)
      {
        if(cursor != NVOCMP_NULLOFFSET && cursor != NVOCMP_PGDATAOFS) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_RDY_CURSOR, (uint8_t)(cursor & 0xFF));
      }
      else if(cursor != NVOCMP_NULLOFFSET && cursor > FLASH_PAGE_SIZE) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_NACT_CURSOR, (uint8_t)(cursor & 0xFF));
      for(s2 = 0; s2 < 2; s2++)
      {
        const uint8_t *h = &cmp[4 + s2 * 4];
        if(NVOCMP_startupCmpOff(h) != NVOCMP_NULLOFFSET || h[2] != NVOCMP_NULLPAGE)
          return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_SLOT_ERASE, s2);
      }
    }
    if(hdr->state == NVOCMP_PGXDST)
    {
      if(mode != NVOCMP_PGNORMAL && mode != NVOCMP_PGCDST) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_XDST_MODE, mode);
      if(cursor != NVOCMP_NULLOFFSET) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_XDST_CURSOR, (uint8_t)(cursor & 0xFF));
    }
    if(mode == NVOCMP_PGCDST)
    {
      if(hdr->state != NVOCMP_PGXDST && hdr->state != NVOCMP_PGACT &&
         hdr->state != NVOCMP_PGFULL) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_CDST_STATE, hdr->state);
      if(cursor != NVOCMP_NULLOFFSET) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_CDST_CURSOR, (uint8_t)(cursor & 0xFF));
    }
    if((hdr->state == NVOCMP_PGACT || hdr->state == NVOCMP_PGFULL ||
        hdr->state == NVOCMP_PGXSRC) && cursor != NVOCMP_NULLOFFSET)
    {
      /* Stale-smaller cursors are legitimate (a reused page keeps the end
         its earlier transfer recorded); torn-smaller cursors are not
         distinguishable from stale ones, but a torn cursor off every item
         boundary would misparse a header, so only boundaries are admitted.
         Above the true end is impossible: 1->0 writes never grow a value. */
      uint16_t endTrue = NVOCMP_findOffset(pg, FLASH_PAGE_SIZE);
      if(cursor > endTrue) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_CURSOR_ABOVE_END, (uint8_t)(cursor & 0xFF));
      if(cursor < endTrue && !NVOCMP_startupOnBoundary(pg, cursor, endTrue)) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_CURSOR_OFF_BOUNDARY, (uint8_t)(cursor & 0xFF));
    }
    modes[pg] = mode;
    spages[pg] = cmp[6];
    epages[pg] = cmp[10];
    eoffs[pg] = NVOCMP_startupCmpOff(&cmp[8]);
    if(hdr->state == NVOCMP_PGNACT) inactive++;
    if(hdr->state == NVOCMP_PGXDST) destinations++;
    if(hdr->state == NVOCMP_PGXSRC) sources++;
    if(hdr->state == NVOCMP_PGRDY) ready++;
    if(hdr->state == NVOCMP_PGACT || hdr->state == NVOCMP_PGFULL) dataPages++;
    if(hdr->state == NVOCMP_PGACT) actPgs[actN++] = pg;
    /* CH-F3: XSRC originals survive RECOVER_ERASE untouched, so an
       XSRC/ACT divergent pair is a live read-flip. The proof walks
       XSRC pages too; resume topologies carry no XSRC, so the tail
       exception below never excuses an XSRC copy. */
    if(hdr->state == NVOCMP_PGACT || hdr->state == NVOCMP_PGFULL ||
       hdr->state == NVOCMP_PGXSRC) chkPgs[chkN++] = pg;
  }
  /* Reject the upstream FORCE_CLEAN decisions before scanPage initializes even
     a truly blank page. Rejected topology must preserve the complete image.
     ACT pages are admitted only when the F8 agreement proof below shows every
     shared live ID agrees; anything else fails closed. */
  if(destinations > 1 || sources > 1 || ready > 1 ||
     (inactive != NVOCMP_NVSIZE && !destinations && !sources && !dataPages))
    return NVOCMP_startupReject(NVINTF_FAILURE, NVOCMP_NULLPAGE, NVOCMP_REJ_TOPO_COUNTS, (uint8_t)((destinations & 3) | ((sources & 3) << 2) | ((ready & 3) << 4) | (dataPages ? 64 : 0) | ((inactive != NVOCMP_NVSIZE) ? 128 : 0)));
  /* F7: findDstPage consumes only the first PGCDST page, so more than one
     PGCDST metadata page is ambiguous and fails closed. Counted here so
     the F8 resume-topology gate below can use it. */
  for(pg = 0; pg < NVOCMP_NVSIZE; pg++) if(modes[pg] == NVOCMP_PGCDST) cdst++;
  if(cdst > 1) return NVOCMP_startupReject(NVINTF_FAILURE, NVOCMP_NULLPAGE, NVOCMP_REJ_DUP_PGCDST, cdst);
  /* F8 agreement proof: every pair of live copies sharing a compressed ID
     across (or within) ACT, FULL, and XSRC pages must be verbatim twins
     (bounds, both CRCs, payload bytes). RESUME reads from the last ACT
     page while RECOVER_ERASE reads from the first, so divergent copies
     would return different values on the two paths. Anything unparseable
     fails closed. Exception: a divergent pair on the live, CRC-valid
     tail ID of the NULL-cursor last ACT converges only when the driver
     takes NORMAL_RESUME (exactly one XDST and no XSRC, or the
     no-XDST/XSRC resume-mark branch with no PGCDST and a spare NACT):
     resume inactivates exactly one older copy (the first strict match
     below the tail), so the tail-ID census below admits at most one
     older non-twin copy with no older twin alongside, and
     update-transients admit while erase-path, mixed-set, and
     multi-copy divergence fails closed. */
  {
    uint8_t i, j;
    bool tailOk = false;
    bool resumeTopo = (destinations == 1 && sources == 0) ||
        (!destinations && !sources && dataPages && !cdst && inactive);
    uint32_t tailCmpid = 0;
    NVOCMP_itemHdr_t tailH;
    if(actN > 0 && resumeTopo)
    {
      uint8_t lastAct = actPgs[actN - 1];
      uint8_t cursorBytes[4];
      uint16_t tailEnd;
      NVOCMP_read(lastAct, NVOCMP_PGHDRLEN, cursorBytes, sizeof(cursorBytes));
      tailEnd = NVOCMP_findOffset(lastAct, FLASH_PAGE_SIZE);
      if(cursorBytes[0] == 0xFF && cursorBytes[1] == 0xFF && tailEnd >= NVOCMP_PGDATAOFS + NVOCMP_ITEMHDRLEN)
      {
        NVOCMP_readHeader(lastAct, (uint16_t)(tailEnd - NVOCMP_ITEMHDRLEN), &tailH, false);
        if((tailH.stats & NVOCMP_FOLLOWBIT) && (tailH.stats & NVOCMP_ACTIVEIDBIT) &&
           !(tailH.stats & NVOCMP_VALIDIDBIT) && tailH.len <= (uint16_t)(tailEnd - NVOCMP_ITEMHDRLEN - NVOCMP_PGDATAOFS) &&
           NVOCMP_verifyCRC((uint16_t)(tailEnd - NVOCMP_ITEMHDRLEN - tailH.len), tailH.len, tailH.crc8, lastAct, false) == NVINTF_SUCCESS)
        {
          tailOk = true;
          tailCmpid = tailH.cmpid;
        }
      }
    }
    if(tailOk)
    {
      /* Tail-ID census: resume dedups exactly one older copy (the
         first strict match below the tail), so more than one older
         live non-twin copy of the tail ID (across ACT, FULL, and
         XSRC pages) leaves divergent survivors and fails closed.
         Verbatim twins of the tail read identically on every path,
         but a MIXED older set (a twin plus a non-twin, L0-F1) leaves
         the survivor order-dependent (resume kills only the
         nearest-below-tail, which may be the twin) and fails closed.
         Admitted older sets: none, one non-twin, or twins-only. */
      uint8_t c;
      uint8_t older = 0;
      uint8_t olderTwin = 0;
      for(c = 0; c < chkN; c++)
      {
        NVOCMP_startupWalk_t w;
        NVOCMP_itemHdr_t h;
        int8_t r;
        NVOCMP_startupWalkInit(&w, chkPgs[c]);
        for(;;)
        {
          r = NVOCMP_startupWalkNext(&w, &h);
          if(r < 0) return NVOCMP_startupReject(NVINTF_FAILURE, chkPgs[c], NVOCMP_REJ_CENSUS_WALK, c);
          if(r == 0) break;
          if(h.cmpid == tailCmpid && (h.hpage != tailH.hpage || h.hofs != tailH.hofs))
          {
            if(NVOCMP_recoverCopiesEqual(&tailH, &h))
            {
              olderTwin++;
              if(older > 0) return NVOCMP_startupReject(NVINTF_FAILURE, chkPgs[c], NVOCMP_REJ_TAIL_MIXED, c);
            }
            else if(++older > 1 || olderTwin > 0) return NVOCMP_startupReject(NVINTF_FAILURE, chkPgs[c], NVOCMP_REJ_TAIL_MULTI, c);
          }
        }
      }
    }
    for(i = 0; i < chkN; i++)
    {
      NVOCMP_startupWalk_t w;
      NVOCMP_itemHdr_t h;
      int8_t r;
      NVOCMP_startupWalkInit(&w, chkPgs[i]);
      for(;;)
      {
        r = NVOCMP_startupWalkNext(&w, &h);
        if(r < 0) return NVOCMP_startupReject(NVINTF_FAILURE, chkPgs[i], NVOCMP_REJ_PAIR_WALK, i);
        if(r == 0) break;
        for(j = 0; j < chkN; j++)
          if(NVOCMP_startupActConflict(chkPgs[j], &h, tailOk, tailCmpid)) return NVOCMP_startupReject(NVINTF_FAILURE, chkPgs[j], NVOCMP_REJ_PAIR_CONFLICT, i);
      }
    }
  }
  /* F1 RECOVER_ERASE gate: when the driver would consume a PGCDST page's
     source range in cleanPage, admit that range only if fully validated:
     non-null pages, a span that cannot circle the store, a destination
     outside the range, and an end offset consistent with the end page's
     true data end. */
  {
    bool eraseBranch = false;
    uint8_t f = NVOCMP_NVSIZE;
    uint8_t spg;
    uint8_t epg;
    uint16_t eoff;
    uint16_t endTrue;
    uint16_t dse;
    uint16_t dsf;
    if(sources && !destinations && !inactive) eraseBranch = true;
    if(!sources && !destinations && dataPages) eraseBranch = true;
    if(eraseBranch)
    {
      for(pg = 0; pg < NVOCMP_NVSIZE; pg++) if(modes[pg] == NVOCMP_PGCDST) { f = pg; break; }
      if(f < NVOCMP_NVSIZE)
      {
        spg = spages[f];
        epg = epages[f];
        eoff = eoffs[f];
        if(spg == NVOCMP_NULLPAGE || epg == NVOCMP_NULLPAGE) return NVOCMP_startupReject(NVINTF_BADVERSION, f, NVOCMP_REJ_ERASE_NULL_RANGE, (uint8_t)((spg == NVOCMP_NULLPAGE ? 1 : 0) | (epg == NVOCMP_NULLPAGE ? 2 : 0)));
        dse = (uint16_t)((epg >= spg) ? (epg - spg) : (epg + NVOCMP_NVSIZE - spg));
        dsf = (uint16_t)((f >= spg) ? (f - spg) : (f + NVOCMP_NVSIZE - spg));
        if(dse + 1u > (uint16_t)(NVOCMP_NVSIZE - 1u)) return NVOCMP_startupReject(NVINTF_BADVERSION, f, NVOCMP_REJ_ERASE_SPAN, (uint8_t)(dse & 0xFF));
        if(dsf <= dse) return NVOCMP_startupReject(NVINTF_BADVERSION, f, NVOCMP_REJ_ERASE_DST_IN_RANGE, (uint8_t)(dsf & 0xFF));
        /* F6: cleanPage erases non-end range pages unconditionally (the
           offset correction forces PGDATAOFS), so each non-end page must be
           blank/header-only (nothing to destroy) or fully live-twinned
           on dst (CH-F1: erasing originals destroys nothing when every
           live item survives verbatim on dst), or the range fails
           closed. Preservation beats automatic recovery. */
        for(pg = spg; pg != epg; pg = NVOCMP_INCPAGE(pg))
          if(NVOCMP_findOffset(pg, FLASH_PAGE_SIZE) > NVOCMP_PGDATAOFS &&
             !NVOCMP_startupPageTwinned(pg, f)) return NVOCMP_startupReject(NVINTF_BADVERSION, pg, NVOCMP_REJ_ERASE_NONTWINNED, f);
        endTrue = NVOCMP_findOffset(epg, FLASH_PAGE_SIZE);
        if(eoff == NVOCMP_PGDATAOFS)
        {
          /* Fully-drained form: cleanPage erases the end page without
             reading data through the offset. Safe when the end page
             holds no data (blank, or header-only), or when every live
             item on it is twinned on dst (CH-F1: same erasure argument
             as the non-end extension); a torn end offset on an
             untwinned live end page would erase live items. */
          if(endTrue > NVOCMP_PGDATAOFS &&
             !NVOCMP_startupSuffixTwinned(epg, NVOCMP_PGDATAOFS, endTrue, f)) return NVOCMP_startupReject(NVINTF_BADVERSION, epg, NVOCMP_REJ_ERASE_END_NONTWINNED, f);
        }
        /* Below-end erase offsets are fresh partial-consumption
           frontiers or stale/torn values; cleanPage hides everything
           above eoff, so admission needs the suffix proof (every live
           item above eoff verbatim-twinned on dst). */
        else if(eoff > endTrue) return NVOCMP_startupReject(NVINTF_BADVERSION, epg, NVOCMP_REJ_ERASE_EOFF_ABOVE, (uint8_t)(eoff & 0xFF));
        else if(eoff != endTrue && !NVOCMP_startupSuffixTwinned(epg, eoff, endTrue, f)) return NVOCMP_startupReject(NVINTF_BADVERSION, epg, NVOCMP_REJ_ERASE_SUFFIX_NONTWINNED, f);
        /* Tail-markability (L0-F2/F3; P2 tail-in-range): cleanPage
           erases every non-end range page (the offset correction
           forces PGDATAOFS) and the end page iff drained, then
           XDST-marks ADDPAGE(dst, count). NOR programs 1->0 only, so
           the mark succeeds onto an erased (0xFF) state byte, or onto
           a page cleanPage itself erases first (a non-end range page,
           or the end page iff drained); anything else fails the mark,
           fails init, and bricks every boot. */
        {
          uint8_t tail = (uint8_t)(((uint16_t)f + dse + (eoff == NVOCMP_PGDATAOFS ? 1u : 0u)) % NVOCMP_NVSIZE);
          uint8_t tailErased = 0;
          uint8_t q;
          for(q = spg; q != epg; q = NVOCMP_INCPAGE(q))
            if(q == tail) { tailErased = 1; break; }
          if(tail == epg && eoff == NVOCMP_PGDATAOFS) tailErased = 1;
          if(!tailErased)
          {
            uint32_t tailRaw = 0;
            NVOCMP_pageHdr_t *tailHdr = (NVOCMP_pageHdr_t *)&tailRaw;
            NVOCMP_read(tail, NVOCMP_PGHDROFS, (uint8_t *)tailHdr, NVOCMP_PGHDRLEN);
            if(tailHdr->state != NVOCMP_PGNACT) return NVOCMP_startupReject(NVINTF_BADVERSION, tail, NVOCMP_REJ_ERASE_TAIL_MARK, tailHdr->state);
          }
        }
      }
      /* P3: eraseBranch with no PGCDST falls through here (SUCCESS at
         the classify layer). Data-without-destination-and-without-spare
         still fails closed end-to-end via the R10 ERROR_UNKNOWN latch
         with 0 ops (the oracle models that latched outcome as
         DRIVER_UNKNOWN_LATCH); resume-mark shapes (spare NACT) proceed
         to NORMAL_RESUME below. Verdicts agree at the init boundary. */
    }
  }
  return NVINTF_SUCCESS;
}
'''

def function(text,name):
    match=re.search(r'static (?:void|uint8_t|uint32_t|bool) '+name+r'\s*\([^;]*?\)\s*\{',text)
    if not match:raise ValueError('function missing '+name)
    end=match.end();depth=1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[match.start():end]

def apply_guard(nv):
    ex=Exact();text=nv.read_text()
    scan=function(text,'NVOCMP_scanPage')
    ex.replace(nv,scan,HELPER+'\n'+scan,'r10.startup.classifier')
    text=nv.read_text();old=function(text,'NVOCMP_initNv');new=old
    anchor='  // Scan Pages\n'
    if new.count(anchor)!=1:raise ValueError('page scan anchor mismatch')
    new=new.replace(anchor,'''  /* T832-R10: no cleanup until all nonblank headers are understood. */
  status = NVOCMP_startupClassify();
  if(status != NVINTF_SUCCESS)
  {
    NVOCMP_failF = NVOCMP_failW = status;
    return;
  }

'''+anchor)
    for indent in ('    ','      '):
        bad=indent+'NVOCMP_ASSERT(false, "Something wrong serious");\n'+indent+'action = NVOCMP_FORCE_CLEAN;'
        if new.count(bad)!=1:raise ValueError('force clean decision mismatch')
        new=new.replace(bad,indent+'NVOCMP_failF = NVOCMP_failW = NVINTF_FAILURE;\n'+indent+'return; /* T832-R10: preserve ambiguous topology under !NVDEBUG too. */')
    cleanup='''  case NVOCMP_FORCE_CLEAN :
      // Erase All pages before start
      for(pg = 0; pg < NVOCMP_NVSIZE; pg++)
      {
        NVOCMP_failW |= NVOCMP_erase(pNvHandle, pg);
      }
      // init should be followed by force clean'''
    if new.count(cleanup)!=1:raise ValueError('force clean case mismatch')
    new=new.replace(cleanup,'''  case NVOCMP_FORCE_CLEAN :
      NVOCMP_failF = NVOCMP_failW = NVINTF_FAILURE;
      return; /* T832-R10: no destructive fallback. */''')
    unknown='''  case NVOCMP_ERROR_UNKNOWN :
      /* When this error happens, NV area should be erased to restart.
       * This while loop is for only debug purpose */
      NVOCMP_ASSERT1(0);'''
    if new.count(unknown)!=1:raise ValueError('unknown topology stop mismatch')
    new=new.replace(unknown,'''  case NVOCMP_ERROR_UNKNOWN :
      NVOCMP_failF = NVOCMP_failW = NVINTF_FAILURE;
      return; /* T832-R10: report unavailable recovery instead of spinning. */''')
    # A scan failure must latch the public API, not leave failF=SUCCESS.
    bad='''    if(status != NVINTF_SUCCESS)
    {
      return;
    }'''
    if new.count(bad)!=1:raise ValueError('scan failure latch mismatch')
    new=new.replace(bad,'''    if(status != NVINTF_SUCCESS)
    {
      NVOCMP_failF = NVOCMP_failW = status;
      return;
    }''')
    ex.replace(nv,old,new,'r10.startup.preserve-topology')
    old=function(nv.read_text(),'NVOCMP_initNvApi');new=old
    anchor='        NVOCMP_initNv(&NVOCMP_nvHandle);'
    if new.count(anchor)!=1:raise ValueError('init API call mismatch')
    new=new.replace(anchor,anchor+'''
        if(NVOCMP_failW != NVINTF_SUCCESS)
        {
            NVOCMP_failF = NVOCMP_failW;
            goto T832_NV_INIT_DONE; /* Skip optional statistics writes. */
        }''')
    anchor='    return(NVOCMP_failW);'
    if new.count(anchor)!=1:raise ValueError('init API return mismatch')
    new=new.replace(anchor,'T832_NV_INIT_DONE:\n'+anchor)
    ex.replace(nv,old,new,'r10.startup.api-failure-latch')
    # Upstream checkItem only rejects NOTREADY; BADVERSION/FAILURE otherwise
    # reaches the uninitialized page cursor. Cover all public memory traversals.
    # getFreeNvApi reports 0 free: the conservative direction for a dead
    # driver. lock/unlock stay ungated: pure mutex ops with no NV state access
    # (gating lock would break the lock/unlock pairing the API contract
    # requires).
    for name in ('NVOCMP_checkItem','NVOCMP_getFreeNvApi','NVOCMP_doNextApi','NVOCMP_eraseNvApi','NVOCMP_sanityCheckApi'):
        old=function(nv.read_text(),name)
        # F4: sanityCheck reports the TI bitmask contract (1u << status), never
        # the raw code, so a latched fatal init is distinguishable on the wire.
        value='0' if name=='NVOCMP_getFreeNvApi' else ('(uint32_t)(1UL << NVOCMP_failF)' if name=='NVOCMP_sanityCheckApi' else 'NVOCMP_failF')
        guard=f'\n    if(NVOCMP_failF != NVINTF_SUCCESS) return({value}); /* T832-R10 fatal init gate */'
        pos=old.index('{')+1;new=old[:pos]+guard+old[pos:]
        ex.replace(nv,old,new,'r10.startup.fatal-gate.'+name)
    # expectCompApi needs its own gate, scoped INSIDE if(len): nonzero len
    # enters getDstPage with actPage still NULLPAGE after a rejected init, so
    # the fatal-state return there is true ("cannot place without
    # compaction"). true is safe because every follow-on action
    # (compactNV/writeItem/eraseNV) is independently fail-closed. len==0 keeps
    # the upstream false fast path, which performs no traversal and therefore
    # needs no gate; a gate at function top would wrongly force true for the
    # empty request.
    old=function(nv.read_text(),'NVOCMP_expectCompApi')
    anchor='  if(len)\n  {'
    if old.count(anchor)!=1:raise ValueError('expectComp len branch mismatch')
    new=old.replace(anchor,anchor+'\n    if(NVOCMP_failF != NVINTF_SUCCESS) return(true); /* T832-R10 fatal init gate */')
    ex.replace(nv,old,new,'r10.startup.fatal-gate.NVOCMP_expectCompApi')
    verify_guard(nv.read_text())
    return ex.edits

def verify_guard(text):
    init=function(text,'NVOCMP_initNv')
    if HELPER not in text or 'status = NVOCMP_startupClassify();' not in init:
        raise ValueError('nonblank startup classifier absent')
    if 'action = NVOCMP_FORCE_CLEAN;' in init or '// Erase All pages before start' in init:
        raise ValueError('destructive startup fallback remains')
    if 'NVOCMP_ASSERT1(0);' in init or 'report unavailable recovery instead of spinning' not in init:
        raise ValueError('unknown topology startup spin remains')
    if 'goto T832_NV_INIT_DONE;' not in function(text,'NVOCMP_initNvApi'):
        raise ValueError('public API failure not latched')
    for name in ('NVOCMP_checkItem','NVOCMP_getFreeNvApi','NVOCMP_doNextApi','NVOCMP_eraseNvApi','NVOCMP_sanityCheckApi','NVOCMP_expectCompApi'):
        if '/* T832-R10 fatal init gate */' not in function(text,name):raise ValueError('fatal API gate absent '+name)
    classify=function(text,'NVOCMP_startupClassify')
    for marker in ('NVOCMP_startupOnBoundary','RECOVER_ERASE gate','Migration is not qualified','NVOCMP_startupActConflict','Tail-ID census','NVOCMP_startupSuffixTwinned','Tail-markability','NVOCMP_startupPageTwinned'):
        if marker not in classify:raise ValueError('compact preflight marker absent '+marker)
    # Q3: every classify reject path latches status/page/site/raw; the latch
    # clears on entry so a re-init never reports a stale cause.
    if text.count('return NVOCMP_startupReject(') != 41:
        raise ValueError('reject latch coverage is not 41 sites')
    if 't832R10Reject.status = t832R10Reject.page = t832R10Reject.site = t832R10Reject.raw = 0;' not in classify:
        raise ValueError('reject latch clear-on-entry absent')
    if '#if' in classify or '#endif' in classify:
        raise ValueError('legacy detection must be unconditional, not macro-gated')
    if '(1UL << NVOCMP_failF)' not in function(text,'NVOCMP_sanityCheckApi'):
        raise ValueError('sanityCheck fatal gate is not the TI bitmask')
    return {'guard_id':'t832-r10-preserve-startup-nv-03','nonblank_invalid_policy':'preserve-and-reject','whole_region_preflight':True,'fatal_gates':6,
            'compact_preflight':True,'legacy_policy':'fail-closed','sanity_bitmask':True}
