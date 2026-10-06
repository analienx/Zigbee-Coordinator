"""T832 R8 bounded power-cut recovery changes for pinned TI NVOCMP.

M1 root cause (R7 SHA 3d8129d, hosted run 37494326769, TI SDK 8.32 pin
6499c3f53fc5fb5806213be695450a7b43fbaf3d, nvocmp.c LF sha256
d37c7f314696c8669413cfb098900e41ffd2a4d48704481e5dd8c9a8c012d6d6):
ten interrupted-compaction cuts fail per lane out of 108 sampled (201
physical operations total). The exhaustive R8 gate (194 operations after
P3) further exposes a stale-header corner (cut-194). Three upstream
defects, all in NVOCMP_initNv:

P1 (cuts 26/116/144/172/187 init FAILURE, cut 200 reserve FAILURE):
the no-source/no-destination resume branch marks ``pNvHandle->tailPage``
which is still zero from the fresh-handle memset (initNvApi), instead of
the just-selected ``pgXdst``. When page 0 is programmed the NOR-illegal
0x7C/0x78->0xFE state replay is rejected and init returns FAILURE; when
page 0 happens to be erased the wrong page is stranded XDST and 2032
free bytes become invisible (1772 < 2048 on cut 200 whose true free is
3804). One-token fix: mark ``pgXdst``.

P2 (cuts 19/81/109 reserve FAILURE, cut 179 combined FAILURE, exhaustive
cut-194 read FAILURE): the interrupted transfer's destination (PGCDST
mode) holds copies whose originals are still live, because source
invalidation only happens when cleanPage erases a fully drained source
after the transfer ends. RECOVER_COMPACT re-compacts without settling
that page, so both copies are transferred again and the duplicates leak
about one page of reserve permanently (1777/1795/1777/1993 < 2048).
Worse, trusting the destination compact headers to finish the transfer
is unsound: the headers are also written when the copy itself was
rejected, and a reused destination keeps headers from an earlier
transfer, so "completion" can hide live originals behind a wrong end
cursor (cut-194: end cursor 16 over a live anchor). Fix, fail-safe both
ways: never trust the headers and never erase the destination. First
refresh every page offset to its true data end in RAM (a reused page
keeps the smaller cursor its earlier transfer recorded; walking from
it would miss live items and erase the page as falsely drained).
Then, for a lone PGCDST destination, inactivate each of its copies that
still has a live original elsewhere (verbatim copies, so dropping one
is safe; sole survivors are kept) and let the caller re-compact, which
then copies every item exactly once. Headers that disagree with the
topology simply reconcile to nothing and the re-compaction duplicates
but cannot lose data.

P3 (read-only fixture reopen mutation): NORMAL_RESUME's fallback compacts
when NVOCMP_readHeader did not recognize the tail signature (FOLLOWBIT
clear). FOLLOWBIT denotes a recognized signature, not a torn item. The
fixture reaches that fallback; removing it defers this maintenance to
on-demand update-path compaction. Recognized-header processing remains
unchanged. Hosted cut coverage does not prove every malformed-tail case.

Safety properties of the patch: no NV erase/reformat primitive is
added (NVOCMP_eraseNvApi/RECOVER_FROM_COMPACT_FAILURE stay absent),
no reserve constant is relaxed, every added flash write is a 1->0
inactivation over a programmed-active header, and the RAM refresh never
writes flash at all.

All patch strings are built with explicit LF joins so Exact matching
works on Linux checkouts regardless of local line endings.
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from apply_diag import Exact

FIX_ID = 't832-r8-nv-recovery-02'
# LF sha256 of the pristine pinned nvocmp.c this patch applies to.
PRISTINE_ALGO_SHA256 = 'd37c7f314696c8669413cfb098900e41ffd2a4d48704481e5dd8c9a8c012d6d6'
PRISTINE_SDK_COMMIT = '6499c3f53fc5fb5806213be695450a7b43fbaf3d'

MARKER = 'T832-R8 power-cut recovery (t832-r8-nv-recovery-02)'


def _lines(*ls):
    return '\n'.join(ls)


# P1: mark the selected destination page, not the stale zero handle field.
P1_OLD = _lines(
    '        pgXdst = pgNact;',
    '        NVOCMP_changePageState(pNvHandle, pNvHandle->tailPage, NVOCMP_PGXDST);',
    '        action = NVOCMP_NORMAL_RESUME;',
)
P1_NEW = _lines(
    '        pgXdst = pgNact;',
    '        /* ' + MARKER + ' P1: tailPage is still zero here (fresh-handle',
    '           memset in initNvApi); the resume destination is pgXdst. */',
    '        NVOCMP_changePageState(pNvHandle, pgXdst, NVOCMP_PGXDST);',
    '        action = NVOCMP_NORMAL_RESUME;',
)

# P3: defer missing-signature fallback compaction to the update path.
# Recognized-header (FOLLOWBIT set) processing remains unchanged.
P3_OLD = _lines(
    '          if(iHdr.stats & NVOCMP_FOLLOWBIT)',
    '          {',
    '            status = NVOCMP_findItem(pNvHandle, pNvHandle->actPage, pNvHandle->actOffset - NVOCMP_ITEMHDRLEN - iHdr.len,',
    '                            &iHdr, NVOCMP_FINDSTRICT, NULL);',
    '            if((status == NVINTF_SUCCESS) && (iHdr.hofs > 0))',
    '            {',
    '              NVOCMP_setItemInactive(pNvHandle, iHdr.hpage, iHdr.hofs);',
    '            }',
    '          }',
    '          else',
    '          {',
    '            NVOCMP_compactPage(pNvHandle, 0);',
    '          }',
)
P3_NEW = _lines(
    '          /* ' + MARKER + ' P3: defer missing-signature fallback',
    '             compaction to the update path. FOLLOWBIT identifies a',
    '             recognized header signature; its processing stays below.',
    '             Hosted fixture reopen performs no physical mutations. */',
    '          if(iHdr.stats & NVOCMP_FOLLOWBIT)',
    '          {',
    '            status = NVOCMP_findItem(pNvHandle, pNvHandle->actPage, pNvHandle->actOffset - NVOCMP_ITEMHDRLEN - iHdr.len,',
    '                            &iHdr, NVOCMP_FINDSTRICT, NULL);',
    '            if((status == NVINTF_SUCCESS) && (iHdr.hofs > 0))',
    '            {',
    '              NVOCMP_setItemInactive(pNvHandle, iHdr.hpage, iHdr.hofs);',
    '            }',
    '          }',
)

HELPER = _lines(
    '#if (NVOCMP_NVPAGES > NVOCMP_NVTWOP)',
    '/******************************************************************************',
    ' * @fn      NVOCMP_recoverRefreshOffsets',
    ' *',
    ' * @brief   Raise every page offset to its true data end (RAM only)',
    ' *',
    ' * @param   pNvHandle - pointer to NV handle',
    ' *',
    ' * ' + MARKER + ' P2a. A page reused as a transfer destination keeps',
    ' * the smaller end cursor its earlier transfer recorded, while later',
    ' * appends grew real content above it. Walking from the recorded cursor',
    ' * would miss live items and erase the page as falsely drained. Starting',
    ' * the walk at the true data end only ever visits more, never less, and',
    ' * erases still happen solely for fully walked pages. RAM only, never',
    ' * writes flash.',
    ' */',
    'static void NVOCMP_recoverRefreshOffsets(NVOCMP_nvHandle_t *pNvHandle)',
    '{',
    '  uint8_t pg;',
    '  uint16_t end;',
    '  for(pg = 0; pg < NVOCMP_NVSIZE; pg++)',
    '  {',
    '    end = NVOCMP_findOffset(pg, FLASH_PAGE_SIZE);',
    '    if(end > pNvHandle->pageInfo[pg].offset)',
    '    {',
    '      pNvHandle->pageInfo[pg].offset = end;',
    '    }',
    '  }',
    '}',
    '/******************************************************************************',
    ' * @fn      NVOCMP_recoverCopiesEqual',
    ' * @brief   Prove both records are CRC-valid, bounded, equal copies.',
    ' */',
    'static bool NVOCMP_recoverCopiesEqual(const NVOCMP_itemHdr_t *a, const NVOCMP_itemHdr_t *b)',
    '{',
    '  uint8_t aBytes[NVOCMP_XFERBLKMAX], bBytes[NVOCMP_XFERBLKMAX];',
    '  uint16_t done = 0, count;',
    '  if(a->len != b->len || a->hofs < NVOCMP_PGDATAOFS || b->hofs < NVOCMP_PGDATAOFS',
    '     || a->len > a->hofs - NVOCMP_PGDATAOFS || b->len > b->hofs - NVOCMP_PGDATAOFS)',
    '  {',
    '    return(false);',
    '  }',
    '  if(NVOCMP_verifyCRC(a->hofs - a->len, a->len, a->crc8, a->hpage, false)',
    '     || NVOCMP_verifyCRC(b->hofs - b->len, b->len, b->crc8, b->hpage, false))',
    '  {',
    '    return(false);',
    '  }',
    '  while(done < a->len)',
    '  {',
    '    count = a->len - done;',
    '    if(count > NVOCMP_XFERBLKMAX) count = NVOCMP_XFERBLKMAX;',
    '    NVOCMP_read(a->hpage, a->hofs - a->len + done, aBytes, count);',
    '    NVOCMP_read(b->hpage, b->hofs - b->len + done, bBytes, count);',
    '    if(memcmp(aBytes, bBytes, count)) return(false);',
    '    done += count;',
    '  }',
    '  return(true);',
    '}',
    '/******************************************************************************',
    ' * @fn      NVOCMP_recoverFindActive',
    ' *',
    ' * @brief   Quietly test whether an active copy of an item id lives on',
    ' *          any page but the given one (read-only, never heals, never',
    ' *          compacts)',
    ' *',
    ' * @param   pNvHandle - pointer to NV handle',
    ' * @param   copy - destination record requiring an identical valid survivor',
    ' * @param   skipPg - page to exclude from the search',
    ' *',
    ' * @return  true when an active copy was found',
    ' */',
    'static bool NVOCMP_recoverFindActive(NVOCMP_nvHandle_t *pNvHandle, const NVOCMP_itemHdr_t *copy, uint8_t skipPg)',
    '{',
    '  uint8_t pg;',
    '  uint16_t ofs;',
    '  NVOCMP_itemHdr_t iHdr;',
    '  for(pg = 0; pg < NVOCMP_NVSIZE; pg++)',
    '  {',
    '    if(pg == skipPg)',
    '    {',
    '      continue;',
    '    }',
    '    ofs = pNvHandle->pageInfo[pg].offset;',
    '    while(ofs >= (NVOCMP_PGDATAOFS + NVOCMP_ITEMHDRLEN))',
    '    {',
    '      ofs -= NVOCMP_ITEMHDRLEN;',
    '      NVOCMP_readHeader(pg, ofs, &iHdr, false);',
    '      if((iHdr.stats & NVOCMP_ACTIVEIDBIT) && !(iHdr.stats & NVOCMP_VALIDIDBIT)',
    '         && (copy->cmpid == iHdr.cmpid) && NVOCMP_recoverCopiesEqual(copy, &iHdr))',
    '      {',
    '        return(true);',
    '      }',
    '      if((iHdr.stats & NVOCMP_FOLLOWBIT) && (iHdr.len < ofs))',
    '      {',
    '        ofs -= iHdr.len;',
    '      }',
    '      else if(iHdr.stats & NVOCMP_FOLLOWBIT)',
    '      {',
    '        break;',
    '      }',
    '    }',
    '  }',
    '  return(false);',
    '}',
    '/******************************************************************************',
    ' * @fn      NVOCMP_recoverSettleDestination',
    ' *',
    ' * @brief   Drop provable duplicate copies from the interrupted transfer',
    ' *          destination, then let the caller re-compact',
    ' *',
    ' * @param   pNvHandle - pointer to NV handle',
    ' *',
    ' * ' + MARKER + ' P2b. The destination holds verbatim copies: dropping',
    ' * one of two live copies is safe, dropping the sole copy is not.',
    ' * Inactivate each destination copy that still has a live original',
    ' * elsewhere; keep sole survivors. The caller re-compaction then copies',
    ' * every item exactly once with nowhere to duplicate from. Best effort',
    ' * by design: a rejected inactivation only leaks, it never loses.',
    ' * Disagreeing topologies reconcile to nothing and re-compact',
    ' * duplicates but cannot lose data.',
    ' */',
    'static void NVOCMP_recoverSettleDestination(NVOCMP_nvHandle_t *pNvHandle)',
    '{',
    '  uint8_t pg;',
    '  uint8_t dstPg = NVOCMP_NVSIZE;',
    '  uint8_t cdstPages = 0;',
    '  uint16_t ofs;',
    '  NVOCMP_itemHdr_t iHdr;',
    '  for(pg = 0; pg < NVOCMP_NVSIZE; pg++)',
    '  {',
    '    if(pNvHandle->pageInfo[pg].mode == NVOCMP_PGCDST)',
    '    {',
    '      cdstPages++;',
    '      dstPg = pg;',
    '    }',
    '  }',
    '  if(cdstPages != 1)',
    '  {',
    '    return;',
    '  }',
    '  ofs = pNvHandle->pageInfo[dstPg].offset;',
    '  while(ofs >= (NVOCMP_PGDATAOFS + NVOCMP_ITEMHDRLEN))',
    '  {',
    '    ofs -= NVOCMP_ITEMHDRLEN;',
    '    NVOCMP_readHeader(dstPg, ofs, &iHdr, false);',
    '    if((iHdr.stats & NVOCMP_ACTIVEIDBIT) && !(iHdr.stats & NVOCMP_VALIDIDBIT)',
    '       && NVOCMP_recoverFindActive(pNvHandle, &iHdr, dstPg))',
    '    {',
    '      NVOCMP_setItemInactive(pNvHandle, dstPg, ofs);',
    '    }',
    '    if((iHdr.stats & NVOCMP_FOLLOWBIT) && (iHdr.len < ofs))',
    '    {',
    '      ofs -= iHdr.len;',
    '    }',
    '    else if(iHdr.stats & NVOCMP_FOLLOWBIT)',
    '    {',
    '      break;',
    '    }',
    '  }',
    '}',
    '#endif',
)

# Insert the helpers ahead of the multi-page NVOCMP_initNv definition.
HELPER_ANCHOR_OLD = _lines(
    '#if (NVOCMP_NVPAGES > NVOCMP_NVTWOP)',
    '/******************************************************************************',
    ' * @fn      NVOCMP_initNv',
)
HELPER_ANCHOR_NEW = HELPER + '\n\n' + HELPER_ANCHOR_OLD

# Refresh every offset right after the multi-page scan loop, before the
# recovery decision reads pageInfo.
REFRESH_ANCHOR_OLD = _lines(
    '    else',
    '    {',
    '      noPgNdef++;',
    '    }',
    '  }',
    '',
    '  // Decide Action based on Page Informations',
    '#if ((NVOCMP_NVPAGES != NVOCMP_NVONEP) && !defined(NVOCMP_MIGRATE_DISABLED))',
    '  if(noPgLeg > 0)',
)
REFRESH_ANCHOR_NEW = _lines(
    '    else',
    '    {',
    '      noPgNdef++;',
    '    }',
    '  }',
    '',
    '  /* ' + MARKER + ' P2a: walk from true data ends, never stale cursors. */',
    '  NVOCMP_recoverRefreshOffsets(pNvHandle);',
    '',
    '  // Decide Action based on Page Informations',
    '#if ((NVOCMP_NVPAGES != NVOCMP_NVONEP) && !defined(NVOCMP_MIGRATE_DISABLED))',
    '  if(noPgLeg > 0)',
)

CASE_OLD = _lines(
    '  case NVOCMP_RECOVER_COMPACT :',
    '      pNvHandle->tailPage = pgXdst;',
    '      pNvHandle->headPage = NVOCMP_INCPAGE(pgXdst);',
    '      NVOCMP_failW = NVOCMP_erase(pNvHandle, pgXdst);',
    '      NVOCMP_changePageState(pNvHandle, pgXdst, NVOCMP_PGXDST);',
    '      pNvHandle->forceCompact = 1;',
    '      NVOCMP_compactPage(pNvHandle, 0);',
    '      break;',
)
CASE_NEW = _lines(
    '  case NVOCMP_RECOVER_COMPACT :',
    '      /* ' + MARKER + ' P2b: drop provable duplicates first, then',
    '         re-compact exactly once per item. */',
    '      NVOCMP_recoverSettleDestination(pNvHandle);',
    '      pNvHandle->tailPage = pgXdst;',
    '      pNvHandle->headPage = NVOCMP_INCPAGE(pgXdst);',
    '      NVOCMP_failW = NVOCMP_erase(pNvHandle, pgXdst);',
    '      NVOCMP_changePageState(pNvHandle, pgXdst, NVOCMP_PGXDST);',
    '      pNvHandle->forceCompact = 1;',
    '      NVOCMP_compactPage(pNvHandle, 0);',
    '      break;',
)


def apply_fix(nvocmp):
    """Apply P1+P2+P3 to a pristine pinned nvocmp.c. Returns edit records."""
    text = nvocmp.read_bytes()
    if hashlib.sha256(text.replace(b'\r\n', b'\n')).hexdigest() != PRISTINE_ALGO_SHA256:
        raise ValueError(str(nvocmp) + ': TI source pin mismatch, refusing to patch')
    ex = Exact()
    ex.replace(nvocmp, P1_OLD, P1_NEW, 't832-r8.recovery.p1-resume-destination')
    ex.replace(nvocmp, P3_OLD, P3_NEW, 't832-r8.recovery.p3-no-resume-compact')
    ex.replace(nvocmp, HELPER_ANCHOR_OLD, HELPER_ANCHOR_NEW, 't832-r8.recovery.p2-helpers')
    ex.replace(nvocmp, REFRESH_ANCHOR_OLD, REFRESH_ANCHOR_NEW, 't832-r8.recovery.p2a-refresh-call')
    ex.replace(nvocmp, CASE_OLD, CASE_NEW, 't832-r8.recovery.p2b-settle-call')
    return ex.edits


def verify_fixed(text):
    """Fail-closed fingerprint of a patched nvocmp.c. Returns evidence dict."""
    text = text.replace('\r\n', '\n')
    for marker in (MARKER, 'NVOCMP_recoverSettleDestination',
                   'NVOCMP_recoverRefreshOffsets',
                   'NVOCMP_recoverFindActive',
                   'NVOCMP_changePageState(pNvHandle, pgXdst, NVOCMP_PGXDST);'):
        if marker not in text:
            raise ValueError('recovery fix marker missing: ' + marker)
    # P1_OLD is the full stale-tailPage block; the single tailPage-mark line
    # also legitimately occurs in RECOVER_ERASE (with tailPage assigned),
    # so only the block proves the defect.
    for forbidden in (P1_OLD, P3_OLD):
        if forbidden in text:
            raise ValueError('unpatched recovery defect still present')
    added = '\n'.join((P1_NEW, P3_NEW, HELPER, CASE_NEW))
    for forbidden in ('eraseNvApi', 'eraseNV', 'RECOVER_FROM_COMPACT_FAILURE',
                      'FORCE_CLEAN'):
        if forbidden in added:
            raise ValueError('destructive recovery primitive in patch: ' + forbidden)
    return {'fix_id': FIX_ID,
            'patched_sha256': hashlib.sha256(text.encode()).hexdigest(),
            'pristine_sha256': PRISTINE_ALGO_SHA256}
