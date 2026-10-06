"""T832 R8 fail-safe power-cut recovery for pinned TI NVOCMP.

M1 root cause (R7 SHA 3d8129d, hosted run 37494326769, TI SDK 8.32 pin
6499c3f53fc5fb5806213be695450a7b43fbaf3d, nvocmp.c LF sha256
d37c7f314696c8669413cfb098900e41ffd2a4d48704481e5dd8c9a8c012d6d6):
ten interrupted-compaction cuts fail per lane out of 108 sampled (201
physical operations total). Three upstream defects, all in NVOCMP_initNv:

P1 (cuts 26/116/144/172/187 init FAILURE, cut 200 reserve FAILURE):
the no-source/no-destination resume branch marks ``pNvHandle->tailPage``
which is still zero from the fresh-handle memset (initNvApi), instead of
the just-selected ``pgXdst``. When page 0 is programmed the NOR-illegal
0x7C/0x78->0xFE state replay is rejected and init returns FAILURE; when
page 0 happens to be erased the wrong page is stranded XDST and 2032
free bytes become invisible (1772 < 2048 on cut 200 whose true free is
3804). One-token fix: mark ``pgXdst``.

P2 (cuts 19/81/109 reserve FAILURE, cut 179 combined FAILURE): the
interrupted transfer's destination (PGCDST mode) holds copies whose
originals are still live, because source invalidation only happens when
cleanPage erases a fully drained source after the transfer ends.
RECOVER_COMPACT re-compacts without settling that page, so both copies
are transferred again and the duplicates leak about one page of reserve
permanently (1777/1795/1777/1993 < 2048). Fix: when the destination
compact headers prove the copy finished, complete the transfer
bookkeeping exactly as a finished transfer would (erase drained
sources, record the end offset, mark the destination done, advance
tail/head) with no re-copying; when the headers are absent or torn the
copy never finished and cleanPage never ran for it, so the partial
destination provably holds only duplicates and is erased before the
caller re-compacts; when the headers disagree with the source states
nothing is erased and the caller re-compacts (duplicates but no loss).

P3 (read-only reopen mutation): NORMAL_RESUME runs a full maintenance
compaction whenever the active page tail item is complete, so every
healthy reopen rewrites page states/modes (persisted per operation).
A fresh-process read-only reopen must perform zero physical mutations
in the normal path, and on-demand (update-path) compaction already
self-regulates space, so the unconditional resume-time compaction is
removed. Genuine tail healing (FOLLOWBIT set) is untouched.

Safety properties of the patch: no NV erase/reformat primitive is
added (NVOCMP_eraseNvApi/RECOVER_FROM_COMPACT_FAILURE stay absent),
no reserve constant is relaxed, erased pages selected as destinations
are no-ops to erase, and every added flash write is either over erased
bytes or gated on NOR 1->0 legality with the RAM view always updated.

All patch strings are built with explicit LF joins so Exact matching
works on Linux checkouts regardless of local line endings.
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from apply_diag import Exact

FIX_ID = 't832-r8-nv-recovery-01'
# LF sha256 of the pristine pinned nvocmp.c this patch applies to.
PRISTINE_ALGO_SHA256 = 'd37c7f314696c8669413cfb098900e41ffd2a4d48704481e5dd8c9a8c012d6d6'
PRISTINE_SDK_COMMIT = '6499c3f53fc5fb5806213be695450a7b43fbaf3d'

MARKER = 'T832-R8 power-cut recovery (t832-r8-nv-recovery-01)'


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

# P3: drop the unconditional resume-time maintenance compaction. Healing a
# torn tail item (FOLLOWBIT set) stays; a complete tail item needs nothing.
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
    '          /* ' + MARKER + ' P3: no maintenance compaction on resume. A',
    '             complete tail item needs no action; on-demand compaction',
    '             still self-regulates space. This keeps a read-only reopen',
    '             free of physical mutations in the normal path. */',
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
    ' * @fn      NVOCMP_recoverInterruptedTransfer',
    ' *',
    ' * @brief   Settle the transfer interrupted by a power cut',
    ' *',
    ' * @param   pNvHandle - pointer to NV handle',
    ' *',
    ' * @return  true when the interrupted transfer was completed and the',
    ' *          caller must skip re-compaction, false when the caller must',
    ' *          run NVOCMP_compactPage (no partial destination, or the',
    ' *          partial destination was discarded, or its headers disagree',
    ' *          with the source states so it is left alone)',
    ' *',
    ' * ' + MARKER + ' P2. An interrupted transfer leaves its destination',
    ' * page in PGCDST mode holding copies whose originals are still live:',
    ' * sources are invalidated only when cleanPage erases a fully drained',
    ' * source after the transfer ends. Re-compacting without settling that',
    ' * page copies both copies and the duplicates leak reserve permanently.',
    ' * Complete destination headers prove the copy finished (they are the',
    ' * last writes of NVOCMP_compact on a freshly erased page, so they',
    ' * cannot be stale), hence every source ahead of the end cursor was',
    ' * fully walked and drained: erase those sources, record the end',
    ' * offset, mark the destination done and advance tail/head exactly as',
    ' * a finished transfer would, without re-copying a single item. Absent',
    ' * or torn headers prove the copy never finished, so cleanPage never',
    ' * ran for this transfer and the partial destination provably holds',
    ' * only duplicates: erase it before the caller re-compacts.',
    ' * Disagreeing headers are never erased: plain re-compaction then',
    ' * duplicates but cannot lose data.',
    ' */',
    'static bool NVOCMP_recoverInterruptedTransfer(NVOCMP_nvHandle_t *pNvHandle)',
    '{',
    '  uint8_t pg;',
    '  uint8_t mode;',
    '  uint8_t dstPg = NVOCMP_NVSIZE;',
    '  uint8_t cdstPages = 0;',
    '  uint8_t cleanPages = 0;',
    '  uint8_t tmpPg;',
    '  uint16_t rangeLen;',
    '  uint16_t dstEnd;',
    '  uint16_t curOff;',
    '  NVOCMP_compactHdr_t startHdr;',
    '  NVOCMP_compactHdr_t endHdr;',
    '  NVOCMP_pageHdr_t pageHdr;',
    '',
    '  for(pg = 0; pg < NVOCMP_NVSIZE; pg++)',
    '  {',
    '    if(pNvHandle->pageInfo[pg].mode == NVOCMP_PGCDST)',
    '    {',
    '      cdstPages++;',
    '      dstPg = pg;',
    '    }',
    '  }',
    '  if(cdstPages == 0)',
    '  {',
    '    return(false);',
    '  }',
    '  if(cdstPages > 1)',
    '  {',
    '    return(false);',
    '  }',
    '  NVOCMP_getCompactHdr(dstPg, XSRCSTARTHDR, &startHdr);',
    '  NVOCMP_getCompactHdr(dstPg, XSRCENDHDR, &endHdr);',
    '  if((startHdr.signature != NVOCMP_SIGNATURE) || (endHdr.signature != NVOCMP_SIGNATURE))',
    '  {',
    '    NVOCMP_failW |= NVOCMP_erase(pNvHandle, dstPg);',
    '    return(false);',
    '  }',
    '  rangeLen = (uint16_t)(((uint16_t)endHdr.page - (uint16_t)startHdr.page + NVOCMP_NVSIZE) % NVOCMP_NVSIZE) + 1u;',
    '  if((startHdr.page >= NVOCMP_NVSIZE) || (endHdr.page >= NVOCMP_NVSIZE)',
    '     || (endHdr.pageOffset > FLASH_PAGE_SIZE) || (endHdr.pageOffset == NVOCMP_NULLOFFSET)',
    '     || (rangeLen >= NVOCMP_NVSIZE))',
    '  {',
    '    return(false);',
    '  }',
    '  if((pNvHandle->pageInfo[startHdr.page].state != NVOCMP_PGXSRC)',
    '     && (pNvHandle->pageInfo[startHdr.page].state != NVOCMP_PGNACT))',
    '  {',
    '    return(false);',
    '  }',
    '  if((pNvHandle->pageInfo[endHdr.page].state == NVOCMP_PGNACT)',
    '     && (endHdr.pageOffset != NVOCMP_PGDATAOFS))',
    '  {',
    '    return(false);',
    '  }',
    '  pg = startHdr.page;',
    '  while(pg != endHdr.page)',
    '  {',
    '    if(pg == dstPg)',
    '    {',
    '      return(false);',
    '    }',
    '    pg = NVOCMP_INCPAGE(pg);',
    '  }',
    '  if(endHdr.page == dstPg)',
    '  {',
    '    return(false);',
    '  }',
    '  pg = startHdr.page;',
    '  while(pg != endHdr.page)',
    '  {',
    '    NVOCMP_failW |= NVOCMP_erase(pNvHandle, pg);',
    '    cleanPages++;',
    '    pg = NVOCMP_INCPAGE(pg);',
    '  }',
    '  pNvHandle->pageInfo[endHdr.page].offset = endHdr.pageOffset;',
    '  NVOCMP_read(endHdr.page, (THISPAGEHDR + 1) * NVOCMP_COMPACTHDRLEN, (uint8_t *)&curOff, sizeof(curOff));',
    '  /* Never dirty an erased page, and never replay offset bits illegally:',
    '     the RAM view above is always updated, the flash record only when',
    '     the write is a no-op or a strict 1->0 transition. */',
    '  if((pNvHandle->pageInfo[endHdr.page].state != NVOCMP_PGNACT)',
    '     && (curOff != endHdr.pageOffset) && ((curOff & endHdr.pageOffset) == endHdr.pageOffset))',
    '  {',
    '    NVOCMP_failW |= NVOCMP_write(endHdr.page, (THISPAGEHDR + 1) * NVOCMP_COMPACTHDRLEN,',
    '                                  (uint8_t *)&endHdr.pageOffset, sizeof(endHdr.pageOffset));',
    '  }',
    '  dstEnd = NVOCMP_findOffset(dstPg, FLASH_PAGE_SIZE);',
    '  pNvHandle->pageInfo[dstPg].offset = dstEnd;',
    '  NVOCMP_read(dstPg, NVOCMP_PGHDROFS, (uint8_t *)&pageHdr, NVOCMP_PGHDRLEN);',
    '  if((pageHdr.state != NVOCMP_PGFULL) && (pageHdr.state != NVOCMP_PGACT))',
    '  {',
    '    NVOCMP_changePageState(pNvHandle, dstPg,',
    '      ((FLASH_PAGE_SIZE - dstEnd) >= 16) ? NVOCMP_PGACT : NVOCMP_PGFULL);',
    '  }',
    '  mode = NVOCMP_PGCDONE;',
    '  NVOCMP_writeByte(dstPg, NVOCMP_COMPMODEOFS, mode);',
    '  pNvHandle->pageInfo[dstPg].mode = mode;',
    '  pNvHandle->tailPage = NVOCMP_ADDPAGE(dstPg, cleanPages);',
    '  pNvHandle->headPage = NVOCMP_INCPAGE(pNvHandle->tailPage);',
    '  tmpPg = NVOCMP_findPage(NVOCMP_PGACT);',
    '  if(tmpPg == NVOCMP_NULLPAGE)',
    '  {',
    '    tmpPg = NVOCMP_findPage(NVOCMP_PGRDY);',
    '    if(tmpPg == NVOCMP_NULLPAGE)',
    '    {',
    '      if(pNvHandle->pageInfo[pNvHandle->headPage].state == NVOCMP_PGNACT)',
    '      {',
    '        tmpPg = pNvHandle->headPage;',
    '        NVOCMP_changePageState(pNvHandle, tmpPg, NVOCMP_PGRDY);',
    '      }',
    '      else',
    '      {',
    '        tmpPg = NVOCMP_DECPAGE(pNvHandle->tailPage);',
    '      }',
    '    }',
    '  }',
    '  pNvHandle->actPage = tmpPg;',
    '  pNvHandle->actOffset = pNvHandle->pageInfo[pNvHandle->actPage].offset;',
    '  pNvHandle->forceCompact = 0;',
    '  return(true);',
    '}',
    '#endif',
)

# Insert the helper ahead of the multi-page NVOCMP_initNv definition.
HELPER_ANCHOR_OLD = _lines(
    '#if (NVOCMP_NVPAGES > NVOCMP_NVTWOP)',
    '/******************************************************************************',
    ' * @fn      NVOCMP_initNv',
)
HELPER_ANCHOR_NEW = HELPER + '\n\n' + HELPER_ANCHOR_OLD

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
    '      pNvHandle->tailPage = pgXdst;',
    '      pNvHandle->headPage = NVOCMP_INCPAGE(pgXdst);',
    '      NVOCMP_failW = NVOCMP_erase(pNvHandle, pgXdst);',
    '      NVOCMP_changePageState(pNvHandle, pgXdst, NVOCMP_PGXDST);',
    '      /* ' + MARKER + ' P2: settle the interrupted transfer first. */',
    '      if(!NVOCMP_recoverInterruptedTransfer(pNvHandle))',
    '      {',
    '        pNvHandle->forceCompact = 1;',
    '        NVOCMP_compactPage(pNvHandle, 0);',
    '      }',
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
    ex.replace(nvocmp, HELPER_ANCHOR_OLD, HELPER_ANCHOR_NEW, 't832-r8.recovery.p2-helper')
    ex.replace(nvocmp, CASE_OLD, CASE_NEW, 't832-r8.recovery.p2-recover-case')
    return ex.edits


def verify_fixed(text):
    """Fail-closed fingerprint of a patched nvocmp.c. Returns evidence dict."""
    text = text.replace('\r\n', '\n')
    for marker in (MARKER, 'NVOCMP_recoverInterruptedTransfer',
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
