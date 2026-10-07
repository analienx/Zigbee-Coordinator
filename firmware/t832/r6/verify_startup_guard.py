"""Actual pinned driver; run only in GitHub-hosted Actions.

R10 preservation corpus v2 (F1-F9): compact-header negatives using
physically plausible 1->0 corruption, legacy fail-closed negatives,
multi-ACT agreement-proof locks (agreeing twins admitted, divergent live
values rejected), exact sanity-bitmask asserts, and derived
(never hard-coded) evidence. The Python oracles below
mirror classifier policy for case construction; they are not independent
proof of the driver. Only the hosted driver-probe runs count as execution
evidence. Q2 adds host-side read accounting plus an analytic per-image
startup-read bound; the cost verb measures, the bound gates.
"""
import argparse
import hashlib
import itertools
import json
import os
import shutil
import subprocess
from pathlib import Path

from nv_recovery_fix import apply_fix

HERE = Path(__file__).resolve().parent
PAGE = 2048
NVPAGES = 15
PGDATAOFS = 16
FLASH_PAGE_SIZE = 2048
CORPUS_VERSION = 'enumerated-v2'
SANITIZER_FLAGS = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                   '-fno-omit-frame-pointer']
ADMIT_MAX_OPS = 8
INVOKE_TIMEOUT = 20
VALID_STATES = frozenset((0xFF, 0xFE, 0x7E, 0x7C, 0x78, 0x70))
LEGACY_STATES = frozenset((0xA5, 0x24))
STATE_NAMES = {0xFF: 'nact', 0xFE: 'xdst', 0x7E: 'rdy', 0x7C: 'act',
               0x78: 'full', 0x70: 'xsrc'}
MODE_VALUES = frozenset((0xFF, 0xFE, 0xFC, 0xF8))
SIG_VALUES = frozenset((0xFF, 0x96))


class GateError(RuntimeError):
    """Explicit evidence-gate failure; never stripped by python -O."""


def check(cond, msg, **ctx):
    if not cond:
        raise GateError(msg + ' :: ' + json.dumps(ctx, default=str, sort_keys=True))


def torn(byte, offset):
    """Valid-NOR torn encoding: clear a strict subset of pristine 1-bits to a
    value the startup classifier must reject. Fails closed if no mask applies."""
    for mask in (0xF0, 0x0F):
        v = byte & mask
        if v == byte:
            continue
        if offset == 0 and v in VALID_STATES:
            continue
        if offset == 2 and (v >> 2) == 0x03:
            continue
        if offset == 3 and v == 0x96:
            continue
        return mask, v
    raise ValueError('no torn encoding for byte 0x%02x at header offset %d' % (byte, offset))


def put1to0(b, off, val, case):
    """Program one byte; refuse anything that is not a plausible NOR 1->0."""
    old = b[off]
    check(((old & val) == val), 'mutation not physically plausible 1->0',
          case=case, offset=off, old=hex(old), new=hex(val))
    b[off] = val


def copy_page_1to0(b, src_pg, dst_pg, case):
    for i in range(PAGE):
        put1to0(b, dst_pg * PAGE + i, b[src_pg * PAGE + i], case)


def find_end(page):
    """Mirror of driver NVOCMP_findOffset(pg, FLASH_PAGE_SIZE): last non-0xFF
    byte + 1 over the whole 2KB page; an all-erased page yields 1."""
    check(len(page) == PAGE, 'find_end page size', size=len(page))
    i = PAGE - 1
    while i >= 0 and page[i] == 0xFF:
        i -= 1
    if i < 0:
        return 1
    return i + 1


def hdr_len(b3, b4):
    # HDRLE=0 branch of NVOCMP_readHeader.
    return ((b3 & 0x3F) << 6) | ((b4 >> 2) & 0x3F)


def on_boundary(page, cursor, end_true):
    """Mirror of the preflight item-boundary walk: NV items pack data-first
    from PGDATAOFS with each 7-byte header last. Walk downward from the true
    data end; true only when cursor lands exactly on an item boundary.
    Structure only; bounded and read-only."""
    pos = end_true
    steps = 0
    if cursor < PGDATAOFS or cursor > end_true:
        return False
    if cursor == end_true:
        return True
    while pos > cursor:
        if pos < PGDATAOFS + 7:
            return False
        ln = hdr_len(page[pos - 7 + 3], page[pos - 7 + 4])
        if ln > pos - 7 - PGDATAOFS:
            return False
        pos -= 7 + ln
        steps += 1
        if steps > 512:
            return False
    return pos == cursor


def parse_item(page, hofs):
    """HDRLE=0 item header parse mirroring NVOCMP_readHeader. Returns dict
    with sysid/itemid/subid/len/crc/stats/follow/live/hofs."""
    b = page[hofs:hofs + 7]
    stats = b[5] & 0x03
    follow = (b[6] == 0x96)
    return {'sysid': (b[0] >> 2) & 0x3F,
            'itemid': ((b[0] & 0x03) << 8) | b[1],
            'subid': ((b[2] << 2) & 0x3FF) | ((b[3] >> 6) & 0x03),
            'len': ((b[3] & 0x3F) << 6) | ((b[4] >> 2) & 0x3F),
            'crc': ((b[4] & 0x03) << 6) | ((b[5] >> 2) & 0x3F),
            'stats': stats, 'follow': follow, 'hofs': hofs,
            'live': bool(follow and (stats & 0x02) and not (stats & 0x01))}


def walk_live(page):
    """Mirror of the C proof walk: collect live headers down the chain,
    sliding past unrecognized tail bytes bounded. Returns (live, anomaly).
    Signature-recognized headers below a dead tail are walked, not
    skipped (the walk keys on FOLLOWBIT like resume's tail check);
    dedup is ID-specific so they converge without effect."""
    live = []
    pos = find_end(page)
    steps = slides = 0
    while True:
        if pos <= PGDATAOFS:
            return live, False
        if pos < PGDATAOFS + 7:
            return live, True
        h = parse_item(page, pos - 7)
        if h['follow']:
            if h['len'] > pos - 7 - PGDATAOFS:
                return live, True
            pos -= 7 + h['len']
            steps += 1
            if steps > 512:
                return live, True
            if h['live']:
                live.append(h)
        else:
            pos -= 1
            slides += 1
            if slides > 64:
                return live, True


# Q2 startup-cost model (T832 constants: FASTOFF=1 whole-page findOffset at
# 1 call x 2048B, no RAM_OPTIMIZATION, readHeader 1 call x 7B,
# XFERBLKMAX=32, HDRCRCINC=5). Every walk is capped (512 steps, 64 slides);
# anomalies only end walks early, so caps computed from a clean-end census
# soundly bound any image.
Q2_WALK_CALLS = 1 + 513 + 65  # findOffset + steps + slides at trip points
Q2_WALK_BYTES = 2048 + (513 + 65) * 7
Q2_DRIVER_CALLS_PER_INIT = NVPAGES * 1200  # flat scan/resume allowance
Q2_DRIVER_BYTES_PER_INIT = NVPAGES * (2048 + 8400)


def _q2_copies_equal(maxlen):
    """(calls, bytes) for one NVOCMP_recoverCopiesEqual at payload maxlen."""
    n = maxlen + 4  # +HDRCRCINC-1
    crc_calls = (n + 31) // 32
    cmp_calls = (maxlen + 31) // 32 if maxlen else 0
    return 2 * crc_calls + 2 * cmp_calls, 2 * n + 2 * maxlen


def q2_parse_stack_su(text):
    """Parse gcc -fstack-usage output (path:line:col:func TAB bytes TAB
    kind) into {func: {'bytes': n, 'kind': k}}."""
    frames = {}
    for line in text.splitlines():
        toks = line.split()
        if len(toks) != 3 or not toks[1].isdigit():
            continue
        frames[toks[0].split(':')[-1]] = {'bytes': int(toks[1]), 'kind': toks[2]}
    return frames


Q2_STACK_FRAMES = ('NVOCMP_startupClassify', 'NVOCMP_startupPageTwinned',
                   'NVOCMP_startupSuffixTwinned', 'NVOCMP_startupActConflict',
                   'NVOCMP_startupWalkNext', 'NVOCMP_startupWalkInit',
                   'NVOCMP_startupOnBoundary', 'NVOCMP_startupErased',
                   'NVOCMP_recoverCopiesEqual')


def q2_census(img):
    """Per-page census for the cost bound: state, compact mode, live-header
    count (capped at walk capacity), max payload length."""
    pages = []
    for pg in range(NVPAGES):
        page = img[pg * PAGE:(pg + 1) * PAGE]
        live, _ = walk_live(page)
        pages.append({'state': page[0], 'mode': page[6],
                      'live': min(len(live), 513),
                      'maxlen': min(max([h['len'] for h in live] + [0]), 2048)})
    return pages


def q2_classify_bound(census):
    """Sound per-init (calls, bytes) ceiling for NVOCMP_startupClassify on
    an image with the given census. Assumes every walk runs to a clean end
    with no early exit; any anomaly or early reject only reads less."""
    calls, nbytes = 0, 0
    for p in census:
        # page-header read, erased scan, compact-meta read, cursor
        # findOffset + boundary walk (513 reads at its trip point).
        calls += 1 + 64 + 1 + 1 + 513
        nbytes += 4 + 2048 + 12 + 2048 + 513 * 7
    chk = [p for p in census if p['state'] in (0x7C, 0x78, 0x70)]
    nchk = len(chk)
    htot = sum(p['live'] for p in chk)
    hmax = max([p['live'] for p in chk] + [0])
    lmax = max([p['maxlen'] for p in chk] + [0])
    ce_calls, ce_bytes = _q2_copies_equal(lmax)
    # tail block: cursor read + findOffset + tail header + tail CRC.
    calls += 1 + 1 + 1 + (lmax + 4 + 31) // 32
    nbytes += 4 + 2048 + 7 + lmax + 4
    # tail-ID census: one walk per chk page + one proof per older copy.
    calls += nchk * Q2_WALK_CALLS + htot * ce_calls
    nbytes += nchk * Q2_WALK_BYTES + htot * ce_bytes
    # pairwise proof: one outer walk per chk page; every live header
    # launches one conflict walk per chk page; cmpid matches re-prove.
    walks = nchk + htot * nchk
    calls += walks * Q2_WALK_CALLS + htot * nchk * hmax * ce_calls
    nbytes += walks * Q2_WALK_BYTES + htot * nchk * hmax * ce_bytes
    # F1 erase-branch twin proofs, only when a PGCDST page exists. The
    # driver runs PageTwinned on non-end range pages and SuffixTwinned on
    # the end page (any state); charging every page the PageTwinned shape
    # plus a boundary walk covers both, wherever the range lands.
    dst = [p for p in census if p['mode'] == 0xFE]
    if dst and nchk:
        hdst = max(p['live'] for p in dst)
        for p in census:
            calls += 1 + 513 + Q2_WALK_CALLS \
                + p['live'] * (Q2_WALK_CALLS + hdst * ce_calls)
            nbytes += 2048 + 513 * 7 + Q2_WALK_BYTES \
                + p['live'] * (Q2_WALK_BYTES + hdst * ce_bytes)
    return calls, nbytes


def _cmp(page, idx):
    o = 4 + idx * 4
    return {'off': page[o] | (page[o + 1] << 8), 'page': page[o + 2],
            'sig': page[o + 3], 'raw': bytes(page[o:o + 4])}


# Q3 reject-site mirror: numeric copy of the C NVOCMP_REJ_* enum in
# nv_startup_guard.py. Order-locked against the C source by
# test_startup_oracle; the hosted latch asserts cross-check every value.
REJ = {
    'NONE': 0, 'LEGACY': 1, 'HDR_SIGVER': 2, 'HDR_STATE': 3,
    'HDR_ALLACTIVE': 4, 'HDR_CYCLE': 5, 'NACT_DATA': 6, 'RDY_DATA': 7,
    'CMP_SIG': 8, 'CMP_MODE': 9, 'XSRC_PAGE': 10, 'XSRC_PAIR': 11,
    'XSRC_SIG': 12, 'XSRC_OFF': 13, 'CURSOR_RANGE': 14,
    'NACT_RDY_MODE': 15, 'RDY_CURSOR': 16, 'NACT_CURSOR': 17,
    'SLOT_ERASE': 18, 'XDST_MODE': 19, 'XDST_CURSOR': 20,
    'CDST_STATE': 21, 'CDST_CURSOR': 22, 'CURSOR_ABOVE_END': 23,
    'CURSOR_OFF_BOUNDARY': 24, 'TOPO_COUNTS': 25, 'DUP_PGCDST': 26,
    'CENSUS_WALK': 27, 'TAIL_MIXED': 28, 'TAIL_MULTI': 29,
    'PAIR_WALK': 30, 'PAIR_CONFLICT': 31, 'ERASE_NULL_RANGE': 32,
    'ERASE_SPAN': 33, 'ERASE_DST_IN_RANGE': 34, 'ERASE_NONTWINNED': 35,
    'ERASE_END_NONTWINNED': 36, 'ERASE_EOFF_ABOVE': 37,
    'ERASE_SUFFIX_NONTWINNED': 38, 'ERASE_TAIL_MARK': 39,
}
NVINTF_SUCCESS = 0
NVINTF_FAILURE = 1
NVINTF_BADVERSION = 12
NULLPAGE = 0xFF


def crc8(data, crc=0):
    """TI crc.c mirror: CRC-8/poly-0x97, MSB-first, init 0, no reflection."""
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x97) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def crc_ok(page, h):
    """NVOCMP_verifyCRC mirror (HDRLE=0): payload plus the first 4 header
    bytes, then the length final byte, must equal the stored CRC."""
    if h['len'] > h['hofs']:
        return False
    span = bytes(page[h['hofs'] - h['len']:h['hofs'] + 4])
    return crc8(span + bytes([(h['len'] & 0x3F) << 2])) == h['crc']


def cmpid(h):
    return (h['sysid'], h['itemid'], h['subid'])


def copies_equal(img, apg, a, bpg, b):
    """NVOCMP_recoverCopiesEqual mirror: equal length, in-bounds headers,
    both CRCs valid, identical payload bytes."""
    if a['len'] != b['len']:
        return False
    for h in (a, b):
        if h['hofs'] < PGDATAOFS or h['len'] > h['hofs'] - PGDATAOFS:
            return False
    apage = img[apg * PAGE:(apg + 1) * PAGE]
    bpage = img[bpg * PAGE:(bpg + 1) * PAGE]
    if not crc_ok(apage, a) or not crc_ok(bpage, b):
        return False
    return (bytes(apage[a['hofs'] - a['len']:a['hofs']]) ==
            bytes(bpage[b['hofs'] - b['len']:b['hofs']]))


def suffix_twinned(img, epg, eoff, fpg):
    """Mirror of the C suffix proof: every live item strictly above eoff
    on the end page must be twinned (bounds, both CRCs, payload bytes)
    on the dst page. The outer walk must reach a clean end; the inner
    walk breaks at the first twin, so dst bytes below a found twin are
    never read and a dst anomaly past every twin still proves."""
    end_page = img[epg * PAGE:(epg + 1) * PAGE]
    if not on_boundary(end_page, eoff, find_end(end_page)):
        return False
    live, anomaly = walk_live(end_page)
    if anomaly:
        return False
    dst_live, _ = walk_live(img[fpg * PAGE:(fpg + 1) * PAGE])
    for h in live:
        if h['hofs'] > eoff:
            if not any(cmpid(g) == cmpid(h) and copies_equal(img, epg, h, fpg, g)
                       for g in dst_live):
                return False
    return True


def page_twinned(img, pg, fpg):
    """Mirror of the C whole-page twin proof (4c): every live item on
    page pg must be twinned (bounds, both CRCs, payload bytes) on the
    dst page. The outer walk must reach a clean end; each inner walk
    breaks at the first twin, so dst bytes below a found twin are never
    read and a dst anomaly past every twin still proves."""
    live, anomaly = walk_live(img[pg * PAGE:(pg + 1) * PAGE])
    if anomaly:
        return False
    dst_live, _ = walk_live(img[fpg * PAGE:(fpg + 1) * PAGE])
    for h in live:
        if not any(cmpid(g) == cmpid(h) and copies_equal(img, pg, h, fpg, g)
                   for g in dst_live):
            return False
    return True


def oracle_compact(page, state):
    """Policy mirror of the C compact preflight (structural half): replays
    the same admission rules, in the same order, for case construction,
    not independent proof. Returns (ok, tag, site, raw); the page is
    added by the caller."""
    this, start, end = _cmp(page, 0), _cmp(page, 1), _cmp(page, 2)
    for idx, h in ((3, this), (7, start), (11, end)):
        if h['sig'] not in SIG_VALUES:
            return False, 'CMP_SIG', REJ['CMP_SIG'], idx
    if this['page'] not in MODE_VALUES:
        return False, 'CMP_MODE', REJ['CMP_MODE'], this['page']
    for s, h in ((0, start), (1, end)):
        if h['page'] != 0xFF and not 0 <= h['page'] < NVPAGES:
            return False, 'CMP_PAGE_RANGE', REJ['XSRC_PAGE'], h['page']
        if (h['page'] == 0xFF) != (h['off'] == 0xFFFF):
            return False, 'CMP_NULL', REJ['XSRC_PAIR'], s
        if h['page'] != 0xFF and h['sig'] != 0x96:
            return False, 'CMP_RANGE_SIG', REJ['XSRC_SIG'], h['sig']
        if h['page'] != 0xFF and not 0 <= h['off'] <= FLASH_PAGE_SIZE:
            return False, 'CMP_OFFSET_RANGE', REJ['XSRC_OFF'], h['off'] & 0xFF
    if state in (0x7C, 0x78, 0x70):
        if this['off'] != 0xFFFF and not PGDATAOFS <= this['off'] <= FLASH_PAGE_SIZE:
            return False, 'CMP_CURSOR_RANGE', REJ['CURSOR_RANGE'], this['off'] & 0xFF
    if state in (0xFF, 0x7E):
        # NACT/RDY pages are never compact writers; mode must stay normal.
        # NACT offsets are forced to PGDATAOFS by scanPage, so the NACT
        # cursor slot tolerates quirk values: cleanPage can cursor-write
        # a fully-drained end offset onto an empty end page without changing
        # its state. RDY cursors are CONSUMED as data-end offsets (scanPage,
        # getDstPage, RESUME), so only the null and drained forms are
        # admitted: any other value, including a torn 16->0, could steer a
        # later write into the page header region. XSRC slots must stay in
        # an erase form, since no writer targets them on these states.
        # (C latches one shared site for both states here.)
        if this['page'] != 0xFF:
            return False, ('CMP_NACT_MODE' if state == 0xFF else 'CMP_RDY_MODE'), \
                REJ['NACT_RDY_MODE'], this['page']
        if state == 0x7E:
            if this['off'] != 0xFFFF and this['off'] != PGDATAOFS:
                return False, 'CMP_RDY_CURSOR', REJ['RDY_CURSOR'], this['off'] & 0xFF
        elif this['off'] != 0xFFFF and not 0 <= this['off'] <= FLASH_PAGE_SIZE:
            return False, 'CMP_QUIRK_CURSOR', REJ['NACT_CURSOR'], this['off'] & 0xFF
        for s2, h in ((0, start), (1, end)):
            if h['raw'] not in (b'\xff\xff\xff\xff', b'\xff\xff\xff\x96'):
                return False, 'CMP_STALE_FORM', REJ['SLOT_ERASE'], s2
    if state == 0xFE:
        if this['page'] not in (0xFF, 0xFE):
            return False, 'CMP_XDST_MODE', REJ['XDST_MODE'], this['page']
        if this['off'] != 0xFFFF:
            return False, 'CMP_XDST_CURSOR', REJ['XDST_CURSOR'], this['off'] & 0xFF
    if this['page'] == 0xFE:
        if state not in (0xFE, 0x7C, 0x78):
            return False, 'CMP_FE_STATE', REJ['CDST_STATE'], state
        if this['off'] != 0xFFFF:
            return False, 'CMP_FE_CURSOR', REJ['CDST_CURSOR'], this['off'] & 0xFF
    if state in (0x7C, 0x78, 0x70) and this['off'] != 0xFFFF:
        end_true = find_end(page)
        if this['off'] > end_true:
            return False, 'CMP_CURSOR_ABOVE_END', REJ['CURSOR_ABOVE_END'], \
                this['off'] & 0xFF
        if this['off'] < end_true and not on_boundary(page, this['off'], end_true):
            return False, 'CMP_CURSOR_MISALIGNED', REJ['CURSOR_OFF_BOUNDARY'], \
                this['off'] & 0xFF
    return True, 'CMP_OK', REJ['NONE'], 0


def _fwd(a, b):
    return (b - a + NVPAGES) % NVPAGES


def act_conflict(img, jpg, ipg, h, tail_ok, tail_id):
    """NVOCMP_startupActConflict mirror: true when page jpg holds a live
    copy of h's ID that is neither h itself nor a verbatim twin (bounds,
    both CRCs, payload) outside the tail exception, or when jpg cannot
    be walked to a clean end (a walk anomaly also returns true)."""
    live, anomaly = walk_live(img[jpg * PAGE:(jpg + 1) * PAGE])
    if anomaly:
        return True
    for g in live:
        if cmpid(g) == cmpid(h) and (jpg, g['hofs']) != (ipg, h['hofs']) \
                and not copies_equal(img, ipg, h, jpg, g) \
                and not (tail_ok and cmpid(h) == tail_id):
            return True
    return False


def oracle_f8_site(img, states, destinations, sources, data, inactive, cdst):
    """Exact C-order mirror of the F8 agreement proof. Returns
    (site, page, raw) for the first C reject, or None when C admits."""
    chk = [pg for pg in range(NVPAGES) if states[pg] in (0x7C, 0x78, 0x70)]
    act_pgs = [pg for pg in chk if states[pg] == 0x7C]
    resume_topo = (destinations == 1 and sources == 0) or \
        (destinations == 0 and sources == 0 and data and not cdst and inactive)
    tail_ok = False
    tail_id = None
    tail_h = None
    last_act = None
    if act_pgs and resume_topo:
        last_act = act_pgs[-1]
        page = img[last_act * PAGE:(last_act + 1) * PAGE]
        tail_end = find_end(page)
        if page[4] == 0xFF and page[5] == 0xFF and tail_end >= PGDATAOFS + 7:
            h = parse_item(page, tail_end - 7)
            if h['follow'] and h['live'] and h['len'] <= tail_end - 7 - PGDATAOFS \
                    and crc_ok(page, h):
                tail_ok = True
                tail_id = cmpid(h)
                tail_h = h
    if tail_ok:
        older = older_twin = 0
        for c, cpg in enumerate(chk):
            live, anomaly = walk_live(img[cpg * PAGE:(cpg + 1) * PAGE])
            if anomaly:
                return REJ['CENSUS_WALK'], cpg, c
            for h in live:
                if cmpid(h) == tail_id and (cpg, h['hofs']) != (last_act, tail_h['hofs']):
                    if copies_equal(img, last_act, tail_h, cpg, h):
                        older_twin += 1
                        if older > 0:
                            return REJ['TAIL_MIXED'], cpg, c
                    else:
                        older += 1
                        if older > 1 or older_twin > 0:
                            return REJ['TAIL_MULTI'], cpg, c
    for i, ipg in enumerate(chk):
        live, anomaly = walk_live(img[ipg * PAGE:(ipg + 1) * PAGE])
        if anomaly:
            return REJ['PAIR_WALK'], ipg, i
        for h in live:
            for j, jpg in enumerate(chk):
                if act_conflict(img, jpg, ipg, h, tail_ok, tail_id):
                    return REJ['PAIR_CONFLICT'], jpg, i
    return None


def _oracle_decision(img):
    """Policy mirror of classifier + driver startup decision: same rules,
    Python-side, for case construction; not independent proof. Returns
    (verdict, tag, latch) where verdict is 'REJECT' or 'ADMIT' and latch
    is the expected Q3 (status, site, page, raw) tuple. First failure in
    page-scan order wins, exactly like the C classifier's early returns."""
    check(len(img) == PAGE * NVPAGES, 'oracle image size', size=len(img))
    states, modes, spages, epages, eoffs = [], [], [], [], []
    inactive = destinations = sources = ready = data = 0
    for pg in range(NVPAGES):
        page = img[pg * PAGE:(pg + 1) * PAGE]
        if page == b'\xff' * PAGE:
            inactive += 1
            states.append(0xFF)
            modes.append(0xFF)
            spages.append(0xFF)
            epages.append(0xFF)
            eoffs.append(0xFFFF)
            continue
        state, verbyte, sig = page[0], page[2], page[3]
        legacy_field = ((verbyte >> 2) << 2) | (verbyte & 0x03)
        if sig == 0x96 and legacy_field == 0x02 and state in LEGACY_STATES:
            return 'REJECT', 'LEGACY', (NVINTF_FAILURE, REJ['LEGACY'], pg, state)
        if sig != 0x96 or (verbyte >> 2) != 0x03 or state not in VALID_STATES:
            # C checks signature/version before state; the latch follows.
            if sig != 0x96 or (verbyte >> 2) != 0x03:
                return 'REJECT', 'BAD_HEADER', \
                    (NVINTF_BADVERSION, REJ['HDR_SIGVER'], pg, sig)
            return 'REJECT', 'BAD_HEADER', \
                (NVINTF_BADVERSION, REJ['HDR_STATE'], pg, state)
        # F9: TI reserves allActive 1/2 and cycle 0x00/0xFF. A non-erased
        # current-format header carrying them is rejected.
        if (verbyte & 0x03) not in (0x00, 0x03):
            return 'REJECT', 'BAD_ALLACTIVE', \
                (NVINTF_BADVERSION, REJ['HDR_ALLACTIVE'], pg, verbyte & 0x03)
        if not 0x01 <= page[1] <= 0xFE:
            return 'REJECT', 'BAD_CYCLE', \
                (NVINTF_BADVERSION, REJ['HDR_CYCLE'], pg, page[1])
        if state == 0xFF and bytes(page[PGDATAOFS:]) != b'\xff' * (PAGE - PGDATAOFS):
            return 'REJECT', 'NACT_DATA', \
                (NVINTF_BADVERSION, REJ['NACT_DATA'], pg, 0)
        # L0-F7/CH-F2: a RDY page carrying data is a flash-fault
        # shape (mark-before-write lands data on ACT only, never RDY),
        # so it fails the scan (mirrored by the 4b C scan rule).
        if state == 0x7E and bytes(page[PGDATAOFS:]) != b'\xff' * (PAGE - PGDATAOFS):
            return 'REJECT', 'RDY_DATA', \
                (NVINTF_BADVERSION, REJ['RDY_DATA'], pg, 0)
        ok, tag, site, raw = oracle_compact(page, state)
        if not ok:
            return 'REJECT', tag, (NVINTF_BADVERSION, site, pg, raw)
        states.append(state)
        modes.append(_cmp(page, 0)['page'])
        spages.append(_cmp(page, 1)['page'])
        epages.append(_cmp(page, 2)['page'])
        eoffs.append(_cmp(page, 2)['off'])
        if state == 0xFF:
            inactive += 1
        elif state == 0xFE:
            destinations += 1
        elif state == 0x70:
            sources += 1
        elif state == 0x7E:
            ready += 1
        else:
            data += 1
    # C packs the topology counters into one raw byte for the latch.
    topo_raw = ((destinations & 3) | ((sources & 3) << 2) |
                ((ready & 3) << 4) | (64 if data else 0) |
                (128 if inactive != NVPAGES else 0))
    if destinations > 1:
        return 'REJECT', 'TOPO_DUP_XDST', \
            (NVINTF_FAILURE, REJ['TOPO_COUNTS'], NULLPAGE, topo_raw)
    if sources > 1:
        return 'REJECT', 'TOPO_DUP_XSRC', \
            (NVINTF_FAILURE, REJ['TOPO_COUNTS'], NULLPAGE, topo_raw)
    if ready > 1:
        return 'REJECT', 'TOPO_DUP_RDY', \
            (NVINTF_FAILURE, REJ['TOPO_COUNTS'], NULLPAGE, topo_raw)
    if inactive != NVPAGES and not destinations and not sources and not data:
        return 'REJECT', 'TOPO_LONE_OR_EMPTY', \
            (NVINTF_FAILURE, REJ['TOPO_COUNTS'], NULLPAGE, topo_raw)
    # F7: the driver consumes only the first PGCDST page, so ambiguous
    # destination metadata fails closed instead of silently picking one.
    cdst = sum(1 for m in modes if m == 0xFE)
    if cdst > 1:
        return 'REJECT', 'CMP_DUP_PGCDST', \
            (NVINTF_FAILURE, REJ['DUP_PGCDST'], NULLPAGE, cdst)
    # F8 agreement proof, mirrored in exact C traversal order (tail
    # census, then the pairwise walks): every pair of live copies
    # sharing an ID across (or within) ACT, FULL, and XSRC pages must
    # be verbatim twins (bounds, both CRCs, payload bytes). RESUME
    # reads from the last ACT while RECOVER_ERASE reads from the first,
    # so divergent copies would return different values on the two
    # paths; XSRC originals survive RECOVER_ERASE untouched, so an
    # XSRC/ACT divergent pair (CH-F3) is a live read-flip. Anything
    # unparseable fails closed. The tail-ID exception (live CRC-valid
    # tail of the NULL-cursor last ACT on a resume topology, resume
    # deduping the single older copy) is mirrored bit-for-bit,
    # including CRC validity.
    f8 = oracle_f8_site(img, states, destinations, sources, data,
                        inactive, cdst)
    if f8 is not None:
        site, page, raw = f8
        return 'REJECT', 'TOPO_ACT_CONFLICT', (NVINTF_FAILURE, site, page, raw)
    first_fe = next((pg for pg in range(NVPAGES) if modes[pg] == 0xFE), None)
    if inactive == NVPAGES:
        return 'ADMIT', 'ADMIT_INIT', (NVINTF_SUCCESS, REJ['NONE'], 0, 0)
    if sources:
        if destinations:
            return 'ADMIT', 'ADMIT_RECOVER_COMPACT', \
                (NVINTF_SUCCESS, REJ['NONE'], 0, 0)
        if inactive:
            return 'ADMIT', 'ADMIT_RECOVER_COMPACT_NACT', \
                (NVINTF_SUCCESS, REJ['NONE'], 0, 0)
        if first_fe is None:
            # P3: the classifier ADMITs (no latch); the driver then fails
            # with ERROR_UNKNOWN. Latch zeros are the correct expectation.
            return 'REJECT', 'DRIVER_UNKNOWN_LATCH', \
                (NVINTF_SUCCESS, REJ['NONE'], 0, 0)
    elif destinations:
        return 'ADMIT', 'ADMIT_RESUME_DIRECT', \
            (NVINTF_SUCCESS, REJ['NONE'], 0, 0)
    elif data:
        if first_fe is None:
            if inactive:
                return 'ADMIT', 'ADMIT_RESUME_MARK', \
                    (NVINTF_SUCCESS, REJ['NONE'], 0, 0)
            return 'REJECT', 'DRIVER_UNKNOWN_LATCH', \
                (NVINTF_SUCCESS, REJ['NONE'], 0, 0)
    else:
        # Unreachable (the TOPO_LONE_OR_EMPTY check above catches this
        # shape first); mapped to the same C site for completeness.
        return 'REJECT', 'TOPO_LONE_OR_EMPTY', \
            (NVINTF_FAILURE, REJ['TOPO_COUNTS'], NULLPAGE, topo_raw)
    # RECOVER_ERASE branch: the first PGCDST page's range drives cleanPage.
    f = first_fe
    spg, epg, eoff = spages[f], epages[f], eoffs[f]
    if spg == 0xFF or epg == 0xFF:
        return 'REJECT', 'CMP_ERASE_RANGE_NULL', \
            (NVINTF_BADVERSION, REJ['ERASE_NULL_RANGE'], f,
             (1 if spg == 0xFF else 0) | (2 if epg == 0xFF else 0))
    if _fwd(spg, epg) + 1 > NVPAGES - 1:
        return 'REJECT', 'CMP_ERASE_RANGE_SPAN', \
            (NVINTF_BADVERSION, REJ['ERASE_SPAN'], f, _fwd(spg, epg) & 0xFF)
    if _fwd(spg, f) <= _fwd(spg, epg):
        return 'REJECT', 'CMP_ERASE_RANGE_DST', \
            (NVINTF_BADVERSION, REJ['ERASE_DST_IN_RANGE'], f, _fwd(spg, f) & 0xFF)
    # F6: cleanPage erases non-end range pages unconditionally (the offset
    # correction forces PGDATAOFS), so each non-end page must be
    # blank/header-only (nothing to destroy) or fully live-twinned on
    # dst (CH-F1, 4c: erasing originals destroys nothing when every
    # live item survives verbatim on dst), or the range fails closed.
    # (Twinned extension mirrored by the 4d C page-twin proof.)
    p = spg
    while p != epg:
        if find_end(img[p * PAGE:(p + 1) * PAGE]) > PGDATAOFS:
            if not page_twinned(img, p, f):
                return 'REJECT', 'CMP_ERASE_RANGE_MULTI', \
                    (NVINTF_BADVERSION, REJ['ERASE_NONTWINNED'], p, f)
        p = (p + 1) % NVPAGES
    end_true = find_end(img[epg * PAGE:(epg + 1) * PAGE])
    if eoff == PGDATAOFS:
        # Fully-drained form: cleanPage erases the end page without
        # reading data through the offset. Safe when the end page
        # holds no data (blank, or header-only), or when every live
        # item on it is twinned on dst (CH-F1, 4c: same erasure
        # argument as the non-end extension); a torn end offset on an
        # untwinned live end page would erase live items.
        if end_true > PGDATAOFS and not suffix_twinned(img, epg, eoff, f):
            return 'REJECT', 'CMP_ERASE_LIVE_END', \
                (NVINTF_BADVERSION, REJ['ERASE_END_NONTWINNED'], epg, f)
    elif eoff > end_true:
        return 'REJECT', 'CMP_ERASE_ABOVE_END', \
            (NVINTF_BADVERSION, REJ['ERASE_EOFF_ABOVE'], epg, eoff & 0xFF)
    elif eoff != end_true:
        # Below-end erase offsets are fresh partial-consumption
        # frontiers (dst-full rounds stop mid-page) or stale/torn
        # values. cleanPage hides everything above eoff, so admission
        # needs the suffix proof: on-boundary, and every live item above
        # eoff twinned on the dst page.
        if not suffix_twinned(img, epg, eoff, f):
            return 'REJECT', 'CMP_ERASE_BELOW_END', \
                (NVINTF_BADVERSION, REJ['ERASE_SUFFIX_NONTWINNED'], epg, f)
    # Tail-markability (L0-F2/F3, 4b; P2 tail-in-range, 4e): cleanPage
    # erases every non-end range page (the offset correction forces
    # PGDATAOFS) and the end page iff drained, then XDST-marks
    # (dst + count) % NVPAGES. The mark succeeds onto an erased (0xFF)
    # state byte, or onto a page cleanPage itself erases first (a
    # non-end range page, or the end page iff drained); anything else
    # fails init every boot, so it fails closed here. (Tail-in-range
    # completion mirrored by the 4f C erased-set check.)
    cleaned = _fwd(spg, epg) + (1 if eoff == PGDATAOFS else 0)
    tail = (f + cleaned) % NVPAGES
    erased = set()
    p = spg
    while p != epg:
        erased.add(p)
        p = (p + 1) % NVPAGES
    if eoff == PGDATAOFS:
        erased.add(epg)
    if img[tail * PAGE] != 0xFF and tail not in erased:
        return 'REJECT', 'CMP_ERASE_TAIL_STATE', \
            (NVINTF_BADVERSION, REJ['ERASE_TAIL_MARK'], tail, img[tail * PAGE])
    return 'ADMIT', 'ADMIT_RECOVER_ERASE', (NVINTF_SUCCESS, REJ['NONE'], 0, 0)


def oracle_decision(img):
    """(verdict, tag) view of _oracle_decision for existing callers."""
    verdict, tag, _latch = _oracle_decision(img)
    return verdict, tag


def oracle_latch(img):
    """(status, site, page, raw) view: the expected Q3 latch bytes."""
    _verdict, _tag, latch = _oracle_decision(img)
    return latch


def _compositions(n, k):
    for cuts in itertools.combinations(range(n + k - 1), k - 1):
        prev, out = -1, []
        for c in cuts + (n + k - 1,):
            out.append(c - prev - 1)
            prev = c
        yield tuple(out)


def enumerate_topology(nvpages=NVPAGES):
    """Deterministic state-count family enumeration over every 15-page
    composition (nact, xdst, rdy, act, full, xsrc). This is Python model
    combinatorics, not 15,504 driver executions; only the hosted probe runs
    below count as execution evidence. Compact-agnostic: vectors whose
    outcome depends on compact metadata are tagged COMPACT_GATED."""
    fams = {'reject_topo': 0, 'admit_init': 0, 'admit_resume_direct': 0,
            'admit_mark_or_gated': 0, 'admit_recover_compact': 0,
            'compact_gated': 0}
    total = 0
    for nact, xdst, rdy, act, full, xsrc in _compositions(nvpages, 6):
        total += 1
        data = act + full
        if xdst > 1 or xsrc > 1 or rdy > 1:
            fams['reject_topo'] += 1
        elif nact == nvpages:
            fams['admit_init'] += 1
        elif xsrc and xdst:
            fams['admit_recover_compact'] += 1
        elif xsrc and nact:
            fams['admit_recover_compact'] += 1
        elif xsrc:
            fams['compact_gated'] += 1
        elif xdst:
            fams['admit_resume_direct'] += 1
        elif data:
            fams['admit_mark_or_gated'] += 1
        else:
            fams['reject_topo'] += 1
    return {'total': total, 'nvpages': nvpages, 'families': fams}


def program_tail_singleton(b, name):
    """Hand-built live singleton item with an explicit non-seed ID
    (2,99,0) on page 6 (ACT). CRC-stale is fine: singletons take no
    CRC check (no pair to compare), and resume dedup is ID-specific,
    so the tail takes no twin anywhere and resume converges quietly.
    Header bytes are programmed only where the seed left them erased,
    so both seed page forms (NACT-header, fully-erased) work."""
    put1to0(b, 6 * PAGE + 0, 0x7C, name)
    if b[6 * PAGE + 1] == 0xFF:
        put1to0(b, 6 * PAGE + 1, 0x01, name)
    if b[6 * PAGE + 2] == 0xFF:
        put1to0(b, 6 * PAGE + 2, 0x0F, name)
    if b[6 * PAGE + 3] == 0xFF:
        put1to0(b, 6 * PAGE + 3, 0x96, name)
    for i in range(5):
        put1to0(b, 6 * PAGE + PGDATAOFS + i, 0xBB, name)
    for i, v in enumerate((0x08, 0x63, 0x00, 0x00, 0x14, 0x42, 0x96)):
        put1to0(b, 6 * PAGE + 21 + i, v, name)


def hand_picked(name, b, last, info):
    if name == 'signature':
        b[last + 3] = 0x94
    if name == 'version':
        b[last + 2] = 4
    if name == 'state':
        b[last] = 0
    if name == 'erased-header-with-data':
        b[last:last + 16] = b'\xff' * 16
        b[last + 32] = 0
    if name == 'nact-with-data':
        b[0] = 0xff
    if name == 'two-xdst':
        b[2048] = 0xfe
    if name == 'two-ready':
        b[2048] = 0x7e
        b[4096] = 0x7e
    if name == 'blank-before-bad':
        b[2048:4096] = b'\xff' * 2048
        b[last + 3] = 0x94
    if name == 'blank-before-two-xdst':
        b[2048:4096] = b'\xff' * 2048
        b[4096] = 0xfe
    if name == 'blank-before-only-ready':
        b[:2048] = b'\xff' * 2048
        b[2048] = 0x7e
        b[last] = 0xff
    if name in ('full-without-destination', 'source-without-destination'):
        for page in range(15):
            b[page * 2048] = 0x78
        if name == 'source-without-destination':
            b[0] = 0x70
        return {'family': 'hand-picked'}
    if name == 'cmp-fe-nullrange':
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        put1to0(b, 0 * PAGE + 6, 0xFE, name)
        return {'family': 'cmp-erase-null-range'}
    if name == 'cmp-fe-nact-validrange':
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 1 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        for o in (8, 9, 12, 13):
            put1to0(b, base + o, 0x10 if o % 4 == 0 else 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-fe-on-nact'}
    if name == 'cmp-validrange-liveend':
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 14 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        for o in (8, 9, 12, 13):
            put1to0(b, base + o, 0x10 if o % 4 == 0 else 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-erase-live-end'}
    if name == 'cmp-torn-sig':
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 0 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        # Seed headers are NULL-form (sig already 0x96), so the plausible
        # 1->0 corruption here is an over-programmed extra bit, not a torn
        # first program. Either way the byte leaves the admitted set.
        put1to0(b, base + 11, 0x86, name)
        put1to0(b, base + 12, 0x10, name)
        put1to0(b, base + 13, 0x00, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-torn-signature'}
    if name == 'cmp-oob-spage':
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 0 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x0F, name)
        put1to0(b, base + 12, 0x10, name)
        put1to0(b, base + 13, 0x00, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-oob-page-selector'}
    if name == 'cmp-eoffset-flash-boundary':
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 14 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 12, 0x00, name)
        put1to0(b, base + 13, 0x08, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-eoffset-boundary'}
    if name == 'cmp-erase-range-dst':
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 0 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 12, 0x10, name)
        put1to0(b, base + 13, 0x00, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-erase-range-dst'}
    if name == 'cmp-eoffset-oob':
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 0 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 12, 0x01, name)
        put1to0(b, base + 13, 0x08, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-eoffset-oob'}
    if name == 'cmp-cursor-oob-read':
        put1to0(b, 0 * PAGE + 4, 0x01, name)
        put1to0(b, 0 * PAGE + 5, 0x08, name)
        return {'family': 'cmp-cursor-oob'}
    if name == 'cmp-cursor-zero':
        put1to0(b, 0 * PAGE + 4, 0x00, name)
        put1to0(b, 0 * PAGE + 5, 0x00, name)
        return {'family': 'cmp-cursor-zero'}
    if name == 'cmp-cursor-misaligned':
        end = info['E']
        check(end > PGDATAOFS + 1, 'seed page end too small for torn cursor',
              case=name, end=end)
        v = end - 1
        put1to0(b, 0 * PAGE + 4, v & 0xFF, name)
        put1to0(b, 0 * PAGE + 5, (v >> 8) & 0xFF, name)
        return {'family': 'cmp-cursor-misaligned', 'seed_end': end, 'cursor': v}
    if name == 'cmp-half-null':
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 0 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 12, 0x10, name)
        put1to0(b, base + 13, 0x00, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-half-null'}
    if name == 'cmp-eoffset-misaligned':
        end = info['E']
        v = end & ~0x08
        check(v > PGDATAOFS and v < end, 'no off-boundary torn end offset',
              case=name, end=end, candidate=v)
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 14 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 12, v & 0xFF, name)
        put1to0(b, base + 13, (v >> 8) & 0xFF, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-eoffset-misaligned', 'seed_end': end, 'eoffset': v}
    if name in ('legacy-mixed-active', 'legacy-dup-active', 'legacy-dup-xfer',
                'legacy-ambiguous-current'):
        pages = {'legacy-mixed-active': (1,), 'legacy-dup-active': (1, 2),
                 'legacy-dup-xfer': (1, 2), 'legacy-ambiguous-current': (1,)}[name]
        marker = 0x24 if name == 'legacy-dup-xfer' else 0xA5
        for pg in pages:
            base = pg * PAGE
            put1to0(b, base + 0, marker, name)
            put1to0(b, base + 2, 0x02, name)
            for o in range(4, 24):
                put1to0(b, base + o, 0x00, name)
        if name == 'legacy-ambiguous-current':
            put1to0(b, 2 * PAGE + 0, 0xFE, name)
        return {'family': 'legacy-fail-closed', 'pages': list(pages)}
    if name == 'mixed-dup-xdst-xsrc':
        put1to0(b, 0 * PAGE + 0, 0x70, name)
        put1to0(b, 2 * PAGE + 0, 0xFE, name)
        return {'family': 'mixed-dup-recovery'}
    if name == 'mixed-multiact-dup-xdst':
        copy_page_1to0(b, 0, 1, name)
        put1to0(b, 2 * PAGE + 0, 0xFE, name)
        return {'family': 'mixed-multiact-dup'}
    if name == 'rdy-cursor-zero':
        # RDY cursors are consumed as data-end offsets: a torn 16->0 here
        # would steer a later write into the page header region. Only the
        # null and drained forms are admitted.
        put1to0(b, 2 * PAGE + 0, 0x7E, name)
        put1to0(b, 2 * PAGE + 4, 0x00, name)
        put1to0(b, 2 * PAGE + 5, 0x00, name)
        return {'family': 'rdy-cursor-zero'}
    if name == 'multi-act-twins':
        # F8: byte-identical ACT twins. Every shared live ID agrees, so the
        # agreement proof admits; resume dedups the older copy and the image
        # converges to single-live.
        copy_page_1to0(b, 0, 1, name)
        return {'family': 'multi-act-twins'}
    if name == 'multi-act-rdy':
        copy_page_1to0(b, 0, 1, name)
        put1to0(b, 2 * PAGE + 0, 0x7E, name)
        return {'family': 'multi-act-rdy'}
    if name == 'same-page-divergent-dup':
        # F8: a second live copy of the seed item appended on page 0 with one
        # flipped data bit (CRC now stale). Same ID, differing values on one
        # page: first-match would return either depending on the walk start.
        end = info['E']
        top = parse_item(bytes(b[0 * PAGE:1 * PAGE]), end - 7)
        check(top['live'] and top['len'] == 116, 'seed top item not as expected',
              case=name, end=end, top=top)
        check(end + 123 <= FLASH_PAGE_SIZE, 'seed page too full to append',
              case=name, end=end)
        orig = bytes(b[0 * PAGE + end - 123:0 * PAGE + end])
        for i in range(116):
            put1to0(b, 0 * PAGE + end + i, orig[i], name)
        old = b[0 * PAGE + end + 20]
        check(old != 0x00, 'seed data byte already clear, pick another offset',
              case=name, offset=20, old=hex(old))
        put1to0(b, 0 * PAGE + end + 20, old ^ (old & -old), name)
        for i in range(7):
            put1to0(b, 0 * PAGE + end + 116 + i, orig[116 + i], name)
        return {'family': 'same-page-divergent-dup', 'seed_end': end}
    if name == 'admit-full-nact-mark':
        put1to0(b, 0 * PAGE + 0, 0x78, name)
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        for pg in range(1, 13):
            put1to0(b, pg * PAGE + 0, 0x78, name)
        return {'family': 'admit-full-mark-path'}
    if name == 'admit-drained-short-end':
        # R10 cut-195 shape: the PGCDST source range fully drained while the
        # end offset stays at the drained mark 16 and the end page holds no
        # data (true end 4, below PGDATAOFS). A fully-blank end would cost a
        # second scan-heal erase, so the end page carries the power-cut form
        # scanPage healing itself leaves behind: page header written, compact
        # slots still erased. Recovery erases the end page once; the tail
        # (dst + cleaned count) lands on the NACT page, which carries a
        # valid header (the driver-observed cut-195 pg03 form) so the
        # second init converges with zero operations.
        put1to0(b, 0 * PAGE + 0, 0x78, name)
        base = 0 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x05, name)
        put1to0(b, base + 12, 0x10, name)
        put1to0(b, base + 13, 0x00, name)
        put1to0(b, base + 14, 0x05, name)
        b[1 * PAGE:1 * PAGE + 16] = bytes((0xFF, 0x05, 0x0F, 0x96,
                                           0xFF, 0xFF, 0xFF, 0x96,
                                           0xFF, 0xFF, 0xFF, 0x96,
                                           0xFF, 0xFF, 0xFF, 0x96))
        b[1 * PAGE + 16:2 * PAGE] = b'\xff' * (PAGE - PGDATAOFS)
        b[5 * PAGE:5 * PAGE + 16] = (bytes((0xFF, 0x02, 0x0F, 0x96))
                                    + b'\xff' * 12)
        b[5 * PAGE + 16:6 * PAGE] = b'\xff' * (PAGE - PGDATAOFS)
        for pg in list(range(2, 5)) + list(range(6, 15)):
            put1to0(b, pg * PAGE + 0, 0x78, name)
        return {'family': 'admit-drained-short-end'}
    if name == 'cmp-erase-range-multi-live':
        # F6: structurally valid stale range [0..1] with a blank end page.
        # Page 0 holds the live seed item; cleanPage erases non-end pages
        # unconditionally, so pre-fix admission would erase live-only data.
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 14 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 12, 0x10, name)
        put1to0(b, base + 13, 0x00, name)
        put1to0(b, base + 14, 0x01, name)
        return {'family': 'cmp-erase-range-multi'}
    if name == 'cmp-dup-pgdst':
        # F7: two PGCDST metadata pages. Page 13 carries a valid single-page
        # drained range; page 14 carries a null range. Pre-fix code silently
        # consumes the first; ambiguous metadata must fail closed.
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 13 * PAGE
        # Seed page 13 already carries a valid NACT header (same init that
        # headers page 2 per rdy-cursor-zero); only state and compact slots
        # are programmed here.
        put1to0(b, base + 0, 0x78, name)
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x05, name)
        put1to0(b, base + 11, 0x96, name)
        put1to0(b, base + 12, 0x10, name)
        put1to0(b, base + 13, 0x00, name)
        put1to0(b, base + 14, 0x05, name)
        put1to0(b, base + 15, 0x96, name)
        put1to0(b, 14 * PAGE + 6, 0xFE, name)
        return {'family': 'cmp-dup-pgdst'}
    if name == 'mixed-divergent-act':
        # F8: identical twin except one cleared data bit on page 1 (CRC now
        # stale). Same live ID, differing values: the agreement proof fails.
        copy_page_1to0(b, 0, 1, name)
        old = b[1 * PAGE + 20]
        check(old != 0x00, 'seed data byte already clear, pick another offset',
              case=name, offset=20, old=hex(old))
        put1to0(b, 1 * PAGE + 20, old ^ (old & -old), name)
        return {'family': 'mixed-divergent-act'}
    if name in ('hdr-cycle-zero', 'hdr-cycle-erased', 'hdr-allactive-1',
                'hdr-allactive-2'):
        # F9: fully programmed FULL header on page 2 with one reserved field.
        # Torn-program form: every byte is a 1->0 program from erased.
        fields = {'hdr-cycle-zero': (0x00, 0x0F),
                  'hdr-cycle-erased': (0xFF, 0x0F),
                  'hdr-allactive-1': (0x01, 0x0D),
                  'hdr-allactive-2': (0x01, 0x0E)}[name]
        b[2 * PAGE:2 * PAGE + 16] = (bytes((0x78, fields[0], fields[1], 0x96))
                                    + b'\xff\xff\xff\x96' * 3)
        b[2 * PAGE + 16:3 * PAGE] = b'\xff' * (PAGE - PGDATAOFS)
        return {'family': 'hdr-reserved'}
    if name == 'mixed-divergent-act-erase':
        # F8/P0: ERASE topology (no XDST/XSRC, valid drained range) with
        # a divergent pair on the CRC-valid tail ID: page 1 (last ACT)
        # keeps the pristine seed copy as tail, page 0 holds the same ID
        # with one cleared data bit (stale CRC). RECOVER_ERASE runs no
        # dedup and reads from the first ACT, so the tail exception must
        # not excuse this pair; only resume topologies converge.
        copy_page_1to0(b, 0, 1, name)
        check(b[1 * PAGE + 4] == 0xFF and b[1 * PAGE + 5] == 0xFF,
              'tail page cursor not null', case=name)
        old = b[0 * PAGE + 20]
        check(old != 0x00, 'seed data byte already clear, pick another offset',
              case=name, offset=20, old=hex(old))
        put1to0(b, 0 * PAGE + 20, old ^ (old & -old), name)
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 0 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x05, name)
        put1to0(b, base + 12, 0x10, name)
        put1to0(b, base + 13, 0x00, name)
        put1to0(b, base + 14, 0x05, name)
        b[5 * PAGE:5 * PAGE + 16] = (bytes((0xFF, 0x02, 0x0F, 0x96))
                                    + b'\xff' * 12)
        b[5 * PAGE + 16:6 * PAGE] = b'\xff' * (PAGE - PGDATAOFS)
        return {'family': 'mixed-divergent-act-erase'}
    if name == 'mixed-divergent-act-trio':
        # F8/census: RESUME topology with three live copies of one ID:
        # page 2 (last ACT) keeps the pristine seed copy as CRC-valid
        # tail, pages 0 and 1 hold the same ID with different cleared
        # data bits. Resume dedups exactly one older copy, so two
        # survivors diverge and the tail exception must not excuse them.
        copy_page_1to0(b, 0, 1, name)
        copy_page_1to0(b, 0, 2, name)
        check(b[2 * PAGE + 4] == 0xFF and b[2 * PAGE + 5] == 0xFF,
              'tail page cursor not null', case=name)
        old = b[0 * PAGE + 20]
        check(old != 0x00, 'seed data byte already clear, pick another offset',
              case=name, offset=20, old=hex(old))
        put1to0(b, 0 * PAGE + 20, old ^ (old & -old), name)
        old = b[1 * PAGE + 40]
        check(old != 0x00, 'seed data byte already clear, pick another offset',
              case=name, offset=40, old=hex(old))
        put1to0(b, 1 * PAGE + 40, old ^ (old & -old), name)
        return {'family': 'mixed-divergent-act-trio'}
    if name == 'cmp-eoffset-stale-boundary':
        # F1/P1: ERASE range [0..0] over a two-item end page with the end
        # offset on the interior item boundary (stale-smaller).
        # cleanPage cursor-writes the stale offset and marks the page
        # FULL, hiding the live item above it; admission needs the
        # suffix proof (every hidden live item twinned on dst), which
        # fails here (no twin), so only the true end, the drained mark
        # over a blank end, or a proved-twinned suffix is consumable.
        end = info['E']
        top = parse_item(bytes(b[0 * PAGE:1 * PAGE]), end - 7)
        check(top['live'] and top['len'] == 116, 'seed top item not as expected',
              case=name, end=end, top=top)
        check(end + 123 <= FLASH_PAGE_SIZE, 'seed page too full to append',
              case=name, end=end)
        orig = bytes(b[0 * PAGE + end - 123:0 * PAGE + end])
        for i in range(116):
            put1to0(b, 0 * PAGE + end + i, orig[i], name)
        for i in range(7):
            put1to0(b, 0 * PAGE + end + 116 + i, orig[116 + i], name)
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 14 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 12, end & 0xFF, name)
        put1to0(b, base + 13, (end >> 8) & 0xFF, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-eoffset-stale-boundary', 'seed_end': end,
                'eoffset': end}
    if name == 'cmp-erase-tail-singleton':
        # L0-F2 (4a red-first anchor admit-erase-twinned-singleton):
        # below-end twinned suffix on a singleton range [0..0]. The
        # suffix proof passes, but cleanPages=0 lands the XDST
        # tail-mark on the FULL dst page itself, failing init every
        # boot; the 4b tail-markability gate fails it closed.
        end = info['E']
        top = parse_item(bytes(b[0 * PAGE:1 * PAGE]), end - 7)
        check(top['live'] and top['len'] == 116, 'seed top item not as expected',
              case=name, end=end, top=top)
        check(end + 123 <= FLASH_PAGE_SIZE, 'seed page too full to append',
              case=name, end=end)
        orig = bytes(b[0 * PAGE + end - 123:0 * PAGE + end])
        for i in range(116):
            put1to0(b, 0 * PAGE + end + i, orig[i], name)
        for i in range(7):
            put1to0(b, 0 * PAGE + end + 116 + i, orig[116 + i], name)
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 14 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 12, end & 0xFF, name)
        put1to0(b, base + 13, (end >> 8) & 0xFF, name)
        put1to0(b, base + 14, 0x00, name)
        for i in range(116):
            put1to0(b, 14 * PAGE + 16 + i, orig[i], name)
        for i in range(7):
            put1to0(b, 14 * PAGE + 16 + 116 + i, orig[116 + i], name)
        return {'family': 'cmp-erase-tail-singleton', 'seed_end': end,
                'eoffset': end}
    if name == 'cmp-erase-tail-unmarkable':
        # L0-F3 (4a red-first anchor admit-erase-twinned-unmarkable):
        # multi-page range [4..5] with a blank non-end page and a
        # twinned below-end suffix. Tail is (dst+1)%15 = page 0 (ACT,
        # occupied), so the driver's XDST tail-mark fails every boot;
        # the 4b tail-markability gate fails it closed.
        copy_page_1to0(b, 0, 5, name)
        end = info['E']
        top = parse_item(bytes(b[5 * PAGE:6 * PAGE]), end - 7)
        check(top['live'] and top['len'] == 116, 'seed top item not as expected',
              case=name, end=end, top=top)
        check(end + 123 <= FLASH_PAGE_SIZE, 'seed page too full to append',
              case=name, end=end)
        orig = bytes(b[5 * PAGE + end - 123:5 * PAGE + end])
        for i in range(116):
            put1to0(b, 5 * PAGE + end + i, orig[i], name)
        for i in range(7):
            put1to0(b, 5 * PAGE + end + 116 + i, orig[116 + i], name)
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 14 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x04, name)
        put1to0(b, base + 12, end & 0xFF, name)
        put1to0(b, base + 13, (end >> 8) & 0xFF, name)
        put1to0(b, base + 14, 0x05, name)
        for i in range(116):
            put1to0(b, 14 * PAGE + 16 + i, orig[i], name)
        for i in range(7):
            put1to0(b, 14 * PAGE + 16 + 116 + i, orig[116 + i], name)
        return {'family': 'cmp-erase-tail-unmarkable', 'seed_end': end,
                'eoffset': end}
    if name == 'cmp-erase-tail-exact':
        # L0-F2 companion (4a red-first anchor
        # admit-erase-exact-singleton): singleton range [0..0] with an
        # exact live end offset. cleanPages=0 lands the tail-mark on
        # dst itself and the driver bricks; the 4b tail-markability
        # gate fails it closed.
        end = info['E']
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 14 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 12, end & 0xFF, name)
        put1to0(b, base + 13, (end >> 8) & 0xFF, name)
        put1to0(b, base + 14, 0x00, name)
        return {'family': 'cmp-erase-tail-exact', 'seed_end': end,
                'eoffset': end}
    if name == 'mixed-divergent-full-act':
        # L1-F10 pin: ACT+FULL divergent pair with a torn (CRC-stale)
        # tail, so neither the oracle nor C excuses it. Pins FULL in
        # the F8 proof scope: a C regression dropping FULL admits.
        copy_page_1to0(b, 0, 1, name)
        put1to0(b, 1 * PAGE + 0, 0x78, name)
        old = b[0 * PAGE + 20]
        check(old != 0x00, 'seed data byte already clear, pick another offset',
              case=name, offset=20, old=hex(old))
        put1to0(b, 0 * PAGE + 20, old ^ (old & -old), name)
        old = b[1 * PAGE + 40]
        check(old != 0x00, 'seed data byte already clear, pick another offset',
              case=name, offset=40, old=hex(old))
        put1to0(b, 1 * PAGE + 40, old ^ (old & -old), name)
        return {'family': 'mixed-divergent-full-act'}
    if name == 'mixed-divergent-xsrc-act':
        # CH-F3 (4a red-first anchor): XSRC/ACT divergent pair on a
        # compact topology. The proof walks XSRC (4b C chkPgs) and
        # rejects; pre-4b C admitted and the driver compacted.
        copy_page_1to0(b, 0, 1, name)
        put1to0(b, 1 * PAGE + 0, 0x70, name)
        old = b[1 * PAGE + 20]
        check(old != 0x00, 'seed data byte already clear, pick another offset',
              case=name, offset=20, old=hex(old))
        put1to0(b, 1 * PAGE + 20, old ^ (old & -old), name)
        return {'family': 'mixed-divergent-xsrc-act'}
    if name == 'rdy-with-data':
        # L0-F7/CH-F2 (4a red-first anchor): RDY page carrying a live
        # item. The driver never writes data to RDY (mark-before-write
        # lands data on ACT only), so RDY data is a flash-fault shape
        # the scan fails closed (RDY_DATA; 4b C rule).
        end = info['E']
        put1to0(b, 2 * PAGE + 0, 0x7E, name)
        for i in range(end - PGDATAOFS):
            put1to0(b, 2 * PAGE + PGDATAOFS + i, b[0 * PAGE + PGDATAOFS + i], name)
        return {'family': 'rdy-with-data', 'seed_end': end}
    if name == 'mixed-divergent-act-trio-twinned':
        # L0-F1 (4a red-first anchor): resume topology with a pristine
        # tail (page 2), a pristine twin (page 1) and a divergent older
        # copy (page 0). Resume dedups the nearest-below-tail (the
        # twin), leaving the divergent copy live, so the 4b census
        # rejects mixed older sets.
        copy_page_1to0(b, 0, 1, name)
        copy_page_1to0(b, 0, 2, name)
        check(b[2 * PAGE + 4] == 0xFF and b[2 * PAGE + 5] == 0xFF,
              'tail page cursor not null', case=name)
        old = b[0 * PAGE + 20]
        check(old != 0x00, 'seed data byte already clear, pick another offset',
              case=name, offset=20, old=hex(old))
        put1to0(b, 0 * PAGE + 20, old ^ (old & -old), name)
        return {'family': 'mixed-divergent-act-trio-twinned'}
    if name == 'admit-erase-twinned-multi':
        # Converging twinned-suffix admit (4c pin, green on 4b C):
        # multi-page range [2..3] with a blank non-end page, a
        # below-end twinned suffix on the end page, an erased tail
        # (page 13), and a singleton tail ID on page 6 so resume
        # dedup (ID-specific) converges quietly on the second init.
        # First hosted driver execution of the suffix-true branch
        # (closes L0-F4/L1-F11/L2-N6).
        copy_page_1to0(b, 0, 3, name)
        end = info['E']
        top = parse_item(bytes(b[3 * PAGE:4 * PAGE]), end - 7)
        check(top['live'] and top['len'] == 116, 'seed top item not as expected',
              case=name, end=end, top=top)
        check(end + 123 <= FLASH_PAGE_SIZE, 'seed page too full to append',
              case=name, end=end)
        orig = bytes(b[3 * PAGE + end - 123:3 * PAGE + end])
        for i in range(116):
            put1to0(b, 3 * PAGE + end + i, orig[i], name)
        for i in range(7):
            put1to0(b, 3 * PAGE + end + 116 + i, orig[116 + i], name)
        program_tail_singleton(b, name)
        put1to0(b, 12 * PAGE + 0, 0x78, name)
        base = 12 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x02, name)
        put1to0(b, base + 12, end & 0xFF, name)
        put1to0(b, base + 13, (end >> 8) & 0xFF, name)
        put1to0(b, base + 14, 0x03, name)
        for i in range(116):
            put1to0(b, 12 * PAGE + 16 + i, orig[i], name)
        for i in range(7):
            put1to0(b, 12 * PAGE + 16 + 116 + i, orig[116 + i], name)
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        return {'family': 'admit-erase-twinned-multi', 'seed_end': end,
                'eoffset': end}
    if name == 'admit-erase-twinned-nonend':
        # CH-F1 (4c red-first anchor): range [2..3] with a live-twinned
        # (fully-consumed) non-end page. cleanPage erases it, which
        # destroys nothing (twins survive on dst); the 4d page-twin
        # proof admits it (pre-4d C false-bricked).
        copy_page_1to0(b, 0, 2, name)
        copy_page_1to0(b, 0, 3, name)
        end = info['E']
        top = parse_item(bytes(b[3 * PAGE:4 * PAGE]), end - 7)
        check(top['live'] and top['len'] == 116, 'seed top item not as expected',
              case=name, end=end, top=top)
        check(end + 123 <= FLASH_PAGE_SIZE, 'seed page too full to append',
              case=name, end=end)
        orig = bytes(b[3 * PAGE + end - 123:3 * PAGE + end])
        for i in range(116):
            put1to0(b, 3 * PAGE + end + i, orig[i], name)
        for i in range(7):
            put1to0(b, 3 * PAGE + end + 116 + i, orig[116 + i], name)
        program_tail_singleton(b, name)
        put1to0(b, 12 * PAGE + 0, 0x78, name)
        base = 12 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x02, name)
        put1to0(b, base + 12, end & 0xFF, name)
        put1to0(b, base + 13, (end >> 8) & 0xFF, name)
        put1to0(b, base + 14, 0x03, name)
        for i in range(116):
            put1to0(b, 12 * PAGE + 16 + i, orig[i], name)
        for i in range(7):
            put1to0(b, 12 * PAGE + 16 + 116 + i, orig[116 + i], name)
        for i in range(116):
            put1to0(b, 12 * PAGE + end + i, orig[i], name)
        for i in range(7):
            put1to0(b, 12 * PAGE + end + 116 + i, orig[116 + i], name)
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        return {'family': 'admit-erase-twinned-nonend', 'seed_end': end,
                'eoffset': end}
    if name == 'admit-erase-twinned-drained':
        # CH-F1 (4c red-first anchor): drained singleton range [5..5]
        # with a live-twinned end page. cleanPage erases it (5 ops:
        # erase + NACT header + 3 NULL slots), which destroys nothing
        # (twins survive on dst); the 4d suffix proof at eoff 16
        # admits it (pre-4d C false-bricked). Tail is (12+1)%15 =
        # page 13 (erased); first-init cost 6 ops (erase + tail-mark).
        copy_page_1to0(b, 0, 5, name)
        program_tail_singleton(b, name)
        put1to0(b, 12 * PAGE + 0, 0x78, name)
        base = 12 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x05, name)
        put1to0(b, base + 12, 0x10, name)
        put1to0(b, base + 13, 0x00, name)
        put1to0(b, base + 14, 0x05, name)
        end = info['E']
        orig = bytes(b[0 * PAGE + 16:0 * PAGE + end])
        check(len(orig) == 123, 'seed item not as expected',
              case=name, end=end, size=len(orig))
        for i in range(116):
            put1to0(b, 12 * PAGE + 16 + i, orig[i], name)
        for i in range(7):
            put1to0(b, 12 * PAGE + 16 + 116 + i, orig[116 + i], name)
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        return {'family': 'admit-erase-twinned-drained', 'seed_end': end}
    if name == 'admit-erase-tail-inrange':
        # P2 (4e red-first anchor): drained singleton range [0..0] with
        # a live-twinned end page, dst page 14. Tail is (14+0+1)%15 =
        # page 0: the drained end itself, which cleanPage erases (5
        # ops) before the XDST mark lands on it; the 4f erased-set
        # check admits it (pre-4f C false-bricked). First-init cost
        # 6 ops.
        program_tail_singleton(b, name)
        put1to0(b, 14 * PAGE + 0, 0x78, name)
        base = 14 * PAGE
        put1to0(b, base + 6, 0xFE, name)
        put1to0(b, base + 8, 0x10, name)
        put1to0(b, base + 9, 0x00, name)
        put1to0(b, base + 10, 0x00, name)
        put1to0(b, base + 12, 0x10, name)
        put1to0(b, base + 13, 0x00, name)
        put1to0(b, base + 14, 0x00, name)
        end = info['E']
        orig = bytes(b[0 * PAGE + 16:0 * PAGE + end])
        check(len(orig) == 123, 'seed item not as expected',
              case=name, end=end, size=len(orig))
        for i in range(116):
            put1to0(b, 14 * PAGE + 16 + i, orig[i], name)
        for i in range(7):
            put1to0(b, 14 * PAGE + 16 + 116 + i, orig[116 + i], name)
        return {'family': 'admit-erase-tail-inrange', 'seed_end': end}
    return {'family': 'hand-picked'}


def generated(name, b):
    """Enumerated deterministic corpus v1. Every mutation is preserve-and-reject
    by construction: torn headers break signature/version/state, topology pairs
    exceed the single destination/source/ready budget, lone-ready has no
    destination/source/data page, torn-erase leaves data under an erased header."""
    if name.startswith('gen-torn-state-') or name.startswith('gen-torn-version-') or name.startswith('gen-torn-signature-'):
        pg = int(name.rsplit('-', 1)[1])
        off = {'state': 0, 'version': 2, 'signature': 3}[name.split('-')[2]]
        at = pg * PAGE + off
        mask, v = torn(b[at], off)
        b[at] = v
        return {'family': 'gen-torn-header', 'page': pg, 'header_offset': off,
                'mask': '0x%02x' % mask, 'torn_byte': '0x%02x' % v,
                'nor_valid_bit_clear': True}
    if name.startswith('gen-two-'):
        kind, i, j = name.split('-')[2:5]
        i, j = int(i), int(j)
        state = {'xdst': 0xFE, 'xsrc': 0x70, 'ready': 0x7E}[kind]
        b[i * PAGE] = state
        b[j * PAGE] = state
        return {'family': 'gen-ambiguous-topology', 'kind': kind, 'pages': [i, j],
                'state': '0x%02x' % state}
    if name.startswith('gen-lone-ready-'):
        pg = int(name.rsplit('-', 1)[1])
        for p in range(15):
            b[p * PAGE:(p + 1) * PAGE] = b'\xff' * PAGE
        b[pg * PAGE:pg * PAGE + 4] = bytes((0x7E, 0x01, 0x0C, 0x96))
        return {'family': 'gen-lone-ready', 'page': pg}
    if name.startswith('gen-torn-erase-'):
        pg = int(name.rsplit('-', 1)[1])
        b[pg * PAGE:(pg + 1) * PAGE] = b'\xff' * PAGE
        b[pg * PAGE + 64] = 0x00
        return {'family': 'gen-torn-erase-remnant', 'page': pg, 'remnant_offset': 64}
    raise ValueError('unknown generated case ' + name)


REJECT_CASES = ['signature', 'version', 'state', 'erased-header-with-data',
                'nact-with-data', 'two-xdst', 'two-ready', 'blank-before-bad',
                'blank-before-two-xdst', 'blank-before-only-ready',
                'full-without-destination', 'source-without-destination',
                'cmp-fe-nullrange', 'cmp-fe-nact-validrange',
                'cmp-validrange-liveend', 'cmp-torn-sig', 'cmp-oob-spage',
                'cmp-eoffset-flash-boundary', 'cmp-eoffset-oob',
                'cmp-cursor-oob-read', 'cmp-cursor-zero', 'cmp-cursor-misaligned',
                'cmp-half-null', 'cmp-eoffset-misaligned', 'cmp-erase-range-dst',
                'legacy-mixed-active', 'legacy-dup-active', 'legacy-dup-xfer',
                'legacy-ambiguous-current', 'mixed-dup-xdst-xsrc',
                'mixed-multiact-dup-xdst', 'rdy-cursor-zero',
                'cmp-erase-range-multi-live', 'cmp-dup-pgdst',
                'mixed-divergent-act', 'hdr-cycle-zero', 'hdr-cycle-erased',
                'hdr-allactive-1', 'hdr-allactive-2', 'same-page-divergent-dup',
                'mixed-divergent-act-erase', 'mixed-divergent-act-trio',
                'cmp-eoffset-stale-boundary', 'mixed-divergent-full-act',
                'mixed-divergent-xsrc-act', 'rdy-with-data',
                'mixed-divergent-act-trio-twinned',
                'cmp-erase-tail-singleton', 'cmp-erase-tail-unmarkable',
                'cmp-erase-tail-exact']
for _pg in (0, 1, 7, 13, 14):
    for _f in ('state', 'version', 'signature'):
        REJECT_CASES.append('gen-torn-%s-%d' % (_f, _pg))
for _pair in ((0, 1), (0, 14), (7, 13)):
    for _k in ('xdst', 'xsrc', 'ready'):
        REJECT_CASES.append('gen-two-%s-%d-%d' % (_k, _pair[0], _pair[1]))
for _pg in (3, 8, 11):
    REJECT_CASES.append('gen-lone-ready-%d' % _pg)
for _pg in (2, 5, 9, 12):
    REJECT_CASES.append('gen-torn-erase-%d' % _pg)
ADMIT_CASES = ['multi-act-twins', 'multi-act-rdy', 'admit-full-nact-mark',
               'admit-drained-short-end', 'admit-erase-twinned-multi',
               'admit-erase-twinned-nonend', 'admit-erase-twinned-drained',
               'admit-erase-tail-inrange']

EXPECTED_TAG = {
    'signature': 'BAD_HEADER', 'version': 'BAD_HEADER', 'state': 'BAD_HEADER',
    'erased-header-with-data': 'BAD_HEADER', 'nact-with-data': 'NACT_DATA',
    'two-xdst': 'TOPO_DUP_XDST', 'two-ready': 'TOPO_DUP_RDY',
    'blank-before-bad': 'BAD_HEADER',
    'blank-before-two-xdst': 'TOPO_DUP_XDST',
    'blank-before-only-ready': 'TOPO_LONE_OR_EMPTY',
    'full-without-destination': 'DRIVER_UNKNOWN_LATCH',
    'source-without-destination': 'DRIVER_UNKNOWN_LATCH',
    'cmp-fe-nullrange': 'CMP_ERASE_RANGE_NULL',
    'cmp-fe-nact-validrange': 'CMP_NACT_MODE',
    'cmp-validrange-liveend': 'CMP_ERASE_LIVE_END',
    'cmp-torn-sig': 'CMP_SIG', 'cmp-oob-spage': 'CMP_PAGE_RANGE',
    'cmp-eoffset-flash-boundary': 'CMP_ERASE_ABOVE_END',
    'cmp-eoffset-oob': 'CMP_OFFSET_RANGE',
    'cmp-cursor-oob-read': 'CMP_CURSOR_RANGE',
    'cmp-cursor-zero': 'CMP_CURSOR_RANGE',
    'cmp-cursor-misaligned': 'CMP_CURSOR_MISALIGNED',
    'cmp-half-null': 'CMP_NULL',
    'cmp-eoffset-misaligned': 'CMP_ERASE_BELOW_END',
    'mixed-divergent-act-erase': 'TOPO_ACT_CONFLICT',
    'mixed-divergent-act-trio': 'TOPO_ACT_CONFLICT',
    'cmp-eoffset-stale-boundary': 'CMP_ERASE_BELOW_END',
    'cmp-erase-range-dst': 'CMP_ERASE_RANGE_DST',
    'legacy-mixed-active': 'LEGACY', 'legacy-dup-active': 'LEGACY',
    'legacy-dup-xfer': 'LEGACY', 'legacy-ambiguous-current': 'LEGACY',
    'mixed-dup-xdst-xsrc': 'TOPO_DUP_XDST',
    'mixed-multiact-dup-xdst': 'TOPO_DUP_XDST',
    'rdy-cursor-zero': 'CMP_RDY_CURSOR',
    'cmp-erase-range-multi-live': 'CMP_ERASE_RANGE_MULTI',
    'cmp-dup-pgdst': 'CMP_DUP_PGCDST',
    'mixed-divergent-act': 'TOPO_ACT_CONFLICT',
    'hdr-cycle-zero': 'BAD_CYCLE',
    'hdr-cycle-erased': 'BAD_CYCLE',
    'hdr-allactive-1': 'BAD_ALLACTIVE',
    'hdr-allactive-2': 'BAD_ALLACTIVE',
    'same-page-divergent-dup': 'TOPO_ACT_CONFLICT',
    'mixed-divergent-full-act': 'TOPO_ACT_CONFLICT',
    'mixed-divergent-xsrc-act': 'TOPO_ACT_CONFLICT',
    'rdy-with-data': 'RDY_DATA',
    'mixed-divergent-act-trio-twinned': 'TOPO_ACT_CONFLICT',
    'cmp-erase-tail-singleton': 'CMP_ERASE_TAIL_STATE',
    'cmp-erase-tail-unmarkable': 'CMP_ERASE_TAIL_STATE',
    'cmp-erase-tail-exact': 'CMP_ERASE_TAIL_STATE',
    'multi-act-twins': 'ADMIT_RESUME_DIRECT',
    'multi-act-rdy': 'ADMIT_RESUME_DIRECT',
    'admit-full-nact-mark': 'ADMIT_RESUME_MARK',
    'admit-drained-short-end': 'ADMIT_RECOVER_ERASE',
    'admit-erase-twinned-multi': 'ADMIT_RECOVER_ERASE',
    'admit-erase-twinned-nonend': 'ADMIT_RECOVER_ERASE',
    'admit-erase-twinned-drained': 'ADMIT_RECOVER_ERASE',
    'admit-erase-tail-inrange': 'ADMIT_RECOVER_ERASE',
}
for _name in REJECT_CASES:
    if _name.startswith('gen-torn-'):
        EXPECTED_TAG[_name] = 'BAD_HEADER'
    elif _name.startswith('gen-two-xdst-'):
        EXPECTED_TAG[_name] = 'TOPO_DUP_XDST'
    elif _name.startswith('gen-two-xsrc-'):
        EXPECTED_TAG[_name] = 'TOPO_DUP_XSRC'
    elif _name.startswith('gen-two-ready-'):
        EXPECTED_TAG[_name] = 'TOPO_DUP_RDY'
    elif _name.startswith('gen-lone-ready-'):
        EXPECTED_TAG[_name] = 'TOPO_LONE_OR_EMPTY'
    elif _name.startswith('gen-torn-erase-'):
        EXPECTED_TAG[_name] = 'BAD_HEADER'
# 4a: RDY pages carrying data fail the scan before the topology census,
# so the two ready-pair cases touching the live seed page now tag
# RDY_DATA (C still rejects: duplicate RDY).
EXPECTED_TAG['gen-two-ready-0-1'] = 'RDY_DATA'
EXPECTED_TAG['gen-two-ready-0-14'] = 'RDY_DATA'


def verify(sdk, out):
    out.mkdir(parents=True, exist_ok=False)
    source = out / 'nvocmp.c'
    shutil.copy2(sdk / 'source/ti/common/nv/nvocmp.c', source)
    apply_fix(source)
    rows = []
    failures = []
    reject_done = sanitizer_done = admit_done = cost_done = 0
    for embedded in (False, True):
        for sanitizer in (False, True):
            tag = ('embedded' if embedded else 'asserting') + ('-sanitizer' if sanitizer else '')
            exe = out / tag
            cmd = ['gcc', '-std=c11', '-O1', '-g', '-D_GNU_SOURCE', '-DNV_LINUX',
                   '-DNVOCMP_POSIX_MUTEX', '-DENABLE_SANITY_CHECK', '-DDeviceFamily_CC26X4',
                   '-DNVOCMP_NVPAGES=15',
                   '-I' + str(out), '-I' + str(HERE), '-I' + str(sdk / 'source'),
                   '-I' + str(sdk / 'source/ti/common/nv'),
                   str(HERE / 'startup_guard_probe.c'), str(sdk / 'source/ti/common/nv/crc.c'),
                   str(HERE / 'nv_linux.c'), '-pthread', '-o', str(exe)]
            if embedded:
                cmd.insert(1, '-DNVLAB_EMBEDDED_ASSERT=1')
            if sanitizer:
                cmd[1:1] = list(SANITIZER_FLAGS)

            def compile_probe():
                subprocess.run(cmd, check=True)

            try:
                compile_probe()
            except Exception as exc:
                failures.append({'lane': tag, 'phase': 'compile', 'error': str(exc)[:2000]})
                continue

            def invoke(image, verb, *args):
                env = dict(os.environ, NVLAB_IMAGE=str(image))
                env.pop('NVLAB_CUT_OP', None)
                try:
                    p = subprocess.run([str(exe), verb, *args], env=env, capture_output=True,
                                       text=True, timeout=INVOKE_TIMEOUT)
                except subprocess.TimeoutExpired as exc:
                    after = Path(image).read_bytes() if Path(image).is_file() else b''
                    raise GateError('probe hang/timeout :: ' + json.dumps(
                        {'image': Path(image).name, 'verb': verb,
                         'timeout': INVOKE_TIMEOUT,
                         'sha_after': hashlib.sha256(after).hexdigest()}))
                if p.returncode:
                    raise GateError('probe failed :: ' + json.dumps(
                        {'image': Path(image).name, 'verb': verb,
                         'exit': p.returncode, 'stderr': p.stderr[-2000:],
                         'stdout': p.stdout[-2000:]}))
                try:
                    return json.loads(p.stdout)
                except ValueError:
                    raise GateError('probe printed no JSON :: ' + json.dumps(
                        {'image': Path(image).name, 'verb': verb,
                         'stderr': p.stderr[-2000:], 'stdout': p.stdout[-2000:]}))

            lane = {'embedded_asserts': embedded, 'sanitizer': sanitizer,
                    'rejections': {}, 'admits': {}, 'lane_failures': []}

            def measure_cost(cname, cimg):
                """Q2: run the bare-init cost verb on a copy of cimg and prove
                the measured startup reads sit under the analytic bound."""
                cp = out / (exe.name + '-costrun-' + cname + '.bin')
                cp.write_bytes(cimg)
                cost = invoke(cp, 'cost')
                census = q2_census(cimg)
                cc, cb = q2_classify_bound(census)
                cap_calls = 2 * (cc + Q2_DRIVER_CALLS_PER_INIT)
                cap_bytes = 2 * (cb + Q2_DRIVER_BYTES_PER_INIT)
                check(cost['read_calls'] <= cap_calls and cost['read_bytes'] <= cap_bytes,
                      'startup reads exceed analytic bound', lane=tag, case=cname,
                      cost=cost, cap_calls=cap_calls, cap_bytes=cap_bytes)
                lane.setdefault('startup_cost', {})[cname] = {
                    'measured': cost, 'cap_calls': cap_calls,
                    'cap_bytes': cap_bytes, 'census': census}
                return cost

            def setup_lane():
                seed = out / (exe.name + '-seed.bin')
                blank = invoke(seed, 'seed')
                check(blank['physical_operations'] > 0, 'blank init performed no writes',
                      lane=tag, blank=blank)
                pristine = seed.read_bytes()
                before = hashlib.sha256(pristine).hexdigest()
                healthy = invoke(seed, 'healthy')
                check(seed.read_bytes() == pristine, 'healthy reopen mutated image', lane=tag)
                check(healthy['physical_operations'] == 0, 'healthy reopen wrote', lane=tag,
                      healthy=healthy)
                check(healthy['sanity_status'] == 0, 'healthy sanity not clean', lane=tag,
                      healthy=healthy)
                lane['blank_init'] = blank
                lane['healthy'] = healthy
                lane['healthy_sha256'] = before
                return pristine, before

            try:
                pristine, before = setup_lane()
            except Exception as exc:
                lane['lane_failures'].append({'phase': 'setup', 'error': str(exc)[:2000]})
                failures.append({'lane': tag, 'phase': 'setup', 'error': str(exc)[:2000]})
                rows.append(lane)
                continue
            seed_end = find_end(bytes(pristine[0:PAGE]))
            check(PGDATAOFS < seed_end <= FLASH_PAGE_SIZE, 'seed page end out of range',
                  lane=tag, seed_end=seed_end)
            # Q3 CRC self-check: the production driver wrote the seed
            # item, so the CRC mirror must validate it. A mismatch here
            # means the mirror (not the latch) is wrong; fail loudly.
            seed_live, seed_anomaly = walk_live(bytes(pristine[0:PAGE]))
            check(not seed_anomaly, 'seed page walk anomalous', lane=tag)
            seed_items = [h for h in seed_live
                          if (h['sysid'], h['itemid'], h['subid']) == (1, 33, 0)]
            check(len(seed_items) == 1, 'seed item not unique', lane=tag,
                  found=len(seed_items))
            check(crc_ok(bytes(pristine[0:PAGE]), seed_items[0]),
                  'CRC mirror disagrees with production driver', lane=tag,
                  seed=dict(seed_items[0]))
            info = {'E': seed_end}
            for name in REJECT_CASES:
                b = bytearray(pristine)
                last = 14 * 2048
                p = None
                try:
                    if name.startswith('gen-'):
                        mutation = generated(name, b)
                    else:
                        mutation = hand_picked(name, b, last, info)
                    verdict, otag = oracle_decision(bytes(b))
                    check(verdict == 'REJECT', 'oracle admits a reject case', lane=tag,
                          case=name, oracle_tag=otag)
                    check(otag == EXPECTED_TAG[name], 'oracle tag mismatch', lane=tag,
                          case=name, oracle_tag=otag, expected=EXPECTED_TAG[name])
                    p = out / (exe.name + '-' + name + '.bin')
                    p.write_bytes(b)
                    raw = p.read_bytes()
                    r = invoke(p, 'reject')
                    reject_done += 1
                    if sanitizer:
                        sanitizer_done += 1
                    check(p.read_bytes() == raw, 'reject verb mutated image', lane=tag,
                          case=name, result=r)
                    check(r['physical_operations'] == 0, 'reject verb wrote', lane=tag,
                          case=name, result=r)
                    check(r['init_status'] == r['reinit_status'],
                          'reject re-init unstable', lane=tag, case=name, result=r)
                    check(r['sanity_status'] == (1 << r['init_status']),
                          'sanity is not the exact TI failure bit', lane=tag, case=name,
                          result=r)
                    adv = invoke(p, 'adverse')
                    reject_done += 1
                    if sanitizer:
                        sanitizer_done += 1
                    check(p.read_bytes() == raw, 'adverse verb mutated image', lane=tag,
                          case=name, adverse=adv)
                    check(adv['physical_operations'] == 0, 'adverse verb wrote', lane=tag,
                          case=name, adverse=adv)
                    check(adv['init_status'] == adv['reinit_status'],
                          'adverse re-init unstable', lane=tag, case=name, adverse=adv)
                    # Q3: the production init must latch exactly the
                    # oracle-predicted (status, site, page, raw).
                    exp_latch = oracle_latch(bytes(b))
                    got_latch = invoke(p, 'latch')
                    check(p.read_bytes() == raw, 'latch verb mutated image',
                          lane=tag, case=name, latch=got_latch)
                    check(got_latch['physical_operations'] == 0,
                          'latch verb wrote', lane=tag, case=name,
                          latch=got_latch)
                    check((got_latch['rej_status'], got_latch['rej_site'],
                           got_latch['rej_page'], got_latch['rej_raw']) == exp_latch,
                          'reject latch mismatch', lane=tag, case=name,
                          latch=got_latch, expected=exp_latch,
                          oracle_tag=otag)
                    check(got_latch['init_status'] == r['init_status'],
                          'latch init disagrees with reject init', lane=tag,
                          case=name, latch=got_latch, result=r)
                    lane['rejections'][name] = {**r, 'mutation': mutation,
                                                 'oracle_tag': otag,
                                                 'latch': got_latch,
                                                 'expected_latch': exp_latch,
                                                 'unchanged_sha256': hashlib.sha256(raw).hexdigest(),
                                                 'adverse': adv}
                except Exception as exc:
                    after = p.read_bytes() if p is not None and p.is_file() else b''
                    lane['lane_failures'].append({'case': name, 'error': str(exc)[:2000],
                                                  'sha_after': hashlib.sha256(after).hexdigest()})
                    failures.append({'lane': tag, 'case': name, 'error': str(exc)[:2000],
                                     'sha_after': hashlib.sha256(after).hexdigest()})
            for name in ADMIT_CASES:
                b = bytearray(pristine)
                last = 14 * 2048
                p = None
                try:
                    mutation = hand_picked(name, b, last, info)
                    verdict, otag = oracle_decision(bytes(b))
                    check(verdict == 'ADMIT', 'oracle rejects an admit case', lane=tag,
                          case=name, oracle_tag=otag)
                    check(otag == EXPECTED_TAG[name], 'admit oracle tag mismatch', lane=tag,
                          case=name, oracle_tag=otag, expected=EXPECTED_TAG[name])
                    p = out / (exe.name + '-admit-' + name + '.bin')
                    p.write_bytes(b)
                    measure_cost('admit-' + name, bytes(b))
                    cost_done += 1
                    first = invoke(p, 'admit')
                    admit_done += 1
                    check(first['init_status'] == 0 and first['reinit_status'] == 0,
                          'admit case failed to init', lane=tag, case=name, result=first)
                    check(first['sanity_status'] == 0, 'admit sanity not clean', lane=tag,
                          case=name, result=first)
                    check(first['physical_operations'] <= ADMIT_MAX_OPS,
                          'admit init wrote too much', lane=tag, case=name, result=first)
                    mid_sha = hashlib.sha256(p.read_bytes()).hexdigest()
                    second = invoke(p, 'admit')
                    admit_done += 1
                    check(second['init_status'] == 0 and second['reinit_status'] == 0,
                          'admit case unstable on second run', lane=tag, case=name,
                          result=second)
                    check(second['physical_operations'] == 0,
                          'admit case did not converge', lane=tag, case=name,
                          result=second)
                    # Q3: an admitted init latches zeros (clear-on-entry,
                    # no reject path taken).
                    got_latch = invoke(p, 'latch')
                    check((got_latch['rej_status'], got_latch['rej_site'],
                           got_latch['rej_page'], got_latch['rej_raw']) == (0, 0, 0, 0),
                          'admit latched a rejection', lane=tag, case=name,
                          latch=got_latch)
                    lane['admits'][name] = {**first, 'mutation': mutation,
                                            'oracle_tag': otag,
                                            'latch': got_latch,
                                            'mid_sha256': mid_sha,
                                            'stability': second,
                                            'stability_operations': second['physical_operations']}
                except Exception as exc:
                    after = p.read_bytes() if p is not None and p.is_file() else b''
                    lane['lane_failures'].append({'case': name, 'error': str(exc)[:2000],
                                                  'sha_after': hashlib.sha256(after).hexdigest()})
                    failures.append({'lane': tag, 'case': name, 'error': str(exc)[:2000],
                                     'sha_after': hashlib.sha256(after).hexdigest()})
            dense_cases = []
            try:
                dense = out / (exe.name + '-cost-dense.bin')
                f = invoke(dense, 'fill', '220')
                check(f['created'] == 220, 'dense fill short', lane=tag, fill=f)
                dense_cases.append(('dense-single', dense.read_bytes()))
                twin = bytearray(dense.read_bytes())
                copy_page_1to0(twin, 0, 1, 'dense-twinned')
                dense_cases.append(('dense-twinned', bytes(twin)))
            except Exception as exc:
                lane['lane_failures'].append({'case': 'dense-build',
                                              'error': str(exc)[:2000]})
                failures.append({'lane': tag, 'case': 'dense-build',
                                 'error': str(exc)[:2000]})
            for cname, cimg in dense_cases:
                try:
                    measure_cost(cname, cimg)
                    cost_done += 1
                except Exception as exc:
                    lane['lane_failures'].append({'case': cname,
                                                  'error': str(exc)[:2000]})
                    failures.append({'lane': tag, 'case': cname,
                                     'error': str(exc)[:2000]})
            rows.append(lane)
    check(len(REJECT_CASES) == len(set(REJECT_CASES)), 'duplicate reject case names')
    check(len(ADMIT_CASES) == len(set(ADMIT_CASES)), 'duplicate admit case names')
    check(set(EXPECTED_TAG) >= set(REJECT_CASES) | set(ADMIT_CASES),
          'oracle tag table does not cover the corpus')
    lanes_built = len(rows)
    reject_expected = lanes_built * len(REJECT_CASES) * 2
    sanitizer_lanes = len([l for l in rows if l['sanitizer']])
    sanitizer_expected = sanitizer_lanes * len(REJECT_CASES) * 2
    admit_expected = lanes_built * len(ADMIT_CASES) * 2
    cost_expected = lanes_built * (len(ADMIT_CASES) + 2)
    cost_short = cost_done != cost_expected
    if cost_short:
        failures.append({'phase': 'cost-coverage', 'cost_done': cost_done,
                         'cost_expected': cost_expected})
    stack_usage = {'available': False}
    try:
        tu = out / 'stack_tu.c'
        tu.write_text('#include "nvocmp.c"\n')
        # -O0 measurement build: -O1 inlines the single-callsite guard
        # helpers into initNv and the .su file loses their frames.
        subprocess.run(['gcc', '-std=c11', '-O0', '-fstack-usage', '-D_GNU_SOURCE',
                        '-DNV_LINUX', '-DNVOCMP_POSIX_MUTEX', '-DENABLE_SANITY_CHECK',
                        '-DDeviceFamily_CC26X4', '-DNVOCMP_NVPAGES=15',
                        '-I' + str(out), '-I' + str(HERE), '-I' + str(sdk / 'source'),
                        '-I' + str(sdk / 'source/ti/common/nv'),
                        '-c', str(tu), '-o', str(out / 'stack_tu.o')],
                       check=True, cwd=out, capture_output=True, text=True, timeout=120)
        su = out / 'stack_tu.su'
        if su.is_file():
            frames = q2_parse_stack_su(su.read_text())
            t832 = {k: frames[k] for k in Q2_STACK_FRAMES if k in frames}
            stack_usage = {'available': True, 't832_frames': t832,
                           'classify': frames.get('NVOCMP_startupClassify')}
        else:
            stack_usage = {'available': False, 'error': 'stack_tu.su not emitted'}
    except Exception as exc:
        stack_usage = {'available': False, 'error': str(exc)[:500]}
    missing = [k for k in Q2_STACK_FRAMES
               if k not in stack_usage.get('t832_frames', {})]
    if missing:
        failures.append({'phase': 'stack-frame-missing', 'missing': missing})
    if stack_usage.get('classify') and stack_usage['classify']['bytes'] > 1024:
        failures.append({'phase': 'stack-frame',
                         'frames': stack_usage['t832_frames']})
    enumeration = enumerate_topology()
    check(enumeration['total'] == 15504, 'topology enumeration incomplete',
          enumeration=enumeration)
    check(sum(enumeration['families'].values()) == enumeration['total'],
          'topology families do not partition', enumeration=enumeration)
    ok = not failures and lanes_built == 4
    result = {'ok': ok, 'lanes': rows,
              'rejection_cases': reject_done,
              'sanitizer_sweeps': sanitizer_done,
              'admit_runs': admit_done,
              'cost_runs': cost_done,
              'reject_runs_expected': reject_expected,
              'sanitizer_runs_expected': sanitizer_expected,
              'admit_runs_expected': admit_expected,
              'cost_runs_expected': cost_expected,
              'stack_usage': stack_usage,
              'corpus': {'version': CORPUS_VERSION, 'reject_names': REJECT_CASES,
                         'admit_names': ADMIT_CASES,
                         'reject_count': len(REJECT_CASES),
                         'admit_count': len(ADMIT_CASES)},
              'oracle': {'kind': 'python-state-count-model (policy mirror, '
                                 'not independent driver proof)',
                         'enumeration': enumeration},
              'sanitizer_flags': SANITIZER_FLAGS,
              'hardware_validated': False, 'private_data_used': False,
              'failures': failures}
    (out / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'ok': ok, 'rejection_cases': reject_done,
                      'sanitizer_sweeps': sanitizer_done, 'admit_runs': admit_done,
                      'cost_runs': cost_done, 'failures': len(failures)}))
    check(ok, 'startup preservation gate failed; see report failures',
          failures=len(failures))
    check(reject_done == reject_expected, 'reject runs incomplete',
          done=reject_done, expected=reject_expected)
    check(sanitizer_done == sanitizer_expected, 'sanitizer runs incomplete',
          done=sanitizer_done, expected=sanitizer_expected)
    check(admit_done == admit_expected, 'admit runs incomplete',
          done=admit_done, expected=admit_expected)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--sdk', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    verify(a.sdk.resolve(), a.out.resolve())
