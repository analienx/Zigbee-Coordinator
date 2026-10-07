"""Actual pinned driver; run only in GitHub-hosted Actions.

R10 preservation corpus v2 (F1-F9): compact-header negatives using
physically plausible 1->0 corruption, legacy fail-closed negatives,
multi-ACT agreement-proof locks (agreeing twins admitted, divergent live
values rejected), exact sanity-bitmask asserts, and derived
(never hard-coded) evidence. The Python oracles below
mirror classifier policy for case construction; they are not independent
proof of the driver. Only the hosted driver-probe runs count as execution
evidence.
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
    # HDRLE branch of NVOCMP_readHeader (NVOCMP_HDRLE is 0 on this target).
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
    sliding past unrecognized tail bytes bounded. Returns (live, anomaly)."""
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


def _cmp(page, idx):
    o = 4 + idx * 4
    return {'off': page[o] | (page[o + 1] << 8), 'page': page[o + 2],
            'sig': page[o + 3], 'raw': bytes(page[o:o + 4])}


def oracle_compact(page, state):
    """Policy mirror of the C compact preflight (structural half): replays
    the same admission rules for case construction, not independent proof.
    Returns (ok, tag)."""
    this, start, end = _cmp(page, 0), _cmp(page, 1), _cmp(page, 2)
    for h in (this, start, end):
        if h['sig'] not in SIG_VALUES:
            return False, 'CMP_SIG'
    if this['page'] not in MODE_VALUES:
        return False, 'CMP_MODE'
    for h in (start, end):
        if h['page'] != 0xFF and not 0 <= h['page'] < NVPAGES:
            return False, 'CMP_PAGE_RANGE'
        if (h['page'] == 0xFF) != (h['off'] == 0xFFFF):
            return False, 'CMP_NULL'
        if h['page'] != 0xFF and h['sig'] != 0x96:
            return False, 'CMP_RANGE_SIG'
        if h['page'] != 0xFF and not 0 <= h['off'] <= FLASH_PAGE_SIZE:
            return False, 'CMP_OFFSET_RANGE'
    if state in (0x7C, 0x78, 0x70):
        if this['off'] != 0xFFFF and not PGDATAOFS <= this['off'] <= FLASH_PAGE_SIZE:
            return False, 'CMP_CURSOR_RANGE'
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
        if this['page'] != 0xFF:
            return False, 'CMP_NACT_MODE' if state == 0xFF else 'CMP_RDY_MODE'
        if state == 0x7E:
            if this['off'] != 0xFFFF and this['off'] != PGDATAOFS:
                return False, 'CMP_RDY_CURSOR'
        elif this['off'] != 0xFFFF and not 0 <= this['off'] <= FLASH_PAGE_SIZE:
            return False, 'CMP_QUIRK_CURSOR'
        for h in (start, end):
            if h['raw'] not in (b'\xff\xff\xff\xff', b'\xff\xff\xff\x96'):
                return False, 'CMP_STALE_FORM'
    if state == 0xFE:
        if this['page'] not in (0xFF, 0xFE):
            return False, 'CMP_XDST_MODE'
        if this['off'] != 0xFFFF:
            return False, 'CMP_XDST_CURSOR'
    if this['page'] == 0xFE:
        if state not in (0xFE, 0x7C, 0x78):
            return False, 'CMP_FE_STATE'
        if this['off'] != 0xFFFF:
            return False, 'CMP_FE_CURSOR'
    if state in (0x7C, 0x78, 0x70) and this['off'] != 0xFFFF:
        end_true = find_end(page)
        if this['off'] > end_true:
            return False, 'CMP_CURSOR_ABOVE_END'
        if this['off'] < end_true and not on_boundary(page, this['off'], end_true):
            return False, 'CMP_CURSOR_MISALIGNED'
    return True, 'CMP_OK'


def _fwd(a, b):
    return (b - a + NVPAGES) % NVPAGES


def oracle_decision(img):
    """Policy mirror of classifier + driver startup decision: same rules,
    Python-side, for case construction; not independent proof. Returns
    (verdict, tag) where verdict is 'REJECT' or 'ADMIT'. First failure in
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
            return 'REJECT', 'LEGACY'
        if sig != 0x96 or (verbyte >> 2) != 0x03 or state not in VALID_STATES:
            return 'REJECT', 'BAD_HEADER'
        # F9: TI reserves allActive 1/2 and cycle 0x00/0xFF. A non-erased
        # current-format header carrying them is rejected.
        if (verbyte & 0x03) not in (0x00, 0x03):
            return 'REJECT', 'BAD_ALLACTIVE'
        if not 0x01 <= page[1] <= 0xFE:
            return 'REJECT', 'BAD_CYCLE'
        if state == 0xFF and bytes(page[PGDATAOFS:]) != b'\xff' * (PAGE - PGDATAOFS):
            return 'REJECT', 'NACT_DATA'
        ok, tag = oracle_compact(page, state)
        if not ok:
            return 'REJECT', tag
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
    if destinations > 1:
        return 'REJECT', 'TOPO_DUP_XDST'
    if sources > 1:
        return 'REJECT', 'TOPO_DUP_XSRC'
    if ready > 1:
        return 'REJECT', 'TOPO_DUP_RDY'
    if inactive != NVPAGES and not destinations and not sources and not data:
        return 'REJECT', 'TOPO_LONE_OR_EMPTY'
    # F7: the driver consumes only the first PGCDST page, so ambiguous
    # destination metadata fails closed instead of silently picking one.
    if sum(1 for m in modes if m == 0xFE) > 1:
        return 'REJECT', 'CMP_DUP_PGCDST'
    # F8 agreement proof (mirrors the C gate): every pair of live copies
    # sharing an ID across (or within) ACT pages must agree in length and
    # payload bytes. RESUME reads from the last ACT while RECOVER_ERASE
    # reads from the first, so divergent copies would return different
    # values on the two paths. Anything unparseable fails closed. C
    # additionally requires both CRCs valid (strict superset); every corpus
    # verdict here is CRC-decisive-identical (twins valid, conflicts differ).
    act_live = {}
    for pg in range(NVPAGES):
        if states[pg] != 0x7C:
            continue
        live, anomaly = walk_live(img[pg * PAGE:(pg + 1) * PAGE])
        if anomaly:
            return 'REJECT', 'TOPO_ACT_CONFLICT'
        for h in live:
            key = (h['sysid'], h['itemid'], h['subid'])
            payload = bytes(img[pg * PAGE + h['hofs'] - h['len']:
                                pg * PAGE + h['hofs']])
            for seen in act_live.get(key, []):
                if seen != (h['len'], payload):
                    return 'REJECT', 'TOPO_ACT_CONFLICT'
            act_live.setdefault(key, []).append((h['len'], payload))
    first_fe = next((pg for pg in range(NVPAGES) if modes[pg] == 0xFE), None)
    if inactive == NVPAGES:
        return 'ADMIT', 'ADMIT_INIT'
    if sources:
        if destinations:
            return 'ADMIT', 'ADMIT_RECOVER_COMPACT'
        if inactive:
            return 'ADMIT', 'ADMIT_RECOVER_COMPACT_NACT'
        if first_fe is None:
            return 'REJECT', 'DRIVER_UNKNOWN_LATCH'
    elif destinations:
        return 'ADMIT', 'ADMIT_RESUME_DIRECT'
    elif data:
        if first_fe is None:
            if inactive:
                return 'ADMIT', 'ADMIT_RESUME_MARK'
            return 'REJECT', 'DRIVER_UNKNOWN_LATCH'
    else:
        return 'REJECT', 'TOPO_LONE_OR_EMPTY'
    # RECOVER_ERASE branch: the first PGCDST page's range drives cleanPage.
    f = first_fe
    spg, epg, eoff = spages[f], epages[f], eoffs[f]
    if spg == 0xFF or epg == 0xFF:
        return 'REJECT', 'CMP_ERASE_RANGE_NULL'
    if _fwd(spg, epg) + 1 > NVPAGES - 1:
        return 'REJECT', 'CMP_ERASE_RANGE_SPAN'
    if _fwd(spg, f) <= _fwd(spg, epg):
        return 'REJECT', 'CMP_ERASE_RANGE_DST'
    # F6: cleanPage erases non-end range pages unconditionally (the offset
    # correction forces PGDATAOFS), so each non-end page must be
    # blank/header-only (nothing to destroy) or the range fails closed.
    p = spg
    while p != epg:
        if find_end(img[p * PAGE:(p + 1) * PAGE]) > PGDATAOFS:
            return 'REJECT', 'CMP_ERASE_RANGE_MULTI'
        p = (p + 1) % NVPAGES
    end_true = find_end(img[epg * PAGE:(epg + 1) * PAGE])
    if eoff == PGDATAOFS:
        # Fully-drained form: cleanPage erases the end page without
        # reading data through the offset. Safe only when the end page
        # holds no data (blank, or header-only); a torn end offset on a
        # live end page would erase live items.
        if end_true > PGDATAOFS:
            return 'REJECT', 'CMP_ERASE_LIVE_END'
    elif eoff > end_true:
        return 'REJECT', 'CMP_ERASE_ABOVE_END'
    if (eoff != PGDATAOFS and eoff < end_true
            and not on_boundary(img[epg * PAGE:(epg + 1) * PAGE], eoff, end_true)):
        return 'REJECT', 'CMP_ERASE_MISALIGNED'
    return 'ADMIT', 'ADMIT_RECOVER_ERASE'


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
                'hdr-allactive-1', 'hdr-allactive-2', 'same-page-divergent-dup']
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
               'admit-drained-short-end']

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
    'cmp-eoffset-misaligned': 'CMP_ERASE_MISALIGNED',
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
    'multi-act-twins': 'ADMIT_RESUME_DIRECT',
    'multi-act-rdy': 'ADMIT_RESUME_DIRECT',
    'admit-full-nact-mark': 'ADMIT_RESUME_MARK',
    'admit-drained-short-end': 'ADMIT_RECOVER_ERASE',
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


def verify(sdk, out):
    out.mkdir(parents=True, exist_ok=False)
    source = out / 'nvocmp.c'
    shutil.copy2(sdk / 'source/ti/common/nv/nvocmp.c', source)
    apply_fix(source)
    rows = []
    failures = []
    reject_done = sanitizer_done = admit_done = 0
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

            def invoke(image, verb):
                env = dict(os.environ, NVLAB_IMAGE=str(image))
                env.pop('NVLAB_CUT_OP', None)
                try:
                    p = subprocess.run([str(exe), verb], env=env, capture_output=True,
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
                    lane['rejections'][name] = {**r, 'mutation': mutation,
                                                 'oracle_tag': otag,
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
                    lane['admits'][name] = {**first, 'mutation': mutation,
                                            'oracle_tag': otag,
                                            'mid_sha256': mid_sha,
                                            'stability': second,
                                            'stability_operations': second['physical_operations']}
                except Exception as exc:
                    after = p.read_bytes() if p is not None and p.is_file() else b''
                    lane['lane_failures'].append({'case': name, 'error': str(exc)[:2000],
                                                  'sha_after': hashlib.sha256(after).hexdigest()})
                    failures.append({'lane': tag, 'case': name, 'error': str(exc)[:2000],
                                     'sha_after': hashlib.sha256(after).hexdigest()})
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
              'reject_runs_expected': reject_expected,
              'sanitizer_runs_expected': sanitizer_expected,
              'admit_runs_expected': admit_expected,
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
                      'failures': len(failures)}))
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
