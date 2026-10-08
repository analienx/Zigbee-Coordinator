"""Q4: offline checker for a next-trial evidence bundle.

Validates manifest integrity (presence/size/sha256), NV image geometry,
observed-vs-claimed page diffs, required first-boot records in order
(single BOOT first, every a9 with a preceding a7, every a7 with a
following a9), the NV_RESULT a9 rejection-latch decoding, and the
recorded network-state comparison verdict. Pure stdlib; runs on
synthetic fixtures in public CI and on real captures offline. Exit 0
+ JSON summary on success, exit 1 + errors otherwise.
"""
import argparse
import hashlib
import json
from pathlib import Path

SCHEMA = 'trial-bundle/1.0'
PLAN_VERSION = '1.0.0'
NV_IMAGE_SIZE = 15 * 2048
PAGE = 2048
REQUIRED_ROLES = ('pre_nv', 'post_program_nv', 'post_boot_nv', 'records')
REQUIRED_META = ('operator', 'tools', 'hex_sha256', 'capture_window_s')
MAX_SITE = 39
INIT_ACTIONS = 7  # NVOCMP_NORMAL_INIT..NVOCMP_ERROR_UNKNOWN
NVINTF_STATUS = {0: 'SUCCESS', 1: 'FAILURE', 12: 'BADVERSION'}


def fail(errors, message, **ctx):
    errors.append({'error': message, **ctx})


def load_manifest(bundle):
    manifest = bundle / 'manifest.json'
    if not manifest.is_file():
        return None, [{'error': 'missing manifest.json'}]
    try:
        doc = json.loads(manifest.read_text())
    except (ValueError, OSError) as exc:
        return None, [{'error': 'manifest unreadable', 'detail': str(exc)[:200]}]
    if doc.get('schema') != SCHEMA:
        return None, [{'error': 'manifest schema mismatch',
                       'want': SCHEMA, 'got': doc.get('schema')}]
    if doc.get('plan_version') != PLAN_VERSION:
        return None, [{'error': 'plan version unsupported',
                       'want': PLAN_VERSION, 'got': doc.get('plan_version')}]
    sha = doc.get('candidate_sha', '')
    if not isinstance(sha, str) or len(sha) != 40 or \
            any(c not in '0123456789abcdef' for c in sha.lower()):
        return None, [{'error': 'candidate_sha not 40-hex (TBD fails)',
                       'got': doc.get('candidate_sha')}]
    meta = doc.get('meta', {})
    if not isinstance(meta, dict):
        return None, [{'error': 'manifest meta not an object'}]
    for key in REQUIRED_META:
        if key not in meta:
            return None, [{'error': 'manifest meta missing', 'key': key}]
    if not isinstance(meta['operator'], str) or not meta['operator'].strip():
        return None, [{'error': 'meta.operator empty'}]
    if not isinstance(meta['tools'], list) or not meta['tools']:
        return None, [{'error': 'meta.tools not a non-empty list'}]
    hexsha = meta['hex_sha256']
    if not isinstance(hexsha, str) or len(hexsha) != 64 or \
            any(c not in '0123456789abcdef' for c in hexsha.lower()):
        return None, [{'error': 'meta.hex_sha256 not 64-hex'}]
    if not isinstance(meta['capture_window_s'], int) or \
            meta['capture_window_s'] < 120:
        return None, [{'error': 'meta.capture_window_s below 120 s'}]
    netst = doc.get('network_state', {})
    if not isinstance(netst, dict):
        return None, [{'error': 'network_state not an object'}]
    if not isinstance(netst.get('preserved'), bool):
        return None, [{'error': 'network_state.preserved not a bool'}]
    if not isinstance(netst.get('note'), str) or not netst['note'].strip():
        return None, [{'error': 'network_state.note empty'}]
    return doc, []


def check_files(bundle, doc, errors):
    blobs = {}
    files = doc.get('files', {})
    if not isinstance(files, dict):
        fail(errors, 'manifest files not an object')
        return blobs
    for role in REQUIRED_ROLES:
        spec = files.get(role)
        if not spec:
            fail(errors, 'missing file role', role=role)
            continue
        if not isinstance(spec, dict):
            fail(errors, 'file role not an object', role=role)
            continue
        raw = spec.get('file', '')
        if not isinstance(raw, str) or not raw:
            fail(errors, 'file path not a string', role=role)
            continue
        path = bundle / raw
        try:
            inside = path.resolve().relative_to(bundle.resolve())
        except (OSError, ValueError):
            inside = None
        if inside is None or str(inside).startswith('..'):
            fail(errors, 'file path escapes bundle', role=role, file=raw)
            continue
        if not path.is_file():
            fail(errors, 'file absent', role=role, file=spec.get('file'))
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            fail(errors, 'file unreadable', role=role, detail=str(exc)[:200])
            continue
        if 'size' not in spec:
            fail(errors, 'size pin missing', role=role)
        elif len(data) != spec['size']:
            fail(errors, 'size mismatch', role=role, want=spec['size'],
                 got=len(data))
        digest = hashlib.sha256(data).hexdigest()
        if digest != spec.get('sha256'):
            fail(errors, 'sha256 mismatch', role=role, want=spec.get('sha256'),
                 got=digest)
        blobs[role] = data
    return blobs


def changed_pages(before, after):
    return [pg for pg in range(15)
            if before[pg * PAGE:(pg + 1) * PAGE] != after[pg * PAGE:(pg + 1) * PAGE]]


def check_images(blobs, doc, errors, report):
    for role in ('pre_nv', 'post_program_nv', 'post_boot_nv'):
        if role in blobs and len(blobs[role]) != NV_IMAGE_SIZE:
            fail(errors, 'NV image geometry', role=role,
                 want=NV_IMAGE_SIZE, got=len(blobs[role]))
    if not all(r in blobs and len(blobs[r]) == NV_IMAGE_SIZE
               for r in ('pre_nv', 'post_program_nv', 'post_boot_nv')):
        return
    prog_diff = changed_pages(blobs['pre_nv'], blobs['post_program_nv'])
    boot_diff = changed_pages(blobs['post_program_nv'], blobs['post_boot_nv'])
    report['program_diff_pages'] = prog_diff
    report['boot_diff_pages'] = boot_diff
    ranges = doc.get('ranges', {})
    if not isinstance(ranges, dict):
        fail(errors, 'manifest ranges not an object')
        return
    expected = ranges.get('expected_changed_pages')
    if expected is None:
        fail(errors, 'manifest lacks ranges.expected_changed_pages')
        return
    if not isinstance(expected, list):
        fail(errors, 'expected_changed_pages not a list')
        return
    unexpected = [pg for pg in prog_diff if pg not in expected]
    if unexpected:
        fail(errors, 'program diff outside claimed ranges',
             unexpected_pages=unexpected, expected=sorted(expected))
    # Claim slack is reported for operator review: an over-broad claim
    # (up to all 15 pages) would make containment vacuous, so the
    # claimed-but-untouched set is always visible next to the diffs.
    # Range trust itself rests on the G3 tool-log evidence (plan §3).
    report['claim_slack_pages'] = sorted(set(expected) - set(prog_diff))
    # Boot diff is reported for operator review; it is additionally
    # gated only when the manifest claims a boot allowlist.
    allowed = ranges.get('boot_allowed_pages')
    if allowed is not None:
        if not isinstance(allowed, list):
            fail(errors, 'boot allowlist not a list', allowed=allowed)
        else:
            bad_boot = [pg for pg in boot_diff if pg not in allowed]
            if bad_boot:
                fail(errors, 'boot diff outside claimed allowlist',
                     unexpected_pages=bad_boot, allowed=sorted(allowed))


def check_records(blobs, errors, report):
    try:
        records = json.loads(blobs['records'].decode('utf-8'))
    except (ValueError, UnicodeError) as exc:
        fail(errors, 'records unreadable', detail=str(exc)[:200])
        return
    if not isinstance(records, list):
        fail(errors, 'records not a list')
        return
    for n, r in enumerate(records):
        if not isinstance(r, dict) or not isinstance(r.get('kind_name'), str):
            fail(errors, 'record malformed', index=n, record=r)
    seq = [r for r in records if isinstance(r, dict) and
           r.get('kind_name') in ('BOOT', 'NV_RESULT')]
    kinds = [r.get('kind_name') for r in seq]
    boots = [n for n, k in enumerate(kinds) if k == 'BOOT']
    if not boots:
        fail(errors, 'missing BOOT record')
    elif len(boots) > 1:
        fail(errors, 'multiple BOOT records (reset in capture window)',
             count=len(boots), positions=boots)
    elif boots[0] != 0:
        fail(errors, 'BOOT not first (out-of-order evidence)',
             position=boots[0])
    results = [r for r in seq if r.get('kind_name') == 'NV_RESULT']
    a7 = [r for r in results if r.get('a') == 7]
    a9 = [r for r in results if r.get('a') == 9]
    if not a7:
        fail(errors, 'missing NV_RESULT a7 (init action) record')
    if not a9:
        fail(errors, 'missing NV_RESULT a9 (rejection latch) record')
    # Per-poll emission is unconditionally a7-then-a9 (r6_nv_export.inc),
    # so in concatenated polls every a9 has a preceding a7 and every a7
    # has a following a9. A lone leading a9 is out-of-order; a trailing
    # lone a7 is truncated (or its a9 was buried on the routine ring).
    a7pos = [n for n, r in enumerate(seq)
             if r.get('kind_name') == 'NV_RESULT' and r.get('a') == 7]
    a9pos = [n for n, r in enumerate(seq)
             if r.get('kind_name') == 'NV_RESULT' and r.get('a') == 9]
    for p in a9pos:
        if not any(q < p for q in a7pos):
            fail(errors, 'a9 without preceding a7 (out-of-order)',
                 position=p)
    for q in a7pos:
        if not any(p > q for p in a9pos):
            fail(errors, 'a7 without following a9 (truncated evidence)',
                 position=q)
    report['boot_count'] = len(boots)
    report['a7_count'] = len(a7pos)
    report['a9_count'] = len(a9pos)
    for n, r in enumerate(a7):
        action = r.get('b')
        if not isinstance(action, int) or not 0 <= action < INIT_ACTIONS:
            fail(errors, 'a7 init action out of range', index=n, record=r)
        elif n == 0:
            report['init_action'] = action
            report['first_failure'] = r.get('c')
        first_failure = r.get('c')
        if not isinstance(first_failure, int) or \
                not 0 <= first_failure <= 0xFFFF:
            fail(errors, 'a7 first_failure not u16', index=n, record=r)
    for n, r in enumerate(a9):
        b, c = r.get('b'), r.get('c')
        if not isinstance(b, int) or not isinstance(c, int):
            fail(errors, 'a9 fields not integers', index=n, record=r)
            continue
        if not 0 <= b <= 0xFFFF or not 0 <= c <= 0xFFFF:
            fail(errors, 'a9 fields not u16', index=n, record=r)
            continue
        status, page = (b >> 8) & 0xFF, b & 0xFF
        site, raw = (c >> 8) & 0xFF, c & 0xFF
        if status not in NVINTF_STATUS:
            fail(errors, 'a9 status unknown', index=n, status=status,
                 record=r)
        if page != 0xFF and page > 14:
            fail(errors, 'a9 page out of range', index=n, page=page,
                 record=r)
        if site > MAX_SITE:
            fail(errors, 'a9 site out of range', index=n, site=site,
                 record=r)
        if n == 0:
            report['latch'] = {'status': status, 'page': page,
                               'site': site, 'raw': raw}


def check_bundle(bundle):
    report = {'bundle': str(bundle)}
    errors = []
    doc, manifest_errors = load_manifest(bundle)
    errors.extend(manifest_errors)
    if doc is None:
        return {'ok': False, 'errors': errors, **report}
    report['plan_version'] = doc.get('plan_version')
    report['candidate_sha'] = doc.get('candidate_sha')
    blobs = check_files(bundle, doc, errors)
    if all(r in blobs for r in ('pre_nv', 'post_program_nv', 'post_boot_nv')):
        check_images(blobs, doc, errors, report)
    if 'records' in blobs:
        check_records(blobs, errors, report)
    netst = doc.get('network_state', {})
    report['network_state'] = {'preserved': netst.get('preserved'),
                               'note': netst.get('note')}
    if netst.get('preserved') is False:
        fail(errors, 'trial finding: network state not preserved',
             note=netst.get('note'))
    return {'ok': not errors, 'errors': errors, **report}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle', type=Path, required=True)
    a = ap.parse_args()
    result = check_bundle(a.bundle)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['ok'] else 1)


if __name__ == '__main__':
    main()
