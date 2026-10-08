"""Q4: offline checker for a next-trial evidence bundle.

Validates manifest integrity (presence/size/sha256), NV image geometry,
observed-vs-claimed page diffs, required first-boot records, and the
NV_RESULT a9 rejection-latch decoding. Pure stdlib; runs on synthetic
fixtures in public CI and on real captures offline. Exit 0 + JSON
summary on success, exit 1 + errors otherwise.
"""
import argparse
import hashlib
import json
from pathlib import Path

SCHEMA = 'trial-bundle/1.0'
NV_IMAGE_SIZE = 15 * 2048
PAGE = 2048
REQUIRED_ROLES = ('pre_nv', 'post_program_nv', 'post_boot_nv', 'records')
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
    return doc, []


def check_files(bundle, doc, errors):
    blobs = {}
    files = doc.get('files', {})
    for role in REQUIRED_ROLES:
        spec = files.get(role)
        if not spec:
            fail(errors, 'missing file role', role=role)
            continue
        path = bundle / spec.get('file', '')
        if not path.is_file():
            fail(errors, 'file absent', role=role, file=spec.get('file'))
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            fail(errors, 'file unreadable', role=role, detail=str(exc)[:200])
            continue
        if 'size' in spec and len(data) != spec['size']:
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
    expected = doc.get('ranges', {}).get('expected_changed_pages')
    if expected is None:
        fail(errors, 'manifest lacks ranges.expected_changed_pages')
        return
    unexpected = [pg for pg in prog_diff if pg not in expected]
    if unexpected:
        fail(errors, 'program diff outside claimed ranges',
             unexpected_pages=unexpected, expected=sorted(expected))


def check_records(blobs, errors, report):
    try:
        records = json.loads(blobs['records'].decode('utf-8'))
    except (ValueError, UnicodeError) as exc:
        fail(errors, 'records unreadable', detail=str(exc)[:200])
        return
    if not isinstance(records, list):
        fail(errors, 'records not a list')
        return
    kinds = [r.get('kind_name') for r in records if isinstance(r, dict)]
    if 'BOOT' not in kinds:
        fail(errors, 'missing BOOT record')
    results = [r for r in records
               if isinstance(r, dict) and r.get('kind_name') == 'NV_RESULT']
    a7 = [r for r in results if r.get('a') == 7]
    a9 = [r for r in results if r.get('a') == 9]
    if not a7:
        fail(errors, 'missing NV_RESULT a7 (init action) record')
    if not a9:
        fail(errors, 'missing NV_RESULT a9 (rejection latch) record')
    for r in a7[:1]:
        action = r.get('b')
        if not isinstance(action, int) or not 0 <= action < INIT_ACTIONS:
            fail(errors, 'a7 init action out of range', record=r)
        else:
            report['init_action'] = action
            report['first_failure'] = r.get('c')
    for r in a9[:1]:
        b, c = r.get('b'), r.get('c')
        if not isinstance(b, int) or not isinstance(c, int):
            fail(errors, 'a9 fields not integers', record=r)
            continue
        status, page = (b >> 8) & 0xFF, b & 0xFF
        site, raw = (c >> 8) & 0xFF, c & 0xFF
        if status not in NVINTF_STATUS:
            fail(errors, 'a9 status unknown', status=status, record=r)
        if page != 0xFF and page > 14:
            fail(errors, 'a9 page out of range', page=page, record=r)
        if site > MAX_SITE:
            fail(errors, 'a9 site out of range', site=site, record=r)
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
