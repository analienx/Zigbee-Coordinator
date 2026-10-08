"""Q3: trace and pin the production NV-init caller chain on hosted CI.

The pinned TI SDK and Z-Stack example trees are download-only checkouts.
The gate records every relevant source hit, requires at least one real initNV
call, and pins the two production Z-Stack callers whose ignored return value
keeps boot progressing after a rejected NV init.
"""
import argparse
import json
import re
from pathlib import Path

PATTERNS = (
    'initNV', 'initNvApi', 'loadApiPtrs', 'NVOCMP_loadApiPtrs',
    'NVINTF_nvFuncts', 'nvoctp', 'osal_nv_init', 'NV_init',
)
SKIP_DIRS = {'.git', '.github', '__pycache__', 'node_modules'}
TEXT_SUFFIXES = {'.c', '.h', '.cpp', '.hpp', '.md', '.txt', '.cfg', '.projectspec'}
MAX_EXCERPTS = 60
CONTEXT = 8
REQUIRED_CALLERS = (
    ('znp_startup',
     'source/ti/zstack/startup/main.c',
     re.compile(r'zstack_user0Cfg\.nvFps\.initNV\s*\(\s*NULL\s*\)')),
    ('osal_nv',
     'source/ti/zstack/osal/osal_nv.c',
     re.compile(r'pZStackCfg->nvFps\.initNV\s*\(\s*NULL\s*\)')),
)


def iter_text_files(root):
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def analyze_hits(hits):
    prod = [h for h in hits
            if 'common/nv/nvocmp.c' not in h['file'].replace('\\', '/')
            and 'common/nv/nvintf.h' not in h['file'].replace('\\', '/')]
    if not prod:
        raise ValueError('Q3 trace found no production NV-init caller evidence')
    calls = [h for h in prod
             if re.search(r'(->|\.)initNV\s*\(|[^_a-zA-Z]initNV\s*\([^;]*$',
                          h['match'])
             and 'NVOCMP_initNvApi' not in h['match']]
    if not calls:
        raise ValueError('Q3 trace found production mentions but zero actual initNV calls')

    required = {}
    for label, suffix, pattern in REQUIRED_CALLERS:
        matched = [h for h in calls
                   if h['file'].replace('\\', '/').endswith(suffix)
                   and pattern.search(h['match'])]
        if len(matched) != 1:
            raise ValueError('Q3 required caller %s expected exactly once, got %d'
                             % (label, len(matched)))
        required[label] = matched[0]
    return prod, calls, required


def collect_hits(roots):
    hits = []
    for root in roots:
        for path in iter_text_files(root):
            try:
                lines = path.read_text(encoding='utf-8', errors='strict').splitlines()
            except (UnicodeError, OSError):
                continue
            for n, line in enumerate(lines, 1):
                if any(p in line for p in PATTERNS):
                    lo = max(0, n - 1 - CONTEXT)
                    hi = min(len(lines), n + CONTEXT)
                    hits.append({'file': str(path.relative_to(root.parent)),
                                 'line': n, 'match': line.strip()[:160],
                                 'context': lines[lo:hi]})
                    if len(hits) >= MAX_EXCERPTS * 4:
                        break
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--sdk', type=Path, required=True)
    ap.add_argument('--examples', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()

    hits = collect_hits((a.sdk, a.examples))
    try:
        prod, calls, required = analyze_hits(hits)
    except ValueError as exc:
        raise SystemExit(str(exc))

    a.out.mkdir(parents=True, exist_ok=True)
    report = {'hits': len(hits), 'production': len(prod), 'calls': len(calls),
              'required_callers': required,
              'excerpts': prod[:MAX_EXCERPTS]}
    (a.out / 'nv-caller-trace.json').write_text(
        json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'hits': len(hits), 'production': len(prod),
                      'calls': len(calls),
                      'required_callers': sorted(required)}))
    for h in calls[:30]:
        print('CALL %s:%d: %s' % (h['file'], h['line'], h['match']))
    for label in sorted(required):
        h = required[label]
        print('REQUIRED %s %s:%d: %s' %
              (label, h['file'], h['line'], h['match']))
    prio = [h for h in calls if 'ti/zstack/' in h['file'].replace('\\', '/')]
    for h in prio[:8]:
        print('CTX %s:%d begin' % (h['file'], h['line']))
        for line in h['context']:
            print('CTX | ' + line[:200])
        print('CTX %s:%d end' % (h['file'], h['line']))


if __name__ == '__main__':
    main()
