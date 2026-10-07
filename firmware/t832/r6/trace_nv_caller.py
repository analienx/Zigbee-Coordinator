"""Q3: trace the production NV-init caller chain on hosted CI.

The pinned TI SDK and Z-Stack example trees are download-only checkouts;
this script greps them for every NVOCMP init entry reference and prints
bounded excerpts so the fatal-init behavior (does MT/SYS/DEBUG still
start after a rejected init?) can be read from the actual sources.
Fails when no production caller is found: a trace that finds nothing is
not a trace.
"""
import argparse
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


def iter_text_files(root):
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--sdk', type=Path, required=True)
    ap.add_argument('--examples', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    hits = []
    for root in (a.sdk, a.examples):
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
    prod = [h for h in hits
            if 'common/nv/nvocmp.c' not in h['file']
            and 'common/nv/nvintf.h' not in h['file']]
    if not prod:
        raise SystemExit('Q3 trace found no production NV-init caller')
    a.out.mkdir(parents=True, exist_ok=True)
    import json
    (a.out / 'nv-caller-trace.json').write_text(
        json.dumps({'hits': len(hits), 'production': len(prod),
                    'excerpts': prod[:MAX_EXCERPTS]}, indent=2) + '\n')
    print(json.dumps({'hits': len(hits), 'production': len(prod)}))


if __name__ == '__main__':
    main()
