#!/usr/bin/env python3
"""Generate a HOST-ONLY trace of the exact flashed NV4 observer, never firmware.

The Linux program runs the untouched and traced C observers over the same
immutable stdin bytes and compares all result fields and every read request.
No private input is accepted by this generator or included in its receipts.
Only line-ending normalization is allowed before checking the public sources.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from functools import lru_cache
from urllib.request import urlopen


QUAL = Path(__file__).resolve().parent
LIVE_FIRMWARE_SHA = '828b1b5e55d24a13dccf88bffe74108bf4b56bcc'
PINS = {
    'nv4_readonly_admission.c':
        'c5d1d399e40bd8b4b71705befa14a0297b9bd246a0771508cc5a785a6b6d1fc9',
    'nv4_readonly_admission.h':
        '34846468e2b423c3058b66872e1db52bd486246383dd9066237e440aed149271',
    'nv4_b1_bridge.py':
        '4a945bc47815a88d0eb2352c0d3eb60607a5b444b946c4f2138c11507e56ea95',
    'b1_admission.h':
        'f1d2e7b230546bfed739d930667be2971f1716230c22e97049faf3c1da402d61',
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@lru_cache(maxsize=4)
def public_source(name: str) -> str:
    path = QUAL.parent / 'b1' / name if name == 'b1_admission.h' else QUAL / name
    raw = path.read_bytes().replace(b'\r\n', b'\n')
    if digest(raw) != PINS[name]:
        # This oracle describes the actually flashed 828b1b5 image. Later
        # firmware fixes must not silently change its saved-media diagnosis.
        root = QUAL.parents[3]
        relative = path.relative_to(root).as_posix()
        try:
            raw = subprocess.check_output(
                ['git', '-C', str(root), 'show', f'{LIVE_FIRMWARE_SHA}:{relative}'],
                stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            # Shallow hosted checkouts need only these public, hash-pinned
            # historical sources; no private capture is sent over the network.
            with urlopen('https://raw.githubusercontent.com/analienx/'
                         f'Zigbee-Coordinator/{LIVE_FIRMWARE_SHA}/{relative}',
                         timeout=20) as response:
                raw = response.read(262144)
        raw = raw.replace(b'\r\n', b'\n')
    if digest(raw) != PINS[name]:
        raise ValueError('NV4_ORACLE_PIN_DRIFT_' + name)
    return raw.decode('utf-8')


def hook(reason: str, *values: str) -> str:
    if not re.fullmatch(r'[a-z_]+', reason) or len(values) > 8:
        raise ValueError('NV4_ORACLE_INVALID_HOOK')
    args = list(values) + ['0u'] * (8 - len(values))
    return (f'r4_nv4_host_trace_event("{reason}", __LINE__, ' +
            ', '.join(args) + '); ')


def instrument(source: str) -> str:
    """Add notifications only; retain original source line numbers and branches."""
    if digest(source.encode()) != PINS['nv4_readonly_admission.c']:
        raise ValueError('NV4_ORACLE_OBSERVER_SOURCE_DRIFT')
    before = {
        50: hook('scan_bounds', 'offset', 'length'),
        56: hook('read_failure', 'offset', 'length'),
        114: hook('record_limit', 'page_base + end'),
        119: hook('short_item_tail', 'page_base + end'),
        129: hook('item_header', 'page_base + header_offset', 'length'),
        151: hook('item_crc', 'page_base + header_offset'),
        159: hook('item_status_invalid', 'page_base + header_offset + 5u'),
        166: hook('active_identity_limit', 'page_base + header_offset'),
        172: hook('duplicate_active_identity', 'page_base + header_offset'),
        241: hook('page_header', 'page', 'header[0]',
                  '(uint32_t)(header[4] | ((uint32_t)header[5] << 8u))',
                  'header[6]', '(uint32_t)erased_compaction_journal(header)',
                  '(uint32_t)valid_completed_journal(header, page)'),
        246: hook('bad_page_header', 'base'),
        268: hook('page_metadata', 'base + 4u', 'logical', 'mode',
                  '(uint32_t)erased_compaction_journal(header)',
                  '(uint32_t)valid_completed_journal(header, page)',
                  '(uint32_t)(logical == 0xffffu || '
                  '(logical >= R4_DATA_START && logical <= R4_NV4_PAGE_SIZE))'),
        278: hook('page_state', 'base'),
        294: hook('page_end', 'page', 'end'),
        297: hook('empty_page_contents', 'base + end'),
        305: hook('aggregate', 'active', 'full', 'destination', 'inactive',
                  'live_count', 'zstack_live_count'),
        308: hook('page_counts'),
        312: hook('no_zstack_records'),
        318: hook('semantic_markers', 'markers.bdb_seen',
                  '(uint32_t)(markers.bdb_on_network == 0u ? 0u : '
                  '(markers.bdb_on_network == 1u ? 1u : 2u))',
                  'markers.role_seen', '(uint32_t)(markers.logical_type == 0u)',
                  'markers.nib_seen', 'markers.malformed'),
    }
    lines = source.splitlines(keepends=True)
    for number, notification in before.items():
        line = lines[number - 1]
        # Pinning the complete source is primary; these anchor checks make an
        # accidental wrong line-table update fail closed as well.
        if number in (241, 294, 305, 318):
            if not line.lstrip().startswith(('if (header', 'if (active',
                                              'if (!markers')):
                raise ValueError('NV4_ORACLE_BRANCH_ANCHOR_DRIFT')
        elif not re.search(r'\br(?:->|\.)code\s*=', line):
            raise ValueError('NV4_ORACLE_RESULT_ANCHOR_DRIFT')
        indent = line[:len(line) - len(line.lstrip())]
        lines[number - 1] = indent + notification + line.lstrip()
    null_reader = '    if (reader == NULL) return r;\n'
    if lines[228] != null_reader:
        raise ValueError('NV4_ORACLE_NULL_READER_ANCHOR_DRIFT')
    lines[228] = ('    if (reader == NULL) { ' + hook('no_reader') +
                  'return r; }\n')
    terminal = '    r.code = R4_NV4_READONLY_STRUCTURE_ACCEPTED;\n'
    if lines[325] != terminal:
        raise ValueError('NV4_ORACLE_ACCEPT_ANCHOR_DRIFT')
    lines[325] = ('    r4_nv4_host_trace_event('
                  'r.semantic_state == R4_NV4_STATE_UNKNOWN_HOLD ? '
                  '"semantic_unknown_hold" : "structure_candidate", '
                  '__LINE__, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u); ' +
                  terminal.lstrip())
    prefix = ('#include <stdint.h>\n'
              'extern void r4_nv4_host_trace_event(const char *, unsigned, '
              'uint32_t, uint32_t, uint32_t, uint32_t, '
              'uint32_t, uint32_t, uint32_t, uint32_t);\n'
              '#define r4_nv4_admit r4_nv4_admit_traced\n'
              '#line 1 "nv4_readonly_admission.c"\n')
    return prefix + ''.join(lines)


def bridge_c(source: str) -> str:
    """Compile the actual bridge's C switch, rather than re-model its mapping."""
    if digest(source.encode()) != PINS['nv4_b1_bridge.py']:
        raise ValueError('NV4_ORACLE_BRIDGE_SOURCE_DRIFT')
    assignments = [n for n in ast.parse(source).body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'NEW_ADMISSION'
                           for t in n.targets)]
    if len(assignments) != 1:
        raise ValueError('NV4_ORACLE_BRIDGE_CONSTANT_DRIFT')
    block = ast.literal_eval(assignments[0].value)
    start = block.index('            switch (admission.code)')
    end = block.index('            b1_management_note_nv_probe(reason);')
    return ('#include "nv4_readonly_admission.h"\n'
            '#include "b1_admission.h"\n'
            'unsigned r4_nv4_host_bridge_reason(r4_nv4_result admission) {\n'
            '    uint8_t reason = B1_NV_HOLD_UNKNOWN_LAYOUT;\n' +
            block[start:end] + '    return reason;\n}\n')


def generate(out: Path, source_sha: str) -> dict:
    if not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise ValueError('NV4_ORACLE_EXACT_SOURCE_SHA_REQUIRED')
    sources = {name: public_source(name) for name in PINS}
    files = {
        'nv4_readonly_admission.c': sources['nv4_readonly_admission.c'],
        'nv4_readonly_admission.h': sources['nv4_readonly_admission.h'],
        'b1_admission.h': sources['b1_admission.h'],
        'nv4_admission_traced.c': instrument(sources['nv4_readonly_admission.c']),
        'nv4_bridge_reason.c': bridge_c(sources['nv4_b1_bridge.py']),
        'nv4_b1_bridge.py': sources['nv4_b1_bridge.py'],
        'nv4_admission_host_trace.py': Path(__file__).read_text().replace('\r\n', '\n'),
        'nv4_admission_trace_cli.c':
            (QUAL / 'nv4_admission_trace_cli.c').read_text().replace('\r\n', '\n'),
        'oracle_build.h':
            f'#define ORACLE_SOURCE_SHA "{source_sha}"\n'
            f'#define ORACLE_LIVE_FIRMWARE_SHA "{LIVE_FIRMWARE_SHA}"\n'
            f'#define ORACLE_OBSERVER_SHA "{PINS["nv4_readonly_admission.c"]}"\n',
        'README.txt':
            'HOST ONLY; no device or firmware write interface.\n'
            'Verify the exact Actions source head and build-receipt.json binary SHA.\n'
            'Linux/WSL: chmod +x nv4-admission-oracle-linux\n'
            'Full saved 704KiB capture, explicit A4000..ABFFF slice in RAM:\n'
            '  ./nv4-admission-oracle-linux --stdin-full-a4000 < PRIVATE_CAPTURE\n'
            'Already-extracted exact 32KiB current NV region:\n'
            '  ./nv4-admission-oracle-linux --stdin-nv4-a4000 < PRIVATE_NV_REGION\n'
            'Exit0 means oracle executed with exact original/traced parity.\n'
            'Admission outcome is code/semantic_state/bridge_probe in sanitized JSON.\n'
            'Saved-media admission does not prove the current live NVS reader state.\n'
            'No hardware operation or flash authorization follows from this output.\n',
    }
    if out.exists() and any(out.iterdir()):
        raise ValueError('NV4_ORACLE_NONEMPTY_OUTPUT_DENIED')
    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out / name).write_bytes(text.encode())
    report = {
        'schema': 'p7u-nv4-host-oracle-build-v1',
        'source_sha': source_sha,
        'source_compatible_live_firmware_sha': LIVE_FIRMWARE_SHA,
        'public_source_sha256_normalized_lf': PINS,
        'nv_region': ['0xA4000', '0xAC000'],
        'full_capture_size': 0xB0000,
        'stdin_modes': ['--stdin-full-a4000', '--stdin-nv4-a4000'],
        'scope': 'HOST_ONLY_SAVED_MEDIA_C_OBSERVER',
        'files': {name: digest(text.encode()) for name, text in files.items()},
        'native_ti_recovery_validated': False,
        'firmware_modified': False,
        'flash_authorized': False,
    }
    (out / 'source-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def seal(out: Path) -> dict:
    report = json.loads((out / 'source-receipt.json').read_text())
    if report.get('schema') != 'p7u-nv4-host-oracle-build-v1':
        raise ValueError('NV4_ORACLE_RECEIPT_SCHEMA')
    for name, expected in report['files'].items():
        if Path(name).name != name or digest((out / name).read_bytes()) != expected:
            raise ValueError('NV4_ORACLE_GENERATED_SOURCE_DRIFT')
    binary = (out / 'nv4-admission-oracle-linux').read_bytes()
    # Hosted artifact is specifically an ELF64 little-endian x86-64 program.
    if (len(binary) < 64 or binary[:6] != b'\x7fELF\x02\x01' or
            struct.unpack_from('<H', binary, 18)[0] != 62):
        raise ValueError('NV4_ORACLE_LINUX_BINARY_REQUIRED')
    report['files']['nv4-admission-oracle-linux'] = digest(binary)
    for name in ('compiler-version.txt', 'build.log'):
        report['files'][name] = digest((out / name).read_bytes())
    report['parity_required_on_every_invocation'] = True
    report['private_inputs_present'] = False
    (out / 'build-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    gen = sub.add_parser('generate')
    gen.add_argument('--out-dir', type=Path, required=True)
    gen.add_argument('--source-sha', required=True)
    seal_parser = sub.add_parser('seal')
    seal_parser.add_argument('--out-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'generate':
        generate(args.out_dir, args.source_sha)
    else:
        seal(args.out_dir)


if __name__ == '__main__':
    main()
