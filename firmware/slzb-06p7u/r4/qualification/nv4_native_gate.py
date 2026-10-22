#!/usr/bin/env python3
"""Audit HISTORICAL stock-20240716 native ZNP build only (NEVER FLASH 20260311).

Current stock-20260311 P7U has NV at A4000, resident boot at AC000 and
CCFG IMAGE_VALID=AC000. This archived A6000/direct-ROM-vector-zero gate
cannot validate the current device. No flash authorization is possible here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'b0' / 'tools'))
from b0_image_audit import _parse_intel_hex

APP_END = 0xA6000
NV_END = 0xAE000
CCFG_START = 0xAFFA8
CHIP_END = 0xB0000
ERASE_SIZE = 0x2000
STOCK_20240716_CCFG_SHA256 = (
    'fa750d46003f4cc059140ac75a83282ec61543b0d898c50cd2add61988c08b47'
)


def reject(reason: str) -> None:
    raise ValueError('P7U_NV4_NATIVE_BLOCKED: ' + reason)


def verify_payload(data: dict[int, int]) -> dict:
    if not data or not set(range(0, 0x3C)).issubset(data):
        reject('direct-ROM reset vectors at 0x0 missing')
    sp = int.from_bytes(bytes(data[i] for i in range(4)), 'little')
    reset = int.from_bytes(bytes(data[i] for i in range(4, 8)), 'little')
    if not 0x20000000 < sp <= 0x20024000 or sp % 8 or not (reset & 1):
        reject('initial SRAM stack or Thumb reset vector invalid')
    entry = reset & ~1
    if entry < 0x3C or entry >= APP_END:
        reject('reset vector does not point into isolated application')
    if min(data) < 0 or max(data) >= CHIP_END:
        reject('bytes outside P7 flash')
    if any(APP_END <= address < NV_END for address in data):
        reject('linked HEX contains stock four-page network data')
    if any(NV_END <= address < CCFG_START for address in data):
        reject('linked HEX contains non-CCFG top-sector bytes')
    if not set(range(CCFG_START, CHIP_END)).issubset(data):
        reject('expected native CCFG bytes absent')
    app = {a for a in data if a < APP_END}
    if not app or max(app) >= APP_END:
        reject('application intersects stock NV4')
    if entry not in app or entry + 1 not in app:
        reject('reset handler target is not backed by linked application bytes')
    sectors = sorted({a // ERASE_SIZE * ERASE_SIZE for a in app})
    if any(x + ERASE_SIZE > APP_END for x in sectors):
        reject('application erase sector intersects stock NV4')
    return {
        'status': 'REAL_LINKED_ADDRESS_ENVELOPE_ACCEPTED_NO_FLASH',
        'vector_address': '0x0',
        'reset_vector': hex(reset & ~1),
        'stack_pointer': hex(sp),
        'app_end_exclusive': hex(max(app) + 1),
        'application_sectors': [hex(s) for s in sectors],
        'protected_nv4': ['0xA6000', '0xAE000'],
        'protected_ccfg_erase_sector': ['0xAE000', '0xB0000'],
        'whole_image_erase_allowed': False,
        'nv4_erase_allowed': False,
        'ccfg_erase_allowed': False,
        'flash_authorized': False,
    }


def evaluate(artifacts: Path) -> dict:
    root = artifacts.resolve()
    mpath = root / 'manifest.json'
    if mpath.is_symlink() or not mpath.is_file():
        reject('native artifact manifest missing')
    manifest = json.loads(mpath.read_text())
    if manifest.get('schema') != 'r4-b0-artifact-manifest-v1':
        reject('native collector provenance missing')
    paths = {}
    for kind in ('elf', 'hex', 'bin', 'xml'):
        item = manifest.get('files', {}).get(kind, {})
        name, digest = item.get('file'), item.get('sha256')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name):
            reject('unsafe ' + kind + ' basename')
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            reject(kind + ' is not SHA-256 bound')
        p = root / name
        if p.is_symlink() or not p.is_file() or p.resolve().parent != root:
            reject('missing ' + kind + ' artifact')
        if hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            reject(kind + ' digest mismatches actual artifact')
        paths[kind] = p
    if not paths['elf'].read_bytes().startswith(b'\x7fELF'):
        reject('native ELF header missing')
    log = root / 'build.log'
    if log.is_symlink() or not log.is_file():
        reject('native build log missing')
    data, error = _parse_intel_hex(paths['hex'])
    if error:
        reject(error)
    report = verify_payload(data)
    ccfg = bytes(data[i] for i in range(CCFG_START, CHIP_END))
    ccfg_sha = hashlib.sha256(ccfg).hexdigest()
    if ccfg_sha != STOCK_20240716_CCFG_SHA256:
        reject('linked 88-byte CCFG differs from installed stock 20240716')
    report['linked_ccfg_sha256'] = ccfg_sha
    report['linked_ccfg_exact_stock_20240716'] = True
    report['schema'] = 'r4-stock-p7u-nv4-real-linked-hex-gate-v1'
    report['manifest_digests'] = {k: manifest['files'][k]['sha256'] for k in paths}
    report['real_native_linked'] = True
    report['private_nv_material_seen'] = False
    report['existing_network_security_continuity_verified'] = False
    report['resident_boot_and_fitted_ccfg_compatibility_verified'] = False
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    report = evaluate(args.artifacts)
    if args.receipt.exists() or args.receipt.is_symlink():
        reject('refuse to overwrite existing receipt')
    args.receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'flash_authorized': False}))


if __name__ == '__main__':
    main()
