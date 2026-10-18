#!/usr/bin/env python3
"""Offline NV4 native -> current-board APP-only package, PRIVATE output only.

Requires a real linked no-flash NV4 gate PASS, exact binary manifest digest,
an externally pinned current P7U profile and matching private full capture.
Reuses the tested current-board sector package and private-only exporter,
which conservatively stops at 0xA0000 even though stock NV4 starts 0xA6000.
Neither this module nor its dependencies construct a programmer or reset radio.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'release'))
sys.path.insert(0, str(HERE.parent / 'b0' / 'tools'))
import r4_current_app_package as current
from r4_native_bundle import BundleError, capture_native
from b0_image_audit import _parse_intel_hex
from nv4_native_gate import evaluate as audit_nv4


def deny(message: str) -> None:
    raise ValueError('R4_NV4_APP_PACKAGE_BLOCKED_' + message)


def from_artifacts(artifacts: Path, profile: dict, snapshot: bytes, *,
                   expected_profile_sha256: str, expected_manifest_sha256: str):
    root = artifacts.resolve()
    with tempfile.TemporaryDirectory(prefix='r4-nv4-native-frozen-') as directory:
        frozen = Path(directory)
        try:
            data = capture_native(root, frozen, expected_manifest_sha256)
        except BundleError as exc:
            deny(str(exc))
        report = audit_nv4(frozen)
        if (report.get('status') != 'REAL_LINKED_ADDRESS_ENVELOPE_ACCEPTED_NO_FLASH' or
                report.get('linked_ccfg_exact_stock_20240716') is not True or
                report.get('flash_authorized') is not False):
            deny('NATIVE_NV4_OR_STOCK_CCFG_AUDIT_NOT_ACCEPTED')
        linked, error = _parse_intel_hex(frozen / data['files']['hex']['file'])
        if error or not linked:
            deny('NATIVE_HEX_UNREADABLE')
        evidence = {'manifest_sha256': expected_manifest_sha256}
        evidence.update({k + '_sha256': data['files'][k]['sha256']
                         for k in ('elf', 'hex', 'bin', 'xml')})
        package = current._bind_payload(linked, profile, snapshot, evidence,
                                        expected_profile_sha256=expected_profile_sha256)
        if any(address >= 0xA0000 for address in package.sectors):
            deny('NONCONSERVATIVE_APP_SECTOR')
        return package


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--current-profile', type=Path, required=True)
    parser.add_argument('--private-capture', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--private-output', type=Path, required=True)
    args = parser.parse_args()
    package = from_artifacts(args.artifacts,
                             json.loads(args.current_profile.read_text()),
                             args.private_capture.read_bytes(),
                             expected_profile_sha256=args.profile_sha256,
                             expected_manifest_sha256=args.manifest_sha256)
    current.export_private(package, args.private_output,
                           expected_profile_sha256=args.profile_sha256,
                           expected_package_sha256=package.manifest['package_sha256'])
    print(json.dumps({'status': 'PRIVATE_APP_ONLY_PACKAGE_NO_FLASH',
                      'sectors': len(package.sectors),
                      'package_sha256': package.manifest['package_sha256'],
                      'flash_authorized': False}))


if __name__ == '__main__':
    main()
