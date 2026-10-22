#!/usr/bin/env python3
"""Offline NV4 native -> current-board APP-only package, PRIVATE output only.

This is a conservative diagnostic artifact path, NOT a FULL_B0_B4 release seal.
Freeze every externally pinned byte before interpreting any native file. The
same sealed snapshot is used for the native audit, HEX parser and package
binding; no original artifact path is read again after freezing.
No hardware access, reset, serial owner or flash authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'release'))
sys.path.insert(0, str(HERE.parent / 'b0' / 'tools'))
import r4_current_app_package as current
from b0_image_audit import _parse_intel_hex
from nv4_native_gate import evaluate as audit_nv4
from r4_native_bundle import BundleError, _read_regular

KINDS = ('elf', 'hex', 'bin', 'xml')
SAFE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*')
SHA256 = re.compile(r'[0-9a-f]{64}')
CAPS = {'elf': 8 * 1024 * 1024, 'hex': 4 * 1024 * 1024,
        'bin': 1024 * 1024, 'xml': 2 * 1024 * 1024,
        'build.log': 8 * 1024 * 1024}


def deny(message: str) -> None:
    raise ValueError('R4_NV4_APP_PACKAGE_BLOCKED_' + message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_regular(path: Path, kind: str) -> bytes:
    # Share the parent's no-follow file-descriptor read; retain this path's
    # tighter per-artifact limits and diagnostic-only receipt checks.
    try:
        return _read_regular(path, kind)
    except BundleError as exc:
        deny(str(exc))


def _freeze_native(artifacts: Path, destination: Path, expected_manifest_sha256: str):
    """Single-load a pinned manifest and all its bytes into a private staging dir.

    The immutable byte snapshot defeats manifest/HEX/ELF substitution between
    independent audit and payload construction. A rejected input cannot create
    an apparently valid receipt.
    """
    if artifacts.is_symlink() or not artifacts.is_dir():
        deny('UNTRUSTED_ARTIFACT_DIRECTORY')
    root = artifacts.resolve(strict=True)
    manifest_path = root / 'manifest.json'
    if not isinstance(expected_manifest_sha256, str) or not SHA256.fullmatch(expected_manifest_sha256):
        deny('NATIVE_MANIFEST_DIGEST_INVALID')
    if manifest_path.is_symlink() or not manifest_path.is_file():
        deny('NATIVE_MANIFEST_UNBOUND')
    original_manifest = read_regular(manifest_path, 'NATIVE_MANIFEST')
    if sha(original_manifest) != expected_manifest_sha256:
        deny('NATIVE_MANIFEST_UNBOUND')
    try:
        manifest = json.loads(original_manifest)
    except (ValueError, UnicodeDecodeError):
        deny('NATIVE_MANIFEST_MALFORMED')
    if not isinstance(manifest, dict) or manifest.get('schema') != 'r4-b0-artifact-manifest-v1':
        deny('NATIVE_MANIFEST_SCHEMA')
    files = manifest.get('files')
    if not isinstance(files, dict):
        deny('NATIVE_FILES_MISSING')
    names = []
    contents = {}
    for kind in KINDS:
        item = files.get(kind)
        if not isinstance(item, dict):
            deny('NATIVE_ARTIFACT_BINDING_' + kind.upper())
        name, digest = item.get('file'), item.get('sha256')
        if (not isinstance(name, str) or len(name) > 128 or
                not SAFE_NAME.fullmatch(name) or name.startswith('.') or
                name in ('manifest.json', 'build.log') or
                not isinstance(digest, str) or not SHA256.fullmatch(digest)):
            deny('NATIVE_ARTIFACT_BINDING_' + kind.upper())
        names.append(name)
        source = root / name
        if source.is_symlink() or not source.is_file() or source.resolve().parent != root:
            deny('NATIVE_ARTIFACT_UNSAFE_' + kind.upper())
        if source.stat().st_size > CAPS[kind]:
            deny('NATIVE_ARTIFACT_OVERSIZE_' + kind.upper())
        raw = read_regular(source, 'NATIVE_' + kind.upper())
        if len(raw) > CAPS[kind]:
            deny('NATIVE_ARTIFACT_OVERSIZE_' + kind.upper())
        if sha(raw) != digest:
            deny('NATIVE_ARTIFACT_CHANGED_' + kind.upper())
        contents[name] = raw
    if len(set(names)) != len(names):
        deny('NATIVE_ARTIFACT_NAMES_COLLIDE')
    log_path = root / 'build.log'
    if log_path.is_symlink() or not log_path.is_file():
        deny('NATIVE_BUILD_LOG_MISSING')
    if log_path.stat().st_size > CAPS['build.log']:
        deny('NATIVE_BUILD_LOG_OVERSIZE')
    log = read_regular(log_path, 'NATIVE_BUILD_LOG')
    if len(log) > CAPS['build.log']:
        deny('NATIVE_BUILD_LOG_OVERSIZE')
    # Every later reader (auditor, HEX parser, private payload binder) uses
    # this staging directory; never reopen the originals after this point.
    (destination / 'manifest.json').write_bytes(original_manifest)
    (destination / 'build.log').write_bytes(log)
    for name, raw in contents.items():
        (destination / name).write_bytes(raw)
    return manifest


def from_artifacts(artifacts: Path, profile: dict, snapshot: bytes, *,
                   expected_profile_sha256: str, expected_manifest_sha256: str):
    with tempfile.TemporaryDirectory(prefix='p7u-r4-frozen-native-') as temp:
        frozen = Path(temp)
        data = _freeze_native(artifacts, frozen, expected_manifest_sha256)
        report = audit_nv4(frozen)
        if (report.get('status') != 'REAL_LINKED_ADDRESS_ENVELOPE_ACCEPTED_NO_FLASH' or
                report.get('linked_ccfg_exact_stock_20240716') is not True or
                report.get('flash_authorized') is not False):
            deny('NATIVE_NV4_OR_STOCK_CCFG_AUDIT_NOT_ACCEPTED')
        candidate = frozen / data['files']['hex']['file']
        linked, error = _parse_intel_hex(candidate)
        if error or not linked:
            deny('NATIVE_HEX_UNREADABLE')
        # Independently bind the auditor to the same fixed manifest and bytes.
        if sha(candidate.read_bytes()) != data['files']['hex']['sha256']:
            deny('FROZEN_NATIVE_HEX_CHANGED')
        if report.get('manifest_digests') != {
                kind: data['files'][kind]['sha256'] for kind in KINDS}:
            deny('AUDITOR_MANIFEST_BINDING_MISMATCH')
        # _bind_payload intentionally accepts only SHA-256 evidence fields;
        # this path's class is diagnostic-only, never a full B0-B4 seal.
        evidence = {'manifest_sha256': expected_manifest_sha256}
        evidence.update({k + '_sha256': data['files'][k]['sha256'] for k in KINDS})
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
    print(json.dumps({'status': 'PRIVATE_B1_NV4_DIAGNOSTIC_APP_ONLY_NOT_FULL_B0_B4',
                      'sectors': len(package.sectors),
                      'package_sha256': package.manifest['package_sha256'],
                      'flash_authorized': False}))


if __name__ == '__main__':
    main()
