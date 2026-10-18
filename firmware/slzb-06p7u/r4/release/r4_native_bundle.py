#!/usr/bin/env python3
"""Freeze an externally pinned native artifact bundle for offline consumers.

This prevents source-directory mutation between audit and extraction. It does
not authenticate native build provenance or grant flash/release authorization;
each consumer must still run its own full native or scoped geometry audit.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat


class BundleError(ValueError):
    pass


MAX_CAPTURE_FILE_BYTES = 64 * 1024 * 1024


def _read_regular(path: Path, kind: str) -> bytes:
    """Open one regular file without following a swapped-in symlink or FIFO."""
    if path.is_symlink():
        raise BundleError(kind + '_NOT_REGULAR')
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise BundleError(kind + '_NOT_REGULAR')
            raw = source.read(MAX_CAPTURE_FILE_BYTES + 1)
            if len(raw) > MAX_CAPTURE_FILE_BYTES:
                raise BundleError(kind + '_TOO_LARGE')
            return raw
    except OSError as exc:
        raise BundleError(kind + '_NOT_REGULAR') from exc


def capture_native(root: Path, frozen: Path, expected_manifest_sha256: str) -> dict:
    """Capture and hash-check every native gate input before the first audit.

    `frozen` must be an exclusively owned private temporary directory whose
    lifetime includes both the native audit and all downstream extraction.
    The manifest digest is pinned externally; each of its four artifact
    digests is independently checked against the bytes captured here.
    """
    manifest_path = root / 'manifest.json'
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise BundleError('NATIVE_MANIFEST_UNBOUND')
    raw_manifest = _read_regular(manifest_path, 'NATIVE_MANIFEST')
    if hashlib.sha256(raw_manifest).hexdigest() != expected_manifest_sha256:
        raise BundleError('NATIVE_MANIFEST_UNBOUND')
    try:
        data = json.loads(raw_manifest)
    except (ValueError, UnicodeDecodeError) as exc:
        raise BundleError('NATIVE_MANIFEST_INVALID') from exc
    if not isinstance(data, dict) or data.get('schema') != 'r4-b0-artifact-manifest-v1':
        raise BundleError('NATIVE_MANIFEST_SCHEMA')
    if data.get('build_log') != 'build.log':
        raise BundleError('NATIVE_BUILD_LOG_NAME')
    files = data.get('files')
    if not isinstance(files, dict):
        raise BundleError('NATIVE_MANIFEST_FILES')
    (frozen / 'manifest.json').write_bytes(raw_manifest)
    names = {'manifest.json', 'build.log'}
    for kind in ('elf', 'hex', 'bin', 'xml'):
        entry = files.get(kind)
        if not isinstance(entry, dict):
            raise BundleError('NATIVE_' + kind.upper() + '_ENTRY')
        name, digest = entry.get('file'), entry.get('sha256')
        if (not isinstance(name, str) or
                not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name) or
                name in names):
            raise BundleError('NATIVE_' + kind.upper() + '_BASENAME')
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise BundleError('NATIVE_' + kind.upper() + '_DIGEST')
        names.add(name)
        raw = _read_regular(root / name, 'NATIVE_' + kind.upper())
        if hashlib.sha256(raw).hexdigest() != digest:
            raise BundleError('NATIVE_' + kind.upper() + '_DIGEST_MISMATCH')
        (frozen / name).write_bytes(raw)
    (frozen / 'build.log').write_bytes(_read_regular(root / 'build.log', 'NATIVE_BUILD_LOG'))
    return data
