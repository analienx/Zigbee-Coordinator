"""Fixed /share artifact installer. No radio, service, shell or HTTP operations.

prepare creates one private transfer directory. install consumes its intent,
checks externally pinned archive/package/input hashes, rejects links/escapes,
then publishes two new directories without replacing any existing directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile

SHARE = Path('/share')
INPUT = SHARE/'p7u-r4-input-afbb7a8'
NAMES = {'installed-candidate.json', 'installed-app.hex', 'installed-handoff.bin',
         'installed-plan.json', 'installed-result.json', 'installed-before.bin',
         'management.json', 'historical-backup.json'}


def need(ok, why):
    if not ok: raise ValueError('STAGE_HOLD_'+why)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def pin(value):
    need(re.fullmatch('[a-f0-9]{64}', value) is not None, 'PIN')
    return value


def transfer(archive_pin): return SHARE/('p7u-r4-afbb7a8-transfer-'+pin(archive_pin)[:16])


def safe_name(value):
    p = Path(value)
    need(re.fullmatch('[a-zA-Z0-9_./+-]+', value) is not None and not p.is_absolute() and
         all(v not in ('.', '..', '') for v in value.split('/')) and len(p.parts) >= 2 and
         p.parts[0] in ('package', 'input'), 'MEMBER_PATH')
    return p


def once(root, name, raw):
    with (root/name).open('xb') as f:
        os.chmod(f.name, 0o600); f.write(raw); f.flush(); os.fsync(f.fileno())


def verify(root, manifest_name, expected, names=None):
    need(root.is_dir() and not root.is_symlink() and root.stat().st_mode & 0o077 == 0, 'PRIVATE_ROOT')
    need(digest((root/manifest_name).read_bytes()) == pin(expected), 'MANIFEST')
    m = json.loads((root/manifest_name).read_bytes()); files = m['files']
    need(type(files) is dict and (names is None or set(files) == names), 'FILE_SET')
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    need(actual == set(files) | {manifest_name}, 'EXTRA_FILE')
    for name, expected_hash in files.items():
        safe_name('package/'+name)
        target = root/name
        need(target.is_file() and target.resolve().is_relative_to(root) and
             all(not p.is_symlink() for p in (target, *target.parents) if p != root.parent), 'SYMLINK')
        need(digest((root/name).read_bytes()) == pin(expected_hash), 'FILE_HASH')
    return m


def prepare(archive_pin):
    root = transfer(archive_pin)
    need(not root.exists() and not root.is_symlink(), 'EXISTS')
    root.mkdir(mode=0o700)
    return {'status': 'PRIVATE_TRANSFER_CREATED', 'path': str(root)}


def install(archive_pin, package_pin, input_pin):
    root = transfer(archive_pin); pin(package_pin); pin(input_pin)
    need(root.is_dir() and not root.is_symlink() and root.stat().st_mode & 0o077 == 0, 'PRIVATE_ROOT')
    archive = root/'payload.tar'
    need(archive.is_file() and not archive.is_symlink() and archive.stat().st_size < 32*1024*1024, 'ARCHIVE')
    need(digest(archive.read_bytes()) == archive_pin, 'ARCHIVE_HASH')
    destination = SHARE/('p7u-r4-afbb7a8-operator-'+package_pin[:16])
    need(not destination.exists() and not destination.is_symlink() and not INPUT.is_symlink(), 'TARGET_EXISTS')
    reuse_input = INPUT.exists()
    if reuse_input: verify(INPUT, 'INPUT.json', input_pin, NAMES)
    once(root, 'install-intent.json', json.dumps({'archive': archive_pin, 'package': package_pin, 'input': input_pin}).encode())
    with tarfile.open(archive, 'r:') as t:
        members = t.getmembers(); names = [m.name for m in members]
        need(0 < len(members) <= 1000 and len(set(names)) == len(names), 'MEMBER_COUNT')
        need(all(m.isfile() and 0 <= m.size <= 4*1024*1024 for m in members), 'MEMBER_TYPE')
        need(sum(m.size for m in members) <= 24*1024*1024, 'ARCHIVE_BUDGET')
        # Validate the complete name set before writing a member.
        for m in members: safe_name(m.name)
        for m in members:
            target = root/safe_name(m.name); target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            need(target.resolve().is_relative_to(root), 'ESCAPE')
            once(target.parent, target.name, t.extractfile(m).read())
    package = verify(root/'package', 'PACKAGE.json', package_pin)
    verify(root/'input', 'INPUT.json', input_pin, NAMES)
    need(package['firmware_source_sha'] == '4cfe317083c2a3d1b784350b0ab960e27218e618' and
         package['arm64_reader'] == 'STATIC_AARCH64_QEMU_MATCHED_NATIVE_X86_ON_PUBLIC_NV4', 'PACKAGE_CLASS')
    os.chmod(root/'package/security-reader-aarch64', 0o700)
    os.rename(root/'package', destination)
    if not reuse_input: os.rename(root/'input', INPUT)
    result = {'status': 'QUALIFIED_OPERATOR_AND_INPUT_STAGED_NO_HOST_STOP',
              'package': str(destination), 'package_pin': package_pin, 'input_pin': input_pin,
              'operator_source': package['operator_source_sha']}
    once(root, 'staged.json', json.dumps(result).encode())
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('action', choices=('prepare', 'install'))
    p.add_argument('--archive-pin', required=True); p.add_argument('--package-pin'); p.add_argument('--input-pin')
    a = p.parse_args()
    if a.action == 'prepare': need(a.package_pin is None and a.input_pin is None, 'ARGS'); value = prepare(a.archive_pin)
    else: need(a.package_pin is not None and a.input_pin is not None, 'ARGS'); value = install(a.archive_pin, a.package_pin, a.input_pin)
    print(json.dumps(value), flush=True)
