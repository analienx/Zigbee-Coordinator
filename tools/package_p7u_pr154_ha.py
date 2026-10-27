"""Hosted-only immutable HA operator artifact; never accesses live hardware."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def qualified_reader(package):
    """Reuse only the byte-pinned reader already cross-compiled/QEMU qualified.

    Firmware, reader C source and ABI did not change in an operator-only repair.
    This removes an unrelated package-manager/network dependency from recovery.
    """
    raw = (package/'PACKAGE.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'b18be817fde67a86d8efd6375efb93f8c40a44dcc2be7d8a40d2726f15ef402f'
    m = json.loads(raw)
    assert m['firmware_source_sha'] == '2499154215c40ab6435b90886be96c8af6e37a74'
    assert m['arm64_reader'] == 'STATIC_AARCH64_QEMU_MATCHED_NATIVE_X86_ON_PUBLIC_NV4'
    reader = package/'security-reader-aarch64'
    assert not reader.is_symlink() and sha(reader) == m['files']['security-reader-aarch64']
    return reader.read_bytes()


def main():
    a = argparse.ArgumentParser(); a.add_argument('--candidate', type=Path, required=True)
    a.add_argument('--out', type=Path, required=True)
    a.add_argument('--reader-package', type=Path)
    a.add_argument('--host-release', type=Path, required=True)
    args = a.parse_args()
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    assert source == os.environ['OPERATOR_SOURCE_SHA']
    c = json.loads((args.candidate/'candidate.json').read_bytes())
    assert c['source_sha'] == source == os.environ['FIRMWARE_SOURCE_SHA']
    host = json.loads(args.host_release.read_bytes())
    assert host['schema'] == 'p7u-host-release-v1' and host['source_sha'] == source
    paired_image = host['profiles']['diagnostic']['image_id']
    import re
    assert re.fullmatch('sha256:[0-9a-f]{64}', paired_image)
    assert sha(args.candidate/'security-reader.c') == 'a8bbbf32add1cf79a2ddb2370f06ff8f1cdc53279dc5c953f595d5674aed25e7'
    args.out.mkdir(exist_ok=False)
    for directory in ('release', 'release/rom_writer', 'qualification', 'b0/tools', 'b1/tools'):
        base = Path('firmware/slzb-06p7u/r4')/directory
        for p in base.glob('*.py'):
            dest = args.out/'source'/p; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(p, dest)
    dest = args.out/'source/host/flash/p7u_pr154_ha.py'; dest.parent.mkdir(parents=True)
    shutil.copyfile('host/flash/p7u_pr154_ha.py', dest)
    shutil.copyfile('host/flash/p7u_pr154_stage.py', dest.with_name('p7u_pr154_stage.py'))
    shutil.copyfile('host/flash/p7u_paired_binding.py', dest.with_name('p7u_paired_binding.py'))
    if args.reader_package:
        (args.out/'security-reader-aarch64').write_bytes(qualified_reader(args.reader_package))
    else:
        subprocess.run(['aarch64-linux-gnu-gcc', '-std=c11', '-O1', '-static',
                    '-I', 'firmware/slzb-06p7u/r4/b1', '-I', 'firmware/slzb-06p7u/r4/b1/include',
                    args.candidate/'security-reader.c', '-o', args.out/'security-reader-aarch64'], check=True)
    elf = (args.out/'security-reader-aarch64').read_bytes()
    assert elf[:6] == b'\x7fELF\x02\x01' and int.from_bytes(elf[18:20], 'little') == 183
    if not args.reader_package:
        from tests.test_r4_nv4_startup_replay import startup_fixture
        sample = startup_fixture()
        x86 = subprocess.run([str((args.candidate/'security-reader-linux').resolve())], input=sample, capture_output=True)
        arm = subprocess.run(['qemu-aarch64', str(args.out/'security-reader-aarch64')], input=sample, capture_output=True)
        assert x86.returncode == arm.returncode == 0 and x86.stdout == arm.stdout and not x86.stderr and not arm.stderr
        for binary in ([str((args.candidate/'security-reader-linux').resolve())],
                       ['qemu-aarch64', str(args.out/'security-reader-aarch64')]):
            bad = subprocess.run(binary, input=bytes(32768), capture_output=True)
            assert bad.returncode != 0 and not bad.stdout
    subprocess.run(['python', '-m', 'pip', 'install', '--no-compile', '--target', str(args.out/'vendor'),
                    'pyserial==3.5', 'pyserial-asyncio==0.6'], check=True)
    report = {'schema': 'p7u-r4-afbb7a8-ha-package-v1', 'operator_source_sha': source,
              'firmware_source_sha': c['source_sha'], 'run_id': os.environ['GITHUB_RUN_ID'],
              'paired_host_image': paired_image, 'paired_host_source_sha': host['source_sha'],
              'arm64_reader': 'STATIC_AARCH64_QEMU_MATCHED_NATIVE_X86_ON_PUBLIC_NV4',
              'hardware_tested': False,
              'reader_origin_package': 'b18be817fde67a86d8efd6375efb93f8c40a44dcc2be7d8a40d2726f15ef402f' if args.reader_package else None,
              'files': {p.relative_to(args.out).as_posix(): sha(p) for p in sorted(args.out.rglob('*')) if p.is_file()}}
    raw = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
    (args.out/'PACKAGE.json').write_bytes(raw)
    print('OPERATOR_PACKAGE_SHA256='+hashlib.sha256(raw).hexdigest())


if __name__ == '__main__': main()
