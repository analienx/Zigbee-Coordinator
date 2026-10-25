"""Hosted-only immutable HA operator artifact; never accesses live hardware."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    a = argparse.ArgumentParser(); a.add_argument('--candidate', type=Path, required=True)
    a.add_argument('--out', type=Path, required=True); args = a.parse_args()
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    assert source == os.environ['OPERATOR_SOURCE_SHA']
    c = json.loads((args.candidate/'candidate.json').read_bytes())
    assert c['source_sha'] == '2499154215c40ab6435b90886be96c8af6e37a74'
    assert sha(args.candidate/'security-reader.c') == 'a8bbbf32add1cf79a2ddb2370f06ff8f1cdc53279dc5c953f595d5674aed25e7'
    args.out.mkdir(exist_ok=False)
    for directory in ('release', 'release/rom_writer', 'qualification', 'b0/tools', 'b1/tools'):
        base = Path('firmware/slzb-06p7u/r4')/directory
        for p in base.glob('*.py'):
            dest = args.out/'source'/p; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(p, dest)
    dest = args.out/'source/host/flash/p7u_pr154_ha.py'; dest.parent.mkdir(parents=True)
    shutil.copyfile('host/flash/p7u_pr154_ha.py', dest)
    subprocess.run(['aarch64-linux-gnu-gcc', '-std=c11', '-O1', '-static',
                    '-I', 'firmware/slzb-06p7u/r4/b1', '-I', 'firmware/slzb-06p7u/r4/b1/include',
                    args.candidate/'security-reader.c', '-o', args.out/'security-reader-aarch64'], check=True)
    elf = (args.out/'security-reader-aarch64').read_bytes()
    assert elf[:6] == b'\x7fELF\x02\x01' and int.from_bytes(elf[18:20], 'little') == 183
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
    report = {'schema': 'p7u-pr154-ha-package-v1', 'operator_source_sha': source,
              'firmware_source_sha': c['source_sha'], 'run_id': os.environ['GITHUB_RUN_ID'],
              'arm64_reader': 'STATIC_AARCH64_QEMU_MATCHED_NATIVE_X86_ON_PUBLIC_NV4',
              'hardware_tested': False,
              'files': {p.relative_to(args.out).as_posix(): sha(p) for p in sorted(args.out.rglob('*')) if p.is_file()}}
    raw = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
    (args.out/'PACKAGE.json').write_bytes(raw)
    print('OPERATOR_PACKAGE_SHA256='+hashlib.sha256(raw).hexdigest())


if __name__ == '__main__': main()
