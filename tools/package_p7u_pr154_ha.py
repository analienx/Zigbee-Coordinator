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
    assert c['source_sha'] == os.environ['FIRMWARE_SOURCE_SHA']
    host = json.loads(args.host_release.read_bytes())
    assert host['schema'] == 'p7u-host-release-v1' and host['source_sha'] == os.environ.get('HOST_SOURCE_SHA',c['source_sha'])
    priority_pair=(c['source_sha']=='e3a0f3b7726adf1f6c182973f135665a5c3857e0' and host['source_sha']=='85ce37c24802b0f16fec0afd00a1a0457656cd80')
    owned_stage_pair=(c['source_sha']=='66ed700c2818c7a0963dad9160d55109009bbaac' and host['source_sha']=='66ed700c2818c7a0963dad9160d55109009bbaac')
    # This exact independently qualified host adds passive startup instrumentation
    # but preserves the V6 radio wire ABI. No arbitrary host revision is accepted.
    startup_capture_pair=(c['source_sha']=='66ed700c2818c7a0963dad9160d55109009bbaac' and
        host['source_sha']=='2c2d96d6334b424f6364a982ad976a674b260e04' and
        host['profiles']['diagnostic']['image_id']=='sha256:d00b59b26e28872e4027f2eab16800b00560876ce592fd81bae503871ec96367')
    v47_pair=(c['source_sha']=='391d7a5b24d459f347a8ff2378c751ebcc7eec4b' and
        host['source_sha']=='2c2d96d6334b424f6364a982ad976a674b260e04' and
        host['profiles']['diagnostic']['image_id']=='sha256:d00b59b26e28872e4027f2eab16800b00560876ce592fd81bae503871ec96367')
    v48_pair=(c['source_sha']=='250441cd17c55e25c78d97e041f056574355ade7' and
        host['source_sha']=='2c2d96d6334b424f6364a982ad976a674b260e04' and
        host['profiles']['diagnostic']['image_id']=='sha256:d00b59b26e28872e4027f2eab16800b00560876ce592fd81bae503871ec96367')
    v50_pair=(c['source_sha']=='540d75a23d11587fb45fd892c5e9ae01ec0aab15' and
        host['source_sha']=='2c2d96d6334b424f6364a982ad976a674b260e04' and
        host['profiles']['diagnostic']['image_id']=='sha256:d00b59b26e28872e4027f2eab16800b00560876ce592fd81bae503871ec96367')
    assert host['source_sha']==c['source_sha'] or owned_stage_pair or startup_capture_pair or v47_pair or v48_pair or v50_pair or priority_pair or (c['source_sha']=='899f179031aae74db2e48699900f1cf5722bb4de' and host['source_sha']==c['source_sha']), 'UNQUALIFIED_F2_COMPATIBILITY_PAIR'
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
    shutil.copyfile('host/flash/p7u_paired_hold.py', dest.with_name('p7u_paired_hold.py'))
    shutil.copyfile('host/flash/p7u_paired_finish.py', dest.with_name('p7u_paired_finish.py'))
    shutil.copyfile('host/flash/p7u_paired_boot.py', dest.with_name('p7u_paired_boot.py'))
    shutil.copyfile('host/flash/p7u_v6_rom_recovery.py', dest.with_name('p7u_v6_rom_recovery.py'))
    shutil.copyfile('host/flash/p7u_v6_recover_local.py', dest.with_name('p7u_v6_recover_local.py'))
    shutil.copyfile('host/flash/p7u_v6_startup_host_config.py', dest.with_name('p7u_v6_startup_host_config.py'))
    shutil.copyfile('host/flash/p7u_v6_startup_host_install.py', dest.with_name('p7u_v6_startup_host_install.py'))
    shutil.copyfile('host/flash/p7u_v6_startup_capture_once.py', dest.with_name('p7u_v6_startup_capture_once.py'))
    shutil.copyfile('host/flash/p7u_v6_instrumented_rom_once.py', dest.with_name('p7u_v6_instrumented_rom_once.py'))
    shutil.copyfile('host/r4-b4/f2_progress_contract.py', dest.with_name('f2_progress_contract.py'))
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
              'f2_wire_contract': ('R4D4_MINOR4_R4D5_PAGED_AND_R4D6_OWNED_V1' if (owned_stage_pair or startup_capture_pair or v47_pair or v48_pair or v50_pair) else
                                   'R4D4_MINOR4_AND_R4D5_PAGED_V1' if priority_pair else
                                   'R4D4_MINOR3_240_V1' if c['source_sha']=='899f179031aae74db2e48699900f1cf5722bb4de' else None),
              'arm64_reader': 'STATIC_AARCH64_QEMU_MATCHED_NATIVE_X86_ON_PUBLIC_NV4',
              'hardware_tested': False,
              'reader_origin_package': 'b18be817fde67a86d8efd6375efb93f8c40a44dcc2be7d8a40d2726f15ef402f' if args.reader_package else None,
              'files': {p.relative_to(args.out).as_posix(): sha(p) for p in sorted(args.out.rglob('*')) if p.is_file()}}
    raw = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
    (args.out/'PACKAGE.json').write_bytes(raw)
    print('OPERATOR_PACKAGE_SHA256='+hashlib.sha256(raw).hexdigest())


if __name__ == '__main__': main()
