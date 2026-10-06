"""Regression through the actual patched driver; GitHub-hosted execution only."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from nv_recovery_fix import apply_fix

HERE = Path(__file__).resolve().parent

def verify(sdk, out):
    out.mkdir(parents=True, exist_ok=False)
    source = out / 'nvocmp.c'
    shutil.copy2(sdk / 'source/ti/common/nv/nvocmp.c', source)
    apply_fix(source)
    executable = out / 'corrupt-copy'
    subprocess.run(['gcc', '-std=c11', '-O1', '-g', '-D_GNU_SOURCE', '-DNV_LINUX',
                    '-DNVOCMP_POSIX_MUTEX', '-DDeviceFamily_CC26X4', '-DNVOCMP_NVPAGES=15',
                    '-I'+str(out), '-I'+str(HERE), '-I'+str(sdk/'source'),
                    '-I'+str(sdk/'source/ti/common/nv'), str(HERE/'corrupt_duplicate_probe.c'),
                    str(sdk/'source/ti/common/nv/crc.c'), str(HERE/'nv_linux.c'),
                    '-pthread', '-o', str(executable)], check=True)
    env = dict(os.environ, NVLAB_IMAGE=str(out/'synthetic.bin'))
    env.pop('NVLAB_CUT_OP', None)
    result = subprocess.run([str(executable), 'duplicate'], env=env,
                            capture_output=True, text=True, check=True)
    report = json.loads(result.stdout)
    if not (report['source_crc_status'] and not report['destination_crc_status']
            and report['destination_active_after'] and not report['read_status_after']):
        raise ValueError('corrupt original discarded valid copy')
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    verify(args.sdk.resolve(), args.out.resolve())
