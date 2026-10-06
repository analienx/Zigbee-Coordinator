"""Run the real lab CLI with a rejected write; require failure and saved evidence.

GitHub-hosted execution only. All other lab operations use the actual TI driver.
"""
import argparse
import json
from pathlib import Path
import runpy
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def injected_cli(sdk, out):
    original = subprocess.run

    def run(*args, **kwargs):
        command = args[0] if args else kwargs.get('args')
        image = kwargs.get('env', {}).get('NVLAB_IMAGE', '')
        if (isinstance(command, list) and len(command) == 2
                and command[1] == 'write-proof'
                and Path(image).name == 'write-proof-1.bin'):
            return subprocess.CompletedProcess(command, 21, '', 'injected write rejection\n')
        return original(*args, **kwargs)

    subprocess.run = run
    sys.argv = [str(HERE / 'run_nv_lab.py'), '--sdk', str(sdk), '--out', str(out),
                '--profiles', 'vendor-20240716']
    # Do not catch the CLI exception: the child must actually exit nonzero.
    runpy.run_path(str(HERE / 'run_nv_lab.py'), run_name='__main__')


def verify(sdk, out):
    out.mkdir(parents=True, exist_ok=False)
    lab = out / 'rejected-write-lab'
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                             '--sdk', str(sdk), '--out', str(lab), '--inject'],
                            capture_output=True, text=True, timeout=240)
    (out / 'cli-stderr.txt').write_text(result.stderr)
    evidence = json.loads((lab / 'nv-lab-report.json').read_text())
    rejected = [p for p in evidence['profiles'].values()
                if any(x['classification'] == 'UNRESOLVED_POST_CUT_WRITE_PROOF'
                       and x['cut'] == 1 and 'injected write rejection' in x['error']
                       for x in p['unresolved_recovery_negative_controls'])]
    if (result.returncode == 0 or evidence['all_power_cut_recovery_passed'] is not False
            or len(rejected) != 2
            or 'required vendor-profile recovery/write acceptance failed' not in result.stderr):
        raise ValueError('required write failure did not reject the actual CLI')
    report = {'actual_cli_exit': result.returncode,
              'all_power_cut_recovery_passed': False,
              'lanes_with_injected_write_rejection': len(rejected),
              'failure_evidence_preserved': True}
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--inject', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inject:
        injected_cli(args.sdk.resolve(), args.out.resolve())
    else:
        verify(args.sdk.resolve(), args.out.resolve())
