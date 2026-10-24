"""Plan/hash/install a hosted guard image; never build on HA or start Z2M."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess

GUARD='local_p7u_recovery'
ORIGINAL='45df7312_zigbee2mqtt'
VERSION='0.2.4'
ARTIFACT_ROOT=Path('C:/Workspace/artifacts')
MODULES=('policy.py','executor.py','persistence.py','ha_adapter.py','observer.py',
         'mqtt_settings.py','alerts.py','forensics.py','run.py')
EXPECTED_CORE='button.slzb_06p7u_core_restart'
EXPECTED_RADIO='button.slzb_06p7u_zigbee_restart'


def sha_file(path):
    if path.is_symlink():raise RuntimeError('ARTIFACT_SYMLINK')
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def verify_release(directory):
    directory=directory.resolve(strict=True)
    if not directory.is_relative_to(ARTIFACT_ROOT.resolve()):
        raise RuntimeError('ARTIFACT_OUTSIDE_WORKSPACE_ARTIFACTS')
    receipt=json.loads((directory/'RELEASE.json').read_text())
    source=receipt['source_sha']
    if len(source)!=40 or any(c not in '0123456789abcdef' for c in source):raise RuntimeError('SOURCE_SHA')
    if receipt['schema']!='p7u-native-guard-release-v1' or receipt['version']!='0.2.4-'+source[:12]:raise RuntimeError('RELEASE_SCHEMA')
    if receipt['image_reference']!='localhost:50146/p7u-native-guard:'+receipt['version']:raise RuntimeError('IMAGE_REFERENCE')
    if set(receipt['runtime_files'])!=set(MODULES):raise RuntimeError('RUNTIME_FILE_ALLOWLIST')
    expected={'IMAGE_ID.txt','image.docker.tar','config.yaml','deploy_native_guard_024.py','native_guard_install.py'}
    if set(receipt['files'])!=expected:raise RuntimeError('ARTIFACT_FILE_ALLOWLIST')
    for name,digest in receipt['files'].items():
        if sha_file(directory/name)!=digest:raise RuntimeError('ARTIFACT_HASH_CHANGED '+name)
    if sha_file(Path(__file__))!=receipt['files']['deploy_native_guard_024.py']:raise RuntimeError('DEPLOYER_NOT_QUALIFIED_SOURCE')
    checks=json.loads(subprocess.check_output(['gh','api',f'repos/analienx/Zigbee-Coordinator/commits/{source}/check-runs']))['check_runs']
    for name in ['Policy and one-shot journal regressions','unittest','release']:
        selected=[c for c in checks if c['name']==name]
        if not selected or any(c['conclusion']!='success' for c in selected):raise RuntimeError('EXACT_SOURCE_CHECK_NOT_GREEN '+name)
    return directory,receipt


def remote(directory,receipt,mode,expected='',previous=None):
    payload={'mode':mode,'release':receipt,'config_b64':base64.b64encode((directory/'config.yaml').read_bytes()).decode(),
             'expected_plan_hash':expected}
    if previous is not None:payload['reconcile_previous']=previous
    source='PAYLOAD = '+repr(payload)+'\n'+(directory/'native_guard_install.py').read_text()
    p=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','ha','python3','-'],
                     input=source,capture_output=True,text=True,timeout=650)
    if p.stdout:print(p.stdout,end='',flush=True)
    if p.returncode:raise RuntimeError('GUARD_OPERATION_HOLD; inspect existing receipt before retry; '+p.stderr[-1000:])
    return json.loads(p.stdout.splitlines()[-1])


def main():
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['plan','apply'])
    parser.add_argument('--release',type=Path,required=True);parser.add_argument('--expected-plan-hash',default='')
    parser.add_argument('--reconcile-previous',choices=['06bc5964a82c484d4a073a43b1dc5afe77f47cad'])
    args=parser.parse_args();directory,receipt=verify_release(args.release)
    if args.mode=='plan':remote(directory,receipt,'plan',previous=args.reconcile_previous);return
    current=remote(directory,receipt,'plan',previous=args.reconcile_previous)
    if args.expected_plan_hash!=current['plan_hash']:raise RuntimeError('PLAN_HASH_NOT_EXACT')
    target='/share/p7u-native-guard-024/'+receipt['source_sha']
    setup='from pathlib import Path\np=Path('+repr(target)+')\nr=p.parent\nassert not r.is_symlink()\nr.mkdir(mode=0o700,exist_ok=True)\nassert r.stat().st_mode&0o077==0\nassert not p.exists()\np.mkdir(mode=0o700)\n'
    subprocess.run(['ssh','-o','BatchMode=yes','ha','python3','-'],input=setup,text=True,check=True,timeout=20)
    subprocess.run(['scp','-o','BatchMode=yes',str(directory/'image.docker.tar'),'ha:'+target+'/image.docker.tar'],check=True,timeout=120)
    remote(directory,receipt,'apply',args.expected_plan_hash,previous=args.reconcile_previous)


if __name__=='__main__':main()
