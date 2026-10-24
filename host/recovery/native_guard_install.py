"""Named HA guard-only operation: prebuilt image, no radio or Z2M lifecycle.

The qualified deployer supplies a fixed hash-bound payload, never shell text.
An interrupted deployment retains its global intent and requires reconciliation.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.request import Request,urlopen

GUARD='local_p7u_recovery'
OWNERS=('45df7312_zigbee2mqtt','local_p7u_r4_native_host','local_p7u_r4_fallback')
ROOT=Path('/share/p7u-native-guard-024')
REGISTRY='p7u_native_guard_registry'
PREVIOUS_SOURCE='06bc5964a82c484d4a073a43b1dc5afe77f47cad'
PREVIOUS_IMAGE='sha256:9a61186a57af776a39c17321aece53973cee6b472a69461c931e5af8c2915b4d'
PREVIOUS_PLAN='7bb7ba05ecf158b527465337952522662e5e584a1baaf7dc780058f27d7a8ff1'
UPGRADE_REGISTRY='p7u_native_guard_registry_v2'
REGISTRY_IMAGE='registry@sha256:01cd312e67026f06f5d89c3e133a4a9adc7cb9eeb9b1194e0b2954dfd770efd2'


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def api(path,body=None):
    if body is not None and path not in ['/store/reload',*[f'/addons/{GUARD}/{v}' for v in ['stop','update','start']]]:
        raise RuntimeError('UNAPPROVED_MUTATION_TARGET')
    req=Request('http://supervisor'+path,data=json.dumps(body).encode() if body is not None else None,
                method='POST' if body is not None else 'GET',headers={'Authorization':'Bearer '+os.environ['SUPERVISOR_TOKEN'],'Content-Type':'application/json'})
    with urlopen(req,timeout=180) as response:raw=response.read(1000000)
    result=json.loads(raw)
    if path.startswith('/core/api/'):return result
    if result.get('result')!='ok':raise RuntimeError('SUPERVISOR_NOT_ACKNOWLEDGED')
    return result.get('data')


def command(argv,timeout=90,raw=False):
    p=subprocess.run(argv,capture_output=True,text=not raw,timeout=timeout)
    if p.returncode:raise RuntimeError('COMMAND_FAILED '+str(argv[:2]))
    return p.stdout


def inspect(name):
    p=subprocess.run(['docker','inspect',name],capture_output=True,text=True,timeout=15)
    if p.returncode:
        if 'no such' in p.stderr.casefold():return None
        raise RuntimeError('DOCKER_INSPECT_UNAVAILABLE')
    c=json.loads(p.stdout)[0];s=c['State']
    return {'id':c['Id'],'image':c['Image'],'running':s['Running'],'pid':s['Pid'],'started_at':s['StartedAt']}


def snapshot(previous=None):
    info=api('/addons/'+GUARD+'/info');opts=info['options']
    assert info['state']=='started' and info['version']==('0.2.4-'+PREVIOUS_SOURCE[:12] if previous else '0.2.3') and info['boot']=='manual' and info['watchdog'] is False
    assert opts['enabled'] is False and opts['dry_run'] is True and opts['serial_owner_approved'] is False
    assert opts['allow_private_http_fallback'] is False and opts['notify_on_confirmed_hang'] is True
    assert opts['esp_restart_entity']=='button.slzb_06p7u_core_restart' and opts['zigbee_restart_entity']=='button.slzb_06p7u_zigbee_restart'
    owners={}
    for slug in OWNERS:
        data=api('/addons/'+slug+'/info')
        assert data['watchdog'] is False and data['boot']=='manual' and data['state'] in ['started','error','stopped']
        owners[slug]={'state':data['state'],'version':data['version'],'options_hash':digest(data['options']),'container':inspect('app_'+slug)}
    guard=inspect('app_'+GUARD);assert guard and guard['running']
    if previous:assert guard['image']==PREVIOUS_IMAGE and guard['id']==previous['guard_container_id']
    return {'guard':guard,'guard_version':info['version'],'options_hash':digest(opts),'owners':owners}


def validate_payload(payload):
    assert set(payload) in ({'mode','release','config_b64','expected_plan_hash'},{'mode','release','config_b64','expected_plan_hash','reconcile_previous'}) and payload['mode'] in ['plan','apply']
    if 'reconcile_previous' in payload:assert payload['reconcile_previous']==PREVIOUS_SOURCE
    receipt=payload['release'];sha=receipt['source_sha']
    assert re.fullmatch('[a-f0-9]{40}',sha) and receipt['schema']=='p7u-native-guard-release-v1'
    assert receipt['version']=='0.2.4-'+sha[:12] and receipt['image_reference']=='localhost:50146/p7u-native-guard:'+receipt['version']
    assert re.fullmatch('sha256:[a-f0-9]{64}',receipt['image_id'])
    config=base64.b64decode(payload['config_b64'],validate=True)
    assert 0<len(config)<32768 and hashlib.sha256(config).hexdigest()==receipt['files']['config.yaml']
    assert b'image: localhost:50146/p7u-native-guard' in config and ('version: '+receipt['version']).encode() in config
    assert receipt['physical_action'] is False and receipt['installed'] is False
    return receipt,config


def unique(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def protected_ledger():
    code="""import json,hashlib;from pathlib import Path
p=Path('/data');files=[p/'watchdog-state.json',*sorted((p/'evidence').glob('*.attempt.json')),*sorted((p/'evidence').glob('*.result.json'))]
print(json.dumps({str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files if f.exists()}))"""
    return json.loads(command(['docker','exec','app_'+GUARD,'python','-c',code]))


@contextmanager
def deployment_lock():
    import fcntl
    fd=os.open('/share/p7u-lifecycle/private/exclusive-manager.lock',os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:os.close(fd)


def verified_previous():
    intent=ROOT/'active-deployment.json';receipt=ROOT/PREVIOUS_SOURCE/'receipt.json'
    assert (ROOT/PREVIOUS_SOURCE).is_dir() and not (ROOT/PREVIOUS_SOURCE).is_symlink()
    for p in [intent,receipt]:assert p.is_file() and not p.is_symlink() and p.stat().st_size<65536
    iraw=intent.read_bytes();rraw=receipt.read_bytes();i=json.loads(iraw);r=json.loads(rraw)
    assert i['plan_hash']==PREVIOUS_PLAN and i['plan']['source_sha']==PREVIOUS_SOURCE and i['plan']['image_id']==PREVIOUS_IMAGE
    assert r['status']=='GUARD_PREBUILT_DEPLOYED_UNARMED' and r['plan_hash']==PREVIOUS_PLAN and r['source_sha']==PREVIOUS_SOURCE
    assert r['image_id']==PREVIOUS_IMAGE and r['version']=='0.2.4-'+PREVIOUS_SOURCE[:12]
    assert all(r[k] is True for k in ['options_preserved','ledger_preserved','zigbee_hosts_unchanged']) and r['resets_enabled'] is False
    return {'source_sha':PREVIOUS_SOURCE,'guard_container_id':r['container_id'],'intent_sha256':hashlib.sha256(iraw).hexdigest(),'receipt_sha256':hashlib.sha256(rraw).hexdigest()}


def install(payload):
    with deployment_lock():return _install_locked(payload)


def _install_locked(payload):
    receipt,config=validate_payload(payload)
    assert not ROOT.is_symlink()
    if ROOT.exists():assert ROOT.is_dir() and ROOT.stat().st_mode&0o077==0
    upgrading='reconcile_previous' in payload
    previous=verified_previous() if upgrading else None
    intent=ROOT/('active-upgrade-from-'+PREVIOUS_SOURCE[:12]+'.json' if upgrading else 'active-deployment.json')
    assert not intent.exists() and not intent.is_symlink()
    registry_name=UPGRADE_REGISTRY if upgrading else REGISTRY
    if upgrading:assert receipt['source_sha']!=PREVIOUS_SOURCE
    before=snapshot(previous)
    plan={'operation':'install_prebuilt_native_guard_only','source_sha':receipt['source_sha'],
          'image_id':receipt['image_id'],'config_sha256':receipt['files']['config.yaml'],'before':before,'reconciled_previous':previous}
    ph=digest(plan)
    if payload['mode']=='plan':return {'status':'GUARD_ONLY_PLAN','plan_hash':ph,'plan':plan}
    if payload['expected_plan_hash']!=ph:raise RuntimeError('STALE_PLAN_HASH')
    directory=ROOT/receipt['source_sha'];archive=directory/'image.docker.tar'
    assert directory.is_dir() and directory.stat().st_mode&0o077==0 and not directory.is_symlink() and not archive.is_symlink()
    with archive.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==receipt['files']['image.docker.tar']
    unique(intent,(json.dumps({'plan_hash':ph,'plan':plan},sort_keys=True)+'\n').encode())
    old_options=api('/addons/'+GUARD+'/info')['options'];assert digest(old_options)==before['options_hash']
    unique(directory/'options.private.json',(json.dumps(old_options,sort_keys=True)+'\n').encode())
    ledger=protected_ledger();unique(directory/'ledger-before.json',json.dumps(ledger,sort_keys=True).encode())
    backup=command(['docker','cp','app_'+GUARD+':/data','-'],raw=True)
    assert 0<len(backup)<64*1024*1024;unique(directory/'guard-data-before.private.tar',backup)
    src=Path('/addons/local/p7u_recovery');assert src.is_dir() and not src.is_symlink() and not (src/'config.yaml').is_symlink()
    shutil.copytree(src,directory/'sources-before')
    if inspect(registry_name) is not None:raise RuntimeError('REGISTRY_ALREADY_EXISTS; RECONCILE_BEFORE_RETRY')
    command(['docker','pull',REGISTRY_IMAGE])
    command(['docker','run','--detach','--name',registry_name,'--label','p7u.issue=143','--restart=no',
             '--publish','127.0.0.1:50146:5000','--log-driver','json-file','--log-opt','max-size=2m','--log-opt','max-file=2',REGISTRY_IMAGE])
    registry=inspect(registry_name)
    try:
        command(['docker','load','--input',str(archive)])
        image=json.loads(command(['docker','image','inspect',receipt['image_reference']]))[0]
        assert image['Id']==receipt['image_id'] and image['Architecture']=='arm64' and image['Config']['Labels']['org.opencontainers.image.revision']==receipt['source_sha']
        command(['docker','push',receipt['image_reference']])
        assert snapshot(previous)==before
        temporary=src/'config.yaml.p7u-new';unique(temporary,config);os.replace(temporary,src/'config.yaml')
        api('/store/reload',{})
        assert snapshot(previous)==before
        api('/addons/'+GUARD+'/stop',{})
        api('/addons/'+GUARD+'/update',{})
        info=api('/addons/'+GUARD+'/info')
        assert info['version']==receipt['version'] and info['build'] is False and digest(info['options'])==before['options_hash']
        api('/addons/'+GUARD+'/start',{})
        final=api('/addons/'+GUARD+'/info');assert final['state']=='started' and digest(final['options'])==before['options_hash']
        current=inspect('app_'+GUARD);assert current['image']==receipt['image_id'] and current['running']
        hashes=json.loads(command(['docker','exec','app_'+GUARD,'python','-c',
            'import json,hashlib;from pathlib import Path;print(json.dumps({n:hashlib.sha256((Path("/app")/n).read_bytes()).hexdigest() for n in '+repr(sorted(receipt['runtime_files']))+'}))']))
        assert hashes==receipt['runtime_files'] and protected_ledger()==ledger
        for slug,expected in before['owners'].items():
            info=api('/addons/'+slug+'/info')
            assert {'state':info['state'],'version':info['version'],'options_hash':digest(info['options']),'container':inspect('app_'+slug)}==expected
        result={'status':'GUARD_PREBUILT_DEPLOYED_UNARMED','source_sha':receipt['source_sha'],'version':receipt['version'],
                'image_id':current['image'],'container_id':current['id'],'runtime_files_verified':len(hashes),
                'options_preserved':True,'ledger_preserved':True,'zigbee_hosts_unchanged':True,'resets_enabled':False,
                'plan_hash':ph,'backup_sha256':hashlib.sha256(backup).hexdigest()}
        unique(directory/'receipt.json',(json.dumps(result,sort_keys=True)+'\n').encode())
        return result
    finally:
        if inspect(registry_name)==registry:command(['docker','stop',registry_name],timeout=30)


if __name__=='__main__':print(json.dumps(install(PAYLOAD),sort_keys=True),flush=True)
