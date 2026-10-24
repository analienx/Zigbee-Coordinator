"""Exact-plan gateway for one managed F1 preservation probe, never Z2M recovery.

Only a fresh dedicated manual one-shot app may be installed/started/stopped.
Old radio-owner containers, source/HOLD journals and reset budgets are retained.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.request import Request,build_opener,HTTPRedirectHandler

ROOT=Path('/share/p7u-lifecycle/private/preservation-f1')
OLD=ROOT.parent/'source-3921b7923025'
SLUG='local_p7u_preservation_probe'
INSPECTOR='local_p7u_r4_owner_inspector'
REGISTRY='p7u_preservation_registry'
REGISTRY_IMAGE='registry@sha256:01cd312e67026f06f5d89c3e133a4a9adc7cb9eeb9b1194e0b2954dfd770efd2'
OPERATION='b2660c95-38f5-40b2-9589-6864ed178210'
PORT='/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00'
GUARD_IMAGE='sha256:ffc989d9669e671d9a0199282b9b9074cb899dfdda9acd050f5907177aca7bb9'
INSPECTOR_IMAGE='sha256:ce5c229254f0863d2f51a0655bb5dac9a40d97992fd28764ace521177f708865'
ORIGINAL_ID='f22d7a3dbf786cb30537a918bf470857ffac085aa973f315c6f303a33e60889b'
HOLDS={'source-3921b7923025':'b44213ae2b18e7246fe4326635eb83e82ce76aa86b15f85378ba39fa4a228354',
       'source-a5ce68b3b6a4':'f589697ed9f05af5bb607f3646a6da4f7c414f4d63c3f0fa1425aa49fcba4319'}
ENTRY=['node','/app/dist/p7u_preservation_probe.cjs']
ROM=False
REGISTRY_PORT='127.0.0.1:50148:5000'
COMMAND='SYS_F1_B1Q1_OP0_ONCE'


def select_role(receipt):
    """Two fixed read-only roles, neither admits reset or bootloader entry."""
    global ROM,ROOT,SLUG,REGISTRY,ENTRY,REGISTRY_PORT,COMMAND
    need(receipt.get('schema') in ['p7u-preservation-release-v1','p7u-rom-observe-release-v1'],'RELEASE_SCHEMA')
    ROM=receipt['schema']=='p7u-rom-observe-release-v1'
    ROOT=Path('/share/p7u-lifecycle/private')/('rom-observe' if ROM else 'preservation-f1')
    SLUG='local_p7u_rom_observer' if ROM else 'local_p7u_preservation_probe'
    REGISTRY='p7u_rom_observe_registry' if ROM else 'p7u_preservation_registry'
    REGISTRY_PORT='127.0.0.1:50149:5000' if ROM else '127.0.0.1:50148:5000'
    ENTRY=['node','/app/dist/'+('p7u_rom_observer.cjs' if ROM else 'p7u_preservation_probe.cjs')]
    COMMAND='TI_ROM_PING_CHIPID_NO_ENTRY_OR_RESET' if ROM else 'SYS_F1_B1Q1_OP0_ONCE'


def need(value,reason):
    if not value:raise RuntimeError('PRESERVATION_HOLD_'+reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


def private(path,limit=4*1024*1024):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size<=limit,'PRIVATE_FILE')
    raw=path.read_bytes();need(len(raw)<=limit,'PRIVATE_SIZE');return raw


def unique(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


@contextmanager
def lock():
    import fcntl
    fd=os.open(ROOT.parent/'exclusive-manager.lock',os.O_RDWR|os.O_NOFOLLOW)
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(fd)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise RuntimeError('PRESERVATION_REDIRECT_FORBIDDEN')


def api(path,body=None):
    allowed={'/store/reload',*[f'/addons/{SLUG}/{a}' for a in ['install','start','stop']],f'/addons/{INSPECTOR}/start'}
    if body is not None:need(path in allowed and body=={},'UNAPPROVED_HTTP_MUTATION')
    req=Request('http://supervisor'+path,data=json.dumps(body).encode() if body is not None else None,
                method='POST' if body is not None else 'GET',headers={'Authorization':'Bearer '+os.environ['SUPERVISOR_TOKEN'],'Content-Type':'application/json'})
    with build_opener(NoRedirect()).open(req,timeout=100 if body is not None else 15) as r:raw=r.read(2_000_001)
    need(len(raw)<=2_000_000,'HTTP_SIZE')
    if path.endswith('/logs'):return raw.decode(errors='replace')
    data=json.loads(raw)
    if path.startswith('/core/api/'):return data
    need(data.get('result')=='ok','HTTP_NOT_ACKNOWLEDGED');return data.get('data')


def command(argv,timeout=90,binary=False):
    p=subprocess.run(argv,capture_output=True,text=not binary,timeout=timeout)
    need(p.returncode==0,'COMMAND_'+str(argv[:2]));return p.stdout


def inspect(name):
    p=subprocess.run(['docker','inspect',name],capture_output=True,text=True,timeout=15)
    if p.returncode:need('no such' in p.stderr.lower(),'DOCKER_UNKNOWN');return None
    return json.loads(p.stdout)[0]


def addon(slug):return api('/addons/'+slug+'/info')


def validate(receipt,config):
    source=receipt['source_sha']
    need(receipt['schema']==('p7u-rom-observe-release-v1' if ROM else 'p7u-preservation-release-v1') and re.fullmatch('[a-f0-9]{40}',source),'RELEASE_SCHEMA')
    need(receipt['image_reference']==('localhost:50149/p7u-rom-observe:' if ROM else 'localhost:50148/p7u-preservation:')+'0.1.0-'+source[:12] and
         receipt['version']=='0.1.0-'+source[:12] and re.fullmatch('sha256:[a-f0-9]{64}',receipt['image_id']), 'SOURCE_IMAGE')
    need(receipt['entrypoint']==ENTRY and sha(config)==receipt['config_sha256'],'CONFIG_OR_ENTRYPOINT')
    need(receipt['radio_reset'] is False and receipt['network_startup'] is False and receipt['nv_write'] is False and
         receipt['audited_filesystem_matches'] is True and receipt['stty_arm64_verified'] is True,'SCOPE')
    if ROM:need(receipt.get('bootloader_entry') is False,'ROM_ENTRY_FORBIDDEN')


def snapshot(allow_probe=False):
    owners={}
    for slug in ['45df7312_zigbee2mqtt','local_p7u_r4_native_host','local_p7u_r4_fallback','local_p7u_r4_lifecycle_manager']:
        info=addon(slug);c=inspect('app_'+slug)
        need(info['state'] in ['stopped','error'] and info['boot']=='manual' and info['watchdog'] is False,'OWNER_NOT_INACTIVE')
        need(c is None or c['State']['Running'] is False,'OWNER_RUNNING')
        owners[slug]={'container_id':c['Id'] if c else None,'image_id':c['Image'] if c else None,'options_sha256':sha(canonical(info['options'])),'version':info['version']}
    need(owners['45df7312_zigbee2mqtt']['container_id']==ORIGINAL_ID and owners['45df7312_zigbee2mqtt']['version']=='2.14.0-1','ORIGINAL_EPOCH')
    original=addon('45df7312_zigbee2mqtt')['options'];serial=original.get('serial',{})
    need(serial.get('port')==PORT and serial.get('adapter')=='zstack' and serial.get('baudrate')==115200 and serial.get('rtscts') is False and original.get('socat',{}).get('enabled') is False,'SERIAL_CONFIGURATION')
    guardian=addon('local_p7u_recovery');opts=guardian['options'];g=inspect('app_local_p7u_recovery')
    need(g and g['State']['Running'] and g['Image']==GUARD_IMAGE and guardian['state']=='started','GUARD_IMAGE')
    for key,value in [('enabled',False),('dry_run',True),('serial_owner_approved',False),('allow_private_http_fallback',False),('maintenance',False),('firmware_flash_active',False)]:
        need(opts.get(key,False if key=='firmware_flash_active' else None) is value,'GUARD_NOT_PASSIVE')
    status=json.loads(command(['docker','exec','app_local_p7u_recovery','python','-c',"from pathlib import Path;print(Path('/data/status.json').read_text())"]))
    need(0<=time.time()-status['utc']<65 and status['ota_active'] is False and status['ota_unknown'] is False and status['resets_enabled'] is False,'OTA_OR_STATUS_UNKNOWN')
    for entity in ['automation.boot_deterministic_emqx_then_zigbee2mqtt','automation.zigbee2mqtt_mesh_communication_outage_alert']:
        state=api('/core/api/states/'+entity);need(state['state']=='off' and state['attributes']['current']==0,'COMPETING_AUTOMATION')
    need(Path(PORT).exists(),'USB_MISSING')
    with build_opener(NoRedirect()).open('http://192.168.50.59/ha_info',timeout=8) as r:identity=json.load(r)['Info']
    need(identity['MAC'].lower()=='70:af:09:a5:dc:30' and identity['model']=='SLZB-06p7U' and identity['zb_hw']=='CC2652P7' and identity['coord_mode']==2,'BOARD_IDENTITY')
    installed={a['slug'] for a in api('/addons')['addons']}
    if not allow_probe:need(SLUG not in installed and inspect('app_'+SLUG) is None,'PROBE_ALREADY_EXISTS')
    histories={}
    if ROM:
        prior=addon('local_p7u_preservation_probe');c=inspect('app_local_p7u_preservation_probe')
        need(prior['state']=='error' and prior['boot']=='manual' and prior['watchdog'] is False and c and
             c['Id']=='470d1dad8d171608303d57e6537c11629c08f3cb6f820f3354860b15cd2bf755' and
             c['Image']=='sha256:f4e235ed927b4c26a7c3b6632523d1de77d028e172ace23baed9b41e9b628ed1' and
             c['State']['Running'] is False and c['State']['ExitCode']==2,'PRIOR_F1_EPOCH')
        p=ROOT.parent/'preservation-f1'
        for name,digest in [('probe.result.json','83b532971cce037fb5eeec6f5e4c6afae57345f19a039dccd918240a89a495eb'),
                            ('gateway.result.json','469deaf80e57728777fa135ad74a86b1dc6d0d1d0a5c6b78f22fa84d9269a162')]:
            need(sha(private(p/name))==digest,'PRIOR_F1_EVIDENCE_CHANGED');histories['f1-'+name]=digest
    for folder,expected in HOLDS.items():
        raw=private(ROOT.parent/folder/'journal/events.jsonl')
        need(sha(raw)==expected and json.loads(raw.splitlines()[-1])['phase']=='HOLD','OLD_HOLD_CHANGED');histories[folder]=expected
    pointer=private(ROOT.parent/'active-operation.json');p=json.loads(pointer)
    need(p['operation_id']==OPERATION and p['source_sha']=='3921b79230253e034bf61b506b846cc9c1c64ef4','OLD_POINTER_CHANGED')
    histories['active-operation']=sha(pointer)
    histories['current_hosts_snapshot']=sha(canonical({'owners':owners,'guard_id':g['Id'],'guard_options_hash':sha(canonical(opts))}))
    results={}
    for name in ['native-post-radio-esp-only.result.json','native-post-radio-esp-original-start.result.json']:
        raw=private(OLD/name);r=json.loads(raw)
        need(r['incident_id']==OPERATION.replace('-','') and r['status']=='ACKNOWLEDGED','PRIOR_RECOVERY_CHANGED');results[name]=sha(raw)
    need(sha(private(OLD/'native-post-radio-esp-f22d7a3dbf78.private.log'))=='e89e842c67def9138996e2ddb9320e2e7f1c674e2b2fea43ff30272a49c45ae4','FAILED_LOG_CHANGED')
    data=Path('/config/zigbee2mqtt');manifest=json.loads(private(data/'.p7u-approved.json'))
    db=sha(private(data/'database.db',64*1024*1024));backup=sha(private(data/'coordinator_backup.json'))
    need(db==manifest['database_sha256'] and manifest['devices']==107 and manifest['rows']==128 and
         backup=='8609d816976863702517d82bc80597b082e741e70747e008c0854b6c802f8de4','HOST_DATA_CHANGED')
    need(not any((data/n).exists() or (data/n).is_symlink() for n in ['database.db.tmp','.p7u-approved.json.pending']),'HOST_DATA_PENDING')
    events=[json.loads(l) for l in private(OLD/'journal/events.jsonl').splitlines()]
    cold=next(e['evidence']['cold_backup'] for e in events if e['phase']=='DB_APPROVED');archive=OLD/cold['archive']
    need(archive.resolve().is_relative_to(OLD.resolve()) and not archive.is_symlink(),'COLD_PATH')
    with archive.open('rb') as stream:need(hashlib.file_digest(stream,'sha256').hexdigest()==cold['sha256'],'COLD_BACKUP_CHANGED')
    return {'database_sha256':db,'backup_sha256':backup,'history_sha256':histories,'prior_result_sha256':results}


def zero_holders():
    proofs=[]
    for _ in range(3):
        info=addon(INSPECTOR);need(info['state']!='started' and info['host_pid'] is True and info['protected'] is False,'INSPECTOR_NOT_ADMITTED')
        old=inspect('app_'+INSPECTOR);api('/addons/'+INSPECTOR+'/start',{})
        for tick in range(40):
            time.sleep(.25)
            if addon(INSPECTOR)['state']!='started':break
        c=inspect('app_'+INSPECTOR)
        need(c and not c['State']['Running'] and c['Image']==INSPECTOR_IMAGE and c['HostConfig']['PidMode']=='host' and c['State']['ExitCode']==0 and (old is None or c['Id']!=old['Id']),'INSPECTOR_EPOCH')
        records=[]
        for line in api('/addons/'+INSPECTOR+'/logs').splitlines():
            try:r=json.loads(line)
            except ValueError:continue
            if r.get('schema')=='p7u-host-tty-cgroup-evidence-v2':records.append(r)
        need(records,'INSPECTOR_NO_RECORD');r=records[-1]
        need(r.get('exclusive_owner_verified') is True and r.get('serial_opened') is False and r.get('tty_holders_pids')==[] and set(r.get('slots',{}))=={'official','diagnostic','fallback'} and all(v.get('running') is False for v in r['slots'].values()),'UART_NOT_FREE')
        proofs.append({'utc':time.time(),'container_id':c['Id'],'result':r})
    return proofs


def planned(receipt,evidence):
    return {'schema':'p7u-rom-observe-plan-v1' if ROM else 'p7u-preservation-f1-plan-v1','source_sha':receipt['source_sha'],'operation_id':OPERATION,
            'command':COMMAND,'serial_by_id':PORT,'image_id':receipt['image_id'],'original_container_id':ORIGINAL_ID,**evidence}


def remote(payload):
    need(set(payload)=={'mode','release','config_b64','expected_plan_hash'} and payload['mode'] in ['plan','stage','execute'],'PAYLOAD_SCHEMA')
    receipt=payload['release'];select_role(receipt);config=base64.b64decode(payload['config_b64'],validate=True);validate(receipt,config)
    with lock():
        if payload['mode'] in ['plan','stage']:
            need(not ROOT.exists() and not ROOT.is_symlink(),'PROBE_DIRECTORY_EXISTS_NO_REPLAY')
            plan=planned(receipt,snapshot());raw=canonical(plan);ph=sha(raw)
            if payload['mode']=='plan':return {'status':'PRESERVATION_PLAN','plan_hash':ph,'plan':plan}
            need(ph==payload['expected_plan_hash'],'STALE_PLAN')
            ROOT.mkdir(mode=0o700);unique(ROOT/'plan.json',raw);unique(ROOT/'plan.sha256',(ph+'\n').encode())
            unique(ROOT/'stage.intent.json',canonical({'plan_sha256':ph,'source_sha':receipt['source_sha']}))
            return {'status':'STAGED_NO_DEVICE_ACTION','plan_hash':ph}
        need(ROOT.is_dir() and not ROOT.is_symlink() and ROOT.stat().st_mode&0o077==0,'STAGED_DIRECTORY_UNSAFE')
        raw=private(ROOT/'plan.json');ph=sha(raw)
        need(ph==payload['expected_plan_hash'] and private(ROOT/'plan.sha256').decode().strip()==ph,'STAGED_PLAN_HASH')
        need(json.loads(raw)==planned(receipt,snapshot()),'LIVE_STATE_CHANGED')
        need(not (ROOT/'install.intent.json').exists() and not (ROOT/'install.intent.json').is_symlink(),'INSTALL_ALREADY_ATTEMPTED')
        archive=ROOT/'image.docker.tar'
        need(archive.is_file() and not archive.is_symlink(),'IMAGE_ARCHIVE_UNSAFE')
        with archive.open('rb') as stream:need(hashlib.file_digest(stream,'sha256').hexdigest()==receipt['archive_sha256'],'IMAGE_BYTES_CHANGED')
        need(inspect(REGISTRY) is None,'REGISTRY_EXISTS_NO_REPLAY')
        unique(ROOT/'install.intent.json',canonical({'plan_sha256':ph,'utc':time.time()}))
        command(['docker','pull',REGISTRY_IMAGE])
        command(['docker','run','--detach','--name',REGISTRY,'--restart=no','--publish',REGISTRY_PORT,
                 '--log-driver','json-file','--log-opt','max-size=2m','--log-opt','max-file=2',REGISTRY_IMAGE])
        registry=inspect(REGISTRY)
        try:
            command(['docker','load','--input',str(archive)])
            image=json.loads(command(['docker','image','inspect',receipt['image_reference']]))[0]
            need(image['Id']==receipt['image_id'] and image['Architecture']=='arm64' and image['Config']['Entrypoint']==ENTRY and not image['Config'].get('Cmd'),'IMAGE_ROLE_CHANGED')
            command(['docker','push',receipt['image_reference']])
            destination=Path('/addons/local')/SLUG.removeprefix('local_');need(not destination.exists() and not destination.is_symlink(),'SOURCE_DIRECTORY_EXISTS')
            destination.mkdir(mode=0o755);unique(destination/'config.yaml',config)
            api('/store/reload',{});api('/addons/'+SLUG+'/install',{})
            info=addon(SLUG);need(info['version']==receipt['version'] and info['boot']=='manual' and info['watchdog'] is False and info['build'] is False and info['state']=='stopped','PROBE_PROFILE_NOT_MANUAL')
            need(json.loads(raw)==planned(receipt,snapshot(allow_probe=True)),'STATE_CHANGED_DURING_INSTALL')
            proofs=zero_holders()
            need(time.time()-proofs[0]['utc']<20,'STALE_UART_PROOF')
            need(json.loads(raw)==planned(receipt,snapshot(allow_probe=True)),'STATE_CHANGED_AFTER_PROOF')
            need(time.time()-proofs[0]['utc']<30,'STALE_UART_PROOF_AFTER_ADMISSION')
            unique(ROOT/'authority.intent.json',canonical({'schema':'p7u-preservation-authority-v1','operation_id':OPERATION,
                'source_sha':receipt['source_sha'],'plan_sha256':ph,'utc_ms':int(time.time()*1000),'host_proofs':proofs}))
            start_status='ACKNOWLEDGED'
            try:api('/addons/'+SLUG+'/start',{})
            except Exception:start_status='AMBIGUOUS_NO_RETRY'
            deadline=time.monotonic()+45
            while time.monotonic()<deadline:
                c=inspect('app_'+SLUG)
                if c is not None and c['State']['Running'] is False:break
                time.sleep(.5)
            c=inspect('app_'+SLUG)
            need(c is not None and c['Image']==receipt['image_id'],'PROBE_CONTAINER_UNCONFIRMED')
            if c['State']['Running']:
                unique(ROOT/'cleanup.intent.json',canonical({'container_id':c['Id'],'host_process_only':True,'utc':time.time()}))
                api('/addons/'+SLUG+'/stop',{})
                c=inspect('app_'+SLUG)
                need(c is None or c['State']['Running'] is False,'PROBE_STILL_RUNNING_NO_OTHER_OWNER')
            logs=b''
            if c:
                log_result=subprocess.run(['docker','logs',c['Id']],capture_output=True,timeout=15)
                need(log_result.returncode==0,'PROBE_LOG_UNAVAILABLE');logs=log_result.stdout+log_result.stderr
            if logs:unique(ROOT/'probe.private.log',logs)
            post_proofs=zero_holders()
            need(json.loads(raw)==planned(receipt,snapshot(allow_probe=True)),'ORIGINAL_HOSTS_OR_DATA_CHANGED')
            result=json.loads(private(ROOT/'probe.result.json')) if (ROOT/'probe.result.json').exists() else {'status':'RESULT_MISSING_STATE_UNKNOWN'}
            report={'schema':'p7u-preservation-gateway-result-v1','source_sha':receipt['source_sha'],'operation_id':OPERATION,
                    'plan_sha256':ph,'start_ack':start_status,'result':result,'old_hosts_preserved':True,'post_probe_zero_holders':True,
                    'post_probe_host_proofs':post_proofs,'probe_container_id':c['Id'] if c else None}
            unique(ROOT/'gateway.result.json',canonical(report));return report
        finally:
            if inspect(REGISTRY) is not None and inspect(REGISTRY)['Id']==registry['Id']:command(['docker','stop',REGISTRY],timeout=30)


def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['plan','apply']);p.add_argument('--release',type=Path,required=True);p.add_argument('--expected-plan-hash',default='');p.add_argument('--rom-observe',action='store_true')
    a=p.parse_args();directory=a.release.resolve(strict=True)
    need(directory.is_relative_to(Path('C:/Workspace/artifacts').resolve()),'ARTIFACT_LOCATION')
    receipt=json.loads((directory/('ROM_OBSERVE_RELEASE.json' if a.rom_observe else 'PRESERVATION_RELEASE.json')).read_text());select_role(receipt)
    need(ROM is a.rom_observe,'CLI_ROLE_MISMATCH')
    config=(directory/('rom-observe-config.yaml' if ROM else 'preservation-config.yaml')).read_bytes()
    validate(receipt,config)
    need(sha(Path(__file__).read_bytes())==receipt['gateway_sha256'],'GATEWAY_NOT_QUALIFIED')
    archive=directory/('p7u-rom-observe-arm64.docker.tar' if ROM else 'p7u-preservation-arm64.docker.tar')
    with archive.open('rb') as stream:need(hashlib.file_digest(stream,'sha256').hexdigest()==receipt['archive_sha256'],'ARTIFACT_CHANGED')
    checks=json.loads(subprocess.check_output(['gh','api','repos/analienx/Zigbee-Coordinator/commits/'+receipt['source_sha']+'/check-runs?per_page=100']))['check_runs']
    for label in ['unittest','exact-herdsman-hold','b4-herdsman-real-source']:
        found=[c for c in checks if c['name'].endswith(label)]
        need(found and all(c['conclusion']=='success' for c in found),'EXACT_SOURCE_CI_'+label)
    source=Path(__file__).read_text()
    def invoke(mode,expected=''):
        payload={'mode':mode,'release':receipt,'config_b64':base64.b64encode(config).decode(),'expected_plan_hash':expected}
        proc=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','ha','python3','-'],input='PAYLOAD='+repr(payload)+'\n'+source,
                            capture_output=True,text=True,timeout=600)
        if proc.stdout:print(proc.stdout,end='',flush=True)
        if proc.returncode:raise RuntimeError('PRESERVATION_HOLD_NO_REPLAY '+proc.stderr[-600:])
        return json.loads(proc.stdout.splitlines()[-1])
    plan=invoke('plan')
    if a.mode=='plan':return
    need(a.expected_plan_hash==plan['plan_hash'],'PLAN_NOT_EXACT')
    invoke('stage',a.expected_plan_hash)
    subprocess.run(['scp','-o','BatchMode=yes',str(archive),'ha:'+str(ROOT/'image.docker.tar')],check=True,timeout=120)
    invoke('execute',a.expected_plan_hash)


if __name__=='__main__':
    if 'PAYLOAD' in globals():print(json.dumps(remote(PAYLOAD),sort_keys=True),flush=True)
    else:main()
