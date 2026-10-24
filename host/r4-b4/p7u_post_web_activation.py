"""One managed diagnostic-owner start after the exact completed P7U web trial.

No radio commands, reset, flash, NV restore, fallback, old-intent replay or
arbitrary target is exposed. An ambiguous start consumes the attempt.
"""
import argparse,base64,hashlib,json,os,shlex,subprocess,sys,threading,time
from pathlib import Path
import p7u_web_flash_trial as t

ROOT=Path('/share/p7u-debug-after-web-20261024')
TARGET='local_p7u_r4_native_host'
HOST_SOURCE='9d13e8ce641968126c0e67fd57ca8de6a69478c4'
VERSION='0.2.1-9d13e8ce6419'
IMAGE='sha256:1b1bdc9497873401ee509e22965f5a7e2519056b21daca5bbcf2288e4fde2175'
OLD_IMAGE='sha256:4272e6be008c952ac331a8a9267ee0379f9d48a99c7eb997c86774d8e13ce78b'
ARCHIVE_SHA='225516c3b2d4f046e57ef4c4ce73588d22e21f2d68e3d3aa7d33134fbaa3eba1'
ARCHIVE_SIZE=200799232
CONFIG_SHA='246c32ccaf478668344d326be4730bff5ec9ad73991f84609186057e101e91cf'
TAG='localhost:50144/p7u-r4-diagnostic:'+VERSION
REGISTRY='p7u_144_release_registry'
CONFIG=Path('/addons/local/p7u_r4_native_host/config.yaml')
MANIFEST=t.DATA/'.p7u-approved-web-trial-20261024.json'
DB_SHA='fd7dc728ae4b53867e5b52503a9bb14c9f2aa92f4364ef00e1377fa9968db302'
BACKUP_SHA='18f303cf5f10769df942257c27efa33b9320e554fc9a5c1453e3af09a912c79f'
need=t.need
sha=t.sha
canonical=t.canonical
unique=t.unique
regular=t.regular
inspect=t.inspect

def api(path,body=None,timeout=25):
 reads={'/addons/'+s+'/info' for s in t.SLOTS+[t.GUARD,t.INSPECTOR]}
 writes={'/store/reload','/addons/'+TARGET+'/update','/addons/'+TARGET+'/start'}
 need(path in (reads if body is None else writes),'ACTIVATION_ROUTE')
 if body is not None:need(body=={},'ACTIVATION_BODY')
 request=t.Request('http://supervisor'+path,method='GET' if body is None else 'POST',
  data=None if body is None else canonical(body),headers={'Authorization':'Bearer '+os.environ['SUPERVISOR_TOKEN'],'Content-Type':'application/json'})
 with t.build_opener(t.NoRedirect()).open(request,timeout=timeout) as response:raw=response.read(1024*1024+1)
 need(len(raw)<=1024*1024,'ACTIVATION_HTTP_SIZE');j=json.loads(raw)
 need(j.get('result')=='ok','ACTIVATION_HTTP_NOT_ACKNOWLEDGED');return j.get('data')

def event(name,extra=None):
 unique(ROOT/(name+'.intent.json'),canonical({'utc':time.time(),'target':TARGET,**(extra or {})}))
 print(json.dumps({'phase':name,'utc':time.time()}),flush=True)

def transformed_config(raw):
 need(sha(raw)==CONFIG_SHA,'HOST_CONFIG_HASH')
 old=b'/config/zigbee2mqtt/.p7u-approved.json'
 need(raw.count(old)==1 and raw.count(b'image: localhost:50144/p7u-r4-diagnostic')==1 and
      b'boot: manual_only' in raw and b'P7U_B4_COLLECTOR' in raw,'CONFIG_CONTRACT')
 return raw.replace(old,str(MANIFEST).encode())

def registry():
 c=inspect(REGISTRY);need(c is not None,'REGISTRY_ABSENT')
 h=c['HostConfig'];need(c['Config'].get('Labels',{}).get('p7u.issue')=='144' and
  h['PortBindings']=={'5000/tcp':[{'HostIp':'127.0.0.1','HostPort':'50144'}]} and
  h['Privileged'] is False and not h.get('Binds') and not h.get('Devices') and
  h['RestartPolicy']['Name']=='no' and not c['State']['Running'] and
  t.re.fullmatch(r'registry@sha256:[a-f0-9]{64}',c['Config']['Image']),'REGISTRY_POLICY')
 return {'container_id':c['Id'],'image_id':c['Image']}

def inactive():
 slots={}
 for s in t.SLOTS:
  a=t.addon(s);c=inspect('app_'+s)
  need(a['state'] in ['stopped','error'] and a['boot']=='manual' and a['watchdog'] is False and
       a['auto_update'] is False and (not c or not c['State']['Running']),'ACTIVE_OR_AUTOMATIC_OWNER')
  slots[s]={'container_id':c['Id'] if c else None,'options_sha256':sha(canonical(a['options'])),'version':a['version']}
 return slots

def retained():
 raw=regular(t.DATA/'database.db');need(sha(raw)==DB_SHA and not (t.DATA/'database.db.tmp').exists(),'QUIESCED_DB_CHANGED')
 need(sha(regular(t.DATA/'coordinator_backup.json'))==BACKUP_SHA,'QUIESCED_BACKUP_CHANGED')
 return t.inventory(raw)

def preflight(config):
 need(not ROOT.exists() and not ROOT.is_symlink() and not MANIFEST.exists() and not MANIFEST.is_symlink(),'ACTIVATION_ALREADY_CONSUMED')
 result=regular(t.ROOT/'stop-reconcile.result.json');r=json.loads(result)
 need(r['status']=='VENDOR_DONE_NOT_YET_ACCEPTED' and r['image_sha256']==t.IMAGE_SHA and
  r['flash_request']=='ACKNOWLEDGED' and r['normal_hosts_started'] is False and r['host_inventory_preserved'] is True,'WEB_TRIAL_NOT_COMPLETED')
 events=json.loads(regular(t.ROOT/'flash-events.private.json'))
 need(sum(e['event']=='ZB_FW_done' for e in events)==1 and not any(e['event']=='ZB_FW_err' for e in events),'WEB_FLASH_RESULT')
 b=t.board();need(b['coord_mode']==2 and b['wifi_mode']==0 and Path(t.PORT).exists(),'MANAGEMENT_OR_USB')
 o=t.passive();need(o['maintenance'] is True and o['firmware_flash_active'] is True,'MAINTENANCE_NOT_SET')
 for entity in ['automation.boot_deterministic_emqx_then_zigbee2mqtt','automation.zigbee2mqtt_mesh_communication_outage_alert']:
  s=t.api('/core/api/states/'+entity);need(s['state']=='off' and s['attributes']['current']==0,'COMPETING_STARTER')
 slots=inactive();c=inspect('app_'+TARGET)
 need(c and c['Image']==OLD_IMAGE,'PREVIOUS_DEBUG_IMAGE')
 need(slots[TARGET]['options_sha256']==slots[t.ORIGINAL]['options_sha256']=='94c3f7be6d479b0df49206492ea2627a7ab2806ff888167ee938b33dbd0752f6','OWNER_OPTIONS_CHANGED')
 journals={}
 for prefix,pin in [('3921b7923025','b44213ae2b18e7246fe4326635eb83e82ce76aa86b15f85378ba39fa4a228354'),('a5ce68b3b6a4','f589697ed9f05af5bb607f3646a6da4f7c414f4d63c3f0fa1425aa49fcba4319')]:
  p=Path('/share/p7u-lifecycle/private')/('source-'+prefix)/'journal/events.jsonl'
  digest=sha(regular(p));need(digest==pin,'OLD_JOURNAL_CHANGED');journals[prefix]=digest
 return {'schema':'p7u-post-web-activation-plan-v1','web_result_sha256':sha(result),'host_source_sha':HOST_SOURCE,
  'image_id':IMAGE,'archive_sha256':ARCHIVE_SHA,'slots':slots,'inventory':retained(),'database_sha256':DB_SHA,
  'backup_sha256':BACKUP_SHA,'guard_options_sha256':sha(canonical(o)),'registry':registry(),
  'old_config_sha256':sha(regular(CONFIG)),'new_config_sha256':sha(transformed_config(config)),
  'old_approval_sha256':sha(regular(t.DATA/'.p7u-approved.json')),'old_journals':journals,
  'active_pointer_sha256':sha(regular(Path('/share/p7u-lifecycle/private/active-operation.json'))),
  'start_budget':1,'radio_resets':0,'flash_requests':0,'restore_requests':0}

def receive_archive(stream):
 p=ROOT/'image.docker.tar';event('receive-prebuilt-image',{'sha256':ARCHIVE_SHA,'bytes':ARCHIVE_SIZE})
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=hashlib.sha256();size=0
 with os.fdopen(fd,'wb') as out:
  while True:
   blob=stream.read(1024*1024)
   if not blob:break
   size+=len(blob);need(size<=ARCHIVE_SIZE,'ARCHIVE_OVERSIZED');h.update(blob);out.write(blob)
  out.flush();os.fsync(out.fileno())
 need(size==ARCHIVE_SIZE and h.hexdigest()==ARCHIVE_SHA,'ARCHIVE_INTEGRITY')

def activate(expected,config,stream):
 plan=preflight(config);need(sha(canonical(plan))==expected,'STALE_ACTIVATION_PLAN')
 ROOT.mkdir(mode=0o700);unique(ROOT/'plan.json',canonical(plan));result={'status':'HOLD','start_requested':False,'radio_reset':False,'radio_flash':False,'source_sha':HOST_SOURCE}
 registry_started=False
 try:
  receive_archive(stream)
  unique(ROOT/'previous-debug-container.private.json',canonical(inspect('app_'+TARGET)))
  logs=subprocess.run(['docker','logs','--tail','500','app_'+TARGET],capture_output=True,timeout=20)
  unique(ROOT/'previous-debug.private.log',(logs.stdout+logs.stderr)[-2*1024*1024:])
  unique(ROOT/'previous-config.yaml',regular(CONFIG));unique(ROOT/'previous-db-approval.json',regular(t.DATA/'.p7u-approved.json'))
  proofs=t.zero_holders();unique(ROOT/'pre-install-owner-proofs.json',canonical(proofs));retained()
  event('stage-image');t.command(['docker','load','--input',str(ROOT/'image.docker.tar')],timeout=180)
  i=json.loads(t.command(['docker','image','inspect',TAG]))[0]
  need(i['Id']==IMAGE and i['Architecture']=='arm64' and i['Os']=='linux','LOADED_IMAGE_ID')
  need(registry()==plan['registry'],'REGISTRY_CHANGED');event('start-temporary-registry')
  t.command(['docker','start',REGISTRY]);registry_started=True
  for tick in range(30):
   try:
    with t.build_opener(t.NoRedirect()).open('http://127.0.0.1:50144/v2/',timeout=2) as response:need(response.status==200,'REGISTRY_HTTP')
    break
   except Exception:
    need(tick<29,'REGISTRY_NOT_READY');time.sleep(.3)
  t.command(['docker','push',TAG],timeout=180)
  need(sha(regular(CONFIG))==plan['old_config_sha256'] and inactive()==plan['slots'],'INSTALL_STATE_CHANGED')
  event('install-config');raw=transformed_config(config)
  # Only the stopped known add-on definition is replaced; all predecessor
  # source bytes, containers/logs and lifecycle journals remain preserved.
  need(CONFIG.parent.is_dir() and not CONFIG.parent.is_symlink() and not CONFIG.is_symlink(),'SOURCE_PATH')
  with CONFIG.open('wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  event('reload-known-store');api('/store/reload',{})
  event('update-known-debug-host');api('/addons/'+TARGET+'/update',{},timeout=300)
  a=t.addon(TARGET);need(a['version']==VERSION and a['state'] in ['stopped','error'] and a['boot']=='manual' and
    a['watchdog'] is False and a['auto_update'] is False and a['build'] is False and
    sha(canonical(a['options']))==plan['slots'][TARGET]['options_sha256'],'INSTALLED_PROFILE')
  t.command(['docker','stop',REGISTRY],timeout=40);registry_started=False
  proofs=t.zero_holders();unique(ROOT/'pre-start-owner-proofs.json',canonical(proofs));inv=retained()
  inactive();o=t.passive();need(sha(canonical(o))==plan['guard_options_sha256'],'GUARD_CHANGED')
  need(sha(regular(CONFIG))==plan['new_config_sha256'],'INSTALLED_CONFIG_CHANGED')
  approval={'schema':'p7u-db-admission-v1','database_sha256':DB_SHA,'inventory_sha256':inv['inventory_sha256'],
   'rows':inv['rows'],'devices':inv['devices'],'generation':'web_trial_20261024_323949a_9d13e8ce6419'}
  event('seal-new-db-sidecar');unique(MANIFEST,canonical(approval))
  from p7u_host_integrity import verify_committed
  verify_committed(t.DATA/'database.db',MANIFEST)
  need(time.time()-proofs[0]['utc']<30,'OWNER_PROOF_EXPIRED')
  event('start-debug-once',{'image_id':IMAGE});result['start_requested']=True
  try:api('/addons/'+TARGET+'/start',{},timeout=30);result['start_acknowledged']=True
  except Exception as e:result['start_acknowledged']=False;result['start_ack_error_class']=type(e).__name__
  # A timeout consumes this exact attempt. Observe existing container only.
  deadline=time.monotonic()+120
  while time.monotonic()<deadline:
   c=inspect('app_'+TARGET)
   if c and c['Image']==IMAGE:
    result['container_id']=c['Id'];result['running']=c['State']['Running'];result['exit_code']=c['State']['ExitCode']
    log=subprocess.run(['docker','logs','--tail','1500',c['Id']],capture_output=True,timeout=20)
    text=(log.stdout+log.stderr).decode(errors='replace')
    result['resumed_seen']='zigbee-herdsman started (resumed)' in text
    result['started_seen']='Zigbee2MQTT started!' in text
    result['srsp_timeout_count']=sum('SRSP -' in l and 'after ' in l for l in text.splitlines())
    result['protected_startup_hold']='P7U HOLD_' in text
    if result['started_seen'] or not c['State']['Running']:break
   time.sleep(2)
  c=inspect('app_'+TARGET);need(c and c['Image']==IMAGE,'START_CONTAINER_IMAGE')
  unique(ROOT/'startup.private.log',(log.stdout+log.stderr)[-2*1024*1024:])
  need(all(not (inspect('app_'+s) or {}).get('State',{}).get('Running',False) for s in t.SLOTS if s!=TARGET),'COMPETING_OWNER_AFTER_START')
  result['host_inventory_preserved']=t.inventory(regular(t.DATA/'database.db'))==plan['inventory']
  result['status']='DEBUG_HOST_RESUMED_PENDING_F2_AND_RX' if c['State']['Running'] and result.get('started_seen') and result.get('resumed_seen') else 'START_FAILED_PRESERVED_NO_RETRY'
 except Exception as e:result['error_class']=str(e) if str(e).startswith('WEB_TRIAL_HOLD_') else type(e).__name__
 finally:
  if registry_started:
   try:t.command(['docker','stop',REGISTRY],timeout=40)
   except Exception:result['registry_cleanup_unconfirmed']=True
  result['utc']=time.time();unique(ROOT/'result.json',canonical(result))
 return result

def remote(payload,stream=None):
 import fcntl
 fd=os.open('/share/p7u-lifecycle/private/exclusive-manager.lock',os.O_RDWR|os.O_NOFOLLOW)
 try:
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  need(set(payload)=={'mode','expected','config_b64'},'ACTIVATION_PAYLOAD')
  if payload['mode']=='report':return json.loads(regular(ROOT/'result.json'))
  config=base64.b64decode(payload['config_b64'],validate=True);transformed_config(config)
  if payload['mode']=='plan':
   p=preflight(config);return {'status':'PLAN_NO_MUTATION','plan_hash':sha(canonical(p)),'plan':p}
  need(payload['mode']=='apply','ACTIVATION_MODE');return activate(payload['expected'],config,stream)
 finally:os.close(fd)

def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['plan','apply','report']);p.add_argument('--release',type=Path,required=True)
 p.add_argument('--host-release',type=Path,required=True);p.add_argument('--expected-plan-hash',default='');a=p.parse_args()
 for d in [a.release,a.host_release]:need(d.resolve(strict=True).is_relative_to(Path('C:/Workspace/artifacts').resolve()),'ARTIFACT_PATH')
 r=json.loads((a.release/'ACTIVATION_RELEASE.json').read_text());files=['p7u_post_web_activation.py','p7u_web_flash_trial.py','p7u_host_integrity.py']
 need(sha(Path(__file__).read_bytes())==r['files']['p7u_post_web_activation.py'],'ACTIVATION_HELPER_NOT_QUALIFIED')
 checks=json.loads(subprocess.check_output(['gh','api','repos/analienx/Zigbee-Coordinator/commits/'+r['source_sha']+'/check-runs?per_page=100']))['check_runs']
 need(any(c['name']=='activation-boundaries' and c['conclusion']=='success' for c in checks),'ACTIVATION_HOSTED_QUALIFICATION')
 for name in files:need(sha((a.release/name).read_bytes())==r['files'][name],'COMPANION_HASH')
 host=json.loads((a.host_release/'RELEASE.json').read_text());profile=host['profiles']['diagnostic']
 need(host['source_sha']==HOST_SOURCE and profile['image_id']==IMAGE and profile['image_archive_sha256']==ARCHIVE_SHA,'HOST_RELEASE_BINDING')
 d=a.host_release/'p7u_r4_native_host';config=(d/'config.yaml').read_bytes();transformed_config(config)
 if a.mode=='apply':
  with (d/'image.docker.tar').open('rb') as f:need(hashlib.file_digest(f,'sha256').hexdigest()==ARCHIVE_SHA,'LOCAL_IMAGE_INTEGRITY')
 payload={'mode':a.mode,'expected':a.expected_plan_hash,'config_b64':base64.b64encode(config).decode()}
 # Execute sealed modules in memory. Binary stdin is exclusively the pinned
 # prebuilt image; no shell command or arbitrary target comes from payload.
 code='import sys,types,base64\n'
 for name in files[1:]:
  module=Path(name).stem;encoded=base64.b64encode((a.release/name).read_bytes()).decode()
  code+=f"m=types.ModuleType({module!r});sys.modules[{module!r}]=m;exec(base64.b64decode({encoded!r}),m.__dict__)\n"
 code+='PAYLOAD='+repr(payload)+'\n'
 code+='exec(base64.b64decode('+repr(base64.b64encode((a.release/files[0]).read_bytes()).decode())+'),{\'__name__\':\'remote_activation\',\'PAYLOAD\':PAYLOAD})\n'
 # Frame source over stdin as well, avoiding Windows command-line limits.
 bootstrap="import sys;size=int(sys.stdin.buffer.readline(16));assert 0<size<262144;source=sys.stdin.buffer.read(size);assert len(source)==size;exec(source)"
 command='python3 -c '+shlex.quote(bootstrap)
 proc=subprocess.Popen(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','ha',command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 def send():
  try:
   source=code.encode();need(len(source)<262144,'SOURCE_FRAME_SIZE')
   proc.stdin.write(str(len(source)).encode()+b'\n'+source);proc.stdin.flush()
   if a.mode=='apply':
    with (d/'image.docker.tar').open('rb') as f:
     while blob:=f.read(1024*1024):proc.stdin.write(blob)
  except BrokenPipeError:pass
  finally:proc.stdin.close()
 sender=threading.Thread(target=send,daemon=True);sender.start()
 for line in proc.stdout:print(line.decode(errors='replace'),end='',flush=True)
 code=proc.wait(timeout=900);sender.join(timeout=2)
 need(code==0,'REMOTE_ACTIVATION_UNCONFIRMED_NO_RETRY')

if __name__=='__main__':main()
elif 'PAYLOAD' in globals():print(json.dumps(remote(PAYLOAD,sys.stdin.buffer),sort_keys=True),flush=True)
