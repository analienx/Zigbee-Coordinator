"""Named one-attempt P7U web-flash trial, authorized in the current user chat.

Fixed board, file hash, two-region scope, original host epoch and web routes.
No reset/flash CLI, transport switch, NV restore or normal host start exists.
An ambiguous request is consumed. A displayed vendor DONE is not acceptance.
"""
import argparse,base64,gzip,hashlib,io,json,os,re,subprocess,tarfile,threading,time,zipfile
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler

ROOT=Path('/share/p7u-web-trial-20261024-323949a')
ORIGINAL='45df7312_zigbee2mqtt'
GUARD='local_p7u_recovery'
INSPECTOR='local_p7u_r4_owner_inspector'
PORT='/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00'
CONTAINER='8d0ef31410b1ce97f788c2705a832609a0da35ce79f10125bb869d910538adfd'
IMAGE_SHA='82c63645fd64e1d17074826d798d5d0f1b01e9bdb5d5a61891aa235c66afd255'
RADIO_SOURCE='323949a95c9a07901c4ffc3d026fca414982c148'
UI_SHA='3414b5c9a1ff3abb62350bba47ed462b46cfe4e5be52fa362ed8e645f773bb23'
API_SHA='2d50552d71bf55f8f87aeabece9f4dae01d589d9e2e88699ec0b15e8e8e600ed'
FLASH_ROUTE='/api2?action=6&local=1&fwVer=-1&fwType=0&baud=0&fwCh=2&eraseNVM=0'
DATA=Path('/config/zigbee2mqtt')
SLOTS=[ORIGINAL,'local_p7u_r4_native_host','local_p7u_r4_fallback','local_p7u_r4_lifecycle_manager','local_p7u_preservation_probe']

def need(ok,why):
 if not ok:raise RuntimeError('WEB_TRIAL_HOLD_'+why)
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(x):return (json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode()
def regular(p,limit=64*1024*1024):
 need(p.is_file() and not p.is_symlink() and p.stat().st_size<=limit,'FILE_UNSAFE')
 b=p.read_bytes();need(len(b)<=limit,'FILE_SIZE');return b
def unique(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def intent(name,extra=None):
 unique(ROOT/(name+'.intent.json'),canonical({'utc':time.time(),'image_sha256':IMAGE_SHA,**(extra or {})}))
 print(json.dumps({'phase':name,'utc':time.time()}),flush=True)
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise RuntimeError('WEB_TRIAL_REDIRECT_DENIED')
def request(origin,path,*,method='GET',data=None,content_type=None,timeout=20,limit=1024*1024):
 if origin=='ha':
  writes={('/addons/'+GUARD+'/options','POST'),('/addons/'+ORIGINAL+'/stop','POST'),('/addons/'+INSPECTOR+'/start','POST')}
  if method!='GET':need((path,method) in writes,'UNAPPROVED_HA_MUTATION')
  else:
   reads={'/addons/'+s+'/info' for s in SLOTS+[GUARD,INSPECTOR]}
   reads.update('/core/api/states/'+e for e in ['automation.boot_deterministic_emqx_then_zigbee2mqtt','automation.zigbee2mqtt_mesh_communication_outage_alert'])
   need(path in reads,'HA_READ_ROUTE')
  url='http://supervisor'+path;headers={'Authorization':'Bearer '+os.environ['SUPERVISOR_TOKEN']}
 else:
  need(origin=='slzb','ORIGIN')
  safe=['/ha_info','/ha_sensors','/js/functions.js','/js/httpApi.js','/api2?action=5','/api2?action=14&param=4&dir=%2Ffw.bin','/api2?action=14&param=1&dir=%2Ffw.bin']
  need((method=='GET' and path in safe) or (method=='GET' and path==FLASH_ROUTE) or
       (method=='POST' and path=='/fileUpload?customName=/fw.bin'),'UNAPPROVED_SLZB_ROUTE')
  url='http://192.168.50.59'+path;headers={}
 if content_type:headers['Content-Type']=content_type
 with build_opener(NoRedirect()).open(Request(url,data=data,headers=headers,method=method),timeout=timeout) as r:
  need(r.status==200,'HTTP_STATUS');b=r.read(limit+1)
 need(len(b)<=limit,'HTTP_SIZE')
 return b
def api(path,body=None):
 b=request('ha',path,method='POST' if body is not None else 'GET',data=canonical(body) if body is not None else None,content_type='application/json')
 j=json.loads(b)
 if path.startswith('/core/api/'):return j
 need(j.get('result')=='ok','HA_NOT_ACKNOWLEDGED');return j.get('data')
def addon(slug):return api('/addons/'+slug+'/info')
def command(argv,timeout=30):
 p=subprocess.run(argv,capture_output=True,timeout=timeout)
 need(p.returncode==0,'COMMAND_FAILED');return p.stdout
def inspect(name):
 p=subprocess.run(['docker','inspect',name],capture_output=True,timeout=15)
 if p.returncode:need(b'No such' in p.stderr or b'no such' in p.stderr,'DOCKER_UNKNOWN');return None
 return json.loads(p.stdout)[0]
def inventory(raw):
 rows=[json.loads(l) for l in raw.decode().splitlines()];ids=[x['id'] for x in rows]
 need(len(set(ids))==len(ids) and sum(r.get('type')=='Coordinator' for r in rows)==1,'DB_SHAPE')
 identities=sorted(r['ieeeAddr'].lower() for r in rows if r.get('ieeeAddr'))
 need(len(identities)==len(set(identities))==107,'ORIGINAL_INVENTORY')
 return {'devices':len(identities),'rows':len(rows),'inventory_sha256':sha(('\n'.join(identities)+'\n').encode())}
def board():
 j=json.loads(request('slzb','/ha_info'))['Info']
 need(j['model']=='SLZB-06p7U' and j['MAC'].lower()=='70:af:09:a5:dc:30' and j['hw_version']==173 and
      j['coord_mode']==2 and j['sw_version']=='v3.4.3.dev1','BOARD_IDENTITY')
 return j
def passive():
 a=addon(GUARD);c=inspect('app_'+GUARD);o=a['options']
 need(a['state']=='started' and c and c['State']['Running'] and
      c['Image']=='sha256:ffc989d9669e671d9a0199282b9b9074cb899dfdda9acd050f5907177aca7bb9','GUARD_EPOCH')
 for k,v in [('enabled',False),('dry_run',True),('serial_owner_approved',False),('allow_private_http_fallback',False)]:need(o[k] is v,'GUARD_NOT_PASSIVE')
 return o
def snapshot(in_maintenance=False):
 b=board();need(b['zb_version']==20260311,'STOCK_BASELINE')
 for route,pin in [('/js/functions.js',UI_SHA),('/js/httpApi.js',API_SHA)]:
  raw=request('slzb',route)
  if raw.startswith(b'\x1f\x8b'):raw=gzip.decompress(raw)
  need(sha(raw)==pin,'WEB_CODE_CHANGED');time.sleep(1.05)
 slots={}
 for slug in SLOTS:
  a=addon(slug);c=inspect('app_'+slug)
  need(a['boot']=='manual' and a['watchdog'] is False and a['auto_update'] is False,'AUTOSTART_OR_UPDATE')
  need(a['state']=='started' if slug==ORIGINAL else a['state'] in ['error','stopped'],'HOST_STATE')
  if slug==ORIGINAL:need(c and c['State']['Running'] and c['Id']==CONTAINER and a['version']=='2.14.0-1','STOCK_OWNER_EPOCH')
  else:need(c is None or not c['State']['Running'],'OTHER_HOST_ACTIVE')
  slots[slug]={'container_id':c['Id'] if c else None,'options_sha256':sha(canonical(a['options']))}
 for entity in ['automation.boot_deterministic_emqx_then_zigbee2mqtt','automation.zigbee2mqtt_mesh_communication_outage_alert']:
  s=api('/core/api/states/'+entity);need(s['state']=='off' and s['attributes']['current']==0,'COMPETING_STARTER')
 guard=passive();need(guard['maintenance'] is in_maintenance and guard['firmware_flash_active'] is in_maintenance,'EXISTING_MAINTENANCE')
 status=json.loads(command(['docker','exec','app_'+GUARD,'python','-c',"from pathlib import Path;print(Path('/data/status.json').read_text())"]))
 need(status['resets_enabled'] is False,'GUARD_RESETS_ENABLED')
 if not in_maintenance:need(0<=time.time()-status['utc']<65 and status['ota_active'] is False and status['ota_unknown'] is False,'OTA_OR_GUARD_STATUS')
 # A large standard backup response can overflow the guard's bounded log
 # window. The continuation below is restricted to this exact pre-flash HOLD,
 # with both maintenance inhibitors still set and no physical action begun.
 normalized_guard=dict(guard);normalized_guard.update(maintenance=False,firmware_flash_active=False)
 need(Path(PORT).exists() and not (DATA/'database.db.tmp').exists(),'USB_OR_DB_TEMP')
 return {'schema':'p7u-web-flash-trial-plan-v1','radio_source_sha':RADIO_SOURCE,'image_sha256':IMAGE_SHA,
  'container_id':CONTAINER,'board_mac':'70:af:09:a5:dc:30','os_version':'v3.4.3.dev1','stock_version':20260311,
  'serial_by_id':PORT,'slots':slots,'guard_options_sha256':sha(canonical(normalized_guard)),
  'inventory':inventory(regular(DATA/'database.db')),'flash_route':FLASH_ROUTE,'erase_nvm':False,
  'trial_of_unqualified_backend_explicitly_authorized':True,'authorization':'Direct user chat: Go and try it'}
def archive(name):
 output=io.BytesIO();hashes={}
 with tarfile.open(fileobj=output,mode='w:gz') as tar:
  for filename in ['database.db','coordinator_backup.json','configuration.yaml','state.json','.p7u-approved.json']:
   p=DATA/filename
   if not p.exists():continue
   raw=regular(p);entry=tarfile.TarInfo(filename);entry.size=len(raw);entry.mode=0o600
   tar.addfile(entry,io.BytesIO(raw));hashes[filename]=sha(raw)
 raw=output.getvalue();unique(ROOT/name,raw)
 return {'sha256':sha(raw),'files':hashes}

BACKUP_SCRIPT=r'''
import base64,json,sys,threading,uuid,os
from pathlib import Path
from mqtt_settings import load_broker_settings
import paho.mqtt.client as mqtt
b=load_broker_settings(Path('/homeassistant/zigbee2mqtt/configuration.yaml'))
transaction='p7u-web-trial-'+uuid.uuid4().hex;done=threading.Event();answer=[]
c=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,client_id=transaction,reconnect_on_failure=False)
if b.username:c.username_pw_set(b.username,b.password)
def connected(client,userdata,flags,reason,properties):
 if reason.is_failure:done.set();return
 client.subscribe(b.base_topic+'/bridge/response/backup',qos=1)
def subscribed(client,userdata,mid,reason,properties):client.publish(b.base_topic+'/bridge/request/backup',json.dumps({'transaction':transaction}),qos=1,retain=False)
def message(client,userdata,msg):
 if msg.retain or len(msg.payload)>16*1024*1024:return
 try:j=json.loads(msg.payload)
 except ValueError:return
 if j.get('transaction')!=transaction:return
 if j.get('status')=='ok':answer.append(base64.b64decode(j['data']['zip'],validate=True))
 done.set()
c.on_connect=connected;c.on_subscribe=subscribed;c.on_message=message
c.connect(b.host,b.port,keepalive=15);c.loop_start()
try:
 if not done.wait(65) or len(answer)!=1:sys.exit(2)
 os.write(sys.stdout.fileno(),answer[0])
finally:c.disconnect();c.loop_stop()
'''
def fresh_backup():
 before=json.loads(regular(DATA/'coordinator_backup.json'))
 intent('network-backup')
 p=subprocess.run(['docker','exec','app_'+GUARD,'python','-c',BACKUP_SCRIPT],capture_output=True,timeout=80)
 if p.returncode:
  unique(ROOT/'network-backup.private.error',p.stderr);need(False,'NETWORK_BACKUP_UNCONFIRMED')
 blob=p.stdout
 need(0<len(blob)<=12*1024*1024,'BACKUP_SIZE');unique(ROOT/'fresh-owner-backup.zip',blob)
 with zipfile.ZipFile(io.BytesIO(blob)) as z:
  names=[n for n in z.namelist() if n.endswith('coordinator_backup.json')]
  need(len(names)==1 and z.getinfo(names[0]).file_size<4*1024*1024,'BACKUP_COORDINATOR_FILE')
  after=json.loads(z.read(names[0]))
 for k in ['coordinator_ieee','pan_id','extended_pan_id','channel']:need(after[k]==before[k],'BACKUP_IDENTITY_CHANGED')
 need(after['network_key']['key']==before['network_key']['key'] and
      after['network_key']['frame_counter']>=before['network_key']['frame_counter'],'BACKUP_KEY_OR_COUNTER')
 return {'zip_sha256':sha(blob),'identity_matches':True,'key_matches':True,'counter_monotonic':True,'utc':time.time()}
def zero_holders():
 proofs=[]
 for _ in range(3):
  a=addon(INSPECTOR);old=inspect('app_'+INSPECTOR)
  need(a['state']!='started' and a['protected'] is False and a['host_pid'] is True,'INSPECTOR_POLICY')
  api('/addons/'+INSPECTOR+'/start',{})
  for tick in range(40):
   time.sleep(.3)
   if addon(INSPECTOR)['state']!='started':break
  c=inspect('app_'+INSPECTOR)
  need(c and not c['State']['Running'] and c['State']['ExitCode']==0 and c['Image']=='sha256:ce5c229254f0863d2f51a0655bb5dac9a40d97992fd28764ace521177f708865' and (not old or c['Id']!=old['Id']),'INSPECTOR_EPOCH')
  raw=command(['docker','logs',c['Id']]);records=[]
  for line in raw.decode().splitlines():
   try:j=json.loads(line)
   except ValueError:continue
   if j.get('schema')=='p7u-host-tty-cgroup-evidence-v2':records.append(j)
  need(records,'INSPECTOR_RESULT');r=records[-1]
  need(r['exclusive_owner_verified'] is True and r['serial_opened'] is False and r['tty_holders_pids']==[],'UART_NOT_RELEASED')
  proofs.append({'container_id':c['Id'],'utc':time.time(),'result':r})
 return proofs
def image(blob):need(type(blob) is bytes and len(blob)==204830 and sha(blob)==IMAGE_SHA and blob[:6]==b'\x01\x02SLZB','FIXED_IMAGE')
def multipart(blob):
 image(blob);boundary='p7u-web-trial-82c63645fd64e1d1'
 return (b'--'+boundary.encode()+b'\r\nContent-Disposition: form-data; name="update"; filename="upload.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'+blob+b'\r\n--'+boundary.encode()+b'--\r\n','multipart/form-data; boundary='+boundary)
def flash_events(ready,finished,out):
 try:
  with build_opener(NoRedirect()).open(Request('http://192.168.50.59/events',headers={'Accept':'text/event-stream'}),timeout=360) as r:
   ready.set();event='';data=[];deadline=time.monotonic()+330
   while time.monotonic()<deadline:
    line=r.readline(2049)
    if not line:break
    need(len(line)<=2048,'SSE_LINE_LIMIT');s=line.decode(errors='replace').rstrip('\r\n')
    if s.startswith('event:'):event=s[6:].strip()
    elif s.startswith('data:'):data.append(s[5:].strip())
    elif not s:
     if event in ['ZB_FW_prgs','ZB_FW_info','ZB_FW_done','ZB_FW_err']:
      out.append({'event':event,'data':'\n'.join(data)[:1000],'utc':time.time()})
      if event=='ZB_FW_prgs' and re.fullmatch(r'[0-9.]{1,7}',''.join(data)):
       print(json.dumps({'phase':'vendor-flash-progress','percent':''.join(data)}),flush=True)
      if event in ['ZB_FW_done','ZB_FW_err']:finished.set();break
     event='';data=[]
 except Exception:out.append({'event':'SSE_OBSERVATION_LOST','utc':time.time()})
 finally:ready.set()

def after_backup(plan,blob,result):
 intent('stop-original',{'container_id':CONTAINER});api('/addons/'+ORIGINAL+'/stop',{})
 c=inspect('app_'+ORIGINAL);need(c and c['Id']==CONTAINER and not c['State']['Running'],'ORIGINAL_STOP_UNCONFIRMED')
 for slug in SLOTS:need(addon(slug)['state'] in ['stopped','error'],'HOST_STILL_ACTIVE')
 db=regular(DATA/'database.db');need(inventory(db)==plan['inventory'] and not (DATA/'database.db.tmp').exists(),'QUIESCED_INVENTORY_CHANGED')
 result['post_stop_archive']=archive('quiesced-stock.tar.gz');result['quiesced_database_sha256']=sha(db)
 unique(ROOT/'stock-container.json',canonical(c));unique(ROOT/'stock.private.log',command(['docker','logs','--tail','200',CONTAINER]))
 proofs=zero_holders();unique(ROOT/'pre-flash-owner-proofs.json',canonical(proofs));need(time.time()-proofs[0]['utc']<20,'STALE_OWNER_PROOF')
 need(board()['zb_version']==20260311,'STOCK_CHANGED_BEFORE_UPLOAD')
 body,content_type=multipart(blob);intent('upload')
 response=request('slzb','/fileUpload?customName=/fw.bin',method='POST',data=body,content_type=content_type,timeout=30)
 unique(ROOT/'upload.response',response)
 time.sleep(1.1)
 staged=request('slzb','/api2?action=14&param=1&dir=%2Ffw.bin',limit=300000)
 need(staged==blob,'STAGED_FILE_HASH_MISMATCH')
 unique(ROOT/'staged-image.result.json',canonical({'sha256':sha(staged),'bytes':len(staged)}))
 ready=threading.Event();done=threading.Event();events=[]
 reader=threading.Thread(target=flash_events,args=(ready,done,events),daemon=True);reader.start();need(ready.wait(12) and reader.is_alive(),'SSE_NOT_CONNECTED')
 need(all(addon(s)['state'] in ['stopped','error'] for s in SLOTS),'OWNER_RESTARTED')
 zero_holders();intent('flash',{'route':FLASH_ROUTE,'erase_nvm':False})
 try:response=request('slzb',FLASH_ROUTE,timeout=30);unique(ROOT/'flash.response',response);result['flash_request']='ACKNOWLEDGED'
 except Exception:result['flash_request']='AMBIGUOUS_NO_RETRY'
 done.wait(330);unique(ROOT/'flash-events.private.json',canonical(events))
 result['status']='VENDOR_DONE_NOT_YET_ACCEPTED' if any(e['event']=='ZB_FW_done' for e in events) else 'VENDOR_ERROR' if any(e['event']=='ZB_FW_err' for e in events) else 'FLASH_STATE_UNKNOWN_NO_RETRY'
 result['events']=[e['event'] for e in events];result['post_flash_owner_proofs']=zero_holders()
 need(inventory(regular(DATA/'database.db'))==plan['inventory'],'HOST_DB_CHANGED')
 result['host_inventory_preserved']=True;result['radio_nv_preservation_verified']=False

def apply(plan_hash,blob):
 image(blob);need(not ROOT.exists() and not ROOT.is_symlink(),'TRIAL_ALREADY_EXISTS_NO_REPLAY')
 plan=snapshot();need(sha(canonical(plan))==plan_hash,'STALE_PLAN')
 ROOT.mkdir(mode=0o700);unique(ROOT/'plan.json',canonical(plan));unique(ROOT/'image.bin',blob)
 result={'schema':'p7u-web-flash-trial-result-v1','plan_sha256':plan_hash,'image_sha256':IMAGE_SHA,'status':'HOLD','normal_hosts_started':False}
 try:
  result['pre_backup_archive']=archive('before-backup.tar.gz')
  options=passive();options.update(maintenance=True,firmware_flash_active=True)
  intent('maintenance');api('/addons/'+GUARD+'/options',{'options':options})
  result['network_backup']=fresh_backup();unique(ROOT/'network-backup.result.json',canonical(result['network_backup']))
  after_backup(plan,blob,result)
 except Exception as e:result['error_class']=str(e) if str(e).startswith('WEB_TRIAL_HOLD_') else type(e).__name__
 finally:
  result['utc']=time.time();unique(ROOT/'result.json',canonical(result))
 return result

def continuation_plan():
 need(ROOT.is_dir() and not ROOT.is_symlink(),'NO_EXISTING_TRIAL')
 for name in ['stop-original.intent.json','upload.intent.json','flash.intent.json','continue.intent.json','continuation.result.json']:
  p=ROOT/name;need(not p.exists() and not p.is_symlink(),'PHYSICAL_PHASE_OR_CONTINUATION_ALREADY_CONSUMED')
 old_result=regular(ROOT/'result.json');r=json.loads(old_result)
 need(r['status']=='HOLD' and r['error_class']=='WEB_TRIAL_HOLD_NETWORK_BACKUP_UNCONFIRMED','UNRELATED_HOLD')
 raw_plan=regular(ROOT/'plan.json');plan=json.loads(raw_plan)
 need(sha(raw_plan)==r['plan_sha256'] and plan==snapshot(in_maintenance=True),'ORIGINAL_TRIAL_STATE_CHANGED')
 image(regular(ROOT/'image.bin'));requested=json.loads(regular(ROOT/'network-backup.intent.json'))['utc']
 p=DATA/'coordinator_backup.json';raw=regular(p);now=json.loads(raw)
 need(p.stat().st_mtime>=requested and now['metadata']['format']=='zigpy/open-coordinator-backup','PERSISTED_BACKUP_NOT_FRESH')
 with tarfile.open(ROOT/'before-backup.tar.gz') as t:before=json.load(t.extractfile('coordinator_backup.json'))
 for k in ['coordinator_ieee','pan_id','extended_pan_id','channel']:need(now[k]==before[k],'PERSISTED_BACKUP_IDENTITY')
 need(now['network_key']['key']==before['network_key']['key'] and now['network_key']['frame_counter']>=before['network_key']['frame_counter'],'PERSISTED_BACKUP_KEY_OR_COUNTER')
 need(regular(p)==raw,'BACKUP_CHANGED_WHILE_VALIDATING')
 return {'schema':'p7u-web-trial-persisted-backup-continuation-v1','original_plan_sha256':sha(raw_plan),
         'prior_result_sha256':sha(old_result),'fresh_backup_sha256':sha(raw),'image_sha256':IMAGE_SHA,
         'source_of_backup':'CURRENT_OWNER_PERSISTED_BACKUP_AFTER_EXACT_REQUEST_NO_REISSUE'}

def continue_trial(expected,blob):
 image(blob);p=continuation_plan();need(sha(canonical(p))==expected,'STALE_CONTINUATION_PLAN')
 intent('continue',{'continuation_plan_sha256':expected});unique(ROOT/'continuation-plan.json',canonical(p))
 raw=regular(DATA/'coordinator_backup.json');need(sha(raw)==p['fresh_backup_sha256'],'FRESH_BACKUP_CHANGED')
 unique(ROOT/'fresh-owner-coordinator-backup.json',raw)
 result={'schema':'p7u-web-flash-trial-result-v1','plan_sha256':p['original_plan_sha256'],
  'continuation_plan_sha256':expected,'image_sha256':IMAGE_SHA,'status':'HOLD','normal_hosts_started':False,
  'network_backup':{'sha256':sha(raw),'identity_matches':True,'key_matches':True,'counter_monotonic':True,'reissued':False}}
 try:after_backup(json.loads(regular(ROOT/'plan.json')),blob,result)
 except Exception as e:result['error_class']=str(e) if str(e).startswith('WEB_TRIAL_HOLD_') else type(e).__name__
 finally:result['utc']=time.time();unique(ROOT/'continuation.result.json',canonical(result))
 return result
def remote(payload):
 import fcntl
 fd=os.open('/share/p7u-lifecycle/private/exclusive-manager.lock',os.O_RDWR|os.O_NOFOLLOW)
 try:
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  need(set(payload)=={'mode','expected_plan_hash','image_b64'},'PAYLOAD')
  if payload['mode']=='report':return json.loads(regular(ROOT/('continuation.result.json' if (ROOT/'continuation.result.json').exists() else 'result.json')))
  if payload['mode']=='continue-plan':
   p=continuation_plan();return {'status':'CONTINUATION_PLAN_NO_MUTATION','plan_hash':sha(canonical(p)),'plan':p}
  if payload['mode']=='continue':return continue_trial(payload['expected_plan_hash'],base64.b64decode(payload['image_b64'],validate=True))
  need(payload['mode'] in ['plan','apply'] and not ROOT.exists(),'MODE_OR_CONSUMED')
  if payload['mode']=='plan':
   p=snapshot();return {'status':'PLAN_NO_MUTATION','plan_hash':sha(canonical(p)),'plan':p}
  return apply(payload['expected_plan_hash'],base64.b64decode(payload['image_b64'],validate=True))
 finally:os.close(fd)
def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['plan','apply','report','continue-plan','continue']);p.add_argument('--release',type=Path,required=True);p.add_argument('--expected-plan-hash',default='')
 a=p.parse_args();d=a.release.resolve(strict=True);need(d.is_relative_to(Path('C:/Workspace/artifacts').resolve()),'ARTIFACT_PATH')
 receipt=json.loads((d/'WEB_TRIAL_RELEASE.json').read_text());need(sha(Path(__file__).read_bytes())==receipt['helper_sha256'],'HELPER_NOT_QUALIFIED')
 checks=json.loads(subprocess.check_output(['gh','api','repos/analienx/Zigbee-Coordinator/commits/'+receipt['source_sha']+'/check-runs?per_page=100']))['check_runs']
 need(any(c['name']=='trial-boundaries' and c['conclusion']=='success' for c in checks),'HOSTED_QUALIFICATION')
 blob=(d/'image.bin').read_bytes();image(blob)
 payload={'mode':a.mode,'expected_plan_hash':a.expected_plan_hash,'image_b64':base64.b64encode(blob).decode() if a.mode in ['apply','continue'] else ''}
 source=Path(__file__).read_text()
 run=subprocess.Popen(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','ha','python3','-'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 run.stdin.write('PAYLOAD='+repr(payload)+'\n'+source);run.stdin.close()
 for line in run.stdout:print(line,end='',flush=True)
 code=run.wait(timeout=600)
 need(code==0,'REMOTE_UNCONFIRMED_NO_RETRY')

if __name__=='__main__':
 if 'PAYLOAD' in globals():print(json.dumps(remote(PAYLOAD),sort_keys=True),flush=True)
 else:main()
