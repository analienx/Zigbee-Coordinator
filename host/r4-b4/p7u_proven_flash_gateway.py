"""Fixed control-plane for the user-authorized proven-writer redeployment.

The writer remains the existing independently qualified ROM transaction.
No web custom upload, automatic fallback, NV restore or generic shell route.
Each control action has one durable intent. Prior operations are preserved.
"""
import argparse,base64,gzip,hashlib,json,os,shlex,subprocess,sys,time
from pathlib import Path
from urllib.parse import urlencode
import p7u_web_flash_trial as t

ROOT=Path('/share/p7u-proven-reflash-20261024-323949a')
t.ROOT=ROOT
t.CONTAINER='17ac9da1f95793391c0b7f10cc510db865b369a8155f55d478329332ee56970d'
TARGET='local_p7u_r4_native_host'
IMAGE='sha256:1b1bdc9497873401ee509e22965f5a7e2519056b21daca5bbcf2288e4fde2175'
MANIFEST=t.DATA/'.p7u-approved-web-trial-20261024.json'
need=t.need
sha=t.sha
canonical=t.canonical
regular=t.regular
unique=t.unique

def control(path,body):
 need((path,body)==('/addons/'+TARGET+'/start',{}),'PROVEN_CONTROL_ROUTE')
 req=t.Request('http://supervisor'+path,method='POST',data=canonical(body),headers={'Authorization':'Bearer '+os.environ['SUPERVISOR_TOKEN'],'Content-Type':'application/json'})
 with t.build_opener(t.NoRedirect()).open(req,timeout=30) as r:j=json.load(r)
 need(j.get('result')=='ok','PROVEN_CONTROL_ACK');return j.get('data')

def fixed_vendor(action):
 # The three exact payloads are derived from this board's current form.
 # oUsbMod=0 and keepWeb=on are preserved. No Wi-Fi settings are touched.
 if action in ['ethernet','usb']:
  data=urlencode({'pageId':'1','coordMode':'0' if action=='ethernet' else '2','keepWeb':'on','oUsbMod':'0'}).encode()
  req=t.Request('http://192.168.50.59/settings/saveParams',data=data,method='POST',headers={'Content-Type':'application/x-www-form-urlencoded'})
 elif action in ['bsl-capture','bsl-program','boot']:
  req=t.Request('http://192.168.50.59/api2?action=4&cmd='+('1' if action=='boot' else '2'))
 else:need(False,'PROVEN_VENDOR_ACTION')
 with t.build_opener(t.NoRedirect()).open(req,timeout=12) as r:raw=r.read(4097)
 need(len(raw)<=4096,'PROVEN_VENDOR_SIZE')
 if action in ['bsl-capture','bsl-program','boot']:need(raw.strip()==b'ok','PROVEN_VENDOR_ACK')
 return {'response_sha256':sha(raw),'acknowledged':True}

def board(mode):
 j=json.loads(t.request('slzb','/ha_info'))['Info']
 need(j['model']=='SLZB-06p7U' and j['MAC'].lower()=='70:af:09:a5:dc:30' and j['hw_version']==173 and
      j['sw_version']=='v3.4.3.dev1' and j['coord_mode']==mode and j['wifi_mode']==0,'PROVEN_BOARD_IDENTITY_OR_MODE')
 return j

def inactive():
 for s in t.SLOTS:
  a=t.addon(s);c=t.inspect('app_'+s)
  need(a['state'] in ['stopped','error'] and a['boot']=='manual' and a['watchdog'] is False and
       a['auto_update'] is False and (not c or not c['State']['Running']),'PROVEN_OWNER_ACTIVE')
 o=t.passive();need(o['maintenance'] is True and o['firmware_flash_active'] is True,'PROVEN_MAINTENANCE_LOST')

def form():
 with t.build_opener(t.NoRedirect()).open('http://192.168.50.59/api2?action=0&page=1',timeout=10) as r:
  raw=r.read(300001);values=json.loads(r.headers['respValuesArr'])
 need(len(raw)<=300000,'FORM_SIZE')
 if raw.startswith(b'\x1f\x8b'):raw=gzip.decompress(raw)
 text=raw.decode();start=text.rfind('<form',0,text.index('name="coordMode"'));stop=text.index('</form>',start)+7
 snippet=text[start:stop]
 fields=t.re.findall(r'<(?:input|select)[^>]*\bname="([^"]+)"',snippet)
 need(set(fields)=={'coordMode','keepWeb','oUsbMod'} and
      'action="/settings/saveParams"' in snippet and
      str(values.get('keepWeb')).lower()=='true' and values.get('oUsbMod1_hw') is True,'UNEXPECTED_MODE_FORM')
 return {'form_sha256':sha(snippet.encode()),'keep_web':True,'usb_hardware_connection':True}

def preflight():
 need(not ROOT.exists() and not ROOT.is_symlink(),'PROVEN_OPERATION_ALREADY_EXISTS')
 p=t.snapshot(in_maintenance=True);a=t.addon(TARGET)
 need(a['version']=='0.2.1-9d13e8ce6419','VERIFIED_DEBUG_HOST_NOT_INSTALLED')
 for route,pin in [('/js/functions.js',t.UI_SHA),('/js/httpApi.js',t.API_SHA)]:
  raw=t.request('slzb',route)
  if raw.startswith(b'\x1f\x8b'):raw=gzip.decompress(raw)
  need(sha(raw)==pin,'VENDOR_SOURCE_CHANGED')
 return {'schema':'p7u-proven-reflash-plan-v1','snapshot':p,'mode_form':form(),
         'debug_image_id':IMAGE,'existing_manifest_sha256':sha(regular(MANIFEST)),
         'failed_web_operation_preserved':sha(regular(Path('/share/p7u-debug-after-web-20261024/result.json'))),
         'firmware_source':t.RADIO_SOURCE,'writer':'r4_stock20260311_transition.py; unchanged bytewise verification',
         'authorization':'Direct user request: reflash custom using method that worked; prepare automated stock recovery',
         'quiesce_budget':1,'capture_entry_budget':1,'program_entry_budget':1,'boot_budget':1,'debug_start_budget':1}

def quiesce(expected):
 plan=preflight();need(sha(canonical(plan))==expected,'STALE_PROVEN_PLAN')
 ROOT.mkdir(mode=0o700);unique(ROOT/'plan.json',canonical(plan))
 result={'status':'HOLD','radio_touched':False}
 try:
  t.archive('before-stop.tar.gz')
  before=json.loads(regular(t.DATA/'coordinator_backup.json'))
  try:t.fresh_backup()
  except Exception:
   # Reconcile only the freshly persisted file from this exact request.
   requested=json.loads(regular(ROOT/'network-backup.intent.json'))['utc']
   need((t.DATA/'coordinator_backup.json').stat().st_mtime>=requested,'FRESH_BACKUP_MISSING_NO_REISSUE')
  now=json.loads(regular(t.DATA/'coordinator_backup.json'))
  for key in ['coordinator_ieee','pan_id','extended_pan_id','channel']:need(now[key]==before[key],'BACKUP_IDENTITY_CHANGED')
  need(now['network_key']['key']==before['network_key']['key'] and now['network_key']['frame_counter']>=before['network_key']['frame_counter'],'BACKUP_SECURITY_CHANGED')
  unique(ROOT/'fresh-owner-backup.json',regular(t.DATA/'coordinator_backup.json'))
  t.intent('stop-original',{'container_id':t.CONTAINER})
  try:t.api('/addons/'+t.ORIGINAL+'/stop',{})
  except Exception:pass  # Never resend. Reconcile the known container only.
  deadline=time.monotonic()+120
  while time.monotonic()<deadline:
   c=t.inspect('app_'+t.ORIGINAL)
   if not c or not c['State']['Running']:break
   need(c['Id']==t.CONTAINER,'ORIGINAL_EPOCH_CHANGED');time.sleep(2)
  inactive();proofs=t.zero_holders();unique(ROOT/'pre-capture-owner-proofs.json',canonical(proofs))
  inv=t.inventory(regular(t.DATA/'database.db'));need(inv==plan['snapshot']['inventory'],'QUIESCED_INVENTORY_CHANGED')
  cold=t.archive('quiesced-stock.tar.gz');unique(ROOT/'quiesced-backup.json',regular(t.DATA/'coordinator_backup.json'))
  unique(ROOT/'quiesced-database.sha256',sha(regular(t.DATA/'database.db')).encode())
  result.update(status='QUIESCED_WAITING_PROVEN_ROM_WRITER',archive_sha256=cold['sha256'],inventory=inv,
                database_sha256=sha(regular(t.DATA/'database.db')),backup_sha256=sha(regular(t.DATA/'coordinator_backup.json')))
 except Exception as e:result['error_class']=str(e) if str(e).startswith('WEB_TRIAL_HOLD_') else type(e).__name__
 finally:result['utc']=time.time();unique(ROOT/'quiesce.result.json',canonical(result))
 return result

def phase_plan(action):
 need(action in ['ethernet','bsl-capture','bsl-program','boot','usb','start-debug'],'PHASE')
 r=json.loads(regular(ROOT/'quiesce.result.json'));need(r['status']=='QUIESCED_WAITING_PROVEN_ROM_WRITER','NOT_QUIESCED')
 need(not (ROOT/(action+'.intent.json')).exists(),'PROVEN_ACTION_CONSUMED')
 inactive();need(sha(regular(t.DATA/'database.db'))==r['database_sha256'],'QUIESCED_DB_CHANGED')
 board(2 if action in ['ethernet','start-debug'] else 0)
 if action!='ethernet':need((ROOT/'ethernet.result.json').is_file(),'ETHERNET_NOT_APPLIED')
 if action=='bsl-program':need((ROOT/'capture-accepted.json').is_file(),'CAPTURE_RECEIPT_REQUIRED')
 if action=='boot':need((ROOT/'flash-accepted.json').is_file(),'FLASH_PARITY_REQUIRED')
 if action=='usb':need((ROOT/'startup-accepted.json').is_file(),'COORDINATOR_STATE9_REQUIRED')
 if action=='start-debug':need((ROOT/'usb.result.json').is_file(),'USB_NOT_RESTORED')
 return {'schema':'p7u-proven-reflash-phase-v1','action':action,'quiesce_result_sha256':sha(regular(ROOT/'quiesce.result.json')),
         'database_sha256':r['database_sha256'],'mode_form':form(),'radio_source':t.RADIO_SOURCE}

def phase(action,expected):
 p=phase_plan(action);need(sha(canonical(p))==expected,'STALE_PHASE_PLAN')
 proofs=t.zero_holders();unique(ROOT/(action+'.owner-proofs.json'),canonical(proofs))
 t.intent(action,{'plan_sha256':expected})
 try:
  if action=='start-debug':result=start_debug()
  else:result=fixed_vendor(action)
  if action in ['ethernet','usb']:
   deadline=time.monotonic()+90
   while time.monotonic()<deadline:
    try:board(0 if action=='ethernet' else 2);break
    except Exception:time.sleep(2)
   board(0 if action=='ethernet' else 2)
  result.update(status='ACKNOWLEDGED_NOT_NETWORK_ACCEPTANCE',action=action,utc=time.time())
 except Exception as e:result={'status':'AMBIGUOUS_NO_RETRY','action':action,'error_class':type(e).__name__,'utc':time.time()}
 unique(ROOT/(action+'.result.json'),canonical(result));return result

def start_debug():
 original=json.loads(regular(ROOT/'plan.json'))
 need(sha(regular(MANIFEST))==original['existing_manifest_sha256'],'PREVIOUS_APPROVAL_CHANGED')
 a=t.addon(TARGET);need(a['version']=='0.2.1-9d13e8ce6419','DEBUG_VERSION_CHANGED')
 c=t.inspect('app_'+TARGET);need(c and c['Image']==IMAGE and not c['State']['Running'],'DEBUG_IMAGE_CHANGED')
 unique(ROOT/'previous-debug-container.private.json',canonical(c))
 p=subprocess.run(['docker','logs','--tail','500',c['Id']],capture_output=True,timeout=20)
 unique(ROOT/'previous-debug.private.log',(p.stdout+p.stderr)[-2*1024*1024:])
 unique(ROOT/'previous-debug-approval.json',regular(MANIFEST))
 r=json.loads(regular(ROOT/'quiesce.result.json'));raw=regular(t.DATA/'database.db');inv=t.inventory(raw)
 need(sha(raw)==r['database_sha256'] and inv==r['inventory'],'DEBUG_DATABASE_CHANGED')
 approval={'schema':'p7u-db-admission-v1','database_sha256':sha(raw),'inventory_sha256':inv['inventory_sha256'],
   'rows':inv['rows'],'devices':inv['devices'],'generation':'proven_reflash_20261024_323949a_9d13e8ce6419'}
 pending=MANIFEST.with_name(MANIFEST.name+'.proven-reflash-pending');unique(pending,canonical(approval))
 os.replace(pending,MANIFEST)
 fd=os.open(MANIFEST.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 # The earlier manifest is archived above; no old lifecycle journal changes.
 try:control('/addons/'+TARGET+'/start',{});ack=True
 except Exception:ack=False
 return {'start_acknowledged':ack,'status_detail':'START_REQUEST_CONSUMED_VERIFY_EXISTING_CONTAINER_ONLY','image_id':IMAGE}

def accept_startup(evidence):
 need(type(evidence) is dict and set(evidence)=={'source','status','post_state','attempts','startup_receipt_sha256','flash_receipt_sha256','capture_sha256','plan_sha256'} and
      evidence['source']==t.RADIO_SOURCE and evidence['status']=='COORDINATOR_STATE9_MARKER_PASS' and
      evidence['post_state']==9 and evidence['attempts']==1 and
      all(t.re.fullmatch('[a-f0-9]{64}',evidence[k]) for k in ['startup_receipt_sha256','flash_receipt_sha256','capture_sha256','plan_sha256']),
      'PHYSICAL_OPERATOR_RECEIPT_REQUIRED')
 inactive();board(0);need((ROOT/'ethernet.result.json').is_file(),'ETHERNET_REQUIRED')
 unique(ROOT/'startup-accepted.json',canonical(evidence))
 return {'status':'QUALIFIED_OPERATOR_STARTUP_RECEIPT_SEALED','source':t.RADIO_SOURCE}

def remote(payload):
 import fcntl
 fd=os.open('/share/p7u-lifecycle/private/exclusive-manager.lock',os.O_RDWR|os.O_NOFOLLOW)
 try:
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  need(set(payload)=={'mode','expected','action','evidence'},'PROVEN_PAYLOAD')
  mode=payload['mode']
  if mode=='plan':
   p=preflight();return {'status':'PLAN_NO_MUTATION','plan_hash':sha(canonical(p)),'plan':p}
  if mode=='quiesce':return quiesce(payload['expected'])
  if mode=='phase-plan':
   p=phase_plan(payload['action']);return {'status':'PHASE_PLAN_NO_MUTATION','plan_hash':sha(canonical(p)),'plan':p}
  if mode=='phase':return phase(payload['action'],payload['expected'])
  if mode=='seal-startup':return accept_startup(payload['evidence'])
  need(mode=='report','MODE');return json.loads(regular(ROOT/'quiesce.result.json'))
 finally:os.close(fd)

def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['plan','quiesce','phase-plan','phase','report','seal-startup']);p.add_argument('--release',type=Path,required=True)
 p.add_argument('--action',choices=['ethernet','bsl-capture','bsl-program','boot','usb','start-debug'],default='ethernet');p.add_argument('--expected-plan-hash',default='');a=p.parse_args()
 need(a.release.resolve(strict=True).is_relative_to(Path('C:/Workspace/artifacts').resolve()),'RELEASE_PATH')
 receipt=json.loads((a.release/'PROVEN_GATEWAY_RELEASE.json').read_text())
 files=['p7u_proven_flash_gateway.py','p7u_web_flash_trial.py']
 for name in files:need(sha((a.release/name).read_bytes())==receipt['files'][name],'GATEWAY_NOT_QUALIFIED')
 need(sha(Path(__file__).read_bytes())==receipt['files'][files[0]],'HELPER_SOURCE')
 checks=json.loads(subprocess.check_output(['gh','api','repos/analienx/Zigbee-Coordinator/commits/'+receipt['source_sha']+'/check-runs?per_page=100']))['check_runs']
 need(any(c['name']=='proven-gateway-boundaries' and c['conclusion']=='success' for c in checks),'HOSTED_QUALIFICATION')
 evidence=None
 if a.mode=='seal-startup':
  # Receipt production is the existing qualified operator, not caller JSON.
  sys.path.insert(0,str(a.release));import p7u_r4_operator as op
  for name in ['p7u_r4_operator.py','p7u_r4_startup_observer.py','p7u_r4_adapter_provision.py']:
   need(sha((a.release/name).read_bytes())==receipt['files'][name],'OPERATOR_SOURCE_BINDING')
  private=Path('C:/Workspace/.analienx/zigbee-private/p7u-r4-323949a-stock-return-20261024')
  candidate=op.candidate_verify(Path('C:/Workspace/artifacts/p7u-r4-release-323949a'),t.RADIO_SOURCE)
  startup=op.startup_verify(private,candidate)
  evidence={k:startup[k] for k in ['source','status','post_state','attempts']}
  evidence.update(startup_receipt_sha256=sha((private/'startup-result.json').read_bytes()),flash_receipt_sha256=sha((private/'flash-result.json').read_bytes()),
   capture_sha256=op.capture_verify(private)['pass1_sha256'],plan_sha256=op.prepare_verify(private,candidate)['plan_sha256'])
 payload={'mode':a.mode,'expected':a.expected_plan_hash,'action':a.action,'evidence':evidence}
 script='import sys,types,base64\nm=types.ModuleType("p7u_web_flash_trial");sys.modules[m.__name__]=m\n'
 script+='exec(base64.b64decode('+repr(base64.b64encode((a.release/files[1]).read_bytes()).decode())+'),m.__dict__)\n'
 script+='exec(base64.b64decode('+repr(base64.b64encode((a.release/files[0]).read_bytes()).decode())+'),{"__name__":"remote_proven","PAYLOAD":'+repr(payload)+'})\n'
 proc=subprocess.Popen(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','ha','python3','-'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 proc.stdin.write(script);proc.stdin.close()
 for line in proc.stdout:print(line,end='',flush=True)
 code=proc.wait(timeout=400)
 if code:
  stderr=proc.stderr.read();reasons=t.re.findall(r'WEB_TRIAL_HOLD_[A-Z_]+',stderr)
  print(json.dumps({'status':'HOLD','reasons':reasons[-2:],'remote_exit':code}),flush=True)
 need(code==0,'GATEWAY_UNCONFIRMED_NO_RETRY')

if __name__=='__main__':main()
elif 'PAYLOAD' in globals():print(json.dumps(remote(PAYLOAD),sort_keys=True),flush=True)
