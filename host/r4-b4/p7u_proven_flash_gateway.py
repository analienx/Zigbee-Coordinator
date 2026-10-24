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
 r=json.loads(regular(ROOT/'quiesce.result.json'));need(r['status']=='QUIESCED_WAITING_PROVEN_ROM_WRITER','NOT_QUIESCED')
 need(not (ROOT/(action+'.intent.json')).exists(),'PROVEN_ACTION_CONSUMED')
 inactive();need(sha(regular(t.DATA/'database.db'))==r['database_sha256'],'QUIESCED_DB_CHANGED')
 board(2 if action=='ethernet' else 0)
 need(action in ['ethernet','bsl-capture','bsl-program','boot','usb','start-debug'],'PHASE')
 if action!='ethernet':need((ROOT/'ethernet.result.json').is_file(),'ETHERNET_NOT_APPLIED')
 if action=='bsl-program':need((ROOT/'capture-accepted.json').is_file(),'CAPTURE_RECEIPT_REQUIRED')
 if action=='boot':need((ROOT/'flash-accepted.json').is_file(),'FLASH_PARITY_REQUIRED')
 if action=='usb':need((ROOT/'startup-accepted.json').is_file(),'COORDINATOR_STATE9_REQUIRED')
 if action=='start-debug':need((ROOT/'usb.result.json').is_file(),'USB_NOT_RESTORED')
 return {'schema':'p7u-proven-reflash-phase-v1','action':action,'quiesce_result_sha256':sha(regular(ROOT/'quiesce.result.json')),
         'database_sha256':r['database_sha256'],'mode_form':form(),'radio_source':t.RADIO_SOURCE}

def phase(action,expected):
 p=phase_plan(action);need(sha(canonical(p))==expected,'STALE_PHASE_PLAN')
 need(action!='start-debug','START_REQUIRES_ACCEPTED_DEPLOYMENT_SIDECAR')
 proofs=t.zero_holders();unique(ROOT/(action+'.owner-proofs.json'),canonical(proofs))
 t.intent(action,{'plan_sha256':expected})
 try:
  result=fixed_vendor(action)
  if action in ['ethernet','usb']:
   deadline=time.monotonic()+90
   while time.monotonic()<deadline:
    try:board(0 if action=='ethernet' else 2);break
    except Exception:time.sleep(2)
   board(0 if action=='ethernet' else 2)
  result.update(status='ACKNOWLEDGED_NOT_NETWORK_ACCEPTANCE',action=action,utc=time.time())
 except Exception as e:result={'status':'AMBIGUOUS_NO_RETRY','action':action,'error_class':type(e).__name__,'utc':time.time()}
 unique(ROOT/(action+'.result.json'),canonical(result));return result

def remote(payload):
 import fcntl
 fd=os.open('/share/p7u-lifecycle/private/exclusive-manager.lock',os.O_RDWR|os.O_NOFOLLOW)
 try:
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  need(set(payload)=={'mode','expected','action'},'PROVEN_PAYLOAD')
  mode=payload['mode']
  if mode=='plan':
   p=preflight();return {'status':'PLAN_NO_MUTATION','plan_hash':sha(canonical(p)),'plan':p}
  if mode=='quiesce':return quiesce(payload['expected'])
  if mode=='phase-plan':
   p=phase_plan(payload['action']);return {'status':'PHASE_PLAN_NO_MUTATION','plan_hash':sha(canonical(p)),'plan':p}
  if mode=='phase':return phase(payload['action'],payload['expected'])
  need(mode=='report','MODE');return json.loads(regular(ROOT/'quiesce.result.json'))
 finally:os.close(fd)

def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['plan','quiesce','phase-plan','phase','report']);p.add_argument('--release',type=Path,required=True)
 p.add_argument('--action',choices=['ethernet','bsl-capture','bsl-program','boot','usb','start-debug'],default='ethernet');p.add_argument('--expected-plan-hash',default='');a=p.parse_args()
 need(a.release.resolve(strict=True).is_relative_to(Path('C:/Workspace/artifacts').resolve()),'RELEASE_PATH')
 receipt=json.loads((a.release/'PROVEN_GATEWAY_RELEASE.json').read_text())
 files=['p7u_proven_flash_gateway.py','p7u_web_flash_trial.py']
 for name in files:need(sha((a.release/name).read_bytes())==receipt['files'][name],'GATEWAY_NOT_QUALIFIED')
 need(sha(Path(__file__).read_bytes())==receipt['files'][files[0]],'HELPER_SOURCE')
 checks=json.loads(subprocess.check_output(['gh','api','repos/analienx/Zigbee-Coordinator/commits/'+receipt['source_sha']+'/check-runs?per_page=100']))['check_runs']
 need(any(c['name']=='proven-gateway-boundaries' and c['conclusion']=='success' for c in checks),'HOSTED_QUALIFICATION')
 payload={'mode':a.mode,'expected':a.expected_plan_hash,'action':a.action}
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
