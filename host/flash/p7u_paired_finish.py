"""Finish source-bound READY verification; never reset or repeat startup."""
import os,time,struct
from f2_progress_contract import FIELDS,valid_progress,valid_congestion

def capture_progress(raw,nonce):
    minor = raw[157] if len(raw) in (240,248) else None
    if not (minor in (3,4) and len(raw)==(248 if minor==4 else 240) and
            raw[:5]==b'R4D4\x04' and int.from_bytes(raw[6:8],'little')==len(raw) and
            raw[132:140]==nonce and int.from_bytes(raw[28:32],'little')>0):
        raise ValueError('PAIRED_F2_NONCE_OR_FRAME')
    progress=dict(zip(FIELDS,struct.unpack('<20I',raw[160:240])))
    if not valid_progress(progress):raise ValueError('PAIRED_F2_PROGRESS_SHAPE')
    result={'sequence':int.from_bytes(raw[28:32],'little'),'minor':minor,'uartProgress':progress}
    if minor==4:
        get=lambda offset:int.from_bytes(raw[offset:offset+4],'little')
        congestion=dict(zip(('srspQueuedBytes','asyncQueuedBytes','srspBytesHighWater',
            'asyncBytesHighWater','maxSrspQueueAgeTicks','maxAsyncQueueAgeTicks',
            'maxReadyServiceGapTicks'),map(get,(140,144,148,152,240,128,244))))
        if get(12)!=0x1ffffff or not valid_congestion(congestion):
            raise ValueError('PAIRED_F2_CONGESTION_SHAPE')
        result['congestion']=congestion
    return result

def finish(ns,package,package_pin,plan_pin,ha):
    from p7u_paired_hold import verified_pair_package
    ns['sealed_tree'](package,'PACKAGE.json',package_pin)
    writer=verified_pair_package(ns,plan_pin);p=ns['verified_write'](writer,plan_pin)
    oldroot=ns['PRIVATE']/'guarded-startup-recovery'
    ns['private_root'](oldroot);prior=ns['load'](oldroot/'startup-result.json')
    need=ns['need'];need(prior['status']=='FAILED_STOP_NO_RETRY' and prior['ready_observed'] is True and
        prior['failure_category']=='READY_OBSERVED_VERIFICATION_INCOMPLETE','FINISH_NATIVE_NOT_READONLY_READY')
    ns['modules'](package)
    from p7u_r4_startup_observer import decode_e1
    from p7u_r4_startup_transport import FramedZnp,PrivateEvidenceJournal,observe_after_srsp
    info=decode_e1(bytes.fromhex(prior['frames']['B1E1']),ns['SOURCE'])
    need(info['state']==4 and info['first_error']==0 and info['flags']&7==7,'FINISH_NATIVE_PRIOR_NOT_READY')
    failed=ha.inspect();need(not failed['running'] and failed['image']==ns['IMAGE'] and
        failed==ns['load'](oldroot/'intent.json')['failed_owner'],'FINISH_NATIVE_OWNER_CHANGED')
    ha.policy();ha.proof(False);need(ha.management()==p['management_sha256'],'FINISH_NATIVE_BOARD')
    root=ns['PRIVATE']/'terminal-readonly-finish'
    need(not root.exists(),'FINISH_NATIVE_CONSUMED');root.mkdir(mode=0o700)
    ns['durable'](root,'intent.json',{'plan_sha256':plan_pin,'package_pin':package_pin,
        'prior_result_sha256':ns['file_sha'](oldroot/'startup-result.json'),
        'failed_owner':failed,'reset_authorized':False,'startup_authorized':False,'at':time.time()})
    port=None;evidence=None
    try:
        port=ns['StartupSerial']();znp=FramedZnp(port,source=ns['SOURCE'])
        nonce=os.urandom(8)
        progress=capture_progress(znp.request(1,242,nonce,deadline=time.monotonic()+10),nonce)
        ns['durable'](root,'f2-v43-live.json',progress)
        evidence=PrivateEvidenceJournal(root/'terminal-evidence.jsonl',ns['SOURCE'])
        os.chmod(root/'terminal-evidence.jsonl',0o600)
        result=observe_after_srsp(znp,ns['SOURCE'],time.monotonic(),absolute_seconds=60,save=evidence)
        ns['durable'](root,'terminal-result.json',result)
        need(result['status']=='COORDINATOR_STATE9_MARKER_PASS','FINISH_NATIVE_TERMINAL_NOT_PROVEN')
    finally:
        if evidence is not None:evidence.close()
        if port is not None:port.close()
    ha.policy();ha.proof(False)
    ns['durable'](root,'host-start-intent.json',{'at':time.time(),'attempts':1})
    ha.owner_action('start');owner=ha.inspect()
    need(owner['running'] and owner['image']==ns['IMAGE'] and owner!=failed,'FINISH_NATIVE_NEW_OWNER')
    ha.proof(True)
    ns['durable'](ns['PRIVATE'],'started-pending-serving.json',{'source':ns['SOURCE'],'owner':owner,'at':time.time()})
    return {'status':'NATIVE_STATE9_AND_F2_V43_VERIFIED_HOST_STARTED_PENDING_SERVING','source':ns['SOURCE']}
