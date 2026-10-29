"""One-shot, source-bound USB-open-first native boot after verified programming."""
import os,time

def boot_native(ns,package,package_pin,plan_pin,ha):
    need=ns['need'];root=ns['PRIVATE']/'native-boot'
    ns['sealed_tree'](package,'PACKAGE.json',package_pin)
    p=ns['verified_write'](package,plan_pin)
    need(not (ns['PRIVATE']/'boot-intent.json').exists() and
         not (ns['PRIVATE']/'start-intent.json').exists() and not root.exists(),
         'NATIVE_BOOT_CONSUMED')
    old=ha.inspect()
    need(not old['running'] and old['image']==ns['IMAGE'],'NATIVE_BOOT_OWNER')
    ha.policy();ha.proof(False)
    need(ha.management()==p['management_sha256'],'NATIVE_BOOT_BOARD')
    entity=ha.boot_binding();ns['modules'](package)
    from p7u_r4_startup_transport import FramedZnp,PrivateEvidenceJournal
    from p7u_paired_finish import capture_progress
    root.mkdir(mode=0o700)
    ns['durable'](ns['PRIVATE'],'boot-intent.json',{'plan_sha256':plan_pin,'package_pin':package_pin,
        'source':ns['SOURCE'],'entity':entity,'operation':'USB_OPEN_FIRST_NATIVE_BOOT_ONCE',
        'at':time.time(),'attempts':1,'automatic_retry':False})
    port=None;evidence=None
    try:
        port=ns['StartupSerial']()
        znp=FramedZnp(port,source=ns['SOURCE'])
        evidence=PrivateEvidenceJournal(root/'startup-evidence.jsonl',ns['SOURCE'])
        os.chmod(root/'startup-evidence.jsonl',0o600)
        ns['durable'](root,'app-boot-intent.json',{'plan_sha256':plan_pin,
            'at':time.time(),'attempts':1,'usb_already_open':True,'consumed_before_send':True})
        ha.restart_radio()
        deadline=time.monotonic()+20
        while True:
            typ,command,data=znp._next(deadline)
            if typ==0x41 and command==0x80:
                need(len(data)==6,'NATIVE_BOOT_RESET_IND_SHAPE');break
        ns['durable'](root,'boot-ready.json',{'fresh_reset_ind':True,'no_request_before_reset_ind':True})
        result=ns['resume_pristine'](znp,root,ns['load'](ns['PRIVATE']/'owner-backup-before-stop.json'),evidence)
        need(result['status']=='COORDINATOR_STATE9_MARKER_PASS','NATIVE_BOOT_STATE9')
        nonce=os.urandom(8)
        progress=capture_progress(znp.request(1,242,nonce,deadline=time.monotonic()+20),nonce)
        need(progress['minor']==4,'NATIVE_BOOT_F2_MINOR')
        ns['durable'](root,'f2-native-live.json',progress)
    except Exception as exc:
        ns['durable'](root,'hold.json',{'phase':'NATIVE_BOOT','error_type':type(exc).__name__,
            'automatic_retry':False,'automatic_boot':False})
        raise
    finally:
        if evidence is not None:evidence.close()
        if port is not None:port.close()
    ha.policy();ha.proof(False)
    ns['durable'](ns['PRIVATE'],'start-intent.json',{'plan_sha256':plan_pin,
        'at':time.time(),'attempts':1,'consumed_before_send':True})
    ack=True
    try:ha.owner_action('start')
    except Exception:ack=False
    deadline=time.monotonic()+30;owner=None
    while time.monotonic()<deadline:
        try:owner=ha.inspect()
        except Exception:owner=None
        if owner and owner['running'] and owner['image']==ns['IMAGE'] and owner!=old:break
        time.sleep(.5)
    need(owner and owner['running'] and owner['image']==ns['IMAGE'] and owner!=old,
         'NATIVE_BOOT_HOST_START_UNKNOWN_NO_RETRY')
    ha.proof(True)
    ns['durable'](ns['PRIVATE'],'started-pending-serving.json',{'source':ns['SOURCE'],
        'owner':owner,'host_api_ack':ack,'native_state9':True,'f2_minor':4,'at':time.time()})
    return {'status':'NATIVE_STATE9_F2_MINOR4_HOST_RUNNING_PENDING_SERVING','source':ns['SOURCE'],
            'owner':owner,'host_api_ack':ack}
