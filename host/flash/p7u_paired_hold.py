"""Pinned continuation ONLY after an immutable, zero-write security HOLD.

No hardware or service mutation occurs here. The existing operator makes a new
server-generated plan, opens a new ROM session, recaptures NV and checks all88
CRCs again. It must not repeat BSL entry or reuse the consumed execution intent.
"""
import hashlib,json

NAMES={'plan.json','reader-baseline-check.json','owner-backup-before-stop.json',
       'execute-intent.json','hold.json','cold-backup.json','cold-before-flash.tar',
       'bsl-entry-intent.json','sparse-receipt.json','fresh-sparse-snapshot.bin','security-receipt.json'}
ATTACH_NAMES={'plan.json','reader-baseline-check.json','owner-backup-before-stop.json',
       'execute-intent.json','hold.json','cold-backup.json','cold-before-flash.tar','rom-reattach-intent.json'}

def absent_owner(ns,ha):
    """Supervisor removes a stopped add-on container. Prove its absence exactly."""
    need=ns['need'];name='app_'+ns['OWNER']
    p=ns['subprocess'].run(['docker','inspect',name],capture_output=True,text=True,timeout=20)
    need(p.returncode==1 and p.stdout.strip() in ('','[]') and
         p.stderr.strip().lower().endswith('no such object: '+name),'PAIRED_OWNER_ABSENCE_NOT_PROVEN')
    info=ha.info(ns['OWNER'])
    need(info['state'] in ('stopped','error') and info['version']==ns['PAIRED_HOST_VERSION'] and
         info['build'] is False and info['boot']=='manual' and info['watchdog'] is False,
         'PAIRED_ABSENT_OWNER_METADATA')
    image=json.loads(ns['run'](['docker','image','inspect',
         'localhost:50144/p7u-r4-diagnostic:'+ns['PAIRED_HOST_VERSION']]))
    need(len(image)==1 and image[0]['Id']==ns['IMAGE'],'PAIRED_ABSENT_OWNER_IMAGE')
    ha.proof(False)
    return {'id':None,'image':ns['IMAGE'],'started_at':None,'running':False,'absent':True}

def fingerprint(root,owner,source,names=NAMES):
    if not root.is_dir() or root.is_symlink() or {f.name for f in root.iterdir()}!=names:
        raise ValueError('PAIRED_READONLY_HOLD_FILE_SET')
    files={}
    for name in sorted(names):
        p=root/name
        if not p.is_file() or p.is_symlink():raise ValueError('PAIRED_READONLY_HOLD_FILE_TYPE')
        with p.open('rb') as f:files[name]=hashlib.file_digest(f,'sha256').hexdigest()
    raw=json.dumps({'operation':root.name,'owner':owner,'source':source,'files':files},
                   sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()

def provenance(ns,ha,owner):
    need=ns['need'];load=ns['load'];root=ns['HELD_ROM'];ns['private_root'](root)
    digest=fingerprint(root,owner,ns['SOURCE'])
    need(digest==ns['PAIRED_ROM_HOLD_PIN'],'PAIRED_READONLY_HOLD_PIN')
    p=load(root/'plan.json');pin=ns['sha'](ns['canonical'](p))
    absent={'id':None,'image':ns['IMAGE'],'started_at':None,'running':False,'absent':True}
    need(pin==ns['PAIRED_ROM_HOLD_PLAN_PIN'] and p['operation_id']==root.name and
         p['source']==ns['SOURCE'] and p['installed']==ns['INSTALLED'] and
         p['candidate_pin']==ns['CANDIDATE_PIN'] and p['input_pin']==ns['PREVIOUS_INPUT_PIN'] and
         p['owner']['running'] is True and p['owner']['image']==ns['IMAGE'] and
         (dict(p['owner'],running=False)==owner or owner==absent) and
         owner['running'] is False and owner['image']==ns['IMAGE'] and
         not p.get('rom_continuation_sha256') and not p.get('bounded_reentry_sha256'),
         'PAIRED_READONLY_HOLD_PLAN')
    need(load(root/'execute-intent.json')['plan_sha256']==pin and
         load(root/'bsl-entry-intent.json')=={'attempts':1,'plan_sha256':pin},'PAIRED_READONLY_HOLD_INTENTS')
    hold=load(root/'hold.json')
    need(hold=={'automatic_boot':False,'automatic_retry':False,'error_type':'Hold',
                'plan_sha256':pin,'safe_code':'P7U_DEPLOY_HOLD_NATIVE_SECURITY'},'PAIRED_READONLY_HOLD_REASON')
    security=load(root/'security-receipt.json');sparse=load(root/'sparse-receipt.json')
    snapshot=ns['read'](root/'fresh-sparse-snapshot.bin')
    need(len(snapshot)==720896 and security['status']=='HOLD' and security['reason_codes']==
         ['ADDRESS_MANAGER_RETAINED_ROWS_CHANGED_NO_MIGRATION_AUTHORIZED'] and
         all(security[k]==0 for k in ('write_attempts','erase_attempts','compaction_attempts')) and
         security['capture_sha256']==ns['sha'](snapshot) and
         sparse['status']=='SPARSE_ROM_CRC_WITH_FRESH_NV_READ_ONLY_NOT_FLASH_ADMISSION' and
         sparse['rom_crc32_sector_checks']==88 and sparse['live_reconstructed_sha256']==ns['sha'](snapshot),
         'PAIRED_READONLY_HOLD_SECURITY')
    cold=load(root/'cold-backup.json')
    need(cold['sha256']==ns['file_sha'](root/'cold-before-flash.tar') and
         cold['bytes']==(root/'cold-before-flash.tar').stat().st_size,'PAIRED_READONLY_HOLD_BACKUP')
    ha.proof(False)
    return digest

def reentry_provenance(ns,ha,owner):
    first=provenance(ns,ha,owner);need=ns['need'];root=ns['FAILED_ATTACH'];ns['private_root'](root)
    marker=ns['OPERATIONS']/('readonly-reentry-'+root.name)
    need(not marker.exists() and not marker.is_symlink(),'PAIRED_ROM_REENTRY_ALREADY_CONSUMED')
    digest=fingerprint(root,owner,ns['SOURCE'],ATTACH_NAMES)
    need(digest==ns['PAIRED_ROM_REENTRY_PIN'],'PAIRED_ATTACH_HOLD_PIN')
    load=ns['load'];p=load(root/'plan.json');pin=ns['sha'](ns['canonical'](p))
    need(pin==ns['PAIRED_ROM_REENTRY_PLAN_PIN'] and p['operation_id']==root.name and
         p['source']==ns['SOURCE'] and p['installed']==ns['INSTALLED'] and p['owner']==owner and
         p['candidate_pin']==ns['CANDIDATE_PIN'] and p['input_pin']==ns['PREVIOUS_INPUT_PIN'] and
         p['rom_continuation_sha256']==first and not p.get('bounded_reentry_sha256'),
         'PAIRED_ATTACH_HOLD_PLAN')
    need(load(root/'execute-intent.json')['plan_sha256']==pin and
         load(root/'rom-reattach-intent.json')=={'plan_sha256':pin,'provenance':first} and
         load(root/'hold.json')=={'automatic_boot':False,'automatic_retry':False,'error_type':'RomWireError',
           'plan_sha256':pin,'safe_code':'BSL_ACK_TIMEOUT_OR_DISCONNECTED'},'PAIRED_ATTACH_HOLD_REASON')
    cold=load(root/'cold-backup.json')
    need(cold['sha256']==ns['file_sha'](root/'cold-before-flash.tar') and
         cold['bytes']==(root/'cold-before-flash.tar').stat().st_size,'PAIRED_ATTACH_HOLD_BACKUP')
    return ns['sha'](ns['canonical']({'first_readonly_hold':first,'failed_attach':digest}))

def consume_reentry(ns,plan_pin):
    root=ns['OPERATIONS']/('readonly-reentry-'+ns['FAILED_ATTACH'].name)
    ns['need'](not root.exists() and not root.is_symlink(),'PAIRED_ROM_REENTRY_ALREADY_CONSUMED')
    root.mkdir(mode=0o700)
    ns['durable'](root,'intent.json',{'new_operation':ns['PRIVATE'].name,'plan_sha256':plan_pin,
          'failed_attach':ns['FAILED_ATTACH'].name,'attempts':1,'action':'FRESH_BSL_ENTRY_AFTER_ZERO_WRITE_ATTACH_TIMEOUT'})
