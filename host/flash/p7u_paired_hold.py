"""Pinned continuation ONLY after an immutable, zero-write security HOLD.

No hardware or service mutation occurs here. The existing operator makes a new
server-generated plan, opens a new ROM session, recaptures NV and checks all88
CRCs again. It must not repeat BSL entry or reuse the consumed execution intent.
"""
import hashlib,json

NAMES={'plan.json','reader-baseline-check.json','owner-backup-before-stop.json',
       'execute-intent.json','hold.json','cold-backup.json','cold-before-flash.tar',
       'bsl-entry-intent.json','sparse-receipt.json','fresh-sparse-snapshot.bin','security-receipt.json'}

def fingerprint(root,owner,source):
    if not root.is_dir() or root.is_symlink() or {f.name for f in root.iterdir()}!=NAMES:
        raise ValueError('PAIRED_READONLY_HOLD_FILE_SET')
    files={}
    for name in sorted(NAMES):
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
    need(pin==ns['PAIRED_ROM_HOLD_PLAN_PIN'] and p['operation_id']==root.name and
         p['source']==ns['SOURCE'] and p['installed']==ns['INSTALLED'] and
         p['candidate_pin']==ns['CANDIDATE_PIN'] and p['input_pin']==ns['PREVIOUS_INPUT_PIN'] and
         p['owner']['running'] is True and dict(p['owner'],running=False)==owner and
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
