"""Fixed-target R4 afbb7a8 deployment. No arbitrary shell, device, firmware or HTTP URL.

plan performs admission without stopping Z2M. deploy consumes one immutable
plan before stopping the sole owner. boot is a separate, once-only phase and
requires a verified write result. A failed phase is never replayed or reset.
The existing transition module remains the ONLY erase/program implementation.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tarfile
import time
import urllib.request

SOURCE = '4cfe317083c2a3d1b784350b0ab960e27218e618'
INSTALLED = '4021fff71421884a2a5e6f6455139e36b02ea28a'
CANDIDATE_PIN = '1168f5547b39a9a672009e990fd55b4131be9bda6f6e27d522094bbf43815f2e'
IMAGE = 'sha256:6c7a5f2c82b46c1785ecedf006514bf009dd7fcc0437382fba99c6396852ce3b'
ROM_ID = '0be85df5dc59b5996f9ebb3339c2ac8491bf1015903817278929cc41ec2fbaf2'
OWNER = 'local_p7u_r4_native_host'
SERIAL = '/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00'
INPUT = Path('/share/p7u-r4-input-4cfe317')
CANDIDATE = Path('/share/p7u-r4-stage-4cfe317')
PRIVATE = Path('/share/p7u-r4-deployment-4cfe317-once')
OPERATIONS = Path('/share/p7u-r4-firmware-operations')
OPERATION_ID = re.compile(r'[0-9a-f]{32}$')
PLAN_TTL_SECONDS = 1800
HELD_ROM = Path('/share/p7u-r4-afbb7a8-no-prior-rom-continuation')
FAILED_ATTACH = Path('/share/p7u-r4-afbb7a8-no-prior-attach')
FLOOR_HOLD = Path('/share/p7u-r4-afbb7a8-no-prior-floor')
FAILED_PRIVATE = Path('/share/p7u-pr154-deployment-2499154')
FAILED_PACKAGE_PIN = 'b18be817fde67a86d8efd6375efb93f8c40a44dcc2be7d8a40d2726f15ef402f'
DATA = Path('/homeassistant/zigbee2mqtt')
INSPECTOR_IMAGE = 'sha256:bc813fe0d598b3c6743449b87cf263b1080b752f45fc4b22c947f9e1fc59a24b'
PREVIOUS_OP = Path('/share/p7u-r4-firmware-operations/19a7dfdc5c22ceb23c7380ef546860a5')
PREVIOUS_OP_PLAN_PIN = 'aa864db7c1feb7637156fb7e6e2bcc9cfa01fe100814ae52fe9ce40bc363fdd9'
PREVIOUS_FROZEN_PIN = '81b79ac3843065d5c0b99181d80bdaa81f17e62262b488bcf75cd2d4264c4fea'
PREVIOUS_SNAPSHOT_PIN = '8f0f506b09ae227d691e51880c93358a57d6aac8e4114e14a199871446a3f438'
PREVIOUS_JOURNAL_PIN = '93c5ee770c97611dc5bf2b7bca68b393e34c1447f7beaddc6cec237e3d3d8a36'
PREVIOUS_CANDIDATE_PIN = '9ea9e89a66081d30be5d190ecdde4e84bd0df838afabd69c7df0899adfcab75e'
PREVIOUS_INPUT_PIN = '7cb008da1d39f4248e8eb9c5979ef0ab4c6a04323d028b485cd513f6609c51d6'
INPUT_NAMES = {'installed-candidate.json', 'installed-app.hex', 'installed-handoff.bin',
               'installed-plan.json', 'installed-result.json', 'installed-before.bin',
               'management.json', 'historical-backup.json'}


class Hold(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Hold('P7U_DEPLOY_HOLD_' + reason)


def select_operation(operation_id=None, *, create=False):
    # This is called under the existing shared lifecycle lock. Prior journals
    # are never removed, mutated, renamed or replayed after expiry.
    if not OPERATIONS.exists():
        need(create and not OPERATIONS.is_symlink(), 'OPERATION_ROOT_MISSING')
        OPERATIONS.mkdir(mode=0o700)
    private_root(OPERATIONS)
    if create:
        need(operation_id is None, 'OPERATION_ID_CLIENT_SELECTED')
        for _ in range(4):
            selected = secrets.token_hex(16)
            target = OPERATIONS/selected
            if not target.exists() and not target.is_symlink():
                return selected, target
        raise Hold('P7U_DEPLOY_HOLD_OPERATION_ID_COLLISION')
    need(isinstance(operation_id, str) and
         OPERATION_ID.fullmatch(operation_id) is not None, 'OPERATION_ID')
    target = OPERATIONS/operation_id
    private_root(target)
    return operation_id, target


def operation_status():
    # Read-only and sanitized; no secret records or identities.
    private_root(PRIVATE)
    p = load(PRIVATE/'plan.json')
    if PRIVATE.parent == OPERATIONS:
        need(p.get('operation_id') == PRIVATE.name, 'OPERATION_PLAN_BINDING')
    elapsed = time.time() - p['created_at']
    if (PRIVATE/'serving-accepted.json').exists():
        state = 'SERVING_ACCEPTED'
    elif (PRIVATE/'started-pending-serving.json').exists():
        state = 'HOST_RUNNING_PENDING_STARTUP'
    elif (PRIVATE/'boot-intent.json').exists():
        state = 'BOOT_DISPATCHED_PENDING_OR_UNKNOWN'
    elif (PRIVATE/'verified-write.json').exists():
        state = 'WRITE_VERIFIED_STILL_IN_ROM'
    elif (PRIVATE/'execute-intent.json').exists():
        state = 'EXECUTION_ADMISSION_CONSUMED'
    elif elapsed >= PLAN_TTL_SECONDS or elapsed < 0:
        state = 'EXPIRED_UNUSED'
    else:
        state = 'PREPARED'
    if (PRIVATE/'hold.json').exists():
        state = 'HELD_WITH_REASON'
    return {'status': state, 'operation_id': PRIVATE.name,
            'plan_sha256': sha(canonical(p)),
            'expires_at': p['created_at'] + PLAN_TTL_SECONDS,
            'execution_admission_consumed': (PRIVATE/'execute-intent.json').exists(),
            'boot_dispatched': (PRIVATE/'boot-intent.json').exists(),
            'firmware_source': SOURCE}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''): digest.update(block)
    return digest.hexdigest()


def read(path, limit=4*1024*1024):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit, 'INPUT_FILE')
    return path.read_bytes()


def load(path):
    return json.loads(read(path))


def private_root(root):
    need(root.is_dir() and not root.is_symlink() and root.resolve() == root and
         root.stat().st_mode & 0o077 == 0, 'PRIVATE_ROOT')


def durable(root, name, value):
    need(re.fullmatch('[a-z0-9-]+[.](json|bin|log)', name) is not None, 'RECEIPT_NAME')
    raw = value if type(value) is bytes else canonical(value)
    with (root/name).open('xb') as f:
        os.chmod(f.name, 0o600); f.write(raw); f.flush(); os.fsync(f.fileno())
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sealed_tree(root, manifest_name, expected, names=None):
    private_root(root)
    raw = read(root/manifest_name); need(sha(raw) == expected, 'MANIFEST_PIN')
    files = json.loads(raw)['files']
    need(type(files) is dict and files and (names is None or set(files) == names), 'MANIFEST_FILES')
    for name, digest in files.items():
        rel = Path(name)
        need(not rel.is_absolute() and '..' not in rel.parts and '\\' not in name, 'PATH_ESCAPE')
        target = root/rel
        need(target.resolve().is_relative_to(root) and
             all(not p.is_symlink() for p in (target, *target.parents) if p != root.parent), 'SYMLINK')
        need(sha(read(target)) == digest, 'FILE_PIN')
    need({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} ==
         set(files) | {manifest_name}, 'UNSEALED_FILES')
    return json.loads(raw)


def runtime_priority_qualification(c):
    """Bind the new delivery to its genuine CI native ELF/priority seal."""
    if SOURCE not in ('e3a0f3b7726adf1f6c182973f135665a5c3857e0',
                      '66ed700c2818c7a0963dad9160d55109009bbaac',
                      '250441cd17c55e25c78d97e041f056574355ade7',
                      '540d75a23d11587fb45fd892c5e9ae01ec0aab15'): return None
    raw=read(CANDIDATE/'b1-native-seal.json')
    need(sha(raw)==c['files'].get('b1-native-seal.json'), 'SRSP_PRIORITY_SEAL_PIN')
    native=json.loads(raw); q=native.get('srsp_runtime_priority') or {}
    count=(q.get('task_num_priorities') or {}).get('value')
    helper=q.get('linked_priority_helper') or {}
    elf=(native.get('artifacts') or {}).get('elf') or {}
    name=elf.get('file','')
    need(native.get('schema')=='r4-b1-native-seal-v1' and native.get('source_sha')==SOURCE and
         type(count) is int and count==8 and
         (q.get('task_num_priorities') or {}).get('symbol')=='ti_sysbios_knl_Task_numPriorities' and q.get('base_priority')==4 and
         q.get('pending_srsp_priority')==6 and helper.get('owner')=='npi_task.o' and
         type(helper.get('address')) is int and type(helper.get('size')) is int and helper['size']>0 and
         re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*',name) is not None,
         'SRSP_PRIORITY_NATIVE')
    need(elf.get('sha256')==c['files'].get('native/'+name) and
         sha(read(CANDIDATE/'native'/name))==elf['sha256'], 'SRSP_PRIORITY_ELF_BINDING')
    return q


def candidate():
    c = load(CANDIDATE/'candidate.json')
    need(sha(canonical(c)) == CANDIDATE_PIN and c['source_sha'] == SOURCE, 'FIRMWARE_PIN')
    for name in ('P7U-STOCK20260311-APP-ONLY.hex', 'P7U-STOCK20260311-AC000-HANDOFF.bin',
                 'profile.json', 'security-native-abi.json', 'handoff-receipt.json'):
        need(sha(read(CANDIDATE/name)) == c['files'][name], 'CANDIDATE_FILE')
    runtime_priority_qualification(c)
    return c


def run(args, timeout=30):
    p = subprocess.run(args, capture_output=True, timeout=timeout)
    need(p.returncode == 0, 'COMMAND_' + args[0])
    return p.stdout


class HA:
    """All side effects are named, fixed-target operations; never shell=True."""
    def request(self, url, payload=None):
        root = 'http://supervisor/'
        slugs = (OWNER, 'local_p7u_r4_fallback', '45df7312_zigbee2mqtt',
                 'local_p7u_recovery', 'local_p7u_r4_lifecycle_manager')
        reads = {root+'addons/'+s+'/info' for s in slugs} | {
            root+'core/api/states/'+e for e in ('automation.boot_deterministic_emqx_then_zigbee2mqtt',
            'automation.zigbee2mqtt_mesh_communication_outage_alert', 'button.slzb_06p7u_zigbee_restart')}
        allowed = url in reads if payload is None else (
            url in {root+'addons/'+OWNER+'/stop', root+'addons/'+OWNER+'/start'} and payload == {} or
            url == root+'core/api/services/button/press' and
            payload == {'entity_id': 'button.slzb_06p7u_zigbee_restart'})
        need(allowed, 'API_SCOPE')
        q = urllib.request.Request(url, data=None if payload is None else canonical(payload),
            headers={'Authorization': 'Bearer '+os.environ['SUPERVISOR_TOKEN'],
                     'Content-Type': 'application/json'}, method='GET' if payload is None else 'POST')
        # A read may time out while Supervisor settles a stopped container.
        # Retrying that read cannot replay a stop/start/reset. Mutations retain
        # exactly one HTTP dispatch, even when the response is unknown.
        for attempt in range(2 if payload is None else 1):
            try:
                with urllib.request.urlopen(q, timeout=180 if payload is not None else 15) as r:
                    return json.load(r)
            except TimeoutError:
                if payload is not None: raise
                if attempt: raise Hold('P7U_DEPLOY_HOLD_READ_TIMEOUT_' + url.removeprefix(root))
                time.sleep(.2)

    def info(self, slug):
        need(slug in (OWNER, 'local_p7u_r4_fallback', '45df7312_zigbee2mqtt',
                       'local_p7u_recovery', 'local_p7u_r4_lifecycle_manager'), 'ADDON_SCOPE')
        a = self.request('http://supervisor/addons/'+slug+'/info')
        need(a['result'] == 'ok', 'ADDON_INFO'); return a['data']

    def owner_action(self, action):
        need(action in ('stop', 'start'), 'OWNER_ACTION')
        a = self.request('http://supervisor/addons/'+OWNER+'/'+action, {})
        need(a.get('result') == 'ok', 'OWNER_ACTION_ACK_UNKNOWN')

    def inspect(self):
        try:
            a = json.loads(run(['docker', 'inspect', 'app_'+OWNER]))[0]
        except Hold:
            if not globals().get('PAIRED_HOST_VERSION'): raise
            from p7u_paired_hold import absent_owner
            return absent_owner(globals(), self)
        return {'id': a['Id'], 'image': a['Image'], 'started_at': a['State']['StartedAt'],
                'running': a['State']['Running']}

    def proof(self, active):
        a = json.loads(run(['docker', 'inspect', 'app_local_p7u_r4_owner_inspector']))[0]
        need(a['Image'] == INSPECTOR_IMAGE and not a['State']['Running'], 'INSPECTOR_IMAGE')
        p = json.loads(run(['docker', 'start', '-a', 'app_local_p7u_r4_owner_inspector'], 40))
        need(p['exclusive_owner_verified'] is True and p['serial_opened'] is False, 'TTY_PROOF')
        need(p['slots']['diagnostic']['running'] is active and
             all(not v['running'] for k, v in p['slots'].items() if k != 'diagnostic'), 'TTY_OWNER')
        if not active:
            need(not p['tty_holders_pids'], 'TTY_NOT_QUIESCENT')
        return p

    def management(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def get(endpoint):
            with opener.open('http://192.168.50.59/'+endpoint, timeout=8) as r:
                need(r.status == 200, 'MANAGEMENT_HTTP'); return json.load(r)
        cfg, info = get('config'), get('ha_info')['Info']
        need(cfg.get('coordMode') == 2 and cfg.get('keepWeb') is True and cfg.get('oUsbMod') == 0,
             'USB_MODE')
        baseline = load(INPUT/'management.json')
        need(all(info.get(k) == baseline.get(k) for k in ('model', 'MAC', 'hw_version', 'zb_hw')),
             'MANAGEMENT_IDENTITY')
        need(info['model'] == 'SLZB-06p7U' and info['zb_hw'] == 'CC2652P7', 'BOARD')
        return sha(canonical(baseline))

    def policy(self):
        for slug in (OWNER, 'local_p7u_r4_fallback', '45df7312_zigbee2mqtt'):
            a = self.info(slug)
            need(a['boot'] == 'manual' and a['watchdog'] is False and a['auto_update'] is False,
                 'HOST_POLICY')
        g = self.info('local_p7u_recovery'); o = g['options']
        need(o['enabled'] is False and o['dry_run'] is True and o['serial_owner_approved'] is False
             and o['allow_private_http_fallback'] is False and g['watchdog'] is False, 'GUARD_POLICY')
        m = self.info('local_p7u_r4_lifecycle_manager')
        need(m['options']['execute'] is False and m['state'] in ('stopped', 'error'), 'MANAGER_POLICY')
        for entity in ('automation.boot_deterministic_emqx_then_zigbee2mqtt',
                       'automation.zigbee2mqtt_mesh_communication_outage_alert'):
            a = self.request('http://supervisor/core/api/states/'+entity)
            need(a['entity_id'] == entity and a['state'] == 'off', 'AUTOMATION_POLICY')

    def boot_binding(self):
        entity = 'button.slzb_06p7u_zigbee_restart'
        entities = load(DATA.parent/'.storage/core.entity_registry')['data']['entities']
        devices = load(DATA.parent/'.storage/core.device_registry')['data']['devices']
        rows = [v for v in entities if v['entity_id'] == entity and not v.get('disabled_by')]
        need(len(rows) == 1, 'BOOT_ENTITY')
        rows = [v for v in devices if v['id'] == rows[0]['device_id']]
        need(len(rows) == 1, 'BOOT_DEVICE')
        norm = lambda x: re.sub('[^0-9a-f]', '', str(x).lower())
        mac = norm(load(INPUT/'management.json')['MAC'])
        need(len(mac) == 12 and any(norm(v) == mac for pair in
             rows[0].get('connections', [])+rows[0].get('identifiers', []) for v in pair), 'BOOT_MAC')
        a = self.request('http://supervisor/core/api/states/'+entity)
        need(a.get('entity_id') == entity and a.get('state') != 'unavailable', 'BOOT_UNAVAILABLE')
        return entity

    def enter_bsl(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('http://192.168.50.59/api2?action=4&cmd=2', timeout=8) as r:
            need(r.status == 200 and r.read(64).strip() == b'ok', 'BSL_ACK_UNKNOWN')

    def restart_radio(self):
        self.request('http://supervisor/core/api/services/button/press',
                     {'entity_id': self.boot_binding()})


def modules(package):
    sys.dont_write_bytecode = True
    root = package/'source/firmware/slzb-06p7u/r4'
    sys.path[:0] = [str(package/'vendor'), str(root/'release'), str(root/'release/rom_writer'),
                   str(root/'qualification'), str(root/'b0/tools')]
    import r4_stock20260311_transition as transition
    import stock20260311_security_preflight as security
    from p7u_usb_current_owner_gate import reconcile_current
    from p7u_usb_fast_rom import SafeFastUsbRom
    from p7u_usb_sparse_capture import capture_sparse
    return transition, security, reconcile_current, SafeFastUsbRom, capture_sparse


def verify_installed_provenance(old, candidate, result):
    # The AFTER image is only justified by the *real* previous one-shot ROM
    # capture, sector journal and sparse full-flash CRC write receipt.
    # Never reinterpret an older stock/3c7dd95 backup as current firmware.
    private_root(PREVIOUS_OP)
    need(sha(read(INPUT/'INPUT.json')) == PREVIOUS_INPUT_PIN,
         'INSTALLED_CURRENT_SEALED_INPUT')
    op = load(PREVIOUS_OP/'plan.json')
    need(sha(canonical(op)) == PREVIOUS_OP_PLAN_PIN and
         op['source'] == INSTALLED and op['operation_id'] == PREVIOUS_OP.name,
         'INSTALLED_ACTUAL_OPERATION')
    raw_plan = read(PREVIOUS_OP/'frozen-plan.json')
    frozen = json.loads(raw_plan)
    pin = frozen.pop('plan_sha256')
    need(pin == PREVIOUS_FROZEN_PIN and sha(canonical(frozen)) == pin and
         frozen['source_sha'] == INSTALLED and
         frozen['capture_sha256'] == PREVIOUS_SNAPSHOT_PIN,
         'INSTALLED_FROZEN_PLAN_PROVENANCE')
    previous_rom = read(PREVIOUS_OP/'fresh-sparse-snapshot.bin')
    need(len(previous_rom) == 720896 and sha(previous_rom) == PREVIOUS_SNAPSHOT_PIN and
         read(INPUT/'installed-before.bin') == previous_rom and
         read(INPUT/'installed-plan.json') == raw_plan and
         old.manifest['plan_sha256'] == pin,
         'INSTALLED_CURRENT_PREWRITE_ROM')
    envelope = load(PREVIOUS_OP/'verified-write.json')
    journal = read(PREVIOUS_OP/'mutation-journal.jsonl')
    need(sha(journal) == PREVIOUS_JOURNAL_PIN and
         envelope['operation_plan_sha256'] == PREVIOUS_OP_PLAN_PIN and
         envelope['frozen_plan_sha256'] == pin and
         envelope['journal_sha256'] == PREVIOUS_JOURNAL_PIN and
         result == envelope['result'] and
         result['status'] == 'APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL' and
         result['verification_scope'] == 'WRITTEN_SHA_PLUS_ALL88_ROM_CRC' and
         all(result[k] is False for k in
             ('nv_touched','ccfg_touched','reset_issued','automatic_rollback')),
         'INSTALLED_PREVIOUS_VERIFIED_WRITE')
    records = [json.loads(x) for x in journal.splitlines()]
    verified = [(x['address'],x['sha256']) for x in records
                if x.get('event') == 'SECTOR_VERIFIED']
    needed = [(a, frozen['sector_sha256'][str(a)])
              for a in result['written_sectors']]
    need(verified == needed and
         result['written_sectors'] == frozen['program_order'] and
         sha(canonical(candidate)) == PREVIOUS_CANDIDATE_PIN,
         'INSTALLED_CURRENT_SECTOR_JOURNAL')
    return {'operation_plan_pin': PREVIOUS_OP_PLAN_PIN,
            'prior_frozen_pin': PREVIOUS_FROZEN_PIN,
            'prior_capture_pin': PREVIOUS_SNAPSHOT_PIN,
            'journal_pin': PREVIOUS_JOURNAL_PIN,
            'current_installed_source': INSTALLED}


def installed(t):
    m = load(INPUT/'installed-plan.json'); c = load(INPUT/'installed-candidate.json')
    need(c['source_sha'] == INSTALLED and sha(canonical(c)) == m['candidate_sha256'], 'INSTALLED_PIN')
    payload, error = t._parse_intel_hex(INPUT/'installed-app.hex')
    need(not error, 'INSTALLED_HEX')
    sectors = {int(a): bytes(payload.get(j, 255) for j in range(int(a), int(a)+8192))
               for a in m['sector_sha256'] if int(a) != 0xAC000}
    sectors[0xAC000] = read(INPUT/'installed-handoff.bin')
    old = t._frozen(t.Transition(m, read(INPUT/'installed-before.bin'), sectors), m['plan_sha256'])
    result = load(INPUT/'installed-result.json')
    need(old.manifest['source_sha'] == INSTALLED and
         sha(read(INPUT/'installed-app.hex')) == c['app_hex_sha256'] and
         sha(read(INPUT/'installed-handoff.bin')) == c['handoff_sha256'] and
         result['written_sectors'] == [a for a in m['program_order'] if sectors[a] != old.snapshot[a:a+8192]],
         'INSTALLED_PAIR_OR_RESULT')
    expected = bytearray(old.snapshot)
    for a, b in sectors.items(): expected[a:a+8192] = b
    verify_installed_provenance(old, c, result)
    return old, c, result, bytes(expected)


def quiescent_provenance(ha, owner):
    '''Read-only admission of stopped owner; fresh ROM/security proof is still required.

    Do not reuse old PR154 intents. Record the stopped add-on/container and
    unchanged data backup/database. Re-evaluate identically at execute.
    '''
    need(owner['running'] is False and owner['image'] == IMAGE, 'QUIESCENT_OWNER')
    info = ha.info(OWNER)
    need(info['state'] in ('error','stopped') and
         info['version'] == globals().get('PAIRED_HOST_VERSION', '0.2.1-068ae05e9f9a') and info['build'] is False,
         'QUIESCENT_APP_VERSION')
    ha.proof(False)
    backup = read(DATA/'coordinator_backup.json')
    database = read(DATA/'database.db')
    from p7u_usb_security_model import parse_backup
    peers = parse_backup(json.loads(backup)).peers
    need(100 <= len(peers) <= 107, 'QUIESCENT_BACKUP_IDENTITY')
    return sha(canonical({'owner': owner, 'addon_state': info['state'],
                          'backup_sha256': sha(backup), 'database_sha256': sha(database),
                          'verified_radio_image': False,
                          'nv_reused_from_prior_capture': False}))


def rom_hold_provenance(ha, owner):
    """Fresh plan after security-only HOLD, with no erase/program ever admitted.

    No BSL command may be repeated. A new read-only ROM synchronization and
    fresh capture must prove the same image before any candidate admission.
    """
    if globals().get('PAIRED_ROM_HOLD_PIN'):
        from p7u_paired_hold import provenance
        return provenance(globals(),ha,owner)
    private_root(HELD_ROM)
    names = {'plan.json', 'reader-baseline-check.json', 'owner-backup-before-stop.json',
             'execute-intent.json', 'hold.json', 'cold-backup.json', 'cold-before-flash.tar',
             'bsl-entry-intent.json', 'sparse-receipt.json', 'fresh-sparse-snapshot.bin', 'security-receipt.json'}
    need({v.name for v in HELD_ROM.iterdir()} == names, 'ROM_HOLD_SCOPE')
    p = load(HELD_ROM/'plan.json'); pin = sha(canonical(p))
    need(pin == '5fb074b7dc296405da3613e643a8c420d7fb64a57ec460f42df4aba187b633fa' and
         p['owner'] == owner and not owner['running'] and owner['image'] == IMAGE,
         'ROM_HOLD_PLAN_OR_OWNER')
    need(load(HELD_ROM/'execute-intent.json')['plan_sha256'] == pin and
         load(HELD_ROM/'bsl-entry-intent.json') == {'attempts': 1, 'plan_sha256': pin} and
         load(HELD_ROM/'hold.json') == {'automatic_boot': False, 'automatic_retry': False,
             'error_type': 'Hold', 'plan_sha256': pin}, 'ROM_HOLD_INTENTS')
    s = load(HELD_ROM/'security-receipt.json'); capture = read(HELD_ROM/'fresh-sparse-snapshot.bin')
    need(s['status'] == 'HOLD' and s['reason_codes'] ==
         ['ADDRESS_MANAGER_RETAINED_ROWS_CHANGED_NO_MIGRATION_AUTHORIZED'] and
         all(s[k] == 0 for k in ('write_attempts', 'erase_attempts', 'compaction_attempts')) and
         s['capture_sha256'] == sha(capture), 'ROM_HOLD_SECURITY')
    ha.proof(False)
    return sha(canonical({'files': {n: file_sha(HELD_ROM/n) for n in sorted(names)}, 'owner': owner}))


def bounded_reentry_provenance(ha, owner):
    """One new ROM-entry session after a proven read-only attach failure.

    Both earlier attempts must have stopped before any flash admission. This
    cannot be used after an uncertain erase/program or a changed owner/image.
    """
    if globals().get('PAIRED_ROM_REENTRY_PIN'):
        from p7u_paired_hold import reentry_provenance
        return reentry_provenance(globals(),ha,owner)
    earlier = rom_hold_provenance(ha, owner); private_root(FAILED_ATTACH)
    names = {'plan.json', 'reader-baseline-check.json', 'owner-backup-before-stop.json',
             'execute-intent.json', 'hold.json', 'cold-backup.json', 'cold-before-flash.tar',
             'rom-reattach-intent.json'}
    need({v.name for v in FAILED_ATTACH.iterdir()} == names, 'REENTRY_SCOPE')
    p = load(FAILED_ATTACH/'plan.json'); pin = sha(canonical(p))
    need(pin == '17faa6a2a670cfd62817e963498acb770ffd78d1234d11cf439b491234c4a773' and
         p['owner'] == owner and p['rom_continuation_sha256'] == earlier and
         load(FAILED_ATTACH/'execute-intent.json')['plan_sha256'] == pin and
         load(FAILED_ATTACH/'rom-reattach-intent.json') == {'plan_sha256': pin, 'provenance': earlier} and
         load(FAILED_ATTACH/'hold.json') == {'automatic_boot': False, 'automatic_retry': False,
             'error_type': 'RomWireError', 'plan_sha256': pin}, 'REENTRY_PROVENANCE')
    evidence = {'earlier': earlier, 'files': {n: file_sha(FAILED_ATTACH/n) for n in sorted(names)}}
    if FLOOR_HOLD.exists():
        private_root(FLOOR_HOLD)
        names = {'plan.json', 'reader-baseline-check.json', 'owner-backup-before-stop.json',
                 'execute-intent.json', 'hold.json', 'cold-backup.json', 'cold-before-flash.tar',
                 'bsl-entry-intent.json', 'sparse-receipt.json', 'fresh-sparse-snapshot.bin', 'security-receipt.json'}
        need({v.name for v in FLOOR_HOLD.iterdir()} == names, 'FLOOR_HOLD_SCOPE')
        p = load(FLOOR_HOLD/'plan.json'); pin = sha(canonical(p))
        s = load(FLOOR_HOLD/'security-receipt.json')
        need(pin == '473ce286d6ed89321159ba66545259c78c8513e82886092eef7850fb6fbb62ac' and
             p['owner'] == owner and p['bounded_reentry_sha256'] == sha(canonical(evidence)) and
             load(FLOOR_HOLD/'bsl-entry-intent.json') == {'attempts': 1, 'plan_sha256': pin} and
             load(FLOOR_HOLD/'execute-intent.json')['plan_sha256'] == pin and
             load(FLOOR_HOLD/'hold.json') == {'automatic_boot': False, 'automatic_retry': False,
                 'error_type': 'KeyError', 'plan_sha256': pin, 'safe_code': 'OMITTED'} and
             s['status'] == 'PASS_RETAINED_SECURITY_OFFLINE_ONLY' and not s['reason_codes'] and
             s['checks']['comparison_scope'] == 'KNOWN_R4_RUNTIME_SHORT_ADDRESS_ONLY' and
             all(s[k] == 0 for k in ('write_attempts', 'erase_attempts', 'compaction_attempts')),
             'FLOOR_HOLD_PROVENANCE')
        evidence['floor_hold'] = {n: file_sha(FLOOR_HOLD/n) for n in sorted(names)}
    return sha(canonical(evidence))


def runtime_inventory_peers():
    """Native-order identities independently known by original backup AND sealed DB."""
    from p7u_usb_security_model import parse_backup
    historical = parse_backup(load(INPUT/'historical-backup.json'))
    raw = read(DATA/'database.db')
    approval = load(DATA/'.p7u-approved.json')
    need(approval.get('schema') == 'p7u-db-admission-v1' and
         approval.get('database_sha256') == sha(raw), 'RUNTIME_INVENTORY_DB_PIN')
    identities = set()
    for line in raw.splitlines():
        if not line.strip(): continue
        row = json.loads(line)
        need(type(row) is dict, 'RUNTIME_INVENTORY_ROW')
        if row.get('type') not in ('Router', 'EndDevice'): continue
        ieee = row.get('ieeeAddr')
        need(type(ieee) is str and re.fullmatch('0x[0-9a-fA-F]{16}', ieee) is not None,
             'RUNTIME_INVENTORY_IEEE')
        identities.add(bytes.fromhex(ieee[2:]))
    return frozenset(peer[::-1] for peer in historical.peers if peer in identities)


def native_network_floor(sec, records, abi):
    nib = sec.get(records, 0, 0x21, abi['structs']['nwkIB_t']['size'])
    pan = sec.field(nib, abi, 'nwkIB_t', 'extendedPANID')
    floors = [sec.number(raw, abi, 'nwkSecMaterialDesc_t', 'FrameCounter')
              for (system, item, index), raw in records.items() if system == 1 and item == 7 and
              sec.field(raw, abi, 'nwkSecMaterialDesc_t', 'extendedPanID') == pan]
    return floors[0] if len(floors) == 1 else None


def plan(package, package_pin, input_pin, ha):
    sealed_tree(package, 'PACKAGE.json', package_pin)
    sealed_tree(INPUT, 'INPUT.json', input_pin, INPUT_NAMES)
    c = candidate(); t, security, reconcile, rom, capture = modules(package)
    old, prior, result, expected = installed(t)
    # Installed AFBB came from a verified sector-limited live ROM operation,
    # not the older full SHA writer. Sparse CRC is explicitly native supported
    # by prepare_upgrade only with exact captured ROM and journal provenance.
    need(result['status'] == 'APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL' and
         result['verification_scope'] == 'WRITTEN_SHA_PLUS_ALL88_ROM_CRC' and
         all(result[k] is False for k in ('nv_touched', 'ccfg_touched', 'reset_issued', 'automatic_rollback')),
         'INSTALLED_SUCCESS')
    abi = load(CANDIDATE/'security-native-abi.json'); reader = package/'security-reader-aarch64'
    bindings = {'capture_sha256': sha(old.snapshot), 'baseline_capture_sha256': sha(old.snapshot),
                'abi_sha256': sha(security.abi_tool.canonical(abi)), 'reader_sha256': sha(read(reader)),
                'profile_sha256': c['profile_sha256'], 'native_manifest_sha256': c['native_manifest_sha256']}
    baseline_check = security.preflight(capture=old.snapshot, baseline=old.snapshot, abi=abi,
                                        reader=reader, bindings=bindings)
    need(baseline_check['status'] == 'PASS_RETAINED_SECURITY_OFFLINE_ONLY', 'ARM64_READER_BASELINE')
    ha.policy(); management = ha.management(); ha.boot_binding()
    owner = ha.inspect(); need(owner['image'] == IMAGE, 'CURRENT_OWNER')
    quiescent = None
    if owner['running']:
        proof = ha.proof(True)
        need(proof['slots']['diagnostic']['container_id'] == owner['id'], 'OWNER_PROOF_CHANGED')
    else:
        quiescent = quiescent_provenance(ha, owner)
    reentry = bounded_reentry_provenance(ha, owner) if FAILED_ATTACH.exists() else None
    rom_continuation = rom_hold_provenance(ha, owner) if HELD_ROM.exists() and not reentry else None
    backup = load(DATA/'coordinator_backup.json')
    from p7u_usb_security_model import parse_backup
    now = parse_backup(backup); need(100 <= len(now.peers) <= 107, 'OWNER_BACKUP')
    need(Path(SERIAL).is_char_device(), 'SERIAL_DEVICE')
    need(not PRIVATE.exists(), 'OPERATION_EXISTS')
    PRIVATE.mkdir(mode=0o700)
    durable(PRIVATE, 'reader-baseline-check.json', baseline_check)
    p = {'schema': 'p7u-r4-firmware-first-operation-v2', 'source': SOURCE, 'installed': INSTALLED,
         'created_at': time.time(), 'operation_id': PRIVATE.name if PRIVATE.parent == OPERATIONS else None,
         'package_pin': package_pin, 'input_pin': input_pin,
         'owner': owner, 'management_sha256': management, 'installed_plan_sha256': old.manifest['plan_sha256'],
         'installed_result_sha256': sha(canonical(result)), 'prior_verified_image_sha256': sha(expected),
         'scope': 'CHANGED_APP_AND_PAIRED_AC000_PRESERVE_NV_CCFG', 'boot_separate': True,
         'candidate_pin': CANDIDATE_PIN, 'automatic_retry': False, 'automatic_rollback': False,
         'quiescent_provenance_sha256': quiescent, 'rom_continuation_sha256': rom_continuation,
         'bounded_reentry_sha256': reentry}
    durable(PRIVATE, 'plan.json', p)
    return {'status': 'PREPARED_OWNER_UNCHANGED', 'plan_sha256': sha(canonical(p)),
            'operation_id': p['operation_id'],
            'expires_at': p['created_at'] + PLAN_TTL_SECONDS,
            'source': SOURCE}


def check_plan(package, pin):
    private_root(PRIVATE); p = load(PRIVATE/'plan.json')
    if PRIVATE.parent == OPERATIONS:
        need(p.get('operation_id') == PRIVATE.name, 'OPERATION_PLAN_BINDING')
    need(sha(canonical(p)) == pin and p['source'] == SOURCE and p['installed'] == INSTALLED and
         p['scope'] == 'CHANGED_APP_AND_PAIRED_AC000_PRESERVE_NV_CCFG', 'PLAN_PIN')
    sealed_tree(package, 'PACKAGE.json', p['package_pin'])
    sealed_tree(INPUT, 'INPUT.json', p['input_pin'], INPUT_NAMES)
    candidate(); return p


def restore_pre_bsl(package, package_pin, pin, ha):
    """One start of unchanged firmware after the precisely bounded v1 hold.

    This is not a retry of deploy: any BSL/capture/write/boot artifact, unknown
    file or prior recovery intent rejects it. The failed operation is retained.
    """
    sealed_tree(package, 'PACKAGE.json', package_pin)
    private_root(FAILED_PRIVATE)
    need(not (FAILED_PRIVATE/'restore-intent.json').exists(), 'RESTORE_CONSUMED')
    names = {'plan.json', 'reader-baseline-check.json', 'owner-backup-before-stop.json',
             'execute-intent.json', 'hold.json'}
    need({v.name for v in FAILED_PRIVATE.iterdir()} == names, 'RESTORE_NOT_PRE_BSL')
    p = load(FAILED_PRIVATE/'plan.json'); hold = load(FAILED_PRIVATE/'hold.json')
    need(sha(canonical(p)) == pin and p['source'] == SOURCE and p['installed'] == INSTALLED and
         p['package_pin'] == FAILED_PACKAGE_PIN and p['candidate_pin'] == CANDIDATE_PIN and
         p['scope'] == 'CHANGED_APP_AND_PAIRED_AC000_PRESERVE_NV_CCFG' and
         load(FAILED_PRIVATE/'execute-intent.json')['plan_sha256'] == pin and
         hold == {'error_type': 'TimeoutError', 'automatic_retry': False,
                  'automatic_boot': False, 'plan_sha256': pin}, 'RESTORE_PROVENANCE')
    sealed_tree(Path('/share/p7u-pr154-operator-'+FAILED_PACKAGE_PIN[:16]),
                'PACKAGE.json', FAILED_PACKAGE_PIN)
    sealed_tree(INPUT, 'INPUT.json', p['input_pin'], INPUT_NAMES); candidate()
    ha.policy(); ha.proof(False)
    need(ha.management() == p['management_sha256'], 'RESTORE_BOARD')
    a = ha.info(OWNER)
    need(a['state'] in ('stopped', 'error') and a['version'] == '0.2.1-068ae05e9f9a'
         and a['build'] is False, 'RESTORE_HOST_VERSION')
    image = json.loads(run(['docker', 'image', 'inspect',
        'localhost:50144/p7u-r4-diagnostic:0.2.1-068ae05e9f9a']))
    need(len(image) == 1 and image[0]['Id'] == IMAGE, 'RESTORE_IMAGE')
    db = sha(read(DATA/'database.db')); backup = sha(read(DATA/'coordinator_backup.json'))
    ha.proof(False)
    need(db == sha(read(DATA/'database.db')) and backup == sha(read(DATA/'coordinator_backup.json')),
         'RESTORE_DATA_CHANGED')
    request = {'failed_plan_sha256': pin, 'failed_hold_sha256': sha(canonical(hold)),
               'package_pin': package_pin, 'action': 'START_UNCHANGED_HOST_NO_RADIO_RESET',
               'database_sha256': db, 'backup_sha256': backup, 'at': time.time()}
    durable(FAILED_PRIVATE, 'restore-intent.json', request)
    ha.owner_action('start')
    owner = ha.inspect()
    need(owner['running'] and owner['image'] == IMAGE and owner != p['owner'], 'RESTORE_NEW_OWNER')
    ha.proof(True)
    durable(FAILED_PRIVATE, 'restored-pending-serving.json',
            {'installed': INSTALLED, 'owner': owner, 'request_sha256': sha(canonical(request)),
             'at': time.time()})
    return {'status': 'UNCHANGED_FIRMWARE_HOST_STARTED_PENDING_SERVING', 'source': INSTALLED}


async def deploy(package, pin, ha):
    p = check_plan(package, pin)
    need(0 <= time.time()-p['created_at'] < PLAN_TTL_SECONDS, 'PLAN_EXPIRED')
    need(not (PRIVATE/'execute-intent.json').exists(), 'EXECUTION_CONSUMED')
    t, sec, reconcile, factory, sparse = modules(package)
    old, prior, result, expected = installed(t)
    need(sha(expected) == p['prior_verified_image_sha256'] and
         sha(canonical(result)) == p['installed_result_sha256'], 'INSTALLED_RECEIPT_CHANGED')
    ha.policy(); need(ha.inspect() == p['owner'] and ha.management() == p['management_sha256'], 'OWNER_CHANGED')
    quiescent = p.get('quiescent_provenance_sha256')
    if quiescent:
        need(quiescent_provenance(ha, p['owner']) == quiescent, 'QUIESCENT_CHANGED')
    else:
        ha.proof(True)
    rom_continuation = p.get('rom_continuation_sha256')
    if rom_continuation:
        need(rom_hold_provenance(ha, p['owner']) == rom_continuation, 'ROM_HOLD_CHANGED')
    reentry = p.get('bounded_reentry_sha256')
    if reentry:
        need(not rom_continuation and bounded_reentry_provenance(ha, p['owner']) == reentry, 'REENTRY_CHANGED')
    backup = read(DATA/'coordinator_backup.json')
    durable(PRIVATE, 'owner-backup-before-stop.json', backup)
    durable(PRIVATE, 'execute-intent.json', {'plan_sha256': pin, 'dispatch_at': time.time()})
    rom = None
    try:
        if not quiescent: ha.owner_action('stop')
        ha.proof(False); ha.policy()
        cold = PRIVATE/'cold-before-flash.tar'
        with tarfile.open(cold, 'x') as archive: archive.add(DATA, arcname='zigbee2mqtt')
        os.chmod(cold, 0o600)
        with cold.open('rb') as f: os.fsync(f.fileno())
        durable(PRIVATE, 'cold-backup.json', {'sha256': file_sha(cold),
                                            'bytes': cold.stat().st_size})
        if rom_continuation:
            durable(PRIVATE, 'rom-reattach-intent.json', {'plan_sha256': pin, 'provenance': rom_continuation})
        rom = factory(); await rom.open(SERIAL)
        if not rom_continuation:
            if reentry and globals().get('PAIRED_ROM_REENTRY_PIN'):
                from p7u_paired_hold import consume_reentry
                consume_reentry(globals(),pin)
            durable(PRIVATE, 'bsl-entry-intent.json', {'plan_sha256': pin, 'attempts': 1})
            ha.enter_bsl(); await asyncio.sleep(1)
        drained = 0
        for _ in range(48):
            try: raw = await asyncio.wait_for(rom.reader.read(128), .015)
            except asyncio.TimeoutError: break
            if not raw: break
            drained += len(raw); need(drained <= 4096, 'PRE_SYNC_TRAFFIC')
        need(await rom.synchronize(), 'ROM_SYNC')
        need(await rom.identity_sha256() == ROM_ID, 'ROM_IDENTITY')
        await rom.enable_fast_reads()
        capture = await sparse(rom, prior_full_verified=expected, expected_identity_sha256=ROM_ID,
                               total_timeout_seconds=60)
        from dataclasses import asdict
        proof = asdict(capture.receipt); current = capture.snapshot
        await rom.assert_read_status()
        if rom_continuation or (reentry and globals().get('PAIRED_ROM_REENTRY_PIN')):
            need(sha(current) == sha(read(HELD_ROM/'fresh-sparse-snapshot.bin')), 'ROM_IMAGE_CHANGED')
        durable(PRIVATE, 'fresh-sparse-snapshot.bin', current)
        durable(PRIVATE, 'sparse-receipt.json', proof)
        c = candidate(); abi = load(CANDIDATE/'security-native-abi.json'); reader = package/'security-reader-aarch64'
        bindings = {'capture_sha256': sha(current), 'baseline_capture_sha256': sha(old.snapshot),
                    'abi_sha256': sha(sec.abi_tool.canonical(abi)), 'reader_sha256': sha(read(reader)),
                    'profile_sha256': c['profile_sha256'], 'native_manifest_sha256': c['native_manifest_sha256']}
        security = sec.preflight(capture=current, baseline=old.snapshot, abi=abi, reader=reader,
                                 bindings={**bindings, 'runtime_database_sha256': sha(read(DATA/'database.db')),
                    'runtime_historical_backup_sha256': sha(read(INPUT/'historical-backup.json'))},
                                 runtime_upgrade=True, runtime_inventory_peers=runtime_inventory_peers())
        durable(PRIVATE, 'security-receipt.json', security)
        need(security['status'] == 'PASS_RETAINED_SECURITY_OFFLINE_ONLY', 'NATIVE_SECURITY')
        records, counts = sec.read_private(reader, current)
        owner = reconcile(historical=load(INPUT/'historical-backup.json'), fresh=json.loads(backup),
            records=records, abi=abi, native_preflight_pass=True, candidate_semantics_pass=True,
            baseline_counter_floor=native_network_floor(sec, records, abi),
            runtime_inventory_peers=runtime_inventory_peers())
        durable(PRIVATE, 'current-owner-security.json', owner)
        need(owner['status'] == 'PASS_CURRENT_OWNER_OFFLINE_ONLY', 'CURRENT_OWNER_SECURITY')
        plan = t.prepare_upgrade(installed_plan=old, expected_installed_plan_sha256=old.manifest['plan_sha256'],
            installed_candidate=prior, expected_installed_candidate_sha256=old.manifest['candidate_sha256'],
            installed_app_hex=read(INPUT/'installed-app.hex'), installed_handoff=read(INPUT/'installed-handoff.bin'),
            installed_result=result, expected_installed_result_sha256=p['installed_result_sha256'],
            handoff_receipt=read(CANDIDATE/'handoff-receipt.json'), candidate=c, expected_candidate_sha256=CANDIDATE_PIN,
            app_hex=read(CANDIDATE/'P7U-STOCK20260311-APP-ONLY.hex'),
            handoff=read(CANDIDATE/'P7U-STOCK20260311-AC000-HANDOFF.bin'), pass1=current, pass2=current,
            expected_capture_sha256=sha(current), board_identity_sha256=p['management_sha256'],
            security_receipt=security, expected_security_receipt_sha256=sha(canonical(security)))
        plan = t.bind_sparse_plan(plan, expected_plan_sha256=plan.manifest['plan_sha256'],
            previous_verified_image=expected, sparse_receipt=proof, expected_sparse_receipt_sha256=sha(canonical(proof)))
        # Exact reviewed v4.5 and V5 images add only APP sector 0x30000. Keep older
        # operator profiles at their original envelope; never infer permission
        # from an untrusted HEX length or widen through NV/CCFG.
        app_end = 0x32000 if SOURCE in (
            '98b882c49cdef2cb422822b8845bee3a4045765f',
            '85ce37c24802b0f16fec0afd00a1a0457656cd80',
            'e3a0f3b7726adf1f6c182973f135665a5c3857e0',
            '66ed700c2818c7a0963dad9160d55109009bbaac',
            '391d7a5b24d459f347a8ff2378c751ebcc7eec4b',
            '250441cd17c55e25c78d97e041f056574355ade7',
            '540d75a23d11587fb45fd892c5e9ae01ec0aab15') else 0x30000
        need(set(plan.sectors) == set(range(0, app_end, 8192)) | {0xAC000}, 'SECTOR_SCOPE')
        durable(PRIVATE, 'frozen-plan.json', plan.manifest)
        admission = await t.admit_sparse(rom, plan, expected_plan_sha256=plan.manifest['plan_sha256'],
            sparse_receipt=proof, expected_sparse_receipt_sha256=sha(canonical(proof)),
            security_receipt=security, expected_security_receipt_sha256=sha(canonical(security)),
            expected_live_identity_sha256=ROM_ID, operation_timeout=15, session_timeout=300)
        durable(PRIVATE, 'admission.json', admission)
        async def journal(event):
            with (PRIVATE/'mutation-journal.jsonl').open('ab') as f:
                os.chmod(f.name, 0o600); f.write(canonical(dict(event, wall_time=time.time()))+b'\n'); f.flush(); os.fsync(f.fileno())
            if event.get('event') in ('BEFORE_ERASE', 'SECTOR_VERIFIED', 'BEFORE_BOOT_VECTOR_COMMIT'):
                print(json.dumps({'event': event['event'], 'address': event['address']}), flush=True)
            return True
        result = await t.execute(rom, plan, admission, expected_plan_sha256=plan.manifest['plan_sha256'],
            expected_admission_sha256=admission['admission_sha256'], capture_receipt=proof,
            expected_capture_receipt_sha256=sha(canonical(proof)), expected_live_identity_sha256=ROM_ID,
            journal=journal, operation_timeout=15, session_timeout=900, same_session_sparse=True)
        durable(PRIVATE, 'verified-write.json', {'operation_plan_sha256': pin,
            'frozen_plan_sha256': plan.manifest['plan_sha256'],
            'journal_sha256': sha(read(PRIVATE/'mutation-journal.jsonl')), 'result': result})
        return result
    except BaseException as exc:
        durable(PRIVATE, 'hold.json', {'error_type': type(exc).__name__, 'automatic_retry': False,
                                      'automatic_boot': False, 'plan_sha256': pin,
                                      'safe_code': str(exc) if re.fullmatch('[A-Z0-9_]+', str(exc)) else 'OMITTED'})
        raise
    finally:
        if rom is not None: await rom.close()


def verified_write(package, pin):
    p = check_plan(package, pin); envelope = load(PRIVATE/'verified-write.json'); result = envelope['result']
    frozen = load(PRIVATE/'frozen-plan.json'); digest = frozen.pop('plan_sha256')
    snapshot = read(PRIVATE/'fresh-sparse-snapshot.bin')
    events = [json.loads(v) for v in read(PRIVATE/'mutation-journal.jsonl').splitlines()]
    need(envelope['operation_plan_sha256'] == pin and sha(canonical(frozen)) == digest and
         envelope['frozen_plan_sha256'] == digest and frozen['source_sha'] == SOURCE and
         frozen['capture_sha256'] == sha(snapshot) and
         envelope['journal_sha256'] == sha(read(PRIVATE/'mutation-journal.jsonl')), 'WRITE_RECEIPT_PIN')
    expected = [a for a in frozen['program_order']
                if frozen['sector_sha256'][str(a)] != sha(snapshot[a:a+8192])]
    verified = [(v['address'], v['sha256']) for v in events if v.get('event') == 'SECTOR_VERIFIED']
    need(result['written_sectors'] == expected and verified ==
         [(a, frozen['sector_sha256'][str(a)]) for a in expected], 'WRITE_JOURNAL')
    need(not (PRIVATE/'hold.json').exists() and
         result['status'] == 'APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL' and
         result['verification_scope'] == 'WRITTEN_SHA_PLUS_ALL88_ROM_CRC' and
         all(result[k] is False for k in ('nv_touched', 'ccfg_touched', 'reset_issued', 'automatic_rollback')),
         'WRITE_NOT_VERIFIED')
    return p


def boot(package, pin, ha):
    p = verified_write(package, pin)
    need(not (PRIVATE/'boot-intent.json').exists(), 'BOOT_CONSUMED')
    ha.policy(); ha.proof(False); need(ha.management() == p['management_sha256'], 'BOOT_BOARD')
    entity = ha.boot_binding()
    durable(PRIVATE, 'boot-intent.json', {'plan_sha256': pin, 'entity': entity, 'at': time.time()})
    ha.restart_radio(); time.sleep(4)
    ha.management(); need(Path(SERIAL).is_char_device(), 'BOOT_USB_MISSING'); ha.proof(False)
    durable(PRIVATE, 'start-intent.json', {'plan_sha256': pin, 'at': time.time()})
    ha.owner_action('start')
    owner = ha.inspect(); need(owner['running'] and owner['image'] == IMAGE and owner != p['owner'], 'NEW_OWNER')
    ha.proof(True)
    durable(PRIVATE, 'started-pending-serving.json', {'source': SOURCE, 'owner': owner, 'at': time.time()})
    return {'status': 'FLASH_VERIFIED_HOST_STARTED_PENDING_SERVING', 'source': SOURCE}


class StartupSerial:
    """Socket-shaped direct USB transport for the existing framed observer."""
    def __init__(self):
        import serial
        self.port = serial.Serial(SERIAL, 115200, timeout=.75, write_timeout=2)

    def settimeout(self, seconds):
        self.port.timeout = seconds; self.port.write_timeout = seconds

    def recv(self, count):
        # Socket recv returns available bytes; Serial.read(count) instead waits
        # for count bytes or its timeout, adding .75s to every short SRSP.
        raw = self.port.read(1)
        if not raw: raise TimeoutError()
        return raw + self.port.read(min(max(0,count-1),self.port.in_waiting))

    def sendall(self, raw):
        need(self.port.write(raw) == len(raw), 'STARTUP_SHORT_WRITE'); self.port.flush()

    def close(self): self.port.close()


def resume_pristine(znp, root, owner, evidence, *, source=None):
    source = SOURCE if source is None else source
    from p7u_r4_startup_observer import Q0, Q2, Q3, checked, decode_e1
    from p7u_r4_startup_transport import observe_after_srsp
    deadline = time.monotonic()+25; frames = {}
    for name, query in (('B1P1', Q2), ('B1S1', Q0), ('B1E1', Q3)):
        raw = znp.request(1, 241, query, deadline=deadline)
        evidence(name, raw, dict(znp.history[-1])); frames[name] = raw
    checked(frames['B1P1'], b'B1P1', 32, source); checked(frames['B1S1'], b'B1S1', 24, source)
    before = decode_e1(frames['B1E1'], source)
    need(frames['B1P1'][6] == 0 and frames['B1P1'][9] == 0 and
         frames['B1S1'][6] == 1 and frames['B1S1'][7] == 0 and frames['B1S1'][10] == 0 and
         before['state'] == 0 and before['first_error'] == 0 and before['milestones'] == 0,
         'STARTUP_NOT_PRISTINE')
    from p7u_r4_startup_observer import Q4, decode_e2, stack_evidence_supported
    if stack_evidence_supported(source):
        # V50 B1E2 is first exercised HERE, before the one retained startup
        # request is consumed: an unarmed NPI owner (native 4, or 6 only
        # while V46 services a pending SRSP) and the native Stack (5).
        raw = znp.request(1, 241, Q4, deadline=deadline)
        evidence('B1E2', raw, dict(znp.history[-1]))
        baseline = decode_e2(raw, source)
        need(not baseline['npi_armed'] and baseline['npi_priority'] in (4, 6) and
             baseline['stack_priority'] == 5 and not baseline['table_fallback'],
             'STARTUP_STACK_EVIDENCE_NOT_PRISTINE')
    def legacy(item):
        raw = znp.request(1, 8, item.to_bytes(2, 'little')+bytes(1), deadline=deadline)
        need(len(raw) >= 2 and raw[0] == 0 and len(raw) == raw[1]+2, 'STARTUP_NV_READ')
        return raw[2:]
    ieee = legacy(1); key = legacy(0x3a)
    need(ieee[::-1].hex() == owner['coordinator_ieee'] and len(key) == 17 and
         key[1:].hex() == owner['network_key']['key'], 'STARTUP_NETWORK_IDENTITY')
    durable(root, 'retained-startup-intent.json', {'source': source, 'attempts': 1,
            'command': 'ZDO_STARTUP_FROM_APP', 'payload': '6400', 'network_formation_authorized': False})
    srsp = znp.request(5, 0x40, bytes((100, 0)), deadline=time.monotonic()+10)
    need(srsp == bytes(1), 'STARTUP_SRSP')
    result = observe_after_srsp(znp, source, time.monotonic(), absolute_seconds=80, save=evidence)
    durable(root, 'startup-result.json', result)
    need(result['status'] == 'COORDINATOR_STATE9_MARKER_PASS', 'STARTUP_NATIVE_STATE9_NOT_PROVEN')
    return result


def startup_recovery(package, package_pin, pin, ha):
    sealed_tree(package, 'PACKAGE.json', package_pin)
    if globals().get('PAIRED_HOST_VERSION'):
        from p7u_paired_hold import verified_pair_package
        old_package=verified_pair_package(globals(),pin)
    else:
        old_package = Path('/share/p7u-pr154-operator-263100aae0a71ef3')
    p = verified_write(old_package, pin)
    root = PRIVATE/'guarded-startup-recovery'
    need(not root.exists(), 'STARTUP_RECOVERY_CONSUMED')
    need(load(PRIVATE/'boot-intent.json')['plan_sha256'] == pin and
         load(PRIVATE/'start-intent.json')['plan_sha256'] == pin and
         not (PRIVATE/'started-pending-serving.json').exists(), 'STARTUP_RECOVERY_NOT_FAILED_BOOT')
    failed = ha.inspect()
    need(not failed['running'] and failed['image'] == IMAGE and failed != p['owner'], 'STARTUP_RECOVERY_OWNER')
    log = run(['docker', 'logs', '--since', failed['started_at'], 'app_'+OWNER]).decode(errors='replace')
    need('AREQ - ZDO - stateChangeInd after 60000ms' in log, 'STARTUP_RECOVERY_FAILURE_NOT_PROVEN')
    ha.policy(); ha.proof(False)
    need(ha.management() == p['management_sha256'], 'STARTUP_RECOVERY_BOARD'); ha.boot_binding()
    root.mkdir(mode=0o700)
    durable(root, 'intent.json', {'plan_sha256': pin, 'package_pin': package_pin,
            'verified_write_sha256': sha(read(PRIVATE/'verified-write.json')), 'failed_owner': failed,
            'action': 'OPEN_USB_RESET_WAIT_SYS_RESET_IND_RESUME_ONCE_VERIFY_STATE9_THEN_HOST', 'at': time.time()})
    modules(package)
    from p7u_r4_startup_transport import FramedZnp, PrivateEvidenceJournal
    port = None; evidence = None
    try:
        port = StartupSerial(); znp = FramedZnp(port, source=SOURCE)
        evidence = PrivateEvidenceJournal(root/'startup-evidence.jsonl', SOURCE)
        os.chmod(root/'startup-evidence.jsonl', 0o600)
        durable(root, 'radio-restart-intent.json', {'at': time.time(), 'attempts': 1})
        ha.restart_radio()
        deadline = time.monotonic()+20
        while True:
            typ, command, data = znp._next(deadline)
            if typ == 0x41 and command == 0x80:
                need(len(data) == 6, 'STARTUP_RESET_IND_SHAPE'); break
        durable(root, 'boot-ready.json', {'no_request_before_reset_ind': True, 'at': time.time()})
        resume_pristine(znp, root, load(PRIVATE/'owner-backup-before-stop.json'), evidence)
    finally:
        if evidence is not None: evidence.close()
        if port is not None: port.close()
    ha.policy(); ha.proof(False)
    durable(root, 'host-start-intent.json', {'at': time.time(), 'attempts': 1})
    ha.owner_action('start'); owner = ha.inspect()
    need(owner['running'] and owner['image'] == IMAGE and owner != failed, 'STARTUP_RECOVERY_NEW_OWNER')
    ha.proof(True)
    durable(PRIVATE, 'started-pending-serving.json', {'source': SOURCE, 'owner': owner, 'at': time.time()})
    return {'status': 'NATIVE_COORDINATOR_STATE9_VERIFIED_HOST_STARTED_PENDING_SERVING', 'source': SOURCE}


def forward_transition(package):
    t, sec, reconcile, factory, sparse = modules(package)
    manifest = load(PRIVATE/'frozen-plan.json'); snapshot = read(PRIVATE/'fresh-sparse-snapshot.bin')
    payload, error = t._parse_intel_hex(CANDIDATE/'P7U-STOCK20260311-APP-ONLY.hex')
    need(not error, 'RECOVERY_FORWARD_HEX')
    sectors = {int(a): bytes(payload.get(i, 255) for i in range(int(a), int(a)+8192))
               for a in manifest['sector_sha256'] if int(a) != 0xAC000}
    sectors[0xAC000] = read(CANDIDATE/'P7U-STOCK20260311-AC000-HANDOFF.bin')
    forward = t._frozen(t.Transition(manifest, snapshot, sectors), manifest['plan_sha256'])
    expected = bytearray(snapshot)
    for a, raw in sectors.items(): expected[a:a+8192] = raw
    return t, sec, reconcile, factory, sparse, forward, bytes(expected)


def rollback_plan(package, package_pin, pin, ha):
    p = verified_write(Path('/share/p7u-pr154-operator-263100aae0a71ef3'), pin)
    failure = load(PRIVATE/'guarded-startup-recovery/startup-result.json')
    need(failure['status'] == 'FAILED_STOP_NO_RETRY' and failure['ready_observed'] is False and
         failure['failure_category'] == 'OBSERVER_TIMEOUT_STATE_UNKNOWN', 'ROLLBACK_NOT_FAILED_STARTUP')
    root = PRIVATE/'rollback-3c7dd95'; need(not root.exists(), 'ROLLBACK_PLAN_CONSUMED')
    owner = ha.inspect(); need(not owner['running'] and owner['image'] == IMAGE, 'ROLLBACK_OWNER')
    ha.policy(); ha.proof(False); need(ha.management() == p['management_sha256'], 'ROLLBACK_BOARD')
    t, sec, reconcile, factory, sparse, forward, expected = forward_transition(package)
    old, prior, result, prior_expected = installed(t)
    need(all(forward.snapshot[a:a+8192] == prior_expected[a:a+8192] for a in forward.sectors), 'ROLLBACK_OLD_PAIR')
    root.mkdir(mode=0o700)
    plan = {'source_to_restore': INSTALLED, 'forward_operation_plan_sha256': pin,
            'forward_plan_sha256': forward.manifest['plan_sha256'], 'package_pin': package_pin,
            'failed_startup_sha256': sha(canonical(failure)), 'owner': owner,
            'management_sha256': p['management_sha256'], 'created_at': time.time(),
            'scope': 'ORIGINAL_APP_AND_MATCHING_AC000_PRESERVE_CURRENT_NV_CCFG', 'automatic_retry': False}
    durable(root, 'plan.json', plan)
    return {'status': 'ROLLBACK_PLAN_PREPARED_NO_RADIO_ACTION', 'plan_sha256': sha(canonical(plan)), 'source': INSTALLED}


def rollback_check(package, pin, ha):
    root = PRIVATE/'rollback-3c7dd95'; private_root(root); p = load(root/'plan.json')
    need(sha(canonical(p)) == pin and p['source_to_restore'] == INSTALLED and
         p['scope'] == 'ORIGINAL_APP_AND_MATCHING_AC000_PRESERVE_CURRENT_NV_CCFG', 'ROLLBACK_PLAN_PIN')
    sealed_tree(package, 'PACKAGE.json', p['package_pin'])
    verified_write(Path('/share/p7u-pr154-operator-263100aae0a71ef3'), p['forward_operation_plan_sha256'])
    need(sha(read(PRIVATE/'guarded-startup-recovery/startup-result.json')) == p['failed_startup_sha256'], 'ROLLBACK_FAILURE_CHANGED')
    ha.policy(); ha.proof(False); need(ha.inspect() == p['owner'] and ha.management() == p['management_sha256'], 'ROLLBACK_OWNER_CHANGED')
    return root, p


async def rollback_write(package, pin, ha):
    root, p = rollback_check(package, pin, ha)
    need(0 <= time.time()-p['created_at'] < 1800 and not (root/'write-intent.json').exists(), 'ROLLBACK_EXPIRED_OR_CONSUMED')
    t, sec, reconcile, factory, sparse, forward, expected = forward_transition(package)
    durable(root, 'write-intent.json', {'plan_sha256': pin, 'at': time.time()})
    backup = read(DATA/'coordinator_backup.json'); durable(root, 'owner-backup.json', backup)
    rom = None
    try:
        rom = factory(); await rom.open(SERIAL)
        durable(root, 'bsl-entry-intent.json', {'attempts': 1, 'at': time.time()}); ha.enter_bsl(); await asyncio.sleep(1)
        for _ in range(48):
            try: raw = await asyncio.wait_for(rom.reader.read(128), .015)
            except asyncio.TimeoutError: break
            if not raw: break
        need(await rom.synchronize(), 'ROLLBACK_SYNC'); need(await rom.identity_sha256() == ROM_ID, 'ROLLBACK_SILICON')
        await rom.enable_fast_reads()
        capture = await sparse(rom, prior_full_verified=expected, expected_identity_sha256=ROM_ID, total_timeout_seconds=60)
        from dataclasses import asdict
        proof = asdict(capture.receipt); current = capture.snapshot; await rom.assert_read_status()
        durable(root, 'fresh-sparse-snapshot.bin', current); durable(root, 'sparse-receipt.json', proof)
        c = candidate(); abi = load(CANDIDATE/'security-native-abi.json'); reader = package/'security-reader-aarch64'
        bindings = {'capture_sha256': sha(current), 'baseline_capture_sha256': sha(forward.snapshot),
                    'abi_sha256': sha(sec.abi_tool.canonical(abi)), 'reader_sha256': sha(read(reader)),
                    'profile_sha256': c['profile_sha256'], 'native_manifest_sha256': c['native_manifest_sha256']}
        security = sec.preflight(capture=current, baseline=forward.snapshot, abi=abi, reader=reader,
                                 bindings=bindings, runtime_upgrade=True)
        durable(root, 'security-receipt.json', security)
        need(security['status'] == 'PASS_RETAINED_SECURITY_OFFLINE_ONLY', 'ROLLBACK_NATIVE_SECURITY')
        records, counts = sec.read_private(reader, current)
        owner = reconcile(historical=load(INPUT/'historical-backup.json'), fresh=json.loads(backup), records=records,
            abi=abi, native_preflight_pass=True, candidate_semantics_pass=True,
            baseline_counter_floor=native_network_floor(sec, records, abi))
        durable(root, 'current-owner-security.json', owner)
        need(owner['status'] == 'PASS_CURRENT_OWNER_OFFLINE_ONLY', 'ROLLBACK_OWNER_SECURITY')
        plan = t.prepare_recovery(forward, expected_forward_plan_sha256=p['forward_plan_sha256'],
            pass1=current, pass2=current, expected_capture_sha256=sha(current),
            security_receipt=security, expected_security_receipt_sha256=sha(canonical(security)))
        plan = t.bind_sparse_plan(plan, expected_plan_sha256=plan.manifest['plan_sha256'],
            previous_verified_image=expected, sparse_receipt=proof, expected_sparse_receipt_sha256=sha(canonical(proof)))
        need(set(plan.sectors) == set(forward.sectors), 'ROLLBACK_SECTOR_SCOPE')
        durable(root, 'frozen-plan.json', plan.manifest)
        admission = await t.admit_sparse(rom, plan, expected_plan_sha256=plan.manifest['plan_sha256'],
            sparse_receipt=proof, expected_sparse_receipt_sha256=sha(canonical(proof)),
            security_receipt=security, expected_security_receipt_sha256=sha(canonical(security)),
            expected_live_identity_sha256=ROM_ID, operation_timeout=15, session_timeout=300)
        durable(root, 'admission.json', admission)
        async def journal(event):
            with (root/'mutation-journal.jsonl').open('ab') as f:
                os.chmod(f.name, 0o600); f.write(canonical(dict(event, wall_time=time.time()))+b'\n'); f.flush(); os.fsync(f.fileno())
            return True
        result = await t.execute(rom, plan, admission, expected_plan_sha256=plan.manifest['plan_sha256'],
            expected_admission_sha256=admission['admission_sha256'], capture_receipt=proof,
            expected_capture_receipt_sha256=sha(canonical(proof)), expected_live_identity_sha256=ROM_ID,
            journal=journal, operation_timeout=15, session_timeout=900, same_session_sparse=True)
        durable(root, 'verified-write.json', {'operation_plan_sha256': pin, 'source_to_restore': INSTALLED,
            'frozen_plan_sha256': plan.manifest['plan_sha256'], 'journal_sha256': sha(read(root/'mutation-journal.jsonl')), 'result': result})
        return result
    except BaseException as exc:
        durable(root, 'hold.json', {'type': type(exc).__name__, 'automatic_retry': False})
        raise
    finally:
        if rom is not None: await rom.close()


def rollback_start(package, pin, ha):
    root, p = rollback_check(package, pin, ha)
    need(not (root/'hold.json').exists() and not (root/'boot-intent.json').exists(), 'ROLLBACK_BOOT_CONSUMED_OR_HELD')
    e = load(root/'verified-write.json'); result = e['result']; frozen = load(root/'frozen-plan.json')
    digest = frozen.pop('plan_sha256'); snapshot = read(root/'fresh-sparse-snapshot.bin')
    events = [json.loads(v) for v in read(root/'mutation-journal.jsonl').splitlines()]
    expected = [a for a in frozen['program_order'] if sha(snapshot[a:a+8192]) != frozen['sector_sha256'][str(a)]]
    need(e['operation_plan_sha256'] == pin and e['source_to_restore'] == INSTALLED and
         e['frozen_plan_sha256'] == digest == sha(canonical(frozen)) and
         e['journal_sha256'] == sha(read(root/'mutation-journal.jsonl')) and
         result['written_sectors'] == expected and
         [(v['address'], v['sha256']) for v in events if v.get('event') == 'SECTOR_VERIFIED'] ==
         [(a, frozen['sector_sha256'][str(a)]) for a in expected] and
         result['status'] == 'APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL' and
         all(result[k] is False for k in ('nv_touched', 'ccfg_touched', 'reset_issued', 'automatic_rollback')),
         'ROLLBACK_WRITE_NOT_VERIFIED')
    modules(package)
    from p7u_r4_startup_transport import FramedZnp, PrivateEvidenceJournal
    durable(root, 'boot-intent.json', {'plan_sha256': pin, 'at': time.time(), 'attempts': 1})
    port = None; evidence = None
    try:
        port = StartupSerial(); znp = FramedZnp(port, source=INSTALLED)
        evidence = PrivateEvidenceJournal(root/'startup-evidence.jsonl', INSTALLED)
        os.chmod(root/'startup-evidence.jsonl', 0o600); ha.restart_radio()
        deadline = time.monotonic()+20
        while True:
            typ, command, data = znp._next(deadline)
            if typ == 0x41 and command == 0x80:
                need(len(data) == 6, 'ROLLBACK_RESET_IND'); break
        need(len(znp.request(1, 2, deadline=time.monotonic()+10)) == 10, 'ROLLBACK_VERSION')
        resume_pristine(znp, root, load(root/'owner-backup.json'), evidence, source=INSTALLED)
    finally:
        if evidence is not None: evidence.close()
        if port is not None: port.close()
    ha.policy(); ha.proof(False); durable(root, 'host-start-intent.json', {'at': time.time(), 'attempts': 1})
    ha.owner_action('start'); owner = ha.inspect()
    need(owner['running'] and owner['image'] == IMAGE and owner != p['owner'], 'ROLLBACK_HOST_START')
    ha.proof(True)
    durable(PRIVATE, 'started-pending-serving.json', {'source': INSTALLED, 'owner': owner, 'at': time.time()})
    return {'status': 'ORIGINAL_FIRMWARE_NATIVE_STATE9_VERIFIED_HOST_STARTED_PENDING_SERVING', 'source': INSTALLED}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'deploy', 'boot', 'boot-native', 'resume-native', 'finish-native', 'rom-recovery-plan', 'rom-recovery-execute', 'startup-host-plan', 'startup-host-publish', 'startup-host-install', 'startup-host-continue', 'startup-capture-plan', 'startup-capture-start', 'instrumented-rom-plan', 'instrumented-rom-execute', 'status'))
    parser.add_argument('--operation-id', help='server-created 32-hex immutable operation ID')
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--package-pin', required=True)
    parser.add_argument('--input-pin')
    parser.add_argument('--plan-pin')
    parser.add_argument('--recovery-plan-pin', help='Immutable fresh V6 ROM recovery plan SHA256')
    parser.add_argument('--startup-host-pin', help='Immutable startup-capture host install plan SHA256')
    parser.add_argument('--capture-plan-pin', help='Immutable instrumented one-shot host startup plan SHA256')
    parser.add_argument('--instrumented-rom-pin', help='Immutable distinct no-write ROM round-trip plan SHA256')
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--binding-pin', required=True)
    a = parser.parse_args()
    need(re.fullmatch('[0-9a-f]{64}', a.package_pin) is not None, 'PACKAGE_PIN')
    package_metadata = sealed_tree(a.package, 'PACKAGE.json', a.package_pin)
    from p7u_paired_binding import binding_values
    globals().update(binding_values(read(a.binding), a.binding_pin, package_metadata))
    need(os.uname().machine == 'aarch64', 'HA_ARCHITECTURE')
    lock = os.open('/share/p7u-lifecycle/private/exclusive-manager.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        global PRIVATE
        if a.action == 'plan':
            need(a.input_pin is not None and a.plan_pin is None and
                 a.operation_id is None, 'PLAN_ARGUMENTS')
            operation_id, PRIVATE = select_operation(create=True)
            result = plan(a.package, a.package_pin, a.input_pin, HA())
        else:
            need(a.input_pin is None, 'EXECUTE_ARGUMENTS')
            operation_id, PRIVATE = select_operation(a.operation_id)
            if a.action == 'status':
                need(a.plan_pin is None and a.recovery_plan_pin is None and a.startup_host_pin is None and a.capture_plan_pin is None and a.instrumented_rom_pin is None, 'STATUS_ARGUMENTS')
                result = operation_status()
            else:
                need(a.plan_pin is not None, 'EXECUTE_ARGUMENTS')
                if a.action in ('instrumented-rom-plan','instrumented-rom-execute'):
                    from p7u_v6_instrumented_rom_once import plan as instrumented_plan, execute as instrumented_execute
                    need(a.capture_plan_pin is None and a.recovery_plan_pin is None and
                         a.startup_host_pin is None, 'INSTRUMENTED_ROM_ARGUMENT_SCOPE')
                    if a.action=='instrumented-rom-plan':
                        need(a.instrumented_rom_pin is None,'INSTRUMENTED_ROM_PLAN_ARGS')
                        result=instrumented_plan(globals(),a.package,a.package_pin,a.plan_pin,HA())
                    else:
                        need(a.instrumented_rom_pin is not None and
                             re.fullmatch('[0-9a-f]{64}',a.instrumented_rom_pin) is not None,
                             'INSTRUMENTED_ROM_PIN_ARGS')
                        result=instrumented_execute(globals(),a.package,a.package_pin,
                                 a.plan_pin,a.instrumented_rom_pin,HA())
                elif a.action in ('startup-capture-plan','startup-capture-start'):
                    from p7u_v6_startup_capture_once import plan as capture_plan, execute as capture_start
                    need(a.startup_host_pin is None and a.recovery_plan_pin is None and
                         a.instrumented_rom_pin is None, 'START_CAPTURE_UNEXPECTED_PLAN')
                    if a.action=='startup-capture-plan':
                        need(a.capture_plan_pin is None,'START_CAPTURE_PLAN_ARGS')
                        result=capture_plan(globals(),a.package,a.package_pin,a.plan_pin,HA())
                    else:
                        need(a.capture_plan_pin is not None and
                             re.fullmatch('[0-9a-f]{64}',a.capture_plan_pin) is not None,
                             'START_CAPTURE_PIN_ARGS')
                        result=capture_start(globals(),a.package,a.package_pin,
                                             a.plan_pin,a.capture_plan_pin,HA())
                elif a.action in ('startup-host-plan','startup-host-publish','startup-host-install','startup-host-continue'):
                    from p7u_v6_startup_host_install import (
                        plan as host_plan, publish as host_publish,
                        install_stopped as host_install,
                        continue_pre_mutation as host_continue)
                    need(a.recovery_plan_pin is None and a.capture_plan_pin is None and a.instrumented_rom_pin is None, 'STARTUP_HOST_RECOVERY_PIN_FORBIDDEN')
                    if a.action == 'startup-host-plan':
                        need(a.startup_host_pin is None, 'STARTUP_HOST_PLAN_ARGUMENTS')
                        result=host_plan(globals(),a.package,a.package_pin,a.plan_pin,HA())
                    else:
                        need(a.startup_host_pin is not None and
                             re.fullmatch('[0-9a-f]{64}',a.startup_host_pin) is not None,
                             'STARTUP_HOST_PLAN_PIN')
                        action=({'startup-host-publish':host_publish,
                                 'startup-host-install':host_install,
                                 'startup-host-continue':host_continue}[a.action])
                        result=action(globals(),a.package,a.package_pin,
                                      a.plan_pin,a.startup_host_pin,HA())
                elif a.action in ('rom-recovery-plan','rom-recovery-execute'):
                    from p7u_v6_rom_recovery import plan as rom_plan, execute as rom_execute
                    need(a.startup_host_pin is None and a.capture_plan_pin is None and a.instrumented_rom_pin is None and
                         (a.action == 'rom-recovery-execute' or a.recovery_plan_pin is None),
                         'RECOVERY_PLAN_PHASE_ARGUMENTS')
                    if a.action == 'rom-recovery-plan':
                        result=rom_plan(globals(),a.package,a.package_pin,a.plan_pin,HA())
                    else:
                        need(a.recovery_plan_pin is not None and
                             re.fullmatch('[0-9a-f]{64}',a.recovery_plan_pin) is not None,
                             'RECOVERY_EXECUTE_PIN')
                        result=rom_execute(globals(),a.package,a.package_pin,
                                           a.plan_pin,a.recovery_plan_pin,HA())
                else:
                    need(a.recovery_plan_pin is None and a.startup_host_pin is None and a.capture_plan_pin is None and a.instrumented_rom_pin is None, 'UNEXPECTED_RECOVERY_PIN')
                    if a.action=='deploy': result=asyncio.run(deploy(a.package,a.plan_pin,HA()))
                    elif a.action=='boot': result=boot(a.package,a.plan_pin,HA())
                    elif a.action=='boot-native':
                        from p7u_paired_boot import boot_native
                        result=boot_native(globals(),a.package,a.package_pin,a.plan_pin,HA())
                    elif a.action=='resume-native': result=startup_recovery(a.package,a.package_pin,a.plan_pin,HA())
                    else:
                        from p7u_paired_finish import finish
                        result=finish(globals(),a.package,a.package_pin,a.plan_pin,HA())

        print(json.dumps(result), flush=True)
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'status': 'HOLD', 'error_type': type(exc).__name__,
                          'reason': str(exc) if isinstance(exc, Hold) else 'INSPECT_PRIVATE_RECEIPTS_NO_RETRY'}), flush=True)
        raise SystemExit(1)
