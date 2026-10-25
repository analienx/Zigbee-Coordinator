"""Fixed-target PR154 deployment. No arbitrary shell, device, firmware or HTTP URL.

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
import subprocess
import sys
import tarfile
import time
import urllib.request

SOURCE = '2499154215c40ab6435b90886be96c8af6e37a74'
INSTALLED = '3c7dd95c99194ec5e62a70ea4ff9e55f47cc470d'
CANDIDATE_PIN = 'c802d65b8ff8cf7777739cc61c5d5efd185d021f6ff5db71dbb9b968747820b6'
IMAGE = 'sha256:6c7a5f2c82b46c1785ecedf006514bf009dd7fcc0437382fba99c6396852ce3b'
ROM_ID = '0be85df5dc59b5996f9ebb3339c2ac8491bf1015903817278929cc41ec2fbaf2'
OWNER = 'local_p7u_r4_native_host'
SERIAL = '/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00'
INPUT = Path('/share/p7u-pr154-input-2499154')
CANDIDATE = Path('/share/p7u-pr154-stage-2499154')
PRIVATE = Path('/share/p7u-pr154-deployment-2499154-v2')
FAILED_PRIVATE = Path('/share/p7u-pr154-deployment-2499154')
FAILED_PACKAGE_PIN = 'b18be817fde67a86d8efd6375efb93f8c40a44dcc2be7d8a40d2726f15ef402f'
DATA = Path('/homeassistant/zigbee2mqtt')
INSPECTOR_IMAGE = 'sha256:bc813fe0d598b3c6743449b87cf263b1080b752f45fc4b22c947f9e1fc59a24b'
INPUT_NAMES = {'installed-candidate.json', 'installed-app.hex', 'installed-handoff.bin',
               'installed-plan.json', 'installed-result.json', 'installed-before.bin',
               'management.json', 'historical-backup.json'}


class Hold(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Hold('P7U_DEPLOY_HOLD_' + reason)


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


def candidate():
    c = load(CANDIDATE/'candidate.json')
    need(sha(canonical(c)) == CANDIDATE_PIN and c['source_sha'] == SOURCE, 'FIRMWARE_PIN')
    for name in ('P7U-STOCK20260311-APP-ONLY.hex', 'P7U-STOCK20260311-AC000-HANDOFF.bin',
                 'profile.json', 'security-native-abi.json', 'handoff-receipt.json'):
        need(sha(read(CANDIDATE/name)) == c['files'][name], 'CANDIDATE_FILE')
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
        a = json.loads(run(['docker', 'inspect', 'app_'+OWNER]))[0]
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
    return old, c, result, bytes(expected)


def quiescent_provenance(ha, owner):
    """Admit only the consumed, pre-BSL v1 stop and its failed one-time start."""
    private_root(FAILED_PRIVATE)
    names = {'plan.json', 'reader-baseline-check.json', 'owner-backup-before-stop.json',
             'execute-intent.json', 'hold.json', 'restore-intent.json'}
    need({v.name for v in FAILED_PRIVATE.iterdir()} == names, 'QUIESCENT_NOT_PRE_BSL')
    p = load(FAILED_PRIVATE/'plan.json'); h = load(FAILED_PRIVATE/'hold.json')
    r = load(FAILED_PRIVATE/'restore-intent.json'); pin = sha(canonical(p))
    need(p['source'] == SOURCE and p['installed'] == INSTALLED and
         p['package_pin'] == FAILED_PACKAGE_PIN and p['candidate_pin'] == CANDIDATE_PIN and
         load(FAILED_PRIVATE/'execute-intent.json')['plan_sha256'] == pin and
         h == {'error_type': 'TimeoutError', 'automatic_retry': False,
               'automatic_boot': False, 'plan_sha256': pin} and
         r['failed_plan_sha256'] == pin and r['failed_hold_sha256'] == sha(canonical(h)) and
         r['package_pin'] == 'f9f6b06e08579f0532c6be9524ab5c8263cb13ee470188d2fb951c3a685fe16a' and
         r['action'] == 'START_UNCHANGED_HOST_NO_RADIO_RESET', 'QUIESCENT_PROVENANCE')
    need(owner['running'] is False and owner['image'] == IMAGE and owner != p['owner'] and
         datetime.datetime.fromisoformat(owner['started_at'].replace('Z', '+00:00')).timestamp() >= r['at'],
         'QUIESCENT_OWNER')
    a = ha.info(OWNER)
    need(a['state'] in ('stopped', 'error') and a['version'] == '0.2.1-068ae05e9f9a', 'QUIESCENT_APP')
    ha.proof(False)
    return sha(canonical({'files': {n: sha(read(FAILED_PRIVATE/n)) for n in sorted(names)}, 'owner': owner}))


def plan(package, package_pin, input_pin, ha):
    sealed_tree(package, 'PACKAGE.json', package_pin)
    sealed_tree(INPUT, 'INPUT.json', input_pin, INPUT_NAMES)
    c = candidate(); t, security, reconcile, rom, capture = modules(package)
    old, prior, result, expected = installed(t)
    need(result['status'] == 'APP_AND_AC000_VERIFIED_STILL_IN_BSL' and
         result['verification_scope'] == 'ALL88_ROM_SHA' and
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
    backup = load(DATA/'coordinator_backup.json')
    from p7u_usb_security_model import parse_backup
    now = parse_backup(backup); need(100 <= len(now.peers) <= 107, 'OWNER_BACKUP')
    need(Path(SERIAL).is_char_device(), 'SERIAL_DEVICE')
    need(not PRIVATE.exists(), 'OPERATION_EXISTS')
    PRIVATE.mkdir(mode=0o700)
    durable(PRIVATE, 'reader-baseline-check.json', baseline_check)
    p = {'schema': 'p7u-pr154-ha-operation-v1', 'source': SOURCE, 'installed': INSTALLED,
         'created_at': time.time(), 'package_pin': package_pin, 'input_pin': input_pin,
         'owner': owner, 'management_sha256': management, 'installed_plan_sha256': old.manifest['plan_sha256'],
         'installed_result_sha256': sha(canonical(result)), 'prior_verified_image_sha256': sha(expected),
         'scope': 'CHANGED_APP_AND_PAIRED_AC000_PRESERVE_NV_CCFG', 'boot_separate': True,
         'candidate_pin': CANDIDATE_PIN, 'automatic_retry': False, 'automatic_rollback': False,
         'quiescent_provenance_sha256': quiescent}
    durable(PRIVATE, 'plan.json', p)
    return {'status': 'PREPARED_OWNER_UNCHANGED', 'plan_sha256': sha(canonical(p)), 'source': SOURCE}


def check_plan(package, pin):
    private_root(PRIVATE); p = load(PRIVATE/'plan.json')
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
    quiescent = p.get('quiescent_provenance_sha256')
    if quiescent:
        need(quiescent_provenance(ha, p['owner']) == quiescent, 'QUIESCENT_CHANGED')
    else:
        ha.proof(True)
    durable(FAILED_PRIVATE, 'restored-pending-serving.json',
            {'installed': INSTALLED, 'owner': owner, 'request_sha256': sha(canonical(request)),
             'at': time.time()})
    return {'status': 'UNCHANGED_FIRMWARE_HOST_STARTED_PENDING_SERVING', 'source': INSTALLED}


async def deploy(package, pin, ha):
    p = check_plan(package, pin)
    need(0 <= time.time()-p['created_at'] < 1800, 'PLAN_EXPIRED')
    need(not (PRIVATE/'execute-intent.json').exists(), 'EXECUTION_CONSUMED')
    t, sec, reconcile, factory, sparse = modules(package)
    old, prior, result, expected = installed(t)
    need(sha(expected) == p['prior_verified_image_sha256'] and
         sha(canonical(result)) == p['installed_result_sha256'], 'INSTALLED_RECEIPT_CHANGED')
    ha.policy(); need(ha.inspect() == p['owner'] and ha.management() == p['management_sha256'], 'OWNER_CHANGED')
    ha.proof(True)
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
        rom = factory(); await rom.open(SERIAL)
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
        durable(PRIVATE, 'fresh-sparse-snapshot.bin', current)
        durable(PRIVATE, 'sparse-receipt.json', proof)
        c = candidate(); abi = load(CANDIDATE/'security-native-abi.json'); reader = package/'security-reader-aarch64'
        bindings = {'capture_sha256': sha(current), 'baseline_capture_sha256': sha(old.snapshot),
                    'abi_sha256': sha(sec.abi_tool.canonical(abi)), 'reader_sha256': sha(read(reader)),
                    'profile_sha256': c['profile_sha256'], 'native_manifest_sha256': c['native_manifest_sha256']}
        security = sec.preflight(capture=current, baseline=old.snapshot, abi=abi, reader=reader, bindings=bindings)
        durable(PRIVATE, 'security-receipt.json', security)
        need(security['status'] == 'PASS_RETAINED_SECURITY_OFFLINE_ONLY', 'NATIVE_SECURITY')
        records, counts = sec.read_private(reader, current)
        nib = sec.get(records, 0, 0x21, abi['structs']['nwkIB_t']['size'])
        pan = sec.field(nib, abi, 'nwkIB_t', 'extendedPANID')
        floors = [sec.number(raw, abi, 'nwkSecMaterialDesc_t', 'FrameCounter')
                  for (system, item, index), raw in records.items() if system == 1 and item == 7 and
                  sec.field(raw, abi, 'nwkSecMaterialDesc_t', 'extendedPANID') == pan]
        owner = reconcile(historical=load(INPUT/'historical-backup.json'), fresh=json.loads(backup),
            records=records, abi=abi, native_preflight_pass=True, candidate_semantics_pass=True,
            baseline_counter_floor=floors[0] if len(floors) == 1 else None)
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
        need(set(plan.sectors) == set(range(0, 0x30000, 8192)) | {0xAC000}, 'SECTOR_SCOPE')
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
                                      'automatic_boot': False, 'plan_sha256': pin})
        raise
    finally:
        if rom is not None: await rom.close()


def boot(package, pin, ha):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'deploy', 'boot', 'restore-pre-bsl'))
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--package-pin', required=True)
    parser.add_argument('--input-pin')
    parser.add_argument('--plan-pin')
    a = parser.parse_args()
    need(re.fullmatch('[0-9a-f]{64}', a.package_pin) is not None, 'PACKAGE_PIN')
    sealed_tree(a.package, 'PACKAGE.json', a.package_pin)
    need(os.uname().machine == 'aarch64', 'HA_ARCHITECTURE')
    lock = os.open('/share/p7u-lifecycle/private/exclusive-manager.lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if a.action == 'plan':
            need(a.input_pin is not None and a.plan_pin is None, 'PLAN_ARGUMENTS')
            result = plan(a.package, a.package_pin, a.input_pin, HA())
        else:
            need(a.plan_pin is not None and a.input_pin is None, 'EXECUTE_ARGUMENTS')
            if a.action == 'restore-pre-bsl':
                result = restore_pre_bsl(a.package, a.package_pin, a.plan_pin, HA())
            else:
                result = asyncio.run(deploy(a.package, a.plan_pin, HA())) if a.action == 'deploy' else boot(a.package, a.plan_pin, HA())
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
