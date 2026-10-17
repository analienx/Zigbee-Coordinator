"""Stage a complete PRIVATE, reversible SONOFF Ember -> MR4U P10 cutover kit.

No live HA writes, app stop/start, radio NV/IEEE writes or unapproved restore.
Use `p10_data_bundle.py capture --mode hot` to rehearse while Z2M runs;
repeat --mode cold after Z2M stops and stage that immutable final bundle.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile
import yaml

from p10_config_stage import render
from p10_cutover_prepare import private_target
from p10_data_bundle import verify as verify_bundle, OPTIONS_NAME
from p10_device_acceptance import parse_database, compare
from p10_target_endpoint import run as verify_endpoint

REQUIRED_EVIDENCE = ('sonoff_physically_isolated', 'p10_znp_chip_verified',
                     'old_ieee_effective_on_p10', 'existing_pan_and_key_restored',
                     'source_frame_counter_state_reviewed', 'single_znp_client_confirmed')


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes) -> str:
    with path.open('xb') as stream:
        stream.write(data)
    return _sha(data)


def inspect_effective_serial(config: dict, options: dict) -> dict:
    """Add-on options may override the Z2M data-folder serial YAML."""
    src = config.get('serial')
    addon = options.get('serial')
    if not isinstance(src, dict) or not isinstance(addon, dict):
        raise ValueError('Both data-folder and add-on serial configuration are required')
    # Require shared explicit source port/adapter; optional source baud
    # and HWFC fields may be absent in either configuration. Only allow
    # absent-vs-present when the explicit value equals the known default.
    for name in ('port', 'adapter'):
        if name not in src or type(addon.get(name)) is not type(src[name]) or addon[name] != src[name]:
            raise ValueError('Serial setting disagreement between YAML and add-on options: ' + name)
    for name, default in (('baudrate', 115200), ('rtscts', False)):
        left, right = src.get(name, default), addon.get(name, default)
        if type(left) is not type(default) or type(right) is not type(default) or left != right:
            raise ValueError('Serial setting disagreement between YAML and add-on options: ' + name)
    socat = options.get('socat')
    if isinstance(socat, dict) and socat.get('enabled') is True:
        raise ValueError('Enabled socat override needs its own reviewed migration path')
    if src['adapter'] != 'ember' or not isinstance(src['port'], str) or not src['port'].startswith('/dev/'):
        raise ValueError('Expected current SONOFF Ember USB source')
    return {'source_adapter': 'ember', 'addon_serial_override_present': True,
            'addon_serial_matches_yaml': True, 'socat_override_active': False}


def render_addon_options(options: dict, host: str, port: int) -> dict:
    target = deepcopy(options)
    target['serial']['port'] = f'tcp://{host}:{port}'
    target['serial']['adapter'] = 'zstack'
    target['serial']['baudrate'] = 115200
    target['serial']['rtscts'] = False
    original_without_serial = deepcopy(options); original_without_serial.pop('serial')
    target_without_serial = deepcopy(target); target_without_serial.pop('serial')
    if original_without_serial != target_without_serial:
        raise RuntimeError('Unexpected change to non-serial add-on options')
    for key in options['serial']:
        if key not in ('port', 'adapter', 'baudrate', 'rtscts') and target['serial'][key] != options['serial'][key]:
            raise RuntimeError('Unexpected add-on serial option changed')
    return target


def identity_checks(database: bytes, coordinator: bytes, config: dict) -> dict:
    devices = parse_database(database)
    stored = json.loads(coordinator)
    old = next((ieee for ieee, item in devices['devices'].items() if item['role'] == 'Coordinator'), None)
    backed = stored.get('coordinator_ieee')
    if old is None or not isinstance(backed, str) or len(backed) != 16:
        raise ValueError('Missing coordinator identity in database or coordinator backup')
    direct = old.removeprefix('0x') == backed.lower()
    reverse = old.removeprefix('0x') == bytes.fromhex(backed)[::-1].hex()
    if not (direct or reverse):
        raise ValueError('Coordinator IEEE mismatch between database and backup')
    declared_channel = config.get('channel', (config.get('advanced') or {}).get('channel'))
    if declared_channel is not None and declared_channel != stored.get('channel'):
        raise ValueError('Configured Zigbee channel disagrees with coordinator backup')
    nwk = stored.get('network_key')
    if not isinstance(nwk, dict) or type(nwk.get('frame_counter')) is not int:
        raise ValueError('Coordinator network security counter not present')
    return {'network_channel': stored.get('channel'), 'source_ieee_records_agree': True,
            'source_ieee_encoding': 'direct' if direct else 'reversed',
            'network_counter_present': True, 'source_device_count': len(devices['devices']),
            'source_group_count': len(devices['group_ids'])}


def stage(bundle: Path, output: Path, host: str | None = None, port: int | None = None) -> dict:
    bundle, output = private_target(bundle), private_target(output)
    checked = verify_bundle(bundle)
    if output.exists():
        raise FileExistsError('Refusing to overwrite an existing cutover staging directory')
    if bool(host) != (port is not None):
        raise ValueError('Target IPv4 address and radio socket port must be given together')
    with zipfile.ZipFile(bundle) as source:
        original = source.read('data/configuration.yaml')
        options_bytes = source.read(OPTIONS_NAME)
        options_wrapper = json.loads(options_bytes)
        options = options_wrapper['options']
        parsed = yaml.safe_load(original)
        effective = inspect_effective_serial(parsed, options)
        identity = identity_checks(source.read('data/database.db'),
                                   source.read('data/coordinator_backup.json'), parsed)
        inventory = parse_database(source.read('data/database.db'))
    target_verified = verify_endpoint(host, port, 20260310) if host else None
    new_yaml = render(original, host, port) if target_verified else None
    new_options = (render_addon_options(options, host, port) if target_verified else None)
    if new_yaml is not None:
        new_parsed = yaml.safe_load(new_yaml)
        new_effective = new_options['serial']
        if any(new_parsed['serial'].get(k) != new_effective.get(k) for k in ('port','adapter','baudrate','rtscts')):
            raise RuntimeError('Staged YAML and staged add-on settings conflict')
    output.mkdir(parents=True, exist_ok=False)
    hashes = {'rollback_configuration.yaml': _write(output / 'rollback_configuration.yaml', original),
              'rollback_addon_options.private.json': _write(output / 'rollback_addon_options.private.json', options_bytes)}
    if new_yaml is not None:
        hashes['target_configuration.yaml'] = _write(output / 'target_configuration.yaml', new_yaml)
        proposed_options = json.dumps(options_wrapper | {'options': new_options}, sort_keys=True, indent=2).encode()
        hashes['target_addon_options.private.json'] = _write(output / 'target_addon_options.private.json', proposed_options)
    baseline = {'captured_at_utc': datetime.now(timezone.utc).isoformat(),
                'baseline': inventory, 'source_database_file': 'verified-private-z2m-bundle'}
    _write(output / 'device_baseline.private.json', json.dumps(baseline, sort_keys=True).encode())
    report = {'status': 'TARGET_CONFIG_STAGED_NOT_DEPLOYED' if target_verified else 'SOURCE_RECOVERY_STAGED',
              'bundle_cold': checked['cold_consistent'], 'bundle_sha256': _sha(bundle.read_bytes()),
              'bundle_integrity_pass': True, 'target_znp_verified_from_ha': bool(target_verified),
              'source': identity | effective, 'rollback_and_target_hashes': hashes,
              'manual_cutover_gates': {name: False for name in REQUIRED_EVIDENCE},
              'app_stop_or_radio_isolation_executed': False,
              'network_restore_implemented': False, 'migration_authorized': False}
    _write(output / 'cutover_state.private.json', json.dumps(report, sort_keys=True, indent=2).encode())
    return {k: v for k, v in report.items() if k not in ('bundle_sha256', 'rollback_and_target_hashes')}


def assess(baseline_file: Path, post_bundle: Path, cutover_at: str, evidence_file: Path | None = None) -> dict:
    if not verify_bundle(post_bundle)['integrity_pass']:
        raise ValueError('Post-cutover bundle integrity mismatch')
    with zipfile.ZipFile(post_bundle) as archive:
        observed = parse_database(archive.read('data/database.db'))
    baseline = json.loads(private_target(baseline_file).read_text(encoding='utf-8'))
    summary, device_details = compare(baseline, observed, datetime.fromisoformat(cutover_at.replace('Z', '+00:00')))
    evidence = {} if evidence_file is None else json.loads(private_target(evidence_file).read_text())
    if any(evidence.get(item) is not True for item in ('unicast_inbound_outbound', 'groupcast',
                                                      'critical_automations', 'routing_and_join_review')):
        summary['functional_acceptance'] = 'NOT_PROVEN'
    else:
        summary['functional_acceptance'] = 'OPERATOR_RECORDED_ONLY_NOT_AUTOMATICALLY_ATTESTED'
    summary['manual_evidence_required'] = True
    return {'summary': summary, 'private_device_details': device_details}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    s = sub.add_parser('stage'); s.add_argument('--bundle', required=True, type=Path)
    s.add_argument('--out', required=True, type=Path)
    s.add_argument('--target-host'); s.add_argument('--target-port', type=int)
    a = sub.add_parser('assess'); a.add_argument('--baseline', required=True, type=Path)
    a.add_argument('--post-bundle', required=True, type=Path)
    a.add_argument('--cutover-utc', required=True)
    a.add_argument('--evidence', type=Path); a.add_argument('--out', required=True, type=Path)
    args = p.parse_args(argv)
    try:
        if args.action == 'stage':
            report = stage(args.bundle, args.out, args.target_host, args.target_port)
        else:
            output = private_target(args.out)
            if output.exists(): raise FileExistsError('Existing private acceptance report')
            report = assess(args.baseline, private_target(args.post_bundle), args.cutover_utc, args.evidence)
            output.parent.mkdir(parents=True, exist_ok=True)
            _write(output, json.dumps(report, sort_keys=True, indent=2).encode())
            report = report['summary']
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, zipfile.BadZipFile) as exc:
        print('P10_WORKFLOW_ERROR: ' + str(exc)[:180], file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
