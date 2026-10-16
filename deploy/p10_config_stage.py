"""Stage a private, reproducible Z2M target config and exact rollback config.

NO writes to HA, Zigbee2MQTT, USB radios or coordinators. With --target-host,
verify the radio-2 ZNP TCP endpoint FROM Home Assistant before staging its URI.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import yaml
from p10_cutover_prepare import offline, private_target
from p10_target_endpoint import check_address, run as verify_target


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def render(raw: bytes, host: str, port: int) -> bytes:
    check_address(host, port)
    source = yaml.safe_load(raw)
    if not isinstance(source, dict) or not isinstance(source.get('serial'), dict):
        raise ValueError('Invalid source Zigbee2MQTT serial config')
    if source['serial'].get('adapter') != 'ember':
        raise ValueError('Source is not the expected Ember network')
    target = deepcopy(source)
    target['serial'].update({'adapter': 'zstack', 'port': f'tcp://{host}:{port}',
                             'baudrate': 115200, 'rtscts': False})
    before = deepcopy(source); after = deepcopy(target)
    before.pop('serial'); after.pop('serial')
    if before != after or target.get('channel') != source.get('channel'):
        raise RuntimeError('Unrelated Zigbee2MQTT config changed during staging')
    encoded = render_minimal(raw, host, port)
    if yaml.safe_load(encoded) != target:
        raise RuntimeError('Staged Zigbee2MQTT config did not roundtrip')
    return encoded


def render_minimal(raw: bytes, host: str, port: int) -> bytes:
    import re
    lines = raw.decode('utf-8').splitlines(keepends=True)
    heads = [i for i, line in enumerate(lines) if re.fullmatch(r'serial:\s*(?:#.*)?\r?\n?', line)]
    if len(heads) != 1:
        raise ValueError('Expected one plain, root-level serial YAML block')
    start = heads[0] + 1
    stop = next((i for i in range(start, len(lines)) if lines[i].strip() and not lines[i][0].isspace() and not lines[i].lstrip().startswith('#')), len(lines))
    # Rewrite only the direct serial scalars; optional baud/flow values
    # must be normalized or inserted (review P2). Preserve the rest of
    # the configuration byte-for-byte, including comments and CRLF.
    newline = '\\r\\n' if b'\\r\\n' in raw else '\\n'
    targets = (('port', f'tcp://{host}:{port}'), ('adapter', 'zstack'),
               ('baudrate', '115200'), ('rtscts', 'false'))
    additions = []
    for key, value in targets:
        matches = [(i, re.fullmatch(r'  ' + key + r':[^\\r\\n]*(\\r?\\n?)', lines[i]))
                   for i in range(start, stop)]
        matches = [(i, match) for i, match in matches if match is not None]
        if len(matches) > 1 or (len(matches) == 0 and key in ('port', 'adapter')):
            raise ValueError('Expected exactly one direct serial.'+key+' scalar line')
        if not matches:
            additions.append('  ' + key + ': ' + value + newline)
        else:
            i, match = matches[0]
            lines[i] = '  ' + key + ': ' + value + match.group(1)
    if additions:
        # An unterminated final scalar would otherwise swallow additions.
        if stop > start and not lines[stop-1].endswith(('\\n', '\\r')):
            lines[stop-1] += newline
        lines[stop:stop] = additions
    return ''.join(lines).encode('utf-8')


def stage(snapshot: Path, destination: Path, backup_id: str,
          host: str | None, port: int) -> dict:
    source = private_target(snapshot)
    output = private_target(destination)
    if not source.is_dir() or output.exists():
        raise ValueError('Missing private source or target already exists')
    if not backup_id or not backup_id.isalnum() or len(backup_id) != 8:
        raise ValueError('Provide the independently verified native HA backup slug')
    report = offline(source)
    if report.get('captured_file_integrity_pass') is not True:
        raise RuntimeError('Input snapshot has no verified integrity manifest')
    original = (source / 'configuration.yaml').read_bytes()
    verified = verify_target(host, port, 20260310) if host else None
    proposed = render(original, host, port) if verified else None
    output.mkdir(parents=True, exist_ok=False)
    with (output / 'rollback_configuration.yaml').open('xb') as stream:
        stream.write(original)
    if proposed is not None:
        with (output / 'target_configuration.yaml').open('xb') as stream:
            stream.write(proposed)
    summary = {'status': 'CONFIG_STAGED_NOT_DEPLOYED' if verified else 'ROLLBACK_CONFIG_STAGED',
               'snapshot_manifest_verified': True, 'native_ha_backup_slug': backup_id,
               'source_config_sha256': digest(original),
               'rollback_config_sha256': digest((output / 'rollback_configuration.yaml').read_bytes()),
               'target_config_sha256': digest(proposed) if proposed else None,
               'target_znp_verified_from_ha': bool(verified), 'target_port': port if verified else None,
               'source_device_records': report['z2m_database']['records'],
               'source_group_records': report['z2m_database']['groups'],
               'coordinator_ieee_transfer_tested': False,
               'coordinator_network_state_restored': False,
               'production_changed': False,
               'migration_authorized': False}
    with (output / 'cutover_plan.private.json').open('x', encoding='utf-8') as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
    return summary


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--native-backup-slug', required=True)
    p.add_argument('--target-host', help='Optional exact MR4U LAN IPv4; no host = rollback-only plan')
    p.add_argument('--target-port', type=int, default=7638,
                   help='Radio-2 socket port; always checked by ZNP SYS_VERSION')
    args = p.parse_args(argv)
    try:
        print(json.dumps(stage(args.snapshot, args.out, args.native_backup_slug,
                               args.target_host, args.target_port), sort_keys=True, indent=2))
        return 0
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print('P10_CONFIG_STAGE_ERROR: ' + str(exc)[:150], file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
