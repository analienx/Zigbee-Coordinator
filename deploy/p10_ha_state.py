"""Conservatively prove the Zigbee2MQTT add-on cannot own the P10 radio.

Both a stopped container and a verified *absent* crashed add-on container
are quiescent; any ambiguity fails closed.
"""
from __future__ import annotations
from p10_data_bundle import addon_info, ADDON


def addon_quiescent(client, info: dict | None = None) -> dict:
    details = addon_info(client) if info is None else info
    state = details.get('state')
    if state not in ('stopped', 'error'):
        raise RuntimeError('Zigbee2MQTT Supervisor state is not stopped or error')
    name = 'app_' + ADDON
    _, output, _ = client.exec_command("docker inspect --format '{{.State.Running}}' " + name, timeout=15)
    raw = output.read().decode('utf-8', 'replace').strip()
    status = output.channel.recv_exit_status()
    if status == 0 and raw == 'false':
        reason = 'stopped_container'
    elif status != 0 and state == 'error':
        # A crashed add-on can have no container at all. Require independent
        # Docker enumeration to prove no app with this slug is present.
        _, listed, _ = client.exec_command("docker ps -a --format '{{.Names}}'", timeout=15)
        names = listed.read().decode('utf-8', 'replace').splitlines()
        if listed.channel.recv_exit_status() != 0 or name in names or any('zigbee2mqtt' in n.lower() for n in names):
            raise RuntimeError('Container absent/duplicate state cannot be verified')
        reason = 'error_addon_no_docker_container'
    else:
        raise RuntimeError('Zigbee2MQTT is running or Docker state cannot be verified')
    return {'addon_quiescent': True, 'supervisor_state': state,
            'addon_container_running': False, 'quiescence_evidence': reason,
            'crash_state_recovered_for_handoff': state == 'error'}
