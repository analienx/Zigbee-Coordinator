"""Private, capture-bound APP plus AC000 transition; no live adapter or CLI.

The historical APP-only writer remains unchanged. This distinct operation
requires separate owner approval for the single boot sector. It cannot erase
NV/CCFG, reset, reconnect, retry, restore NV or automatically roll back.
After any uncertain operation stay in ROM BSL and independently read flash.
Stock rollback is APP plus original boot code only, using a new reviewed plan;
never replay the old NV snapshot after the candidate has run.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import time
from typing import NamedTuple

from r4_app_sector_transaction import _bounded, _sector

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'b0/tools'))
from b0_image_audit import _parse_intel_hex

FLASH, SECTOR, APP_LIMIT, BOOT, TOP = 0xB0000, 0x2000, 0xA0000, 0xAC000, 0xAE000
FACTORY_CCFG_SHA = '74707d474dc5ef0d1fdcc18fcd9d930f9a30030046833bdda7c1237219ae3758'
PACKET = 252


class Transition(NamedTuple):
    manifest: dict
    snapshot: bytes
    sectors: dict[int, bytes]


def deny(reason):
    raise ValueError('P7U_20260311_TRANSITION_BLOCKED_' + reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        deny('EXTERNAL_SHA256_REQUIRED')
    return value


def _envelope(address):
    return type(address) is int and address % SECTOR == 0 and (0 <= address < APP_LIMIT or address == BOOT)


def _frozen(plan, expected_plan_sha256):
    if not isinstance(plan, Transition):
        deny('PLAN_TYPE')
    result = Transition(copy.deepcopy(plan.manifest), bytes(plan.snapshot), dict(plan.sectors))
    m = result.manifest
    digest = m.pop('plan_sha256', None)
    if sha(canonical(m)) != pin(expected_plan_sha256) or digest != expected_plan_sha256:
        deny('PLAN_BINDING')
    m['plan_sha256'] = digest
    if (m.get('schema') != 'p7u-stock20260311-transition-v1' or m.get('flash_authorized') is not False
            or len(result.snapshot) != FLASH or sha(result.snapshot) != m.get('capture_sha256')
            or not result.sectors or not all(_envelope(a) for a in result.sectors)
            or BOOT not in result.sectors or 0 not in result.sectors
            or m.get('program_order') != sorted(set(result.sectors) - {0, BOOT}) + [0, BOOT]
            or m.get('sector_sha256') != {str(a): sha(b) for a, b in result.sectors.items()}
            or any(type(b) is not bytes or len(b) != SECTOR for b in result.sectors.values())):
        deny('PLAN_ENVELOPE')
    return result


def prepare(*, candidate: dict, expected_candidate_sha256: str,
            app_hex: bytes, handoff: bytes, pass1: bytes, pass2: bytes,
            expected_capture_sha256: str, board_identity_sha256: str,
            security_receipt: dict, expected_security_receipt_sha256: str) -> Transition:
    """Freeze externally pinned public bytes and two private same-unit captures.

    Pins must come from the selected exact-head hosted candidate and the owner
    baseline, not from blindly hashing arbitrary files supplied by an adapter.
    The security receipt is produced privately by the genuine TI reader; this
    function never turns structural counts into a security PASS.
    """
    candidate, security = copy.deepcopy(candidate), copy.deepcopy(security_receipt)
    if (sha(canonical(candidate)) != pin(expected_candidate_sha256)
            or candidate.get('schema') != 'p7u-stock20260311-candidate-v1'
            or candidate.get('flash_authorized') is not False
            or not re.fullmatch('[0-9a-f]{40}', candidate.get('source_sha', ''))):
        deny('CANDIDATE_BINDING')
    for key in ('profile_sha256', 'native_manifest_sha256', 'app_hex_sha256', 'handoff_sha256'):
        pin(candidate.get(key))
    if type(app_hex) is not bytes or len(app_hex) > 4 * 1024 * 1024 or sha(app_hex) != candidate['app_hex_sha256']:
        deny('APP_BINDING')
    if type(handoff) is not bytes or len(handoff) != SECTOR or sha(handoff) != candidate['handoff_sha256']:
        deny('HANDOFF_BINDING')
    if (type(pass1) is not bytes or type(pass2) is not bytes or len(pass1) != FLASH
            or pass1 != pass2 or sha(pass1) != pin(expected_capture_sha256)):
        deny('DUPLICATE_CURRENT_CAPTURE')
    pin(board_identity_sha256)
    if (sha(canonical(security)) != pin(expected_security_receipt_sha256)
            or security.get('schema') != 'p7u-stock20260311-security-preflight-v1'
            or security.get('status') != 'PASS_RETAINED_SECURITY_OFFLINE_ONLY'
            or security.get('capture_sha256') != expected_capture_sha256
            or security.get('profile_sha256') != candidate['profile_sha256']
            or security.get('native_manifest_sha256') != candidate['native_manifest_sha256']
            or security.get('flash_authorized') is not False
            or any(type(security.get(k)) is not int or security[k] != 0
                   for k in ('write_attempts', 'erase_attempts', 'compaction_attempts'))):
        deny('RETAINED_SECURITY_NOT_ADMITTED')
    word = lambda address: struct.unpack_from('<I', pass1, address)[0]
    if (word(0) != 0x96F3B83D or word(0xAFFEC) != BOOT
            or word(0xAFFD8) != 0xC5FE0FC5
            or sha(pass1[0xAFFA8:FLASH]) != FACTORY_CCFG_SHA):
        deny('CURRENT_FACTORY_BOOT_OR_CCFG')
    with tempfile.TemporaryDirectory(prefix='p7u-app-envelope-') as directory:
        path = Path(directory) / 'app.hex'
        path.write_bytes(app_hex)
        payload, error = _parse_intel_hex(path)
    if error or not payload or min(payload) != 0 or max(payload) >= APP_LIMIT or not set(range(0x3C)).issubset(payload):
        deny('APP_ONLY_ENVELOPE')
    sp, reset = (int.from_bytes(bytes(payload[i] for i in range(a, a + 4)), 'little') for a in (0, 4))
    if not (0x20000000 < sp <= 0x20024000 and sp % 8 == 0 and reset & 1
            and 0x3C <= (reset & ~1) < APP_LIMIT and (reset & ~1) in payload):
        deny('APP_VECTOR')
    targets = {a // SECTOR * SECTOR for a in payload}
    sectors = {a: bytes(payload.get(i, 255) for i in range(a, a + SECTOR)) for a in sorted(targets)}
    sectors[BOOT] = handoff
    for address in sectors:
        index = address // SECTOR
        if not word(0xAFFF0 + (index // 32) * 4) & (1 << (index % 32)):
            deny('TARGET_WRITE_PROTECTED')
    hs, hp = struct.unpack_from('<II', handoff)
    if not (hs == sp and hp & 1 and BOOT + 54 * 4 <= (hp & ~1) < TOP):
        deny('HANDOFF_VECTOR')
    manifest = {'schema': 'p7u-stock20260311-transition-v1',
        'source_sha': candidate['source_sha'], 'candidate_sha256': expected_candidate_sha256,
        'capture_sha256': expected_capture_sha256, 'board_identity_sha256': board_identity_sha256,
        'profile_sha256': candidate['profile_sha256'],
        'native_manifest_sha256': candidate['native_manifest_sha256'],
        'security_receipt_sha256': expected_security_receipt_sha256,
        'program_order': sorted(targets - {0}) + [0, BOOT],
        'sector_sha256': {str(a): sha(b) for a, b in sectors.items()},
        'boot_sector_before_sha256': sha(pass1[BOOT:TOP]),
        'ccfg_sector_before_sha256': sha(pass1[TOP:FLASH]),
        'separate_boot_sector_approval_required': True,
        'interruption_atomic': False, 'automatic_rollback': False,
        'flash_authorized': False, 'flash_performed': False}
    manifest['plan_sha256'] = sha(canonical(manifest))
    return _frozen(Transition(manifest, pass1, sectors), manifest['plan_sha256'])


async def _observe(rom, live_identity):
    if await rom.identity_sha256() != live_identity:
        deny('LIVE_IDENTITY_CHANGED')
    return {a: sha(await _sector(rom, a)) for a in range(0, FLASH, SECTOR)}


async def _guard(rom, address, expected, live_identity):
    if await rom.identity_sha256() != live_identity:
        deny('LIVE_IDENTITY_CHANGED')
    for guard in sorted(set(range(APP_LIMIT, FLASH, SECTOR)) | {address}):
        if sha(await _sector(rom, guard)) != expected[guard]:
            deny('STATE_CHANGED_BEFORE_ERASE')


async def _journal(rom, callback, event):
    # The journal must use cooperative async I/O, like the injected adapter.
    # It shares the same total deadline rather than extending the window.
    remaining = rom._deadline - time.monotonic()
    if remaining <= 0:
        deny('SESSION_DEADLINE_EXCEEDED')
    try:
        accepted = await asyncio.wait_for(callback(copy.deepcopy(event)),
            timeout=min(rom._operation_timeout, remaining))
    except TimeoutError as error:
        raise ValueError('P7U_20260311_TRANSITION_BLOCKED_JOURNAL_TIMEOUT') from error
    if accepted is not True:
        deny('DURABLE_JOURNAL_REQUIRED')


async def admit(rom, plan: Transition, *, expected_plan_sha256: str,
                capture_receipt: dict, expected_capture_receipt_sha256: str,
                expected_live_identity_sha256: str, operation_timeout=10.0, session_timeout=600.0) -> dict:
    """Read-only: all88 sectors must match the approved duplicate capture."""
    plan = _frozen(plan, expected_plan_sha256)
    capture = copy.deepcopy(capture_receipt)
    live = pin(expected_live_identity_sha256)
    if (sha(canonical(capture)) != pin(expected_capture_receipt_sha256)
            or live == plan.manifest['board_identity_sha256']
            or capture.get('schema') != 'r4-p7u-capture-pair-v1'
            or capture.get('status') != 'DUPLICATE_READBACK_MATCH'
            or capture.get('board_identity_sha256') != live
            or capture.get('pass1_sha256') != plan.manifest['capture_sha256']
            or capture.get('pass2_sha256') != plan.manifest['capture_sha256']
            or capture.get('flash_bytes') != FLASH
            or capture.get('capture_origin') != 'SUPPLIED_ROM_ADAPTER_REQUIRES_OPERATOR_PROVENANCE'
            or any(capture.get(k) is not False for k in ('nv_compatibility_verified', 'reset_issued', 'flash_performed', 'return_to_stock_verified'))):
        deny('LIVE_CAPTURE_IDENTITY_BINDING')
    rom = _bounded(rom, operation_timeout, session_timeout)
    observed = await _observe(rom, live)
    baseline = {a: sha(plan.snapshot[a:a + SECTOR]) for a in range(0, FLASH, SECTOR)}
    if observed != baseline:
        deny('LIVE_BASELINE_CHANGED')
    result = {'schema': 'p7u-stock20260311-transition-admission-v1',
              'plan_sha256': expected_plan_sha256, 'capture_receipt_sha256': expected_capture_receipt_sha256,
              'live_identity_sha256': live, 'observed_sector_sha256': observed,
              'flash_authorized': False, 'flash_performed': False}
    result['admission_sha256'] = sha(canonical(result))
    return result


async def execute(rom, plan: Transition, admission: dict, *, expected_plan_sha256: str,
                  expected_admission_sha256: str, capture_receipt: dict,
                  expected_capture_receipt_sha256: str, expected_live_identity_sha256: str,
                  journal, operation_timeout=10.0, session_timeout=600.0) -> dict:
    """One explicit operator operation. Persist journal before each erase.

    journal(event) must durably record private events and return True; failures
    stop. No hardware adapter is created and no approval is inferred here.
    """
    plan, admission = _frozen(plan, expected_plan_sha256), copy.deepcopy(admission)
    rom = _bounded(rom, operation_timeout, session_timeout)
    current = await admit(rom, plan, expected_plan_sha256=expected_plan_sha256,
        capture_receipt=copy.deepcopy(capture_receipt),
        expected_capture_receipt_sha256=expected_capture_receipt_sha256,
        expected_live_identity_sha256=expected_live_identity_sha256)
    if current != admission or current['admission_sha256'] != pin(expected_admission_sha256):
        deny('STALE_ADMISSION')
    expected = dict(current['observed_sector_sha256'])
    completed = []
    for address in plan.manifest['program_order']:
        # The whole reserved/NV/boot/CCFG range and next target are re-read
        # before every erase. Only our verified writes may change their pins.
        await _guard(rom, address, expected, expected_live_identity_sha256)
        if address == BOOT and await _observe(rom, expected_live_identity_sha256) != expected:
            deny('APP_NOT_VERIFIED_BEFORE_BOOT_COMMIT')
        payload = plan.sectors[address]
        if sha(payload) == expected[address]:
            continue
        if not _envelope(address) or address not in plan.sectors:
            deny('FROZEN_ALLOWLIST')
        event = {'event': 'BEFORE_ERASE', 'plan_sha256': expected_plan_sha256,
                 'address': address, 'before_sha256': expected[address], 'after_sha256': sha(payload)}
        await _journal(rom, journal, event)
        # A journal callback yields control. Revalidate after it, before the
        # first irreversible adapter call, rather than trusting stale reads.
        await _guard(rom, address, expected, expected_live_identity_sha256)
        if address == BOOT and await _observe(rom, expected_live_identity_sha256) != expected:
            deny('APP_NOT_VERIFIED_BEFORE_BOOT_COMMIT')
        if await rom.erase_sector(address) is not True or await rom.status() is not True:
            deny('UNCERTAIN_ERASE_SECTOR')
        # The new reset vector is the boot sector's final write. Until then
        # a reset cannot select a valid half-programmed handoff entry. This is
        # still not interruption-atomic and relies on the independent ROM BSL.
        windows = ((8, SECTOR - 8), (0, 8)) if address == BOOT else ((0, SECTOR),)
        for start, length in windows:
            if address == BOOT and start == 0:
                partial = b'\xff' * 8 + payload[8:]
                if await _sector(rom, BOOT) != partial:
                    deny('BOOT_TAIL_NOT_VERIFIED')
                expected[BOOT] = sha(partial)
                if await _observe(rom, expected_live_identity_sha256) != expected:
                    deny('STATE_CHANGED_BEFORE_BOOT_VECTOR')
                await _journal(rom, journal, {'event': 'BEFORE_BOOT_VECTOR_COMMIT',
                    'address': BOOT, 'plan_sha256': expected_plan_sha256})
                if await _observe(rom, expected_live_identity_sha256) != expected:
                    deny('STATE_CHANGED_BEFORE_BOOT_VECTOR')
            if await rom.begin_download(address + start, length) is not True or await rom.status() is not True:
                deny('UNCERTAIN_BEGIN_DOWNLOAD')
            for offset in range(start, start + length, PACKET):
                packet = payload[offset:min(offset + PACKET, start + length)]
                if await rom.send_data(packet) is not True or await rom.status() is not True:
                    deny('UNCERTAIN_SEND_DATA')
        if await _sector(rom, address) != payload:
            deny('SECTOR_READBACK')
        expected[address] = sha(payload)
        completed.append(address)
        await _journal(rom, journal, {'event': 'SECTOR_VERIFIED', 'address': address,
                                    'sha256': expected[address]})
    if await _observe(rom, expected_live_identity_sha256) != expected:
        deny('FINAL_ALL88_PARITY')
    return {'status': 'APP_AND_AC000_VERIFIED_STILL_IN_BSL', 'written_sectors': completed,
            'nv_touched': False, 'ccfg_touched': False, 'reset_issued': False,
            'automatic_rollback': False, 'physical_boot_qualified': False}
