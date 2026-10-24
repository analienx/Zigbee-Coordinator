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
import binascii
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import time
import weakref
from typing import NamedTuple

from r4_app_sector_transaction import _bounded, _sector

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'b0/tools'))
from b0_image_audit import _parse_intel_hex

FLASH, SECTOR, APP_LIMIT, BOOT, TOP = 0xB0000, 0x2000, 0xA0000, 0xAC000, 0xAE000
FACTORY_CCFG_SHA = '74707d474dc5ef0d1fdcc18fcd9d930f9a30030046833bdda7c1237219ae3758'
PACKET = 252

# Private in-process evidence only: cannot be serialized, replayed or used
# after a different TCP/COM open. The default conservative path is unchanged.
_SAME_SESSION_ADMISSIONS = weakref.WeakKeyDictionary()
FAST_ADMISSION_MAX_AGE_SECONDS = 60.0


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


def _prepare_common(*, candidate: dict, expected_candidate_sha256: str,
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
    if (word(0xAFFEC) != BOOT
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
        'plan_kind': 'INSTALL_CURRENT_APP_AND_COMPILED_HANDOFF',
        'program_order': sorted(targets - {0}) + [0, BOOT],
        'sector_sha256': {str(a): sha(b) for a, b in sectors.items()},
        'boot_sector_before_sha256': sha(pass1[BOOT:TOP]),
        'ccfg_sector_before_sha256': sha(pass1[TOP:FLASH]),
        'separate_boot_sector_approval_required': True,
        'interruption_atomic': False, 'automatic_rollback': False,
        'flash_authorized': False, 'flash_performed': False}
    manifest['plan_sha256'] = sha(canonical(manifest))
    return _frozen(Transition(manifest, pass1, sectors), manifest['plan_sha256'])


def prepare(*, candidate: dict, expected_candidate_sha256: str,
            app_hex: bytes, handoff: bytes, pass1: bytes, pass2: bytes,
            expected_capture_sha256: str, board_identity_sha256: str,
            security_receipt: dict, expected_security_receipt_sha256: str) -> Transition:
    """Original stock-to-R4 path; an installed R4 is never a stock baseline."""
    plan = _prepare_common(candidate=candidate, expected_candidate_sha256=expected_candidate_sha256,
        app_hex=app_hex, handoff=handoff, pass1=pass1, pass2=pass2,
        expected_capture_sha256=expected_capture_sha256, board_identity_sha256=board_identity_sha256,
        security_receipt=security_receipt, expected_security_receipt_sha256=expected_security_receipt_sha256)
    if struct.unpack_from('<I', plan.snapshot)[0] != 0x96F3B83D:
        deny('CURRENT_FACTORY_BOOT_OR_CCFG')
    return plan


def prepare_upgrade(*, installed_plan: Transition, expected_installed_plan_sha256: str,
                    installed_candidate: dict, expected_installed_candidate_sha256: str,
                    installed_app_hex: bytes, installed_handoff: bytes,
                    installed_result: dict, expected_installed_result_sha256: str,
                    handoff_receipt: bytes, **current) -> Transition:
    """Explicit known-R4 upgrade, from a fresh duplicate same-unit capture.

    The previous private frozen plan and successful write receipt bind the
    installed public APP/boot pair. Only NV may have evolved since that install.
    An interrupted/unknown APP or boot is recovery, never an upgrade baseline.
    """
    old = _frozen(installed_plan, expected_installed_plan_sha256)
    if (old.manifest.get('plan_kind') not in ('INSTALL_CURRENT_APP_AND_COMPILED_HANDOFF',
                                           'UPGRADE_KNOWN_R4_APP_AND_COMPILED_HANDOFF') or
            old.manifest['candidate_sha256'] != pin(expected_installed_candidate_sha256) or
            sha(canonical(installed_candidate)) != expected_installed_candidate_sha256 or
            installed_candidate.get('source_sha') != old.manifest['source_sha'] or
            sha(installed_app_hex) != installed_candidate.get('app_hex_sha256') or
            sha(installed_handoff) != installed_candidate.get('handoff_sha256') or
            installed_handoff != old.sectors[BOOT]):
        deny('INSTALLED_PUBLIC_PAIR_BINDING')
    with tempfile.TemporaryDirectory(prefix='p7u-installed-envelope-') as directory:
        path = Path(directory) / 'installed.hex'
        path.write_bytes(installed_app_hex)
        payload, error = _parse_intel_hex(path)
    if error or not payload or min(payload) != 0 or max(payload) >= APP_LIMIT:
        deny('INSTALLED_APP_ENVELOPE')
    old_owned = set(old.sectors) - {BOOT}
    public_owned = {a // SECTOR * SECTOR for a in payload}
    if not public_owned.issubset(old_owned):
        deny('INSTALLED_APP_OWNERSHIP')
    for address in old_owned:
        expected = bytes(payload.get(i, 255) for i in range(address, address + SECTOR))
        if old.sectors[address] != expected:
            deny('INSTALLED_APP_PLAN_MISMATCH')
    result = copy.deepcopy(installed_result)
    expected_writes = [a for a in old.manifest['program_order']
                       if old.sectors[a] != old.snapshot[a:a + SECTOR]]
    verified_full = result.get('status') == 'APP_AND_AC000_VERIFIED_STILL_IN_BSL'
    verified_sparse = (
        result.get('status') == 'APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL'
        and result.get('verification_scope') == 'WRITTEN_SHA_PLUS_ALL88_ROM_CRC'
        and old.manifest.get('capture_mode') == SPARSE_MODE
    )
    if (sha(canonical(result)) != pin(expected_installed_result_sha256) or
            not (verified_full or verified_sparse) or
            result.get('written_sectors') != expected_writes or
            any(result.get(k) is not False for k in ('nv_touched', 'ccfg_touched',
                                                    'reset_issued', 'automatic_rollback'))):
        deny('INSTALLED_SUCCESS_RECEIPT')
    plan = _prepare_common(**current)
    if (plan.manifest['board_identity_sha256'] != old.manifest['board_identity_sha256'] or
            plan.manifest['profile_sha256'] != old.manifest['profile_sha256'] or
            current['security_receipt'].get('baseline_capture_sha256') != old.manifest['capture_sha256']):
        deny('UPGRADE_IDENTITY_PROFILE_OR_SECURITY_BASELINE')
    for address in range(0, FLASH, SECTOR):
        if 0xA4000 <= address < BOOT:
            continue
        expected = old.sectors.get(address, old.snapshot[address:address + SECTOR])
        if plan.snapshot[address:address + SECTOR] != expected:
            deny('INSTALLED_PAIR_OR_NON_TARGET_STATE_CHANGED')
    # The public candidate's hash-bound compiled receipt names the exact APP
    # reset pair used by its checked handoff; a generic SP-range check cannot
    # establish compatibility with the previous boot sector.
    if type(handoff_receipt) is not bytes:
        deny('UPGRADE_HANDOFF_RECEIPT_BYTES_REQUIRED')
    try:
        receipt = json.loads(handoff_receipt)
    except (ValueError, UnicodeDecodeError):
        deny('UPGRADE_HANDOFF_RECEIPT_INVALID')
    candidate = current['candidate']
    if (sha(handoff_receipt) !=
            candidate.get('files', {}).get('handoff-receipt.json') or
            receipt.get('schema') != 'r4-p7u-stock20260311-compiled-handoff-v1' or
            receipt.get('status') != 'COMPILED_M4F_SINGLE_SECTOR_TRANSFER_AUDITED' or
            receipt.get('sector_sha256') != candidate['handoff_sha256'] or
            receipt.get('profile_sha256') != candidate['profile_sha256'] or
            receipt.get('source_native_manifest_sha256') != candidate['native_manifest_sha256'] or
            receipt.get('app_initial_sp') != hex(struct.unpack_from('<I', plan.sectors[0])[0]) or
            receipt.get('app_reset_thumb') != hex(struct.unpack_from('<I', plan.sectors[0], 4)[0])):
        deny('UPGRADE_APP_HANDOFF_PAIR_NOT_PROVEN')
    sectors = dict(plan.sectors)
    retired = old_owned - set(sectors)
    sectors.update({a: b'\xff' * SECTOR for a in retired})
    for address in sectors:
        index = address // SECTOR
        protection = struct.unpack_from('<I', plan.snapshot, 0xAFFF0 + (index // 32) * 4)[0]
        if not protection & (1 << (index % 32)):
            deny('TARGET_WRITE_PROTECTED')
    manifest = copy.deepcopy(plan.manifest)
    manifest.pop('plan_sha256')
    manifest.update(plan_kind='UPGRADE_KNOWN_R4_APP_AND_COMPILED_HANDOFF',
        installed_plan_sha256=expected_installed_plan_sha256,
        installed_candidate_sha256=expected_installed_candidate_sha256,
        installed_result_sha256=expected_installed_result_sha256,
        retired_owned_app_sectors=sorted(retired),
        program_order=sorted(set(sectors) - {0, BOOT}) + [0, BOOT],
        sector_sha256={str(a): sha(b) for a, b in sectors.items()})
    manifest['plan_sha256'] = sha(canonical(manifest))
    return _frozen(Transition(manifest, plan.snapshot, sectors), manifest['plan_sha256'])


def prepare_recovery(forward: Transition, *, expected_forward_plan_sha256: str,
                     pass1: bytes, pass2: bytes, expected_capture_sha256: str,
                     security_receipt: dict, expected_security_receipt_sha256: str) -> Transition:
    """Prepare a NEW, separately approved rollback from a fresh observed state.

    Restore only original APP and boot bytes. In particular the before-image NV
    is never a restore payload. New legitimate NV/counter state must pass the
    private retained-security preflight and stays byte-identical to pass1.
    Unknown damage outside the forward allowlist/NV cannot be papered over.
    """
    original = _frozen(forward, expected_forward_plan_sha256)
    if original.manifest.get('plan_kind') not in ('INSTALL_CURRENT_APP_AND_COMPILED_HANDOFF',
                                               'UPGRADE_KNOWN_R4_APP_AND_COMPILED_HANDOFF'):
        deny('RECOVERY_REQUIRES_ORIGINAL_INSTALL_PLAN')
    if (type(pass1) is not bytes or type(pass2) is not bytes or len(pass1) != FLASH
            or pass1 != pass2 or sha(pass1) != pin(expected_capture_sha256)):
        deny('DUPLICATE_CURRENT_CAPTURE')
    security = copy.deepcopy(security_receipt)
    if (sha(canonical(security)) != pin(expected_security_receipt_sha256)
            or security.get('schema') != 'p7u-stock20260311-security-preflight-v1'
            or security.get('status') != 'PASS_RETAINED_SECURITY_OFFLINE_ONLY'
            or security.get('capture_sha256') != expected_capture_sha256
            or security.get('baseline_capture_sha256') != original.manifest['capture_sha256']
            or security.get('profile_sha256') != original.manifest['profile_sha256']
            or security.get('native_manifest_sha256') != original.manifest['native_manifest_sha256']
            or security.get('flash_authorized') is not False
            or any(type(security.get(k)) is not int or security[k] != 0
                   for k in ('write_attempts', 'erase_attempts', 'compaction_attempts'))):
        deny('RECOVERY_RETAINED_SECURITY_NOT_ADMITTED')
    for address in range(0, FLASH, SECTOR):
        if address in original.sectors or 0xA4000 <= address < BOOT:
            continue
        if pass1[address:address + SECTOR] != original.snapshot[address:address + SECTOR]:
            deny('RECOVERY_UNEXPLAINED_NON_TARGET_DRIFT')
    restored = {a: original.snapshot[a:a + SECTOR] for a in original.sectors}
    manifest = copy.deepcopy(original.manifest)
    manifest.pop('plan_sha256')
    manifest.update(plan_kind='RECOVER_ORIGINAL_APP_AND_BOOT_ONLY',
        recovery_of_plan_sha256=expected_forward_plan_sha256,
        capture_sha256=expected_capture_sha256,
        security_receipt_sha256=expected_security_receipt_sha256,
        sector_sha256={str(a): sha(b) for a, b in restored.items()},
        boot_sector_before_sha256=sha(pass1[BOOT:TOP]),
        ccfg_sector_before_sha256=sha(pass1[TOP:FLASH]))
    manifest['plan_sha256'] = sha(canonical(manifest))
    return _frozen(Transition(manifest, pass1, restored), manifest['plan_sha256'])


async def _observe(rom, live_identity):
    if await rom.identity_sha256() != live_identity:
        deny('LIVE_IDENTITY_CHANGED')
    return {a: sha(await _sector(rom, a)) for a in range(0, FLASH, SECTOR)}


async def _crc_tripwire_all(rom, expected_crc, live_identity, reason):
    """All-88 ROM CRC tripwire after a full SHA admission, not a SHA substitute."""
    if await rom.identity_sha256() != live_identity:
        deny('LIVE_IDENTITY_CHANGED')
    for address in range(0, FLASH, SECTOR):
        if await rom.crc32(address, SECTOR) != expected_crc[address]:
            deny(reason)


def _transport_session(rom):
    raw = rom._adapter if hasattr(rom, '_adapter') else rom
    reader, writer = getattr(raw, 'reader', None), getattr(raw, 'writer', None)
    if reader is None or writer is None or getattr(raw, '_faulted', False):
        deny('FAST_TRANSPORT_NOT_LIVE')
    if getattr(writer, 'is_closing', lambda: False)():
        deny('FAST_TRANSPORT_CLOSING')
    return raw, reader, writer


def _verified_wire_status_embedded(raw):
    """Only the existing qualified TI ROM adapter may omit a second status.

    RomSerial._call() already gets/validates GET_STATUS after every SEND_DATA.
    A different injected adapter always uses the historical extra status read.
    """
    # Both exact source-audited subclasses inherit the same unmodified
    # RomSerial._call for ALL irreversible opcodes. FastUsbRom changes only
    # read-only memory transfer; no broad isinstance/duck-typing relaxation.
    exact = (type(raw).__module__, type(raw).__name__)
    if exact not in {
        ('p7u_stock20260311_rom_adapter', 'Stock20260311ROM'),
        ('p7u_usb_fast_rom', 'SafeFastUsbRom'),
    }:
        return False
    try:
        from p7u_rom_lowlevel import RomSerial
        from p7u_stock20260311_rom_adapter import Stock20260311ROM
        from p7u_usb_fast_rom import SafeFastUsbRom
    except ImportError:
        return False
    if type(raw) not in (Stock20260311ROM, SafeFastUsbRom):
        return False
    return type(raw)._call is RomSerial._call


async def _guard(rom, address, expected, live_identity, expected_crc=None):
    """Check every protected sector and the target before irreversible I/O.

    An already SHA-admitted and immutable capture supplies CRC baselines.
    ROM CRC32 is a *read-only interim tripwire*, never a replacement for the
    admission's 88 SHA readbacks, each written sector's bytewise readback,
    or the final 88-SHA parity. This avoids thousands of 240-byte TCP reads.
    """
    if await rom.identity_sha256() != live_identity:
        deny('LIVE_IDENTITY_CHANGED')
    for guard in sorted(set(range(APP_LIMIT, FLASH, SECTOR)) | {address}):
        if expected_crc is None:
            if sha(await _sector(rom, guard)) != expected[guard]:
                deny('STATE_CHANGED_BEFORE_ERASE')
        elif await rom.crc32(guard, SECTOR) != expected_crc[guard]:
            deny('CRC32_GUARD_CHANGED_BEFORE_ERASE')


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
                expected_live_identity_sha256: str, operation_timeout=10.0, session_timeout=600.0,
                seal_same_session=False) -> dict:
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
    if seal_same_session:
        raw, reader, writer = _transport_session(rom)
        _SAME_SESSION_ADMISSIONS[raw] = {
            'reader': reader, 'writer': writer, 'plan_sha256': expected_plan_sha256,
            'capture_sha256': expected_capture_receipt_sha256,
            'identity_sha256': live, 'admission': copy.deepcopy(result),
            'admitted_monotonic': time.monotonic(),
        }
    return result


async def execute(rom, plan: Transition, admission: dict, *, expected_plan_sha256: str,
                  expected_admission_sha256: str, capture_receipt: dict,
                  expected_capture_receipt_sha256: str, expected_live_identity_sha256: str,
                  journal, operation_timeout=10.0, session_timeout=600.0,
                  same_session_fast=False, same_session_sparse=False) -> dict:
    """One explicit operator operation. Persist journal before each erase.

    journal(event) must durably record private events and return True; failures
    stop. No hardware adapter is created and no approval is inferred here.
    """
    plan, admission = _frozen(plan, expected_plan_sha256), copy.deepcopy(admission)
    rom = _bounded(rom, operation_timeout, session_timeout)
    if same_session_fast and same_session_sparse:
        deny('SHA_AND_SPARSE_MODES_MUTUALLY_EXCLUSIVE')
    if same_session_sparse and (
            sha(canonical(capture_receipt)) != pin(expected_capture_receipt_sha256)
            or capture_receipt.get('status') !=
            'SPARSE_ROM_CRC_WITH_FRESH_NV_READ_ONLY_NOT_FLASH_ADMISSION'
            or capture_receipt.get('nv_bytes_read') != 0xC000
            or capture_receipt.get('rom_crc32_sector_checks') != FLASH // SECTOR):
        deny('SPARSE_RECEIPT_CHANGED_BEFORE_EXECUTION')
    if same_session_fast or same_session_sparse:
        raw, reader, writer = _transport_session(rom)
        witness = _SAME_SESSION_ADMISSIONS.pop(raw, None)  # one-time, no replay
        if (witness is None or witness['reader'] is not reader
                or witness['writer'] is not writer
                or time.monotonic() - witness['admitted_monotonic'] > FAST_ADMISSION_MAX_AGE_SECONDS
                or witness['plan_sha256'] != expected_plan_sha256
                or witness['capture_sha256'] != expected_capture_receipt_sha256
                or witness['identity_sha256'] != expected_live_identity_sha256
                or witness['admission'] != admission
                or (same_session_sparse and
                    (witness.get('mode') != SPARSE_MODE
                     or admission.get('mode') != SPARSE_MODE
                     or admission.get('evidence') !=
                     'ROM_CRC32_ALL88_PLUS_FRESH_48K_NV_NOT_SHA_FULL_CAPTURE'))
                or (same_session_fast and witness.get('mode') is not None)):
            deny('SAME_TRANSPORT_SHA_ADMISSION_REQUIRED' if same_session_fast
                 else 'SAME_TRANSPORT_SPARSE_ADMISSION_REQUIRED')
        current = copy.deepcopy(witness['admission'])
    else:
        # The proven conservative route independently SHA-reads all 88 sectors.
        current = await admit(rom, plan, expected_plan_sha256=expected_plan_sha256,
            capture_receipt=copy.deepcopy(capture_receipt),
            expected_capture_receipt_sha256=expected_capture_receipt_sha256,
            expected_live_identity_sha256=expected_live_identity_sha256)
    if current != admission or current['admission_sha256'] != pin(expected_admission_sha256):
        deny('STALE_ADMISSION')
    expected = dict(current['observed_sector_sha256'])
    expected_crc = {addr: binascii.crc32(plan.snapshot[addr:addr + SECTOR]) & 0xffffffff
                    for addr in range(0, FLASH, SECTOR)}
    if same_session_fast or same_session_sparse:
        # SHA for full baseline; known-image CRC + freshly parsed NV for sparse.
        await _crc_tripwire_all(rom, expected_crc, expected_live_identity_sha256,
                               'STATE_CHANGED_AFTER_SHA_ADMISSION' if same_session_fast
                               else 'STATE_CHANGED_AFTER_SPARSE_ADMISSION')
    else:
        # Unmodified conservative profile retains its four CRC baselines.
        for probe in (0, 0xA4000, BOOT, TOP):
            if await rom.crc32(probe, SECTOR) != expected_crc[probe]:
                deny('ROM_CRC32_NOT_EQUIVALENT_TO_ADMITTED_CAPTURE')
    # In the exact audited ROM adapter, SEND_DATA already validates GET_STATUS
    # before returning True. Avoid the additional round trip per 252-byte packet.
    # All other adapters and the historical profile retain the second query.
    embedded_packet_status = (same_session_fast or same_session_sparse) and _verified_wire_status_embedded(raw)
    completed = []
    for address in plan.manifest['program_order']:
        # The whole reserved/NV/boot/CCFG range and next target are re-read
        # before every erase. Only our verified writes may change their pins.
        await _guard(rom, address, expected, expected_live_identity_sha256, expected_crc)
        if address == BOOT:
            if same_session_fast or same_session_sparse:
                await _crc_tripwire_all(rom, expected_crc, expected_live_identity_sha256,
                                       'APP_NOT_VERIFIED_BEFORE_BOOT_COMMIT')
            elif await _observe(rom, expected_live_identity_sha256) != expected:
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
        await _guard(rom, address, expected, expected_live_identity_sha256, expected_crc)
        if address == BOOT:
            if same_session_fast or same_session_sparse:
                await _crc_tripwire_all(rom, expected_crc, expected_live_identity_sha256,
                                       'APP_NOT_VERIFIED_BEFORE_BOOT_COMMIT')
            elif await _observe(rom, expected_live_identity_sha256) != expected:
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
                expected_crc[BOOT] = binascii.crc32(partial) & 0xffffffff
                if same_session_fast or same_session_sparse:
                    await _crc_tripwire_all(rom, expected_crc, expected_live_identity_sha256,
                                           'STATE_CHANGED_BEFORE_BOOT_VECTOR')
                elif await _observe(rom, expected_live_identity_sha256) != expected:
                    deny('STATE_CHANGED_BEFORE_BOOT_VECTOR')
                await _journal(rom, journal, {'event': 'BEFORE_BOOT_VECTOR_COMMIT',
                    'address': BOOT, 'plan_sha256': expected_plan_sha256})
                if same_session_fast or same_session_sparse:
                    await _crc_tripwire_all(rom, expected_crc, expected_live_identity_sha256,
                                           'STATE_CHANGED_BEFORE_BOOT_VECTOR')
                elif await _observe(rom, expected_live_identity_sha256) != expected:
                    deny('STATE_CHANGED_BEFORE_BOOT_VECTOR')
            if await rom.begin_download(address + start, length) is not True or await rom.status() is not True:
                deny('UNCERTAIN_BEGIN_DOWNLOAD')
            for offset in range(start, start + length, PACKET):
                packet = payload[offset:min(offset + PACKET, start + length)]
                if await rom.send_data(packet) is not True:
                    deny('UNCERTAIN_SEND_DATA')
                if not embedded_packet_status and await rom.status() is not True:
                    deny('UNCERTAIN_SEND_DATA')
        if await _sector(rom, address) != payload:
            deny('SECTOR_READBACK')
        expected[address] = sha(payload)
        expected_crc[address] = binascii.crc32(payload) & 0xffffffff
        completed.append(address)
        await _journal(rom, journal, {'event': 'SECTOR_VERIFIED', 'address': address,
                                    'sha256': expected[address]})
    if same_session_sparse:
        # The sparse lane documents the lower verification level accurately.
        # All written sectors already have exact SHA readback above; all other
        # sectors are checked against the previously verified snapshot by ROM CRC.
        await _crc_tripwire_all(rom, expected_crc, expected_live_identity_sha256,
                               'FINAL_ALL88_SPARSE_CRC_PARITY')
    elif await _observe(rom, expected_live_identity_sha256) != expected:
        deny('FINAL_ALL88_PARITY')
    return {'status': ('APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL' if same_session_sparse
                       else 'APP_AND_AC000_VERIFIED_STILL_IN_BSL'),
            'verification_scope': ('WRITTEN_SHA_PLUS_ALL88_ROM_CRC' if same_session_sparse
                                   else 'ALL88_ROM_SHA'),
            'written_sectors': completed,
            'nv_touched': False, 'ccfg_touched': False, 'reset_issued': False,
            'automatic_rollback': False, 'physical_boot_qualified': False}

SPARSE_MODE = 'SPARSE_CRC_WITH_FRESH_NV_AND_PRIOR_VERIFIED_IMAGE'


def bind_sparse_plan(plan: Transition, *, expected_plan_sha256: str,
                     previous_verified_image: bytes, sparse_receipt: dict,
                     expected_sparse_receipt_sha256: str) -> Transition:
    """Convert a source/security-prepared plan to a distinctly marked sparse plan.

    No ROM I/O and no authorization. Operator MUST obtain sparse_receipt from
    the actual device in the same active ROM session and separately run genuine
    native TI semantic NV security checks against reconstructed plan.snapshot.
    A full 704-KiB capture cannot be fabricated by this function.
    """
    frozen = _frozen(plan, expected_plan_sha256)
    receipt = copy.deepcopy(sparse_receipt)
    if (type(previous_verified_image) is not bytes
            or len(previous_verified_image) != FLASH
            or sha(canonical(receipt)) != pin(expected_sparse_receipt_sha256)
            or receipt.get('status') !=
              'SPARSE_ROM_CRC_WITH_FRESH_NV_READ_ONLY_NOT_FLASH_ADMISSION'
            or receipt.get('source_baseline_sha256') != sha(previous_verified_image)
            or receipt.get('live_reconstructed_sha256') != sha(frozen.snapshot)
            or receipt.get('nv_bytes_read') != 0xC000
            or receipt.get('rom_crc32_sector_checks') != FLASH // SECTOR
            or receipt.get('expected_identity_sha256') is None):
        deny('SPARSE_PROVENANCE_INVALID')
    if any(frozen.snapshot[a:a+SECTOR] != previous_verified_image[a:a+SECTOR]
           for a in range(0,FLASH,SECTOR) if not 0xA0000 <= a < BOOT):
        deny('SPARSE_NON_NV_IMAGE_CHANGED')
    nv_changed = sum(frozen.snapshot[a:a+SECTOR] !=
                     previous_verified_image[a:a+SECTOR]
                     for a in range(0xA0000,BOOT,SECTOR))
    if receipt.get('baseline_nv_changed_sectors') != nv_changed:
        deny('SPARSE_NV_CHANGED_COUNT_MISMATCH')
    manifest = copy.deepcopy(frozen.manifest)
    manifest.pop('plan_sha256')
    if manifest.get('capture_mode') is not None:
        deny('SPARSE_ALREADY_BOUND')
    manifest.update(capture_mode=SPARSE_MODE,
                    sparse_receipt_sha256=expected_sparse_receipt_sha256,
                    sparse_previous_sha256=sha(previous_verified_image))
    manifest['plan_sha256'] = sha(canonical(manifest))
    return _frozen(Transition(manifest,frozen.snapshot,frozen.sectors),
                   manifest['plan_sha256'])


async def admit_sparse(rom, plan: Transition, *, expected_plan_sha256: str,
                       sparse_receipt: dict, expected_sparse_receipt_sha256: str,
                       security_receipt: dict, expected_security_receipt_sha256: str,
                       expected_live_identity_sha256: str, operation_timeout=10.0,
                       session_timeout=600.0) -> dict:
    """Read-only fast admission, NEVER grants flash authorization by itself.

    Unlike admit(), no claim of 88-sector SHA readback is made. Reconstructs
    SHA from the prior cryptographically verified installed image plus freshly
    read/ROM-CRC-checked live NV, then independently checks all 88 live CRCs.
    """
    plan = _frozen(plan,expected_plan_sha256)
    proof = copy.deepcopy(sparse_receipt)
    sec = copy.deepcopy(security_receipt)
    live = pin(expected_live_identity_sha256)
    if (plan.manifest.get('capture_mode') != SPARSE_MODE
            or sha(canonical(proof)) != pin(expected_sparse_receipt_sha256)
            or plan.manifest.get('sparse_receipt_sha256') != expected_sparse_receipt_sha256
            or proof.get('source_baseline_sha256') != plan.manifest.get('sparse_previous_sha256')
            or proof.get('expected_identity_sha256') != live
            or proof.get('live_reconstructed_sha256') != sha(plan.snapshot)
            or proof.get('status') !=
              'SPARSE_ROM_CRC_WITH_FRESH_NV_READ_ONLY_NOT_FLASH_ADMISSION'
            or proof.get('rom_crc32_sector_checks') != FLASH // SECTOR
            or proof.get('nv_bytes_read') != 0xC000
            or live == plan.manifest['board_identity_sha256']):
        deny('SPARSE_LIVE_CAPTURE_EVIDENCE_INVALID')
    if (sha(canonical(sec)) != pin(expected_security_receipt_sha256)
            or expected_security_receipt_sha256 != plan.manifest['security_receipt_sha256']
            or sec.get('schema') != 'p7u-stock20260311-security-preflight-v1'
            or sec.get('status') != 'PASS_RETAINED_SECURITY_OFFLINE_ONLY'
            or sec.get('capture_sha256') != sha(plan.snapshot)
            or any(sec.get(k) != 0 for k in
                   ('write_attempts','erase_attempts','compaction_attempts'))
            or sec.get('flash_authorized') is not False):
        deny('SPARSE_NATIVE_SECURITY_NOT_VERIFIED')
    rom = _bounded(rom,operation_timeout,session_timeout)
    expected_crc = {a: binascii.crc32(plan.snapshot[a:a+SECTOR]) & 0xffffffff
                    for a in range(0,FLASH,SECTOR)}
    await _crc_tripwire_all(rom,expected_crc,live,'SPARSE_BASELINE_DRIFT')
    observed = {a:sha(plan.snapshot[a:a+SECTOR]) for a in range(0,FLASH,SECTOR)}
    result = {'schema':'p7u-stock20260311-sparse-admission-v1',
              'mode':SPARSE_MODE,
              'plan_sha256':expected_plan_sha256,
              'capture_receipt_sha256':expected_sparse_receipt_sha256,
              'live_identity_sha256':live,
              'observed_sector_sha256':observed,
              'evidence':'ROM_CRC32_ALL88_PLUS_FRESH_48K_NV_NOT_SHA_FULL_CAPTURE',
              'flash_authorized':False,'flash_performed':False}
    result['admission_sha256']=sha(canonical(result))
    raw,reader,writer=_transport_session(rom)
    _SAME_SESSION_ADMISSIONS[raw]={
      'reader':reader,'writer':writer,'plan_sha256':expected_plan_sha256,
      'capture_sha256':expected_sparse_receipt_sha256,'identity_sha256':live,
      'admission':copy.deepcopy(result),'admitted_monotonic':time.monotonic(),
      'mode':SPARSE_MODE}
    return result
