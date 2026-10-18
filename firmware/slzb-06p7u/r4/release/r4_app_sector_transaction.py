#!/usr/bin/env python3
"""Bounded current-APP sector core with an injected ROM adapter; NO live CLI.

No adapter is constructed here. No reset, CCFG/NV operation, bank erase,
DOWNLOAD_CRC, retry, or automatic rollback exists. A failed operation raises
immediately and leaves the caller's ROM/BSL session in its existing state.
Adapters must use cooperative async I/O and honor cancellation. A timed-out
erase/program has unknown completion; independently re-read it before any
explicit rollback. The core cannot preempt an adapter blocking the event loop.
"""
from __future__ import annotations

import asyncio
import binascii
import copy
import hashlib
import json
import math
import re
import time
from typing import Protocol

from r4_current_app_package import AppPackage, FLASH, SECTOR, _allowed, canonical, validate_package

PACKET = 252
OPERATION_TIMEOUT = 10.0
SESSION_TIMEOUT = 600.0


class ROM(Protocol):
    async def identity_sha256(self) -> str: ...
    async def read(self, address: int, length: int) -> bytes: ...
    async def crc32(self, address: int, length: int) -> int: ...
    async def erase_sector(self, address: int) -> bool: ...
    async def begin_download(self, address: int, length: int) -> bool: ...
    async def send_data(self, payload: bytes) -> bool: ...
    async def status(self) -> bool: ...


def deny(reason: str):
    raise ValueError("R4_APP_TRANSACTION_BLOCKED_" + reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def crc(raw: bytes) -> int:
    return binascii.crc32(raw) & 0xFFFFFFFF


def _freeze_package(package: AppPackage) -> AppPackage:
    """Take a private, independent input snapshot before any adapter await.

    AppPackage is a NamedTuple, but its manifest/profile/sector dictionaries
    are caller-owned and mutable. In particular the program order and writable
    sector set must never be obtained from them after live preflight begins.
    JSON metadata roundtrips also detach deeply nested geometry and lists.
    """
    if not isinstance(package, AppPackage):
        deny("PACKAGE_TYPE")
    return AppPackage(json.loads(canonical(package.manifest)),
                      json.loads(canonical(package.profile)),
                      package.snapshot,
                      dict(package.sectors))


def _freeze_json(value):
    """Copy an admission/capture/pin mapping before adapter callbacks run."""
    # Admission embeds int-indexed sector hash maps, so JSON roundtripping
    # would silently convert their keys to strings and invalidate admission.
    return copy.deepcopy(value)


def _capture_live_identity(package: AppPackage, receipt: dict, *,
                           expected_capture_receipt_sha256: str,
                           expected_live_identity_sha256: str) -> str:
    """Bind the operator's live management identity to this exact capture.

    Capture identity and the profile's private canonical board identity are
    DIFFERENT digests. Silently treating one as the other would reject the real
    adapter, or invite a caller to return an unverified constant instead of
    re-reading management identity before a physical erase.
    """
    for pin in (expected_capture_receipt_sha256, expected_live_identity_sha256):
        if not isinstance(pin, str) or re.fullmatch(r"[0-9a-f]{64}", pin) is None:
            deny("EXTERNAL_CAPTURE_IDENTITY_PINS_REQUIRED")
    expected_fields = {"schema", "status", "board_identity_sha256", "flash_bytes",
                       "pass1_sha256", "pass2_sha256", "capture_origin",
                       "nv_compatibility_verified", "reset_issued",
                       "flash_performed", "return_to_stock_verified"}
    if (not isinstance(receipt, dict) or set(receipt) != expected_fields or
            sha(canonical(receipt)) != expected_capture_receipt_sha256):
        deny("CAPTURE_RECEIPT_HASH_MISMATCH")
    if expected_live_identity_sha256 == package.profile["board_identity_sha256"]:
        deny("LIVE_AND_PROFILE_IDENTITY_DIGEST_DOMAINS_COLLAPSED")
    if (receipt.get("schema") != "r4-p7u-capture-pair-v1" or
            receipt.get("status") != "DUPLICATE_READBACK_MATCH" or
            receipt.get("capture_origin") != "SUPPLIED_ROM_ADAPTER_REQUIRES_OPERATOR_PROVENANCE" or
            receipt.get("flash_bytes") != FLASH or
            receipt.get("pass1_sha256") != package.profile["capture_sha256"] or
            receipt.get("pass2_sha256") != package.profile["capture_sha256"] or
            receipt.get("board_identity_sha256") != expected_live_identity_sha256 or
            any(receipt.get(field) is not False for field in
                ("nv_compatibility_verified", "reset_issued", "flash_performed",
                 "return_to_stock_verified"))):
        deny("LIVE_CAPTURE_PROVENANCE_NOT_BOUND")
    return expected_live_identity_sha256


class _BoundedROM:
    """One cooperative adapter-await budget shared by every transaction stage."""
    _operations = {"identity_sha256", "read", "crc32", "erase_sector",
                   "begin_download", "send_data", "status"}

    def __init__(self, adapter: ROM, operation_timeout: float, session_timeout: float):
        for value in (operation_timeout, session_timeout):
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                deny("INVALID_TIMEOUT_LIMIT")
        self._adapter = adapter
        self._operation_timeout = operation_timeout
        self._deadline = time.monotonic() + session_timeout

    def __getattr__(self, name):
        if name not in self._operations:
            raise AttributeError(name)

        async def operation(*args):
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                deny("SESSION_DEADLINE_EXCEEDED")
            session_limited = remaining <= self._operation_timeout
            try:
                return await asyncio.wait_for(getattr(self._adapter, name)(*args),
                    timeout=min(self._operation_timeout, remaining))
            except TimeoutError as error:
                reason = ("SESSION_DEADLINE_EXCEEDED" if session_limited
                          else "ADAPTER_OPERATION_TIMEOUT_" + name)
                raise ValueError("R4_APP_TRANSACTION_BLOCKED_" + reason) from error

        return operation


def _bounded(rom, operation_timeout, session_timeout):
    return rom if isinstance(rom, _BoundedROM) else _BoundedROM(rom, operation_timeout, session_timeout)


async def _sector(rom: ROM, address: int) -> bytes:
    raw = await rom.read(address, SECTOR)
    if type(raw) is not bytes or len(raw) != SECTOR:
        deny("BOUNDED_READ_FAILED_" + hex(address))
    reported_crc = await rom.crc32(address, SECTOR)
    if type(reported_crc) is not int or reported_crc != crc(raw):
        deny("INDEPENDENT_READBACK_CRC_DISAGREES_" + hex(address))
    return raw


async def _observe(rom: ROM, package: AppPackage, live_identity_sha256: str) -> dict[int, str]:
    if await rom.identity_sha256() != live_identity_sha256:
        deny("CURRENT_BOARD_IDENTITY_CHANGED")
    # Read/CRC in exact sectors. No mass read/erase command is assumed.
    return {address: sha(await _sector(rom, address)) for address in range(0, FLASH, SECTOR)}


def _baseline(package: AppPackage) -> dict[int, str]:
    return {address: sha(package.snapshot[address:address + SECTOR]) for address in range(0, FLASH, SECTOR)}


async def admit(rom: ROM, package: AppPackage, *, expected_profile_sha256: str,
                expected_package_sha256: str, capture_receipt: dict,
                expected_capture_receipt_sha256: str, expected_live_identity_sha256: str,
                operation_timeout: float = OPERATION_TIMEOUT,
                session_timeout: float = SESSION_TIMEOUT) -> dict:
    """Read-only full current-state check; receipt is not hardware permission."""
    rom = _bounded(rom, operation_timeout, session_timeout)
    package = _freeze_package(package)
    capture_receipt = _freeze_json(capture_receipt)
    validate_package(package, expected_profile_sha256=expected_profile_sha256,
                     expected_package_sha256=expected_package_sha256)
    live_identity = _capture_live_identity(package, capture_receipt,
        expected_capture_receipt_sha256=expected_capture_receipt_sha256,
        expected_live_identity_sha256=expected_live_identity_sha256)
    observed = await _observe(rom, package, live_identity)
    if observed != _baseline(package):
        deny("LIVE_CAPTURE_CHANGED")
    result = {"schema": "r4-p7u-current-app-admission-v1",
              "package_sha256": expected_package_sha256,
              "profile_sha256": expected_profile_sha256,
              "board_identity_sha256": package.profile["board_identity_sha256"],
              "live_management_identity_sha256": live_identity,
              "capture_receipt_sha256": expected_capture_receipt_sha256,
              "observed_sector_sha256": observed,
              "flash_authorized": False, "flash_performed": False}
    result["admission_sha256"] = sha(canonical(result))
    return result


async def _accepted(rom: ROM, operation_result, reason: str):
    if operation_result is not True:
        deny(reason)
    if await rom.status() is not True:
        deny(reason + "_STATUS")


async def _guard_before_erase(rom: ROM, package: AppPackage, address: int,
                              expected_live: dict[int, str], live_identity_sha256: str):
    if await rom.identity_sha256() != live_identity_sha256:
        deny("CURRENT_BOARD_IDENTITY_CHANGED")
    protected = {sector for first, end in package.profile["geometry"]["protected_ranges"]
                 for sector in range(first // SECTOR * SECTOR, end, SECTOR)}
    # Initial/final checks cover ALL flash. Between erases, protect the entire
    # reserved region and the current target, avoiding repeated full-chip reads.
    # Vector0 is checked against its original bytes immediately before its erase.
    for sector in sorted(protected | {address}):
        if sha(await _sector(rom, sector)) != expected_live[sector]:
            deny("LIVE_STATE_CHANGED_BEFORE_ERASE_" + hex(address))


async def _write(rom: ROM, package: AppPackage, targets: dict[int, bytes],
                 expected_live: dict[int, str], live_identity_sha256: str) -> dict:
    # The ONLY target set is the exact externally bound package allowlist.
    if set(targets) != set(package.sectors):
        deny("WRITE_ALLOWLIST_CHANGED")
    completed = []
    for address in package.manifest["program_order"]:
        await _guard_before_erase(rom, package, address, expected_live, live_identity_sha256)
        after = targets[address]
        if sha(after) == expected_live[address]:
            continue
        # Last synchronous check before irreversible hardware access. Neither
        # an injected adapter nor an async caller can expand the frozen APP
        # allowlist to a reserved/NV/CCFG address.
        if type(address) is not int or address not in package.sectors:
            deny("ERASE_TARGET_NOT_IN_FROZEN_PACKAGE")
        _allowed(package.profile, package.profile["geometry"], address)
        await _accepted(rom, await rom.erase_sector(address), "SECTOR_ERASE_REJECTED_" + hex(address))
        await _accepted(rom, await rom.begin_download(address, SECTOR), "PLAIN_DOWNLOAD_REJECTED_" + hex(address))
        for offset in range(0, SECTOR, PACKET):
            packet = after[offset:offset + PACKET]
            if not packet or len(packet) > PACKET or len(packet) % 4:
                deny("INVALID_PACKET_GEOMETRY")
            await _accepted(rom, await rom.send_data(packet), "PACKET_FAILED_" + hex(address))
        readback = await _sector(rom, address)
        if readback != after:
            deny("FINAL_SECTOR_READBACK_FAILED_" + hex(address))
        expected_live[address] = sha(after)
        completed.append(address)
    if await _observe(rom, package, live_identity_sha256) != expected_live:
        deny("FINAL_FULL_STATE_CHANGED")
    return {"written_sectors": completed, "ccfg_touched": False, "nv_touched": False,
            "reset_issued": False, "automatic_rollback": False, "network_rollback_qualified": False}


async def execute(rom: ROM, package: AppPackage, admission: dict, *, expected_profile_sha256: str,
                  expected_package_sha256: str, expected_admission_sha256: str,
                  capture_receipt: dict, expected_capture_receipt_sha256: str,
                  expected_live_identity_sha256: str,
                  operation_timeout: float = OPERATION_TIMEOUT,
                  session_timeout: float = SESSION_TIMEOUT) -> dict:
    """Invoke ONLY from a separately approved operator session; never retries."""
    rom = _bounded(rom, operation_timeout, session_timeout)
    package = _freeze_package(package)
    admission = _freeze_json(admission)
    capture_receipt = _freeze_json(capture_receipt)
    current = await admit(rom, package, expected_profile_sha256=expected_profile_sha256,
                          expected_package_sha256=expected_package_sha256,
                          capture_receipt=capture_receipt,
                          expected_capture_receipt_sha256=expected_capture_receipt_sha256,
                          expected_live_identity_sha256=expected_live_identity_sha256)
    if current != admission or current["admission_sha256"] != expected_admission_sha256:
        deny("ADMISSION_CHANGED")
    result = await _write(rom, package, package.sectors, _baseline(package),
                          expected_live_identity_sha256)
    result["status"] = "APP_SECTORS_READBACK_VERIFIED_STILL_IN_BSL"
    return result


async def rollback_current_app(rom: ROM, package: AppPackage, *, expected_profile_sha256: str,
                               expected_package_sha256: str, expected_live_sector_sha256: dict[int, str],
                               capture_receipt: dict, expected_capture_receipt_sha256: str,
                               expected_live_identity_sha256: str,
                               operation_timeout: float = OPERATION_TIMEOUT,
                               session_timeout: float = SESSION_TIMEOUT) -> dict:
    """Explicit caller action only: restore exact CURRENT app sectors, never NV.

    A caller must independently read and pin every allowlisted current sector,
    including interrupted writes. Non-target sectors must STILL match the
    current capture. This proves byte restoration, not network downgrade safety.
    """
    rom = _bounded(rom, operation_timeout, session_timeout)
    package = _freeze_package(package)
    capture_receipt = _freeze_json(capture_receipt)
    expected_live_sector_sha256 = dict(expected_live_sector_sha256)
    validate_package(package, expected_profile_sha256=expected_profile_sha256,
                     expected_package_sha256=expected_package_sha256)
    live_identity = _capture_live_identity(package, capture_receipt,
        expected_capture_receipt_sha256=expected_capture_receipt_sha256,
        expected_live_identity_sha256=expected_live_identity_sha256)
    if set(expected_live_sector_sha256) != set(package.sectors):
        deny("ROLLBACK_LIVE_SECTOR_PINS_MISSING")
    baseline = _baseline(package)
    expected = dict(baseline)
    expected.update(expected_live_sector_sha256)
    if await _observe(rom, package, live_identity) != expected:
        deny("ROLLBACK_LIVE_OR_PROTECTED_STATE_CHANGED")
    targets = {address: package.snapshot[address:address + SECTOR] for address in package.sectors}
    result = await _write(rom, package, targets, expected, live_identity)
    result["status"] = "EXACT_CURRENT_APP_RESTORED_STILL_IN_BSL"
    return result
