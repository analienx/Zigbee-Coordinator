"""Fast read-only P7U sparse baseline reconstruction; no flash authorization.

The previous *fully verified* installed image is supplied externally, never
derived from a stale baseline claim. Before cutover, require an independent
source/identity/network provenance receipt linking that image to the live unit.

During the single ROM session, compare native 88-sector ROM CRC32 against
the previous full snapshot, but accept drift ONLY in protected NV sectors
A0000..ABFFF. Refresh those sectors byte-for-byte, validate each by native
ROM CRC32 and derive an honest SHA256 of the reconstructed image. CCFG,
boot sector and all 82 non-NV sectors must agree with their expected image.

CRITICAL: CRC32 is not cryptographic authentication. This function is an
operational delta-integrity aid, NOT a replacement for first-use dual captures,
TI-native semantic security preflight, link-key/counter checks, separate owner
authorization, or byte readback of any sectors programmed afterward.
"""
from __future__ import annotations

from dataclasses import dataclass
import asyncio
import binascii
import hashlib
import math
from typing import Protocol

FLASH=0xB0000
SECTOR=0x2000
NV_START=0xA0000
NV_END=0xAC000
PROTECTED_TOP=0xAE000

class ReadROM(Protocol):
    async def identity_sha256(self) -> str: ...
    async def crc32(self, addr: int, length: int) -> int: ...
    async def read_flash(self, addr: int, length: int) -> bytes: ...

def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def _check(ok: bool, message: str):
    if not ok:
        raise ValueError("P7U_SPARSE_" + message)

@dataclass(frozen=True)
class SparseReceipt:
    """Publicly share only aggregate/checksums; raw NV stays private."""
    source_baseline_sha256: str
    live_reconstructed_sha256: str
    expected_identity_sha256: str
    nv_bytes_read: int
    baseline_nv_changed_sectors: int
    rom_crc32_sector_checks: int
    status: str = "SPARSE_ROM_CRC_WITH_FRESH_NV_READ_ONLY_NOT_FLASH_ADMISSION"

@dataclass(frozen=True)
class SparseSnapshot:
    snapshot: bytes
    receipt: SparseReceipt

async def _capture_sparse_body(rom: ReadROM, *, prior_full_verified: bytes,
                               expected_identity_sha256: str) -> SparseSnapshot:
    _check(type(prior_full_verified) is bytes and len(prior_full_verified)==FLASH,
           "SOURCE_BASELINE_REQUIRED")
    _check(type(expected_identity_sha256) is str
           and len(expected_identity_sha256)==64
           and all(c in "0123456789abcdef" for c in expected_identity_sha256),
           "EXTERNAL_HARDWARE_IDENTITY_PIN")
    _check(await rom.identity_sha256()==expected_identity_sha256,"HARDWARE_CHANGED")
    reconstructed=bytearray(prior_full_verified)
    checks=0
    changed=0
    for addr in range(0,FLASH,SECTOR):
        prior=prior_full_verified[addr:addr+SECTOR]
        if NV_START<=addr<NV_END:
            current=await rom.read_flash(addr,SECTOR)
            _check(type(current) is bytes and len(current)==SECTOR,
                   "NV_CAPTURE_SHORT")
            live_crc=await rom.crc32(addr,SECTOR)
            checks+=1
            _check(binascii.crc32(current)&0xffffffff==live_crc,
                   "NV_CAPTURE_CRC_MISMATCH")
            changed+=int(current!=prior)
            reconstructed[addr:addr+SECTOR]=current
        else:
            live_crc=await rom.crc32(addr,SECTOR)
            checks+=1
            _check(binascii.crc32(prior)&0xffffffff==live_crc,
                   "NON_NV_BASELINE_DRIFT")
    _check(await rom.identity_sha256()==expected_identity_sha256,
           "HARDWARE_CHANGED_DURING_SNAPSHOT")
    result=bytes(reconstructed)
    return SparseSnapshot(result, SparseReceipt(
        source_baseline_sha256=_sha(prior_full_verified),
        live_reconstructed_sha256=_sha(result),
        expected_identity_sha256=expected_identity_sha256,
        nv_bytes_read=NV_END-NV_START,
        baseline_nv_changed_sectors=changed,
        rom_crc32_sector_checks=checks))

async def capture_sparse(rom: ReadROM, *, prior_full_verified: bytes,
                         expected_identity_sha256: str,
                         total_timeout_seconds: float = 25.0) -> SparseSnapshot:
    """Time-bound the entire read-only qualification before any erase/write.

    Caller MUST treat timeout as a HOLD; do not blindly retry BSL entry,
    reuse a partially collected NV snapshot or proceed with mutation.
    """
    _check(type(total_timeout_seconds) in (int,float)
           and math.isfinite(total_timeout_seconds)
           and 0 < total_timeout_seconds <= 60, 'INVALID_READONLY_DEADLINE')
    return await asyncio.wait_for(
        _capture_sparse_body(rom, prior_full_verified=prior_full_verified,
                             expected_identity_sha256=expected_identity_sha256),
        timeout=total_timeout_seconds)


# Distinct security contract: known cryptographically verified R4 installation,
# all static sectors checked by LIVE ROM CRC, one freshly read set of protected
# sectors independently verified by ROM CRC/status, and complete final 88-sector
# byte/SHA readback. No claim of duplicate fresh captures.
import time
import weakref

KNOWN_R4_PROFILE = "KNOWN_R4_FRESH_PROTECTED_FULL_FINAL_SHA"
KNOWN_R4_CAPTURE_SECONDS = 60.
_KNOWN_WITNESSES = weakref.WeakKeyDictionary()
FRESH_SECTORS = tuple(range(NV_START, NV_END, SECTOR)) + (PROTECTED_TOP,)
DYNAMIC_NV = tuple(range(0xA4000, NV_END, SECTOR))


class KnownR4FreshProtectedWitness:
    """Opaque one-session capture. Serialization/copying does not transfer trust."""
    __slots__ = ("_rom", "_reader", "_writer", "_created", "_snapshot_sha",
                 "_source_sha", "_capture_sha", "_consumed", "__weakref__")

    def __init__(self, rom, reader, writer, snapshot_sha, source_sha, capture_sha):
        self._rom = weakref.ref(rom)
        self._reader, self._writer = reader, writer
        self._created = time.monotonic()
        self._snapshot_sha = snapshot_sha
        self._source_sha = source_sha
        self._capture_sha = capture_sha
        self._consumed = False

    def __reduce__(self):
        raise TypeError("P7U_KNOWN_CAPTURE_WITNESS_NOT_SERIALIZABLE")

    def __copy__(self):
        raise TypeError("P7U_KNOWN_CAPTURE_WITNESS_NOT_COPYABLE")

    def __deepcopy__(self, memo):
        raise TypeError("P7U_KNOWN_CAPTURE_WITNESS_NOT_COPYABLE")


@dataclass(frozen=True)
class KnownR4Capture:
    snapshot: bytes
    receipt: dict
    witness: KnownR4FreshProtectedWitness


def require_known_witness(rom, witness, receipt: dict, snapshot: bytes,
                          installed_sha: str, *, consume: bool = False):
    _check(type(witness) is KnownR4FreshProtectedWitness, "LIVE_WITNESS_REQUIRED")
    _check(_KNOWN_WITNESSES.get(rom) is witness and
           witness._rom() is rom and not witness._consumed,
           "WITNESS_MISSING_REPLAYED_OR_DIFFERENT_SESSION")
    _check(time.monotonic() - witness._created <= KNOWN_R4_CAPTURE_SECONDS,
           "WITNESS_EXPIRED")
    _check(getattr(rom, "reader", None) is witness._reader and
           getattr(rom, "writer", None) is witness._writer and
           witness._reader is not None and witness._writer is not None and
           not getattr(rom, "_faulted", True),
           "UART_SESSION_REOPENED_OR_FAULTED")
    _check(type(snapshot) is bytes and len(snapshot) == FLASH and
           witness._snapshot_sha == _sha(snapshot) and
           witness._source_sha == installed_sha,
           "WITNESS_SOURCE_OR_IMAGE_MISMATCH")
    _check(type(receipt) is dict and
           receipt.get("profile") == KNOWN_R4_PROFILE and
           receipt.get("live_reconstructed_sha256") == witness._snapshot_sha and
           receipt.get("installed_verified_sha256") == installed_sha and
           receipt.get("protected_reads") == 1 and
           receipt.get("protected_sectors_per_pass") == 7 and
           receipt.get("static_sector_rom_crc_checks") == 84 and
           receipt.get("fresh_capture_bytes") == len(FRESH_SECTORS) * SECTOR,
           "WITNESS_CAPTURE_RECEIPT_MISMATCH")
    from hashlib import sha256
    import json
    digest = sha256(json.dumps(receipt,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    _check(digest == witness._capture_sha, "WITNESS_RECEIPT_REBOUND")
    if consume:
        witness._consumed = True
        _KNOWN_WITNESSES.pop(rom, None)


async def capture_known_installed(rom, *, installed_verified_image: bytes,
                                  expected_identity_sha256: str,
                                  total_timeout_seconds: float = 55.):
    """Read-only known R4 capture: one fresh protected read, live ROM CRC,
    explicit status fences, and an in-process same-UART witness.
    The caller must prove installed_verified_image by its successful previous
    APP+boot installation receipt, not simply claim a file is installed.
    """
    _check(type(total_timeout_seconds) in (int,float) and
           0 < total_timeout_seconds <= 60 and math.isfinite(total_timeout_seconds),
           "INVALID_KNOWN_CAPTURE_DEADLINE")
    _check(type(installed_verified_image) is bytes and
           len(installed_verified_image) == FLASH, "INSTALLED_IMAGE_REQUIRED")
    _check(getattr(rom, "reader", None) is not None and
           getattr(rom, "writer", None) is not None and
           not getattr(rom,"_faulted", True), "SINGLE_LIVE_ROM_SESSION_REQUIRED")
    _check(callable(getattr(rom, "assert_read_status", None)),
           "FAST_ROM_READ_FENCES_REQUIRED")
    async def body():
        _check(await rom.identity_sha256() == expected_identity_sha256,
               "SILICON_IDENTITY_CHANGED")
        actual = bytearray(installed_verified_image)
        static = 0
        expected_crc = [binascii.crc32(installed_verified_image[i:i+SECTOR]) & 0xffffffff
                        for i in range(0, FLASH, SECTOR)]
        # First static pass, including current APP, separate handoff, NV guards,
        # and CCFG. Dynamic NV may differ; its current CRC is checked per pass.
        for addr in range(0, FLASH, SECTOR):
            if addr in DYNAMIC_NV:
                continue
            crc = await rom.crc32(addr,SECTOR)
            static += 1
            _check(crc == expected_crc[addr//SECTOR],
                   "INSTALLED_STATIC_OR_GUARD_SECTOR_DRIFT")
        _check(static == 84, "STATIC_SECTOR_COUNT_ERROR")
        first = {}
        for addr in FRESH_SECTORS:
            part = await rom.read_flash(addr,SECTOR)
            _check(type(part) is bytes and len(part) == SECTOR,
                   "FRESH_PROTECTED_READ_SHORT")
            _check((binascii.crc32(part)&0xffffffff) == await rom.crc32(addr,SECTOR),
                   "PROTECTED_READ_CRC_FAILED")
            first[addr] = part
        await rom.assert_read_status()
        for addr in FRESH_SECTORS:
            if addr not in DYNAMIC_NV:
                _check(first[addr] == installed_verified_image[addr:addr+SECTOR],
                       "PROTECTED_GUARD_OR_CCFG_DRIFT")
            actual[addr:addr+SECTOR] = first[addr]
        _check(await rom.identity_sha256() == expected_identity_sha256,
               "SILICON_IDENTITY_AFTER_CAPTURE_CHANGED")
        await rom.assert_read_status()
        image = bytes(actual)
        receipt = {"schema":"p7u-known-r4-fresh-protected-v1",
                   "profile":KNOWN_R4_PROFILE,
                   "live_reconstructed_sha256":_sha(image),
                   "installed_verified_sha256":_sha(installed_verified_image),
                   "expected_identity_sha256":expected_identity_sha256,
                   "protected_reads":1, "protected_sectors_per_pass":7,
                   "fresh_capture_bytes":len(FRESH_SECTORS)*SECTOR,
                   "static_sector_rom_crc_checks":static,
                   "fresh_dynamic_sectors":4,
                   "full_rom_sha_preflight":False,
                   "full_rom_sha_final_required":True,
                   "status":"FRESH_PROTECTED_PASS_NO_FLASH_AUTHORIZATION"}
        import json
        receipt_hash=_sha(json.dumps(receipt,sort_keys=True,separators=(",",":")).encode())
        witness=KnownR4FreshProtectedWitness(rom,rom.reader,rom.writer,
                                             _sha(image),_sha(installed_verified_image),
                                             receipt_hash)
        _KNOWN_WITNESSES[rom]=witness
        return KnownR4Capture(image,receipt,witness)
    return await asyncio.wait_for(body(),total_timeout_seconds)
