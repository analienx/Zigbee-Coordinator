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
import binascii
import hashlib
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

async def capture_sparse(rom: ReadROM, *, prior_full_verified: bytes,
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
