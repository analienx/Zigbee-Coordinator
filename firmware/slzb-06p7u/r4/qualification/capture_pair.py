"""Bounded duplicate P7U ROM reads through an explicitly supplied read adapter.

No network connection, BSL entry, reset or write API is provided. The operator
must obtain approval for the interruption and own session entry/return to stock.
Raw output is private and may not be placed inside this repository.
"""
from __future__ import annotations

import asyncio
import binascii
import hashlib
import json
from pathlib import Path
import re
from typing import Protocol

FLASH_BYTES = 0xB0000
BLOCK_BYTES = 240
REPO = Path(__file__).resolve().parents[4]


def _inside_git_repository(path: Path) -> bool:
    """Reject real worktrees, not unrelated empty .git placeholder directories."""
    for directory in (path, *path.parents):
        marker = directory / ".git"
        if marker.is_file() or (marker.is_dir() and (marker / "HEAD").is_file()):
            return True
    return False


class ReadOnlyROM(Protocol):
    async def identity_sha256(self) -> str: ...
    async def flash_size(self) -> int: ...
    async def read_flash(self, address: int, length: int) -> bytes: ...
    async def crc32(self, address: int, length: int) -> int: ...


async def capture_pair(rom: ReadOnlyROM, output: Path, *, expected_identity_sha256: str,
                       total_timeout_seconds: float = 600, request_timeout_seconds: float = 6) -> dict:
    if not isinstance(expected_identity_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_identity_sha256):
        raise ValueError("CAPTURE_EXTERNAL_IDENTITY_PIN_REQUIRED")
    if (type(total_timeout_seconds) not in (int, float) or
            type(request_timeout_seconds) not in (int, float) or
            not 0 < request_timeout_seconds <= 10 or
            not request_timeout_seconds <= total_timeout_seconds <= 1800):
        raise ValueError("CAPTURE_FINITE_BOUNDED_TIMEOUTS_REQUIRED")
    if output.is_symlink():
        raise ValueError("CAPTURE_NEW_PRIVATE_DIRECTORY_REQUIRED")
    output = output.resolve()
    if (output == REPO or REPO in output.parents or output.exists() or
            _inside_git_repository(output)):
        raise ValueError("CAPTURE_NEW_PRIVATE_DIRECTORY_REQUIRED")

    async def call(method, *args):
        return await asyncio.wait_for(method(*args), timeout=request_timeout_seconds)

    async with asyncio.timeout(total_timeout_seconds):
        if await call(rom.identity_sha256) != expected_identity_sha256:
            raise ValueError("CAPTURE_LIVE_IDENTITY_MISMATCH")
        size = await call(rom.flash_size)
        if type(size) is not int or size != FLASH_BYTES:
            raise ValueError("CAPTURE_LIVE_FLASH_GEOMETRY_MISMATCH")
        # Only create output after live identity/geometry are established.
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
        hashes = []
        for pass_number in (1, 2):
            digest = hashlib.sha256()
            crc = 0
            with (output / f"current-pass{pass_number}.bin").open("xb") as stream:
                for address in range(0, FLASH_BYTES, BLOCK_BYTES):
                    length = min(BLOCK_BYTES, FLASH_BYTES - address)
                    raw = await call(rom.read_flash, address, length)
                    if type(raw) is not bytes or len(raw) != length:
                        raise ValueError("CAPTURE_SHORT_OR_INVALID_ROM_READ")
                    stream.write(raw)
                    digest.update(raw)
                    crc = binascii.crc32(raw, crc)
            live_crc = await call(rom.crc32, 0, FLASH_BYTES)
            if type(live_crc) is not int or live_crc != crc & 0xFFFFFFFF:
                raise ValueError("CAPTURE_ROM_CRC_MISMATCH")
            hashes.append(digest.hexdigest())
        if hashes[0] != hashes[1]:
            raise ValueError("CAPTURE_TWO_PASSES_DISAGREE")
        if await call(rom.identity_sha256) != expected_identity_sha256:
            raise ValueError("CAPTURE_FINAL_IDENTITY_MISMATCH")
        report = {"schema": "r4-p7u-capture-pair-v1", "status": "DUPLICATE_READBACK_MATCH",
                  "board_identity_sha256": expected_identity_sha256, "flash_bytes": FLASH_BYTES,
                  "pass1_sha256": hashes[0], "pass2_sha256": hashes[1],
                  "capture_origin": "SUPPLIED_ROM_ADAPTER_REQUIRES_OPERATOR_PROVENANCE",
                  "nv_compatibility_verified": False, "reset_issued": False,
                  "flash_performed": False, "return_to_stock_verified": False}
        with (output / "capture-receipt.json").open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        return report
