#!/usr/bin/env python3
"""CC2652P7U-only ROM sector writer core; no serial/network API imported here.

All writes require prior read-only approval from the *same* radio. Never use
SMLIGHT CLI erase/write paths: they auto BANK_ERASE segmented HEX.
Only an explicitly supplied ROM adapter can perform writes. No reset on error.
"""
from __future__ import annotations

import binascii
import hashlib
import importlib.util
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

HERE = Path(__file__).resolve().parent


def module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


gate = module("p7u_strict_gate", HERE / "p7u_rom_bsl_image_gate.py")
sector = module("p7u_strict_sector", HERE / "p7u_app_sector_plan.py")

FCFG_BASE = 0x50001000
FCFG_ICEPICK_ID = FCFG_BASE + 0x318
FCFG_PRIMARY_IEEE = FCFG_BASE + 0x2F0
FLASH_SIZE_REG = 0x40030000 + 0x2C
FAMILY_WAFER_ID = 0xBB77  # CC13x2x7/CC26x2x7, from pinned SMLIGHT CC26xx.async_init
PACKET = 252  # BSL SEND_DATA payload ceiling; multiple of 4
WRITER_VERSION = "1.0.0"
R4_MAX_SECTORS = 23
R4_LAST_APP_END = 0x2E000


class StrictError(ValueError):
    """Bounded public failure code; never include IEEE, CCFG or key bytes."""


def check(ok: bool, code: str) -> None:
    if not ok:
        raise StrictError(code)


class Rom(Protocol):
    async def get_chip_id(self) -> int: ...
    async def read_word(self, addr: int) -> bytes: ...
    async def crc32(self, addr: int, length: int) -> int: ...
    async def erase_sector(self, addr: int) -> bool: ...
    async def begin_download(self, addr: int, length: int) -> bool: ...
    async def send_data(self, packet: bytes) -> bool: ...


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf8")


@dataclass(frozen=True)
class Bundle:
    profile: str
    hex_sha256: str
    plan_sha256: str
    sectors: tuple[tuple[int, bytes], ...]
    # Every sector is padded with 0xff. Any sector absent from the plan is untouched.


def load_bundle(app_hex: bytes, source_evidence: dict, plan_file: dict) -> Bundle:
    try:
        expected_plan = sector.plan(app_hex, source_evidence)
        data = gate.parse_hex(app_hex)
    except ValueError as exc:
        raise StrictError("SOURCE_BUNDLE_INVALID") from exc
    check(plan_file == expected_plan, "SECTOR_PLAN_NOT_REDERIVED_EXACTLY")
    check(expected_plan["execution_implemented"] is False
          and expected_plan["flash_authorized"] is False,
          "UNEXPECTED_AUTHORIZATION_IN_SOURCE_PLAN")
    starts = [int(x, 16) for x in expected_plan["explicit_application_sector_erase_addresses"]]
    check(starts and len(starts) <= 23, "SECTOR_COUNT_OUT_OF_BOUNDS")
    check(starts == list(range(0, starts[-1] + gate.SECTOR, gate.SECTOR)),
          "SPARSE_SECTORS_NEED_EXPLICIT_REVIEW")
    limit = gate.NV2_BASE if expected_plan["profile"] == "p7u-f07-stock" else gate.NV5_BASE
    check(starts[-1] + gate.SECTOR <= limit, "SECTOR_LIST_TOUCHES_NV")
    check(all(0 <= a < limit for a in data), "CANDIDATE_TOUCHES_NV")
    check(set(starts) == {a // gate.SECTOR * gate.SECTOR for a in data},
          "SECTOR_PLAN_ADDRESS_MISMATCH")
    blocks: list[tuple[int, bytes]] = []
    for start in starts:
        check(0 <= start < gate.NV5_BASE and start + gate.SECTOR <= limit,
              "ERASE_ADDRESS_PROTECTED")
        block = bytearray(b"\xff" * gate.SECTOR)
        for addr in range(start, start + gate.SECTOR):
            if addr in data:
                block[addr - start] = data[addr]
        blocks.append((start, bytes(block)))
    check(bool(blocks) and blocks[0][0] == 0, "NO_APPLICATION_VECTOR_SECTOR")
    return Bundle(expected_plan["profile"], sha(app_hex),
                  sha(canonical(expected_plan)), tuple(blocks))


async def read_exact(rom: Rom, addr: int, length: int) -> bytes:
    check(length > 0 and length % 4 == 0 and addr % 4 == 0, "BAD_READ_ALIGNMENT")
    result = bytearray()
    for where in range(addr, addr + length, 4):
        word = await rom.read_word(where)
        check(type(word) is bytes and len(word) == 4, "ROM_READ_NOT_FOUR_BYTES")
        result.extend(word)
    return bytes(result)


def valid_ccfg(blob: bytes) -> None:
    check(len(blob) == gate.CCFG_SIZE, "INSTALLED_CCFG_BAD_SIZE")
    bl = struct.unpack_from("<I", blob, gate.BL_CONFIG_OFFSET)[0]
    erase = struct.unpack_from("<I", blob, gate.ERASE_CONF_OFFSET)[0]
    vector = struct.unpack_from("<I", blob, gate.IMAGE_VALID_OFFSET)[0]
    check((bl & 0xff) == 0xC5 and (bl >> 24) == 0xC5, "INSTALLED_ROM_BSL_DISABLED")
    check(((bl >> 8) & 0xff) == 15 and (bl & 0x10000) == 0,
          "INSTALLED_BACKDOOR_NOT_DIO15_LOW")
    check((erase & 1) == 1, "INSTALLED_ROM_BANK_ERASE_DISABLED")
    check(vector == 0, "INSTALLED_ROM_VECTOR_NONZERO_NOT_QUALIFIED")
    # CCFG differs per unit (IEEE), therefore exact vendor hash is *not* required.


async def observe(rom: Rom) -> dict:
    chip_id = await rom.get_chip_id()
    check(type(chip_id) is int and 0 < chip_id <= 65535, "ROM_CHIP_ID_INVALID")
    wafer = await read_exact(rom, FCFG_ICEPICK_ID, 4)
    wafer_id = (((wafer[3] & 15) << 16) + (wafer[2] << 8) +
                (wafer[1] & 0xF0)) >> 4
    check(wafer_id == FAMILY_WAFER_ID, "NOT_CC26X2X7_SILICON")
    size_reg = await read_exact(rom, FLASH_SIZE_REG, 4)
    check(size_reg[0] * gate.SECTOR == gate.RADIO_SIZE, "NOT_704K_P7_FLASH")
    factory_id = await read_exact(rom, FCFG_PRIMARY_IEEE, 8)
    ccfg = await read_exact(rom, gate.CCFG_START, gate.CCFG_SIZE)
    valid_ccfg(ccfg)
    return {
        "chip_id": chip_id,
        "silicon_wafer": "CC13x2x7_CC26x2x7_0xBB77",
        "flash_bytes": gate.RADIO_SIZE,
        "factory_id_digest": sha(factory_id),
        "ccfg_sha256": sha(ccfg),
        "rom_backdoor_pin": "TI_DIO15_ACTIVE_LOW",
        "read_only_identity": True,
    }


def validate_r4_bundle(bundle: Bundle) -> None:
    """Fail before physical I/O if caller forges a Bundle or expands its scope.

    The legacy load_bundle parser also exists for historical F07 source plans;
    the R4 operator uses only this fixed 23-sector, current-board package.
    """
    check(isinstance(bundle, Bundle), "R4_BUNDLE_CLASS_REQUIRED")
    check(isinstance(bundle.profile, str) and bundle.profile.startswith("p7u-r4-"),
          "R4_PROFILE_REQUIRED")
    check(all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
              for v in (bundle.hex_sha256, bundle.plan_sha256)),
          "R4_EXTERNAL_IMAGE_PINS_REQUIRED")
    check(type(bundle.sectors) is tuple and len(bundle.sectors) == R4_MAX_SECTORS,
          "R4_EXACT_23_SECTORS_REQUIRED")
    expected = range(0, R4_LAST_APP_END, gate.SECTOR)
    for item, address in zip(bundle.sectors, expected):
        check(type(item) is tuple and len(item) == 2 and type(item[0]) is int
              and item[0] == address and type(item[1]) is bytes
              and len(item[1]) == gate.SECTOR,
              "R4_SECTOR_ORDER_ADDRESS_OR_LENGTH")
    # Ensure the new first words are non-erased and vector-like. The final
    # executable boot result still requires independent physical proof.
    sp, reset = struct.unpack_from("<II", bundle.sectors[0][1])
    check(sp % 8 == 0 and 0x20000000 < sp <= 0x20024000
          and (reset & 1) == 1 and 8 <= (reset & ~1) < R4_LAST_APP_END,
          "R4_APP_VECTOR_NOT_STRUCTURALLY_VALID")


async def preflight(rom: Rom, bundle: Bundle, endpoint: str) -> dict:
    validate_r4_bundle(bundle)
    check(bool(endpoint), "ENDPOINT_REQUIRED")
    identity = await observe(rom)
    states: list[dict] = []
    for addr, image in bundle.sectors:
        actual_crc = await rom.crc32(addr, gate.SECTOR)
        check(type(actual_crc) is int and 0 <= actual_crc <= 0xFFFFFFFF,
              "ROM_CRC_INVALID")
        states.append({"address": f"0x{addr:05X}",
                       "before_crc32": f"{actual_crc:08x}",
                       "desired_crc32": f"{binascii.crc32(image) & 0xffffffff:08x}"})
    approved = {"schema": "p7u-spare-radio-approval-v1",
                "writer_version": WRITER_VERSION,
                "target": "SLZB-06P7U_CC2652P7_RADIO_ONLY",
                "endpoint": endpoint, "identity": identity,
                "profile": bundle.profile, "app_hex_sha256": bundle.hex_sha256,
                "sector_plan_sha256": bundle.plan_sha256,
                "sectors": states, "flash_performed": False,
                "image_requires_sector_only_erase": True,
                "ccfg_and_nv_excluded": True,
                "rom_bsl_access_observed": True,
                "rollback_physically_proven": False,
                "flash_authorized": False}
    approved["approval_digest"] = sha(canonical(approved))
    return approved


def validate_approval(bundle: Bundle, approval: dict,
                      supplied_digest: str, endpoint: str) -> str:
    """Validate the complete offline approval before any management BSL reset."""
    raw = dict(approval)
    token = raw.pop("approval_digest", None)
    check(type(token) is str and len(token) == 64 and token == sha(canonical(raw)),
          "APPROVAL_FILE_TAMPERED")
    check(supplied_digest == token, "APPROVAL_TOKEN_MISMATCH")
    check(approval.get("schema") == "p7u-spare-radio-approval-v1"
          and approval.get("writer_version") == WRITER_VERSION
          and approval.get("target") == "SLZB-06P7U_CC2652P7_RADIO_ONLY"
          and approval.get("flash_authorized") is False
          and approval.get("flash_performed") is False,
          "APPROVAL_SCHEMA_CHANGED")
    identity = approval.get("identity")
    check(type(identity) is dict
          and type(identity.get("chip_id")) is int and 0 < identity["chip_id"] <= 65535
          and identity.get("silicon_wafer") == "CC13x2x7_CC26x2x7_0xBB77"
          and identity.get("flash_bytes") == gate.RADIO_SIZE
          and identity.get("rom_backdoor_pin") == "TI_DIO15_ACTIVE_LOW"
          and identity.get("read_only_identity") is True
          and all(type(identity.get(key)) is str
                  and re.fullmatch(r"[0-9a-f]{64}", identity[key]) is not None
                  for key in ("factory_id_digest", "ccfg_sha256")),
          "APPROVAL_IDENTITY_INVALID")
    check(approval.get("endpoint") == endpoint
          and approval.get("app_hex_sha256") == bundle.hex_sha256
          and approval.get("sector_plan_sha256") == bundle.plan_sha256
          and approval.get("profile") == bundle.profile, "APPROVAL_TARGET_OR_IMAGE_CHANGED")
    expected = approval.get("sectors")
    check(type(expected) is list and len(expected) == len(bundle.sectors),
          "APPROVAL_SECTOR_COUNT_CHANGED")
    for (addr, image), row in zip(bundle.sectors, expected):
        check(type(row) is dict and row.get("address") == f"0x{addr:05X}"
              and row.get("desired_crc32") ==
              f"{binascii.crc32(image) & 0xffffffff:08x}",
              "APPROVAL_SECTOR_CHANGED")
        check(type(row.get("before_crc32")) is str
              and re.fullmatch(r"[0-9a-f]{8}", row["before_crc32"]) is not None,
              "APPROVAL_PRIOR_CRC_INVALID")
    return token


async def write_checked(rom: Rom, bundle: Bundle, approval: dict,
                        supplied_digest: str, endpoint: str,
                        *, allow_resume: bool = False) -> dict:
    """Recheck approval and live identity before any sector erase; never reset."""
    validate_r4_bundle(bundle)
    check(allow_resume is False, "UNBOUNDED_RESUME_NOT_PERMITTED")
    token = validate_approval(bundle, approval, supplied_digest, endpoint)
    identity = await observe(rom)
    check(identity == approval.get("identity"), "TARGET_IDENTITY_OR_CCFG_CHANGED")
    before = []
    for (addr, image), row in zip(bundle.sectors, approval["sectors"]):
        live = await rom.crc32(addr, gate.SECTOR)
        check(type(live) is int and 0 <= live <= 0xFFFFFFFF, "ROM_CRC_INVALID")
        check(allow_resume or f"{live:08x}" in
              (row.get("before_crc32"), row.get("desired_crc32")),
              "FLASH_STATE_CHANGED_SINCE_INSPECTION")
        before.append(live)
    # Erase sector zero LAST: until then retain original vector in flash.
    # Never reset mid-transaction. Crash recovery is via TI ROM BSL backdoor.
    tasks = list(zip(bundle.sectors, before))
    tasks = tasks[1:] + tasks[:1]
    changed = 0
    skipped = 0
    for (addr, image), old_crc in tasks:
        desired_crc = binascii.crc32(image) & 0xffffffff
        if old_crc == desired_crc:
            skipped += 1
            continue
        check(addr % gate.SECTOR == 0
              and 0 <= addr < gate.NV5_BASE
              and addr + gate.SECTOR <=
              (gate.NV2_BASE if bundle.profile == "p7u-f07-stock" else gate.NV5_BASE),
              "RUNTIME_ERASE_OUTSIDE_APPLICATION")
        check(await rom.erase_sector(addr) is True, "SECTOR_ERASE_REJECTED")
        check(await rom.begin_download(addr, gate.SECTOR) is True,
              "ROM_DOWNLOAD_REJECTED")
        for pos in range(0, gate.SECTOR, PACKET):
            chunk = image[pos:pos + PACKET]
            check(bool(chunk) and len(chunk) % 4 == 0 and len(chunk) <= PACKET,
                  "BAD_SEND_DATA_PACKET")
            check(await rom.send_data(chunk) is True, "ROM_SEND_DATA_REJECTED")
        check(await rom.crc32(addr, gate.SECTOR) == desired_crc,
              "PROGRAMMED_SECTOR_CRC_MISMATCH")
        # CCFG is the independent ROM BSL escape hatch. Fail after any unexpected change.
        ccfg = await read_exact(rom, gate.CCFG_START, gate.CCFG_SIZE)
        check(sha(ccfg) == identity["ccfg_sha256"], "CCFG_CHANGED_DURING_PROGRAMMING")
        changed += 1
    check((await observe(rom)) == identity, "TARGET_IDENTITY_CHANGED_AFTER_WRITE")
    return {"status": "P7U_SECTOR_WRITE_VERIFIED_LEAVE_BSL_OPEN",
            "sectors_written": changed, "sectors_skipped_same_crc": skipped,
            "chip_id": identity["chip_id"],
            "ccfg_sha256_unchanged": identity["ccfg_sha256"],
            "app_hex_sha256": bundle.hex_sha256,
            "approval_digest": token,
            "never_bank_erase": True,
            "post_flash_radio_reset_issued": False,
            "network_restore_qualified": False}


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf8"))
    check(type(value) is dict, "JSON_NOT_OBJECT")
    return value
