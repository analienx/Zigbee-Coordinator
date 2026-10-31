#!/usr/bin/env python3
"""Offline, hash-bound observations from two CURRENT P7U flash captures.

This module has no transport, reset, erase or programming operations. Capture
origin and capture time are external assertions, never established by matching
bytes. It exports only sanitized configuration/geometry observations; raw flash,
IEEE addresses, keys and security configuration words are never emitted.

The board-identity pin is the SHA256 of canonical JSON (UTF-8, sorted keys,
compact separators). It must be supplied independently of the input files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

SCHEMA = "r4-p7u-current-board-profile-v1"
FLASH_BYTES = 0xB0000
SECTOR_BYTES = 0x2000
APP_LIMIT = 0xA0000
TOP = 0xAE000
RESIDENT_BOOT = 0xAC000
CCFG = 0xAFFA8
IMAGE_VALID = 0xAFFEC
BL_CONFIG = 0xAFFD8
PROTECTION = 0xAFFF0
DIRECT_GATE = "DIRECT_NATIVE_CCFG_UNCHANGED"
RECOVERY_GATE = "AC000_RECOVERY_REQUIRED"
BLOCKED_GATE = "UNKNOWN_BOOT_BLOCKED"


def deny(reason: str) -> None:
    raise ValueError("R4_CURRENT_BOARD_PROFILE_DENIED_" + reason)


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ValueError("R4_CURRENT_BOARD_PROFILE_DENIED_NON_JSON_VALUE") from exc


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pin(value: str, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        deny(name + "_SHA256_FORMAT")
    return value.lower()


def board_identity_digest(identity: dict) -> str:
    """Validate fixed P7U geometry and bind an owner-managed private identity."""
    expected = {"model", "hardware_revision", "soc", "flash_bytes", "board_binding_id"}
    if not isinstance(identity, dict) or set(identity) != expected:
        deny("BOARD_IDENTITY_FIELDS")
    if (identity["model"] != "SLZB-06P7U" or
            identity["hardware_revision"] != "1.73" or
            identity["soc"] != "CC2652P7" or
            type(identity["flash_bytes"]) is not int or
            identity["flash_bytes"] != FLASH_BYTES):
        deny("BOARD_IDENTITY_NOT_SUPPORTED_P7U")
    binding = identity["board_binding_id"]
    if (not isinstance(binding, str) or not 12 <= len(binding) <= 128 or
            re.fullmatch(r"[A-Za-z0-9_.:-]+", binding) is None):
        deny("BOARD_BINDING_ID")
    return sha256(canonical_json(identity))


def profile_digest(profile: dict) -> str:
    if not isinstance(profile, dict):
        deny("PROFILE_NOT_OBJECT")
    return sha256(canonical_json({k: v for k, v in profile.items()
                                  if k != "profile_sha256"}))


def _word(capture: bytes, address: int) -> int:
    return struct.unpack_from("<I", capture, address)[0]


def _vector_valid(capture: bytes, address: int) -> bool:
    if address < 0 or address % 0x100 or address + 8 > TOP:
        return False
    sp, reset = struct.unpack_from("<II", capture, address)
    return (sp % 8 == 0 and 0x20000000 < sp <= 0x20024000 and
            bool(reset & 1) and 8 <= (reset & ~1) < TOP)


def _source_profile(mode: int, mode1: int, size_flags: int) -> dict:
    # TI ccfg.c derives boost mode from these three linked power fields.
    # Do not infer a Boolean from ALT_DCDC_VMIN alone on unfamiliar settings.
    vmin = (mode1 >> 20) & 15
    ext_load = bool(mode & (1 << 25))
    bod_high = bool(mode & (1 << 24))
    if vmin == 12 and not ext_load and bod_high:
        boost = True
    elif vmin == 8 and ext_load:
        boost = False
    else:
        boost = None
    active = not bool(mode & (1 << 26))
    recharge = not bool(mode & (1 << 27))
    ccfg_size_valid = size_flags >> 16 == 88
    source_supported = (boost is not None and active == recharge and ccfg_size_valid)
    source_reasons = []
    if boost is None:
        source_reasons.append("BOOST_FIELD_COMBINATION_UNSUPPORTED")
    if active != recharge:
        source_reasons.append("MIXED_DCDC_CONTROLS_UNSUPPORTED")
    if not ccfg_size_valid:
        source_reasons.append("CCFG_SIZE_NOT_88_BYTES")
    return {
        "ccfg_mode_conf": f"0x{mode:08x}",
        "ccfg_mode_conf_1": f"0x{mode1:08x}",
        "ccfg_size_and_dis_flags": f"0x{size_flags:08x}",
        "dcdc_active_enabled": active,
        "dcdc_recharge_enabled": recharge,
        "force_vddr_hh": boost,
        "source_generation_supported": source_supported,
        "unsupported_reasons": source_reasons,
        "basis": "CURRENT_CAPTURE_ASSERTION_NOT_PHYSICAL_PROOF",
    }


def _boot_gate(image_valid: int, vector_valid: bool, rom_enabled: bool,
               dio15_low: bool) -> tuple[str, list[str]]:
    reasons = []
    if not vector_valid:
        reasons.append("SELECTED_VECTOR_NOT_STRUCTURALLY_VALID")
    if not rom_enabled:
        reasons.append("ROM_BSL_DISABLED")
    if not dio15_low:
        reasons.append("DIO15_LOW_ROM_BACKDOOR_NOT_PRESENT")
    if image_valid not in (0, RESIDENT_BOOT):
        reasons.append("UNSUPPORTED_BOOT_VECTOR_ADDRESS")
    gate = BLOCKED_GATE if reasons else (DIRECT_GATE if image_valid == 0 else RECOVERY_GATE)
    return gate, reasons


def _observations(capture: bytes) -> dict:
    if not isinstance(capture, bytes) or len(capture) != FLASH_BYTES:
        deny("CAPTURE_NOT_COMPLETE_704K")
    mode1 = _word(capture, CCFG + 4)
    size_flags = _word(capture, CCFG + 8)
    mode = _word(capture, CCFG + 12)
    image_valid = _word(capture, IMAGE_VALID)
    bl = _word(capture, BL_CONFIG)
    rom_enabled = (bl >> 24) == 0xC5
    dio15_low = (rom_enabled and bl & 0xFF == 0xC5 and
                 (bl >> 8) & 0xFF == 15 and not bl & 0x10000)
    valid_vector = _vector_valid(capture, image_valid)
    gate, reasons = _boot_gate(image_valid, valid_vector, rom_enabled, dio15_low)

    def writable(index: int) -> bool:
        return bool(_word(capture, PROTECTION + (index // 32) * 4) &
                    (1 << (index % 32)))

    return {
        "boot_gate": gate,
        "boot_gate_reasons": reasons,
        "boot": {
            "image_valid_conf": f"0x{image_valid:08x}",
            "vector_table_valid": valid_vector,
            "rom_bsl_enabled": rom_enabled,
            "dio15_low_backdoor": dio15_low,
            "resident_signature_policy": "UNKNOWN_REQUIRES_SEPARATE_AUDIT",
            "ccfg_change_required_for_native_vector_zero": image_valid != 0,
            "ccfg_recovery_qualified": False,
        },
        "geometry": {
            "flash_bytes": FLASH_BYTES,
            "sector_bytes": SECTOR_BYTES,
            "application_limit_exclusive": APP_LIMIT,
            "protected_ranges": [[APP_LIMIT, FLASH_BYTES]],
        },
        "protection": {
            "writable_application_sector_indices": [
                i for i in range(APP_LIMIT // SECTOR_BYTES) if writable(i)],
            "top_sector_writable": writable(TOP // SECTOR_BYTES),
            "resident_boot_sector_writable": writable(RESIDENT_BOOT // SECTOR_BYTES),
            "scope": "CCFG_BITS_ONLY_FCFG_AND_LIVE_LOCKS_NOT_VERIFIED",
        },
        "source_profile": _source_profile(mode, mode1, size_flags),
        "nv_observations": [{
            "start": APP_LIMIT,
            "end_exclusive": RESIDENT_BOOT,
            "non_erased_bytes": sum(b != 0xFF for b in capture[APP_LIMIT:RESIDENT_BOOT]),
            "schema_compatibility": "UNKNOWN",
            "meaning": "RESERVED_POSSIBLE_NV_BYTES_NOT_PARSED_OR_MIGRATED",
        }],
    }


def analyze_capture_pair(pass1: bytes, pass2: bytes, *,
                         expected_pass1_sha256: str,
                         expected_pass2_sha256: str,
                         board_identity: dict,
                         expected_board_identity_sha256: str) -> dict:
    """Produce a sanitized receipt; never authorize flash or infer NV health."""
    first_pin = _pin(expected_pass1_sha256, "PASS1")
    second_pin = _pin(expected_pass2_sha256, "PASS2")
    identity_pin = _pin(expected_board_identity_sha256, "BOARD_IDENTITY")
    if (not isinstance(pass1, bytes) or not isinstance(pass2, bytes) or
            len(pass1) != FLASH_BYTES or len(pass2) != FLASH_BYTES):
        deny("CAPTURE_NOT_COMPLETE_704K")
    if sha256(pass1) != first_pin or sha256(pass2) != second_pin:
        deny("EXTERNAL_CAPTURE_HASH_MISMATCH")
    if pass1 != pass2:
        deny("CURRENT_CAPTURE_PASSES_DISAGREE")
    identity_hash = board_identity_digest(board_identity)
    if identity_hash != identity_pin:
        deny("EXTERNAL_BOARD_IDENTITY_HASH_MISMATCH")
    result = {
        "schema": SCHEMA,
        "capture_sha256": first_pin,
        "capture_pass_sha256": [first_pin, second_pin],
        "board_identity_sha256": identity_hash,
        "board": {k: board_identity[k] for k in
                  ("model", "hardware_revision", "soc", "flash_bytes")},
        "capture_origin_independently_verified": False,
        "radio_contact": False,
        "flash_authorized": False,
        "boot_proven": False,
        "nv_compatibility_proven": False,
        **_observations(pass1),
    }
    result["profile_sha256"] = profile_digest(result)
    return result


def validate_profile(profile: dict, *, expected_profile_sha256: str,
                     capture: bytes | None = None) -> dict:
    """Validate an independently pinned profile and, optionally, its snapshot."""
    pin = _pin(expected_profile_sha256, "PROFILE")
    if not isinstance(profile, dict) or profile.get("schema") != SCHEMA:
        deny("PROFILE_SCHEMA")
    if (profile.get("profile_sha256") != pin or profile_digest(profile) != pin):
        deny("EXTERNAL_PROFILE_HASH_MISMATCH")
    for field in ("capture_origin_independently_verified", "radio_contact",
                  "flash_authorized", "boot_proven", "nv_compatibility_proven"):
        if profile.get(field) is not False:
            deny("PROFILE_INVALID_PROOF_ASSERTION")
    capture_pin = _pin(profile.get("capture_sha256"), "PROFILE_CAPTURE")
    if profile.get("capture_pass_sha256") != [capture_pin, capture_pin]:
        deny("PROFILE_CAPTURE_BINDING")
    _pin(profile.get("board_identity_sha256"), "PROFILE_BOARD_IDENTITY")
    # A digest pin binds a receipt, but cannot make contradictory fields safe.
    # Recheck its derived source/boot decisions even when raw captures stay private.
    expected_geometry = {"flash_bytes": FLASH_BYTES, "sector_bytes": SECTOR_BYTES,
                         "application_limit_exclusive": APP_LIMIT,
                         "protected_ranges": [[APP_LIMIT, FLASH_BYTES]]}
    if profile.get("geometry") != expected_geometry:
        deny("PROFILE_GEOMETRY")
    source = profile.get("source_profile")
    if not isinstance(source, dict):
        deny("PROFILE_SOURCE_FIELDS")
    words = []
    for field in ("ccfg_mode_conf", "ccfg_mode_conf_1", "ccfg_size_and_dis_flags"):
        value = source.get(field)
        if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-f]{8}", value) is None:
            deny("PROFILE_SOURCE_WORD_FORMAT")
        words.append(int(value, 16))
    if source != _source_profile(*words):
        deny("PROFILE_SOURCE_INCONSISTENT")
    boot = profile.get("boot")
    if not isinstance(boot, dict):
        deny("PROFILE_BOOT_FIELDS")
    vector = boot.get("image_valid_conf")
    if not isinstance(vector, str) or re.fullmatch(r"0x[0-9a-f]{8}", vector) is None:
        deny("PROFILE_BOOT_WORD_FORMAT")
    for flag in ("vector_table_valid", "rom_bsl_enabled", "dio15_low_backdoor"):
        if type(boot.get(flag)) is not bool:
            deny("PROFILE_BOOT_FLAG_TYPE")
    if (boot["dio15_low_backdoor"] and not boot["rom_bsl_enabled"] or
            boot.get("ccfg_recovery_qualified") is not False or
            boot.get("ccfg_change_required_for_native_vector_zero") is not (int(vector, 16) != 0) or
            boot.get("resident_signature_policy") != "UNKNOWN_REQUIRES_SEPARATE_AUDIT"):
        deny("PROFILE_BOOT_INCONSISTENT")
    gate, reasons = _boot_gate(int(vector, 16), boot["vector_table_valid"],
                               boot["rom_bsl_enabled"], boot["dio15_low_backdoor"])
    if profile.get("boot_gate") != gate or profile.get("boot_gate_reasons") != reasons:
        deny("PROFILE_BOOT_GATE_INCONSISTENT")
    if capture is not None:
        if not isinstance(capture, bytes) or sha256(capture) != capture_pin:
            deny("PROFILE_CAPTURE_HASH_MISMATCH")
        for key, value in _observations(capture).items():
            if profile.get(key) != value:
                deny("PROFILE_CAPTURE_OBSERVATION_MISMATCH")
    return profile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("capture-pass1", "capture-pass2", "board-identity-json", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    for flag in ("expected-pass1-sha256", "expected-pass2-sha256",
                 "expected-board-identity-sha256"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args()
    if args.capture_pass1.resolve() == args.capture_pass2.resolve():
        deny("CAPTURE_INPUT_PATHS_ALIAS")
    if args.output.exists() or args.output.is_symlink():
        deny("OUTPUT_ALREADY_EXISTS")
    identity = json.loads(args.board_identity_json.read_text("utf-8"))
    profile = analyze_capture_pair(
        args.capture_pass1.read_bytes(), args.capture_pass2.read_bytes(),
        expected_pass1_sha256=args.expected_pass1_sha256,
        expected_pass2_sha256=args.expected_pass2_sha256,
        board_identity=identity,
        expected_board_identity_sha256=args.expected_board_identity_sha256)
    # Only the sanitized profile is written; raw captures and metadata stay input-only.
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(profile, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"schema": SCHEMA, "profile_sha256": profile["profile_sha256"],
                      "boot_gate": profile["boot_gate"], "flash_authorized": False},
                     sort_keys=True))


if __name__ == "__main__":
    main()
