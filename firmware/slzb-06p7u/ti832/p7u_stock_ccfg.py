#!/usr/bin/env python3
"""Apply the P7U vendor stock DC/DC CCFG setting to the pinned ZNP SysConfig.

SOURCE/NATIVE PROOF ONLY. Does not establish UART/RF wiring, fitted hardware,
flash preservation, or permission to flash. The original P7 build is untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

CCFG_ANCHOR = (
    "for(var setting in ccfgSettings)\n"
    "{\n"
    "    device[setting] = ccfgSettings[setting];\n"
    "}\n"
)
P7U_SETTING = (
    "\n// P7U_R1_VENDOR_CCFG: original 20240710 disables active/recharge DC/DC.\n"
    "device.enableDCDC = false; // P7U_R1_VENDOR_CCFG\n"
)
REQUIRED_MODEL = "SLZB-06P7U"
REQUIRED_TRACK = "R1_STOCK_NV2_REFERENCE"


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def check_binding(binding: dict) -> None:
    if (binding.get("schema") != "p7u-stock-ccfg-source-binding-v1"
            or binding.get("model") != REQUIRED_MODEL
            or binding.get("release_track") != REQUIRED_TRACK
            or binding.get("vendor_revision") != "20240710"
            or binding.get("status") != "SOURCE_BINDING_DEFINED_NOT_NATIVE_BUILT"):
        raise ValueError("P7U_STOCK_BINDING_IDENTITY_MISMATCH")
    required = binding.get("required_generated_field_values")
    if required != {"MODE_CONF_DCDC_RECHARGE": 1, "MODE_CONF_DCDC_ACTIVE": 1}:
        raise ValueError("P7U_STOCK_DCDC_FIELD_CONTRACT_CHANGED")
    macros = binding.get("pinned_ti_source_macro_values")
    if macros != {"SET_CCFG_MODE_CONF_DCDC_RECHARGE": 1,
                  "SET_CCFG_MODE_CONF_DCDC_ACTIVE": 1}:
        raise ValueError("P7U_STOCK_DCDC_MACRO_CONTRACT_CHANGED")
    for field in ("vendor_ccfg_sha256", "ti_reference_ccfg_sha256"):
        value = binding.get(field)
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError("P7U_BINDING_HASH_INVALID_" + field)
    if (binding.get("ti_mode_conf") != "0xf3b9c1ff"
            or binding.get("vendor_mode_conf") != "0xffb9c1ff"):
        raise ValueError("P7U_MODE_CONF_CONTRACT_CHANGED")
    bsl = binding.get("bsl_reference")
    if bsl != {"rom_enable": "0xC5", "backdoor_enable": "0xC5",
               "dio": 15, "level": 0}:
        raise ValueError("P7U_BSL_CONTRACT_CHANGED")
    if any(binding.get(flag) is not False for flag in
           ("board_qualified", "flash_authorized", "network_qualified")):
        raise ValueError("P7U_SOURCE_BINDING_MUST_NOT_AUTHORIZE_FLASH")


def transform_syscfg(source: str, binding: dict) -> str:
    check_binding(binding)
    if source.count(CCFG_ANCHOR) != 1:
        raise ValueError("P7U_CCFG_SETTINGS_ANCHOR_NOT_UNIQUE")
    if "device.enableDCDC" in source or "P7U_R1_VENDOR_CCFG" in source:
        raise ValueError("P7U_CCFG_OVERRIDE_ALREADY_PRESENT")
    if source.count('scripting.addModule("/ti/devices/CCFG")') != 1:
        raise ValueError("P7U_CCFG_MODULE_NOT_UNIQUE")
    return source.replace(CCFG_ANCHOR, CCFG_ANCHOR + P7U_SETTING, 1)


def validate_linked_ccfg(reference: bytes, candidate: bytes, binding: dict) -> dict:
    """Require exact 88-byte vendor CCFG, with ONLY the known MODE_CONF change."""
    check_binding(binding)
    if len(reference) != 88 or len(candidate) != 88:
        raise ValueError("P7U_CCFG_NOT_88_BYTES")
    if digest(reference) != binding["ti_reference_ccfg_sha256"]:
        raise ValueError("P7U_TI_CCFG_REFERENCE_DIGEST_MISMATCH")
    old = int(binding["ti_mode_conf"], 16).to_bytes(4, "little")
    new = int(binding["vendor_mode_conf"], 16).to_bytes(4, "little")
    if reference.count(old) != 1:
        raise ValueError("P7U_MODE_CONF_OFFSET_NOT_UNIQUE")
    offset = reference.index(old)
    expected = bytearray(reference)
    expected[offset:offset + 4] = new
    if candidate != bytes(expected):
        raise ValueError("P7U_CCFG_UNEXPECTED_BYTE_CHANGE")
    if digest(candidate) != binding["vendor_ccfg_sha256"]:
        raise ValueError("P7U_VENDOR_CCFG_DIGEST_MISMATCH")
    return {
        "reference_ccfg_sha256": digest(reference),
        "candidate_ccfg_sha256": digest(candidate),
        "mode_conf_offset_in_88_bytes": offset,
        "mode_conf_before": binding["ti_mode_conf"],
        "mode_conf_after": binding["vendor_mode_conf"],
        "only_mode_conf_changed": True,
        "vendor_exact_match": True,
        "qualification": "CCFG_SOURCE_AND_LINKED_ONLY_NOT_FLASHABLE",
        "flash_authorized": False,
        "board_qualified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syscfg", type=Path, required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    binding = json.loads(args.binding.read_text(encoding="utf-8"))
    before = args.syscfg.read_text(encoding="utf-8")
    after = transform_syscfg(before, binding)
    args.syscfg.write_text(after, encoding="utf-8")
    result = {
        "profile": REQUIRED_MODEL,
        "track": REQUIRED_TRACK,
        "status": "SOURCE_ONLY_NOT_FLASHABLE",
        "change": "SysConfig device.enableDCDC=false",
        "input_sha256": digest(before.encode()),
        "output_sha256": digest(after.encode()),
        "expected_vendor_ccfg_sha256": binding["vendor_ccfg_sha256"],
        "expected_mode_conf": binding["vendor_mode_conf"],
        "flash_authorized": False,
        "physical_board_qualified": False,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
