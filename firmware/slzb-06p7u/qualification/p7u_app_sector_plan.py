#!/usr/bin/env python3
"""Propose application-only, per-sector P7U flash plan. NEVER executes it.

Source manifest links the CCFG-verified full image to a derived app-only HEX.
Prohibits any NV or CCFG sector, bank/chip erase, or ESP core update.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
src = ROOT / "p7u_rom_bsl_image_gate.py"
spec = importlib.util.spec_from_file_location("p7u_gate", src)
gate = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(gate)


def plan(app_bytes: bytes, evidence: dict) -> dict:
    profile = evidence.get("profile")
    gate.require(profile in ("p7u-f07-stock","p7u-cap192-f07"),
                 "PLAN_WRONG_RADIO")
    gate.require(evidence.get("qualification") ==
                 "SOURCE_HEX_BSL_GEOMETRY_PASS_NOT_FLASHABLE" and
                 evidence.get("flash_authorized") is False and
                 evidence.get("ccfg_88_bytes_exact_vendor") is True and
                 evidence.get("nv_loaded_bytes") == 0 and
                 evidence.get("rom_backdoor_enabled") is True and
                 evidence.get("bootloader_enabled") is True,
                 "PLAN_FULL_IMAGE_NOT_QUALIFIED")
    digest = hashlib.sha256(app_bytes).hexdigest()
    gate.require(digest == evidence.get("derived_app_only_hex_sha256"),
                 "PLAN_NOT_SAME_VALIDATED_APP")
    app = gate.parse_hex(app_bytes)
    limit = gate.NV2_BASE if profile == "p7u-f07-stock" else gate.NV5_BASE
    gate.require(all(x < limit for x in app), "PLAN_APP_WRITES_NV_OR_CCFG")
    gate.require(len(app) > 1024 and all(x in app for x in range(8)),
                 "PLAN_MISSING_APP_VECTOR")
    gate.require(evidence.get("derived_app_only_never_flash_with_bank_erase") is True,
                 "PLAN_BANK_ERASE_WARNING_MISSING")
    sectors = sorted({(x // gate.SECTOR) * gate.SECTOR for x in app})
    gate.require(len(sectors)>0 and all(s+gate.SECTOR<=limit for s in sectors),
                 "PLAN_TOUCHES_PROTECTED_SECTOR")
    gate.require(sectors[-1]+gate.SECTOR<=0x2E000,
                 "PLAN_OUTSIDE_REVIEWED_23_SECTOR_APPLICATION_CONTRACT")
    # Stronger than checked image bytes: plan's entire ERASE sector must be
    # within application space, even across sparse/split HEX segments.
    return {
        "target": "SLZB-06P7U_CC2652P7_RADIO_ONLY",
        "profile": profile,
        "validated_app_only_hex_sha256": digest,
        "explicit_application_sector_erase_addresses": [f"0x{s:05X}" for s in sectors],
        "sector_size_bytes": gate.SECTOR,
        "sector_count": len(sectors),
        "last_application_sector_end": f"0x{sectors[-1]+gate.SECTOR:05X}",
        "nv2_base": f"0x{gate.NV2_BASE:05X}",
        "nv5_base": f"0x{gate.NV5_BASE:05X}",
        "ccfg_sector_start": f"0x{gate.CCFG_SECTOR:05X}",
        "rom_bsl_identity_required_before_execution": True,
        "installed_ccfg_equality_and_original_image_backup_required": True,
        "erase_policy": "EXPLICIT_ALLOWLIST_ONLY_NEVER_BANK_OR_CHIP_ERASE",
        "forbidden_operations": ["BANK_ERASE","CHIP_ERASE","ERASE_CCFG",
                                 "DISABLE_BOOTLOADER","FLASH_ESP32_S3",
                                 "WRITE_SECONDARY_IEEE"],
        "execution_implemented": False,
        "flash_authorized": False,
        "qualification": "OFFLINE_SECTOR_PLAN_ONLY_NEVER_FLASHABLE",
    }


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-only-hex", type=Path, required=True)
    parser.add_argument("--full-image-evidence", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args=parser.parse_args()
    try:
        evidence=json.loads(args.full_image_evidence.read_text())
        result=plan(args.app_only_hex.read_bytes(),evidence)
    except (gate.PreflightError,OSError,ValueError,KeyError) as exc:
        result={"flash_authorized":False,"execution_implemented":False,
                "qualification":"REJECT",
                "reason":str(exc) if isinstance(exc,gate.PreflightError) else
                         "PLAN_INPUT_INVALID"}
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(result,sort_keys=True))
        raise SystemExit(2)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
