#!/usr/bin/env python3
"""Hosted static profile gate. SOURCE_ONLY accepts declared unknowns.

BOARD_FLASH_CANDIDATE requires board-scoped evidence; it does not authorize a
flash or claim physical/network acceptance. No force/unknown bypass exists.
"""
import argparse
import json
import re
from pathlib import Path

PROOFS = {
    "physical_revision", "uart_cc_dio", "uart_baud_and_flow", "ccfg_original_sha256",
    "rf_design", "oscillator_settings", "bootloader_access",
    "flash_protocol_and_erase_policy", "usb_bridge_mode", "stock_sys_ping_version",
    "launchpad_dependencies_removed", "board_native_image_audit"
}
REGION = {"start": 0, "end_exclusive": 0xb0000, "sector_bytes": 0x2000,
          "ccfg_sector_start": 0xae000, "ccfg_record_start": 0xaffa8, "ccfg_record_bytes": 88}
LAYOUTS = {"NV2": {"app_end": 0xaa000, "nv_start": 0xaa000, "nv_end": 0xae000, "nv_bytes": 0x4000},
           "NV5": {"app_end": 0xa4000, "nv_start": 0xa4000, "nv_end": 0xae000, "nv_bytes": 0xa000}}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def verify(profile, manifest, intent, expected_model, expected_revision=None, manufacturer_text=None):
    need(intent in ("SOURCE_ONLY", "BOARD_FLASH_CANDIDATE"), "UNKNOWN_INTENT")
    need(expected_model == "SLZB-06P7U" and profile.get("model") == expected_model,
         "WRONG_MODEL")
    need(profile.get("schema") == "p7u-board-contract-v1" and
         profile.get("scope") == "SLZB_06P7U_ONLY", "WRONG_PROFILE_SCOPE")
    need((profile.get("radio_soc"), profile.get("host_soc"), profile.get("ethernet")) ==
         ("CC2652P7", "ESP32-S3", "W5500"), "WRONG_SOC_OR_HOST")
    need(profile.get("flash_authorized") is False and profile.get("network_qualified") is False,
         "PUBLIC_PROFILE_CANNOT_AUTHORIZE_FLASH_OR_NETWORK")
    need(profile.get("flash_region") == REGION and profile.get("layouts") == LAYOUTS,
         "P7_FLASH_GEOMETRY_MISMATCH")
    need(manifest.get("schema") == "p7u-board-evidence-v1" and
         manifest.get("model") == expected_model, "WRONG_EVIDENCE_MODEL")
    need(set(profile.get("proofs", {})) == PROOFS, "PROOF_INVENTORY_MISMATCH")
    revision = profile.get("board_revision_observed")
    if expected_revision is not None:
        need(revision == expected_revision and revision is not None, "BOARD_REVISION_NOT_CONFIRMED")
    reference = profile["reference"]
    need(reference["revision"] == "1.73" and reference["unit_revision_verified"] is False,
         "REFERENCE_CANNOT_QUALIFY_UNIT")
    if manufacturer_text is not None:
        mapping = {"uart2_tx": "pin_uart2_tx", "uart2_rx": "pin_uart2_rx",
                   "uart2_cts": "pin_uart2_cts", "uart2_rts": "pin_uart2_rts",
                   "radio_reset": "pin_uart2_rst", "radio_bsl": "pin_uart2_flash",
                   "usb_device_host": "pin_usb_device_host"}
        for field, key in mapping.items():
            matches = re.findall(r'^\s*' + key + r':\s*"GPIO(\d+)"\s*$', manufacturer_text, re.M)
            need(len(matches) == 1 and int(matches[0]) == reference["esp_gpio"][field],
                 "MANUFACTURER_GPIO_MISMATCH_" + field)
        for field, key in {"radio_reset": "uart2_rst_inverted", "radio_bsl": "uart2_flash_inverted",
                           "usb_device_host": "usb_device_host_inverted"}.items():
            need(re.findall(r'^\s*' + key + r':\s*(true|false)\s*$', manufacturer_text, re.M) ==
                 [str(reference["inverted"][field]).lower()], "MANUFACTURER_INVERSION_MISMATCH_" + field)
        need(re.findall(r'^\s*uart2_baud:\s*(\d+)\s*$', manufacturer_text, re.M) ==
             [str(reference["uart_baud"])], "MANUFACTURER_BAUD_MISMATCH")
    evidence = {item["id"]: item for item in manifest.get("accepted_board_proofs", [])}
    missing = []
    for name in sorted(PROOFS):
        proof = profile["proofs"][name]
        need(type(proof.get("accepted")) is bool and isinstance(proof.get("evidence"), list),
             "INVALID_PROOF_" + name)
        if proof["accepted"] is not True or proof.get("value") in (None, "", False) or not proof["evidence"]:
            missing.append(name)
            continue
        for ref in proof["evidence"]:
            item = evidence.get(ref, {})
            need(item.get("model") == expected_model and item.get("board_revision") == revision and
                 item.get("proof") == name and item.get("accepted") is True and
                 re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")) is not None and
                 bool(item.get("source")), "UNQUALIFIED_BOARD_EVIDENCE_" + name)
    if intent == "BOARD_FLASH_CANDIDATE":
        need(revision is not None and expected_revision == revision, "BOARD_REVISION_NOT_CONFIRMED")
        need(not missing, "MISSING_BOARD_PROOFS:" + ",".join(missing))
        uart = profile["proofs"]["uart_cc_dio"]["value"]
        need(isinstance(uart, dict) and all(type(uart.get(x)) is int and 0 <= uart[x] <= 31
                                          for x in ("tx", "rx")) and uart["tx"] != uart["rx"],
             "INVALID_CC_UART_DIO")
        need(re.fullmatch(r"[0-9a-f]{64}", profile["proofs"]["ccfg_original_sha256"]["value"]) is not None,
             "INVALID_VENDOR_CCFG_DIGEST")
    return {"status": "SOURCE_PROFILE_PASS" if intent == "SOURCE_ONLY" else "DECLARED_BOARD_EVIDENCE_PASS",
            "model": expected_model, "missing_board_proofs": missing,
            "source_reference_checked": manufacturer_text is not None,
            "flash_authorized": False, "physical_qualified": False, "network_qualified": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--intent", choices=["SOURCE_ONLY", "BOARD_FLASH_CANDIDATE"], required=True)
    parser.add_argument("--expected-model", required=True)
    parser.add_argument("--expected-revision")
    parser.add_argument("--manufacturer-file", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.profile.read_text()), json.loads(args.manifest.read_text()),
                            args.intent, args.expected_model, args.expected_revision,
                            args.manufacturer_file.read_text() if args.manufacturer_file else None), indent=2))
