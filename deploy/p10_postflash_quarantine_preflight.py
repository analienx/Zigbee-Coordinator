#!/usr/bin/env python3
"""Fail-closed read-only quarantine audit for a CC2674P10 after firmware flash.

This tool intentionally does NOT:
- start/form a Zigbee network,
- write NVRAM,
- read or print network/link keys,
- start Zigbee2MQTT.

It compares the stored network identity to a private open-coordinator-backup and
uses SYS.NVLength only to prove a minimum Trust Center link-key table capacity.
"""

import argparse
import asyncio
import json
import pathlib
import urllib.request

from zigpy.exceptions import NetworkNotFormed
from zigpy_znp.api import ZNP
from zigpy_znp.commands import SYS
from zigpy_znp.types.nvids import ExNvIds, NvSysIds
from zigpy_znp.zigbee.application import ControllerApplication


def load_expected(path: str) -> dict:
    backup = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return {
        "channel": int(backup["channel"]),
        "coordinator_ieee": backup["coordinator_ieee"].lower(),
        "pan_id": backup["pan_id"].lower(),
        "extended_pan_id": backup["extended_pan_id"].lower(),
        "link_keys": sum(1 for dev in backup.get("devices", []) if dev.get("link_key")),
    }


async def audit(args: argparse.Namespace) -> None:
    expected = load_expected(args.expected_backup)

    with urllib.request.urlopen(f"http://{args.host}/ha_info", timeout=3) as response:
        info = json.loads(response.read().decode("utf-8"))["Info"]

    radio = info["radios"][args.radio_index]
    report = {
        "slzb_radio_hw": radio.get("zb_hw"),
        "slzb_radio_revision": radio.get("zb_version"),
        "slzb_revision_expected": int(args.expected_revision),
        "znp_revision_match": False,
        "radio_hardware_match": False,
        "management_socket_binding_match": False,
        "slzb_revision_match": int(radio.get("zb_version", 0))
        == int(args.expected_revision),
        "expected_link_keys": expected["link_keys"],
        "network_formed": False,
        "identity_match": False,
        "tclk_slot_lengths": {},
        "keys_printed": False,
        "decision": "STOP",
        "reasons": [],
    }

    url = f"socket://{args.host}:{args.port}"
    znp = ZNP(ControllerApplication.SCHEMA({"device": {"path": url}}))

    try:
        await znp.connect()
        version = await znp.request(SYS.Version.Req(), timeout=3)
        report["znp_code_revision"] = int(version.CodeRevision or 0)
        report["znp_revision_match"] = (
            report["znp_code_revision"] == int(args.expected_revision))
        # Do not equate management zb_version with actual ZNP CodeRevision.
        # The selected management radio must also identify the exact
        # endpoint port and expected hardware, or quarantine must STOP.
        # Some SLZB-OS versions do not expose such a mapping: UNKNOWN
        # is intentionally not sufficient to certify a radio.
        reported_port = next((radio[k] for k in (
            "socket_port", "zb_socket_port", "zb_port", "port")
            if k in radio), None)
        report["management_socket_binding_match"] = (
            str(reported_port) == str(args.port))
        report["radio_hardware_match"] = (
            bool(args.expected_radio_hw)
            and str(radio.get("zb_hw", "")).casefold()
            == args.expected_radio_hw.casefold())


        # Length-only probes. No Trust Center key bytes are requested.
        for sub_id in args.tclk_probe:
            rsp = await znp.request(
                SYS.NVLength.Req(
                    SysId=NvSysIds.ZSTACK,
                    ItemId=ExNvIds.TCLK_TABLE,
                    SubId=sub_id,
                ),
                timeout=3,
            )
            report["tclk_slot_lengths"][str(sub_id)] = int(rsp.Length)

        try:
            # Reads network metadata to compare identity. No key material is printed.
            await znp.load_network_info(load_devices=False)
            report["network_formed"] = True

            live = {
                "channel": int(znp.network_info.channel),
                "coordinator_ieee": znp.node_info.ieee.serialize()[::-1].hex().lower(),
                "pan_id": znp.network_info.pan_id.serialize()[::-1].hex().lower(),
                "extended_pan_id": (
                    znp.network_info.extended_pan_id.serialize()[::-1].hex().lower()
                ),
            }
            report["identity_match"] = all(
                live[name] == expected[name] for name in live
            )
        except NetworkNotFormed:
            report["network_formed"] = False
    finally:
        await znp.disconnect()

    minimum_probe = args.minimum_tclk_subid
    minimum_length = report["tclk_slot_lengths"].get(str(minimum_probe), 0)

    if not report["slzb_revision_match"]:
        report["reasons"].append(
            "SLZB-OS does not report the expected radio revision"
        )

    if not report["znp_revision_match"]:
        report["reasons"].append(
            "Direct ZNP SYS_VERSION CodeRevision differs from expected revision"
        )
    if not report["radio_hardware_match"]:
        report["reasons"].append(
            "Selected management radio hardware is not independently pinned"
        )
    if not report["management_socket_binding_match"]:
        report["reasons"].append(
            "Management radio cannot be bound to the connected ZNP socket"
        )

    if minimum_length == 0:
        report["reasons"].append(
            f"TCLK slot {minimum_probe} absent; minimum capacity gate failed"
        )

    if report["network_formed"] and not report["identity_match"]:
        report["reasons"].append(
            "Stored Zigbee network identity does not match the expected backup"
        )

    if report["reasons"]:
        report["decision"] = "STOP"
    elif not report["network_formed"]:
        report["decision"] = "NEEDS_EXPLICIT_RESTORE"
        report["reasons"].append(
            "Firmware responds and capacity floor passed, but no matching formed "
            "network is present; restore the verified backup before startup"
        )
    else:
        report["decision"] = "PASS_QUARANTINE"
        report["reasons"].append(
            "Firmware identity, capacity floor, and stored network identity passed "
            "the read-only preflight"
        )

    print(json.dumps(report, indent=2))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="192.168.50.200")
    parser.add_argument("--port", type=int, default=7638)
    parser.add_argument("--radio-index", type=int, default=1)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-radio-hw", required=True,
                        help="Exact zb_hw value independently verified for this P10 hardware")

    parser.add_argument("--expected-backup", required=True)
    parser.add_argument(
        "--minimum-tclk-subid",
        type=int,
        default=127,
        help="Slot that must exist; 127 proves at least 128 provisioned slots",
    )
    parser.add_argument(
        "--tclk-probe",
        type=int,
        nargs="+",
        default=[0, 100, 127, 199, 200, 399, 400],
    )
    return parser.parse_args()


if __name__ == "__main__":
    asyncio.run(audit(parse_args()))
