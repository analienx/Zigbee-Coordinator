#!/usr/bin/env python3
"""Read-only fail-closed hardware gate for ORIGINAL SMLIGHT SLZB-06P7.

The static G2/G3 CI must never promote a reference image to a qualified
real-board firmware based on TI LaunchPad or another SMLIGHT model.
"""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path

DEFAULT = Path(__file__).with_name("hardware-evidence.json")
KEYS = {"H1","H2","H3","H4","H5","H6","H7"}
FLAGS = {"hardware_qualified","flash_authorized","rf_transmit_authorized",
         "nv_erase_authorized","network_migration_authorized",
         "safe_rollback_verified"}

def require(yes: bool, error: str) -> None:
    if not yes:
        raise ValueError(error)

def validate(data: dict) -> None:
    require(data["schema"]=="slzb-06p7-hardware-evidence-v1","INVALID_SCHEMA")
    require(data["model"]=="ORIGINAL_SLZB_06P7_NON_U","UNKNOWN_VARIANT")
    require(data["silicon_claim"]=="CC2652P7","INCORRECT_SILICON")
    require(data["scope"]=="READ_ONLY_EVIDENCE_REQUEST_NOT_HARDWARE_QUALIFICATION",
            "EVIDENCE_SCOPE_CHANGED")
    require(data["conclusion"]=="HARDWARE_GATES_BLOCKED_NO_PROVEN_AUTHENTIC_UNIT",
            "UNAUTHORIZED_PHYSICAL_GATE_PROMOTION")
    prov=data["provenance"]
    require(prov["physical_unit_seen"] is False,"PHYSICAL_UNIT_UNVERIFIED")
    require(prov["board_schematic_verified"] is False,"SCHEMATIC_UNVERIFIED")
    require(prov["physical_unit_identifier_published"] is False,
            "DEVICE_ID_PUBLICATION_FORBIDDEN")
    for key in ("board_revision","vendor_image_digest","vendor_ccfg_snapshot_digest"):
        require(prov[key] is None,"UNPROVEN_PRIVATE_OR_BOARD_ID_"+key)
    require(prov["credible_sources"]==[],"UNREVIEWED_HARDWARE_SOURCE")
    require(set(data["gate"])==FLAGS,"GATE_FLAG_COVERAGE")
    for flag in FLAGS:
        require(data["gate"][flag] is False,"UNAUTHORIZED_"+flag.upper())
    observations=data["observations"]
    require(len(observations)==len(KEYS),"EVIDENCE_COVERAGE")
    ids={v["id"] for v in observations}
    require(ids==KEYS,"EVIDENCE_ID_SET")
    require(len(ids)==len(observations),"EVIDENCE_DUPLICATE")
    for item in observations:
        require(item["state"]=="BLOCKED","UNVERIFIED_HARDWARE_GATE_"+item["id"])
        require(item["digest"] is None,"PRIVATE_IMAGE_DIGEST_NOT_AUTHORIZED_"+item["id"])
        require(item["method"] is None,"UNREVIEWED_OBSERVATION_"+item["id"])
        require(item["label"] and len(item["scope"])>=45,"INSUFFICIENT_GATE_DESCRIPTION")
    require(len(data["forbidden_assumptions"])>=5,"MISSING_FORBIDDEN_ASSUMPTIONS")
    require("raw flash" in data["confidentiality"],"MISSING_SECRET_PROTECTION")

def negative_tests(data: dict) -> None:
    mutation=[
        lambda x:x["gate"].update(flash_authorized=True),
        lambda x:x["gate"].update(hardware_qualified=True),
        lambda x:x.update(model="SLZB-06P7U"),
        lambda x:x.update(silicon_claim="CC2674P10"),
        lambda x:x["provenance"].update(board_revision="REV-A"),
        lambda x:x["provenance"].update(physical_unit_seen=True),
        lambda x:x["provenance"].update(vendor_ccfg_snapshot_digest="a"*64),
        lambda x:x["observations"][0].update(state="PASS"),
        lambda x:x["observations"][2].update(method="assumed from TI LaunchPad"),
        lambda x:x["observations"].pop(),
        lambda x:x["gate"].pop("nv_erase_authorized"),
        lambda x:x.update(conclusion="PASS"),
    ]
    for idx, fn in enumerate(mutation):
        changed=copy.deepcopy(data); fn(changed)
        try: validate(changed)
        except (ValueError, KeyError,TypeError):
            continue
        raise AssertionError(f"UNVERIFIED_HARDWARE_ACCEPTED_{idx}")
    print(f"PASS G3 real-board fail-closed denial, {len(mutation)} negative tests")

def main() -> None:
    p=argparse.ArgumentParser()
    p.add_argument("--file",type=Path,default=DEFAULT)
    p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    data=json.loads(a.file.read_text())
    validate(data)
    if a.selftest:
        negative_tests(data)
    print("PASS G3 reference CI does not authorize real radio, RF, BSL, NV or flashing")

if __name__=="__main__":
    main()
