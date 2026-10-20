"""Compare two clean hosted native builds of the same exact B1 source."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def load(root):
    seal = json.loads((root / "b1-native-seal.json").read_text())
    for kind in ("elf", "xml", "hex", "bin"):
        item = seal["artifacts"][kind]
        name = item["file"]
        if Path(name).name != name or "/" in name or "\\" in name:
            raise ValueError("Unsafe native comparison artifact path")
        raw = (root / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("Native comparison artifact hash mismatch")
    return seal


LINKED_NV2 = "HOSTED_NATIVE_LINKED"
LINKED_NV4 = "HOSTED_NATIVE_LINKED_NV4_BRIDGE_UNSEALED"
LINKED_STOCK20260311 = "HOSTED_NATIVE_LINKED_STOCK20260311_HANDOFF_REQUIRED"


def validate_linked_mode(item: dict) -> str:
    mode = item.get("classification")
    functions = item.get("linked_functions")
    if mode not in (LINKED_NV2, LINKED_NV4, LINKED_STOCK20260311) or not isinstance(functions, dict):
        raise ValueError("Native comparison requires linked native evidence")
    if item.get("full_b0_b4_sealed") is not False:
        raise ValueError("Native comparison cannot promote an unproved full role seal")
    if mode in (LINKED_NV4, LINKED_STOCK20260311):
        if (item.get("nv4_bridge_compiled") is not True or
                "r4_nv4_admit" not in functions or "b1_nv_probe" in functions):
            raise ValueError("NV4 native comparison requires actual linked observer and no NV2 probe")
        if mode == LINKED_STOCK20260311 and (item.get("stock20260311") is not True or
                item.get("nv4_region_base") != "0xA4000" or item.get("boot_handoff_required") is not True):
            raise ValueError("Current stock20260311 native requires its separate source/boot class")
    elif item.get("nv4_bridge_compiled") is not False or "b1_nv_probe" not in functions:
        raise ValueError("NV2 native comparison requires original linked B1 probe")
    return mode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    a, b = load(args.first), load(args.second)
    for item in (a, b):
        if item["source_sha"] != args.expected_sha:
            raise ValueError("Native replicas differ from expected source")
        validate_linked_mode(item)
    if a["classification"] != b["classification"]:
        raise ValueError("Native replicas mix incompatible NV2 and NV4 image classes")
    if a["replica"] == b["replica"] or {a["replica"], b["replica"]} != {"1", "2"}:
        raise ValueError("Native comparison requires two separate clean replicas")
    for key in ("source_files", "overlay_sha256", "linked_functions"):
        if a[key] != b[key]:
            raise ValueError("Native replicas differ in " + key)
    for kind in ("elf", "hex", "bin"):
        if a["artifacts"][kind] != b["artifacts"][kind]:
            raise ValueError("Native replicas are not byte-identical: " + kind)
    xmls = []
    for root, seal in ((args.first, a), (args.second, b)):
        tree = ET.fromstring((root / seal["artifacts"]["xml"]["file"]).read_bytes())
        times = tree.findall("./link_time")
        if len(times) != 1:
            raise ValueError("Native linker XML timestamp field is not unique")
        times[0].text = "NORMALIZED_NONSEMANTIC_LINK_TIME"
        xmls.append(ET.tostring(tree))
    if xmls[0] != xmls[1]:
        raise ValueError("Native linker XML differs beyond documented link_time")
    report = {"schema": "r4-b1-native-reproducibility-v1",
              "source_sha": args.expected_sha,
              "classification": a["classification"],
              "nv4_bridge_compiled": a["classification"] in (LINKED_NV4, LINKED_STOCK20260311),
              "stock20260311": a["classification"] == LINKED_STOCK20260311,
              "full_b0_b4_sealed": False,
              "result": "TWO_CLEAN_NATIVE_BUILDS_BYTE_IDENTICAL",
              "artifacts": a["artifacts"], "normalized_xml_fields": ["link_time"],
              "b1_source_ready": False, "physical_rf": "NOT_MEASURED"}
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print("B1_TWO_CLEAN_NATIVE_BUILDS_REPRODUCIBLE " + args.expected_sha)


if __name__ == "__main__":
    main()
