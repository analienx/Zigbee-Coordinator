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
        if item["classification"] != "HOSTED_NATIVE_LINKED":
            raise ValueError("Native comparison requires linked native evidence")
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
              "source_sha": args.expected_sha, "classification": "HOSTED_NATIVE_LINKED",
              "result": "TWO_CLEAN_NATIVE_BUILDS_BYTE_IDENTICAL",
              "artifacts": a["artifacts"], "normalized_xml_fields": ["link_time"],
              "b1_source_ready": False, "physical_rf": "NOT_MEASURED"}
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print("B1_TWO_CLEAN_NATIVE_BUILDS_REPRODUCIBLE " + args.expected_sha)


if __name__ == "__main__":
    main()
