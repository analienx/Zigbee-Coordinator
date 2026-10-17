"""Exact two-replica B5 OFFLINE composite digest parity, only AFTER B4
native parity verified ELF/HEX/BIN and normalized linker XML independently.
No network, keys, flashing or hardware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
def fail(text): raise ValueError("B5 offline attestation parity BLOCKED: " + text)
def load(root):
    receipts=list(root.rglob("b5-native-offline-provenance.json"))
    if len(receipts)!=1: fail("missing/ambiguous receipt: "+root.name)
    f=receipts[0]
    if f.is_symlink() or f.stat().st_size > 65536: fail("unsafe attestation receipt")
    a=json.loads(f.read_text(encoding="utf-8"))
    material=a.get("material",{})
    if (a.get("schema")!="r4-b5-native-offline-provenance-v1" or
        a.get("classification")!="HOSTED_NATIVE_LINKED_SOURCE_BOUND" or
        a.get("flash_authorized") is not False or
        a.get("physical_verified") is not False or
        a.get("runtime_radio_attestation") is not False or
        a.get("b1_public_status_digest_is_not_composite") is not True or
        a.get("raw_linker_xml_excluded_from_composite_id") is not True or
        material.get("schema")!="r4-b5-composite-material-v1"):
        fail("source/native classification or forbidden readiness claim")
    native=material.get("native_sha256",{})
    if set(native)!={"elf","hex","bin"} or any(
            type(v)!=str or HEX64.fullmatch(v) is None for v in native.values()):
        fail("stable native fields changed / raw XML entered identifier")
    src=material.get("source_sha256",{})
    if len(src)<12 or not all(type(x)==str and HEX64.fullmatch(x) for x in src.values()):
        fail("final TI source hash inventory invalid")
    if type(a.get("raw_linker_xml_sha256"))!=str or not HEX64.fullmatch(a["raw_linker_xml_sha256"]):
        fail("raw XML evidence invalid")
    raw=json.dumps(material,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
    if a.get("composite_sha256")!=hashlib.sha256(raw).hexdigest():
        fail("composite material/hash mismatch")
    return a

def compare(artifacts):
    root=Path(artifacts)
    if not root.is_dir(): fail("artifact directory missing")
    dirs=sorted(x for x in root.iterdir() if x.is_dir() and not x.is_symlink())
    if len(dirs)!=2: fail("exactly two independent native replicas")
    x,y=(load(z) for z in dirs)
    if x["composite_sha256"]!=y["composite_sha256"] or x["material"]!=y["material"]:
        fail("source/native composite material is NOT reproducible")
    return {
        "schema":"r4-b5-offline-composite-parity-v1",
        "composite_sha256":x["composite_sha256"],
        "native_images_byte_identical":True,
        "source_material_identical":True,
        "raw_xml_sha256_preserved":[x["raw_linker_xml_sha256"],y["raw_linker_xml_sha256"]],
        "linker_xml_parity_verified_by":"b4_artifact_parity.py",
        "hardware_verified":False,"flash_authorized":False,
    }
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--artifacts",required=True,type=Path)
    p.add_argument("--receipt",type=Path)
    a=p.parse_args()
    report=compare(a.artifacts)
    if a.receipt:a.receipt.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
