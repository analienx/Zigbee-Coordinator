"""Fail-closed parity for two actual B4 CCS native outputs.

ELF, HEX and BIN must match *byte for byte*, with their actual bytes bound to
their manifests. Linker XML is separately verified byte-for-byte after
normalizing ONLY the independently confirmed volatile <link_time> field.
Any other XML semantic/text drift fails. Raw XML SHA256s remain in evidence.
This does NOT authorize flashing or assert physical reliability.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

KINDS = ("elf", "xml", "hex", "bin")
CAP_BYTES = 12 * 1024 * 1024
LINK_TIME = re.compile(rb"<link_time>0x[0-9A-Fa-f]{8}</link_time>")

def _file_in(directory, filename):
    if type(filename) is not str or not filename or Path(filename).name != filename:
        raise ValueError("manifest filename not a basename")
    path = directory / filename
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing/symlinked artifact: " + filename)
    if path.stat().st_size > CAP_BYTES:
        raise ValueError("oversized native artifact")
    return path.read_bytes()

def _exact_xml_normalized(blob):
    if len(blob) > CAP_BYTES:
        raise ValueError("oversized XML report")
    root = ET.fromstring(blob)
    if root.tag != "link_info":
        raise ValueError("unexpected CCS link_info XML root")
    stamps = root.findall("link_time")
    if len(stamps) != 1:
        raise ValueError("CCS XML must have exactly one link_time")
    if not re.fullmatch(r"0x[0-9A-Fa-f]{8}", stamps[0].text or ""):
        raise ValueError("unrecognized CCS linker time format")
    errors = root.findall("link_errors")
    if len(errors) != 1 or errors[0].text != "0x0":
        raise ValueError("CCS XML contains linker errors or missing status")
    normalized, n = LINK_TIME.subn(b"<link_time>0x00000000</link_time>", blob)
    if n != 1:
        raise ValueError("link_time XML normalization not exact")
    return normalized

def _load(directory):
    manifests = list(directory.rglob("manifest.json"))
    linked = list(directory.rglob("b4-native-linked.json"))
    patched = list(directory.rglob("b4-native-overlay.json"))
    if not (len(manifests) == len(linked) == len(patched) == 1):
        raise ValueError("not exactly one native receipt per independent artifact")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    proof = json.loads(linked[0].read_text(encoding="utf-8"))
    patch = json.loads(patched[0].read_text(encoding="utf-8"))
    if (manifest.get("schema") != "r4-b0-artifact-manifest-v1"
            or proof.get("schema") != "b4-native-link-proof-v1"
            or proof.get("evidence") != "HOSTED_NATIVE_LINKED"
            or proof.get("f0_native_handler_linked") is not True
            or proof.get("hardware_verified") is not False
            or proof.get("host_installed") is not False
            or patch.get("stage") != "PATCHED_DISPOSABLE_SDK_NOT_LINKED"
            or patch.get("valid_counter_indices") != [0, 1, 2, 3, 4, 5]
            or patch.get("radio_boot_identity") != "UNKNOWN"):
        raise ValueError("native linker proof/patch receipt not qualified")
    files = {}
    sha = {}
    for kind in KINDS:
        entry = manifest.get("files", {}).get(kind, {})
        filename = entry.get("file")
        data = _file_in(manifests[0].parent, filename)
        digest = hashlib.sha256(data).hexdigest()
        if entry.get("sha256") != digest:
            raise ValueError("manifest file digest mismatch: " + kind)
        files[kind] = data
        sha[kind] = digest
    if proof.get("elf_sha256") != sha["elf"]:
        raise ValueError("linked ELF proof hash disagrees with actual ELF")
    if files["elf"][:4] != b"\x7fELF":
        raise ValueError("native ELF magic invalid")
    return {"hashes": sha, "xml_normalized": _exact_xml_normalized(files["xml"])}

def compare(root):
    if not Path(root).is_dir():
        raise ValueError("native artifacts missing")
    groups = sorted(p for p in Path(root).iterdir() if p.is_dir() and not p.is_symlink())
    if len(groups) != 2:
        raise ValueError("exactly two independent artifact directories required")
    a, b = [_load(group) for group in groups]
    for kind in ("elf", "hex", "bin"):
        if a["hashes"][kind] != b["hashes"][kind]:
            raise ValueError("native " + kind + " bytes are NOT reproducible")
    if a["xml_normalized"] != b["xml_normalized"]:
        raise ValueError("linker XML differs beyond allowlisted link_time field")
    return {
        "schema": "b4-exact-native-pair-parity-v1",
        "evidence": "HOSTED_NATIVE_LINKED",
        "images_byte_identical": True,
        "elf_sha256": a["hashes"]["elf"],
        "hex_sha256": a["hashes"]["hex"],
        "bin_sha256": a["hashes"]["bin"],
        "raw_linker_xml_sha256": [a["hashes"]["xml"], b["hashes"]["xml"]],
        "linker_xml_normalization": "ONLY_HEX_LINK_TIME_AS_CONFIRMED_BY_NATIVE_DIFF",
        "normalized_linker_xml_sha256": hashlib.sha256(a["xml_normalized"]).hexdigest(),
        "hardware_verified": False,
        "host_installed": False,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(compare(args.artifacts), sort_keys=True))

if __name__ == "__main__":
    main()
