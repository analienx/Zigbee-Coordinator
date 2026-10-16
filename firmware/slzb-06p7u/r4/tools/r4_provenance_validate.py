"""R4-00 provenance/matrix validator (stdlib only, offline).

Validates firmware/slzb-06p7u/r4/SOURCE_PROVENANCE.json and
firmware/slzb-06p7u/r4/PARITY_MATRIX.json. Exit 0 on success,
exit 1 with error lines on failure.
"""
import json
import re
import sys
from pathlib import Path

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
# R4-00 is source-only: no NATIVE_CI/SYNTHETIC_TEST evidence exists yet and
# no HARDWARE_PROVEN claim is permitted. Only these two statuses validate.
ALLOWED_STATUS = {
    "SOURCE_CONFIRMED",
    "PHYSICAL_UNVERIFIED",
}
REQUIRED_DOMAINS = {
    "startup-order",
    "c-irq-stack",
    "rtos-stacks",
    "uart-pins",
    "uart-callbacks",
    "bridge-line-controls",
    "clock-power",
    "radio-pa",
    "ccfg",
    "bsl",
    "nvs-layout",
    "nvs-compaction",
    "sys-ping-version-abi",
    "mt-frames",
    "npi-tx",
    "npi-rx",
    "nwk-caches",
    "nwk-buffers-retries",
    "concentrator",
    "heap",
    "tc-keys-counters",
    "nv-observability",
}
EXPECTED_PINS = {
    "ti_sdk_sha": "6499c3f53fc5fb5806213be695450a7b43fbaf3d",
    "ti_examples_sha": "87ff5b638b632050228a7504f35cf3b95581c278",
    "herdsman_sha": "0968f979d558874b17396c96b66382d4236bbdcd",
    "herdsman_version": "10.9.1",
    "ccs": "12.8.0.00012",
    "ti_arm_clang": "3.2.2.LTS",
    "sysconfig": "1.21.1.3772",
    "vendor_20260310_sha256": "f18011d2652651e36d5e1e7e1cb1f7cbcb99e9493eacbbf8e404a036c626afbe",
    "vendor_20240710_sha256": "1e257bc066e7a8db9c12e0b826791cc81d8744b9453355af0f4efce194060d6b",
}


def _err(errors, msg):
    errors.append(msg)


def validate_provenance(doc):
    errors = []
    if not isinstance(doc, dict):
        return ["provenance: top-level object required"]
    for key in ("schema", "phase", "issue", "donors", "toolchain",
                "vendor_images", "unknowns"):
        if key not in doc:
            _err(errors, "provenance: missing key %r" % key)
    if errors:
        return errors
    if doc.get("schema") != "r4-source-provenance-v1":
        _err(errors, "provenance: unexpected schema %r" % doc.get("schema"))
    donors = doc["donors"]
    try:
        if donors["ti_lowpower_f2_sdk"]["sha"] != EXPECTED_PINS["ti_sdk_sha"]:
            _err(errors, "provenance: ti_lowpower_f2_sdk sha mismatch")
        if not HEX40.match(donors["ti_lowpower_f2_sdk"]["sha"]):
            _err(errors, "provenance: ti sdk sha not 40-hex")
        if donors["zstack_examples"]["sha"] != EXPECTED_PINS["ti_examples_sha"]:
            _err(errors, "provenance: zstack_examples sha mismatch")
        koenkk = donors["koenkk_zstack_firmware"]
        if koenkk.get("identical_to_20260310") is not False:
            _err(errors, "provenance: koenkk donor must state identical_to_20260310=false")
        if not koenkk.get("patch") or not koenkk.get("changelog"):
            _err(errors, "provenance: koenkk patch+changelog paths required")
        herd = donors["zigbee_herdsman"]
        if herd.get("sha") != EXPECTED_PINS["herdsman_sha"]:
            _err(errors, "provenance: herdsman sha mismatch")
        if herd.get("version") != EXPECTED_PINS["herdsman_version"]:
            _err(errors, "provenance: herdsman version mismatch")
    except (KeyError, TypeError, AttributeError) as exc:
        _err(errors, "provenance: malformed donors: %s" % exc)
    tc = doc["toolchain"]
    for field in ("ccs", "ti_arm_clang", "sysconfig"):
        if tc.get(field) != EXPECTED_PINS[field]:
            _err(errors, "provenance: toolchain %s mismatch" % field)
    revs = [img.get("rev") for img in doc["vendor_images"]]
    if len(revs) != len(set(revs)):
        _err(errors, "provenance: duplicate vendor rev (each rev must appear once; last-wins shadowing of UNKNOWN is not allowed)")
    images = {img.get("rev"): img for img in doc["vendor_images"]}
    img10 = images.get("20260310")
    img407 = images.get("20240710")
    if img10 is None:
        _err(errors, "provenance: vendor 20260310 entry missing")
    else:
        if img10.get("sha256") != EXPECTED_PINS["vendor_20260310_sha256"]:
            _err(errors, "provenance: vendor 20260310 sha256 mismatch")
        if not HEX64.match(img10.get("sha256", "")):
            _err(errors, "provenance: vendor 20260310 sha256 not 64-hex")
        if img10.get("provenance") != "UNKNOWN":
            _err(errors, "provenance: vendor 20260310 provenance must stay UNKNOWN")
        if img10.get("source_unproven") is not True:
            _err(errors, "provenance: vendor 20260310 source_unproven must be true")
    if img407 is None:
        _err(errors, "provenance: vendor 20240710 entry missing")
    elif img407.get("sha256") != EXPECTED_PINS["vendor_20240710_sha256"]:
        _err(errors, "provenance: vendor 20240710 sha256 mismatch")
    if not isinstance(doc["unknowns"], list) or not doc["unknowns"]:
        _err(errors, "provenance: unknowns must be a non-empty list")
    return errors


def validate_matrix(doc):
    errors = []
    if not isinstance(doc, dict):
        return ["matrix: top-level object required"]
    for key in ("schema", "phase", "issue", "entries"):
        if key not in doc:
            _err(errors, "matrix: missing key %r" % key)
    if errors:
        return errors
    if doc.get("schema") != "r4-parity-matrix-v1":
        _err(errors, "matrix: unexpected schema %r" % doc.get("schema"))
    entries = doc["entries"]
    if not isinstance(entries, list) or not entries:
        return ["matrix: entries must be a non-empty list"]
    seen_ids = set()
    seen_domains = set()
    for idx, entry in enumerate(entries):
        where = "matrix.entries[%d]" % idx
        if not isinstance(entry, dict):
            _err(errors, "%s: object required" % where)
            continue
        for key in ("id", "domain", "claim", "status", "evidence"):
            if not entry.get(key):
                _err(errors, "%s: missing/empty %r" % (where, key))
        eid = entry.get("id")
        if eid in seen_ids:
            _err(errors, "%s: duplicate id %r" % (where, eid))
        seen_ids.add(eid)
        domain = entry.get("domain")
        if domain in seen_domains:
            _err(errors, "%s: duplicate domain %r (one entry per domain at R4-00)" % (where, domain))
        seen_domains.add(domain)
        status = entry.get("status")
        if status not in ALLOWED_STATUS:
            _err(errors, "%s: status %r not permitted at R4-00 (only SOURCE_CONFIRMED/PHYSICAL_UNVERIFIED)" % (where, status))
    missing = REQUIRED_DOMAINS - seen_domains
    if missing:
        _err(errors, "matrix: missing domains: %s" % sorted(missing))
    return errors


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv):
    base = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[1]
    prov_path = base / "SOURCE_PROVENANCE.json"
    matrix_path = base / "PARITY_MATRIX.json"
    errors = []
    try:
        errors += ["provenance: " + e for e in validate_provenance(load_json(prov_path))]
    except (OSError, ValueError) as exc:
        errors.append("provenance: unreadable %s (%s)" % (prov_path, exc))
    try:
        errors += ["parity: " + e for e in validate_matrix(load_json(matrix_path))]
    except (OSError, ValueError) as exc:
        errors.append("parity: unreadable %s (%s)" % (matrix_path, exc))
    if errors:
        sys.stdout.write("\n".join(errors) + "\n")
        return 1
    sys.stdout.write("R4-00 provenance+parity OK\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
