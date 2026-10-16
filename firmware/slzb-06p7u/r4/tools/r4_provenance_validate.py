"""R4-00 provenance/matrix validator (stdlib only, offline).

Validates firmware/slzb-06p7u/r4/SOURCE_PROVENANCE.json and
firmware/slzb-06p7u/r4/PARITY_MATRIX.json. Exit 0 on success,
exit 1 with clean error lines on failure (never a traceback:
every malformed shape, including nulls, wrong container types,
unhashable ids/domains and duplicate JSON keys, maps to an
error line).

Donor coherence (issue #85, Wonder P0): the pinned
simplelink-zstack-examples commit 87ff5b63 carries the message
"SimpleLink LPF2 8.33.00.16 zstack examples update" and a
cc13xx_cc26xx_sdk gitlink of 3615ad5d, which is the
simplelink-lowpower-f2-sdk commit "SimpleLink lpf2-8.33.00.16
update". The coherent pair is therefore SDK 3615ad5d +
examples 87ff5b6 at release lpf2-8.33.00.16. Toolchain
compat re-checked against the upstream 8.33.00.16 release
notes at the pinned SDK commit: CCS-12.8.0, TI ARM Clang
3.2.2.LTS, SysConfig 1.21.1 -- the pinned
12.8.0.00012 / 3.2.2.LTS / 1.21.1.3772 stand unchanged.
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
# Frozen R4-00 domain snapshot (27 entries incl. the 5 Wonder-required
# additions). Exact domain-set equality is enforced for phase "R4-00".
# B1 growth procedure (do NOT just append here): add a versioned
# REQUIRED_DOMAINS_B1 set, gate the equality check on doc phase, add the
# new-domain entries + fixtures, and record the change in R4_DESIGN_MEMO.md.
REQUIRED_DOMAINS_R4_00 = frozenset({
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
    "image-vectors",
    "linker-script",
    "memory-geometry",
    "mac-layer",
    "application-version",
})
# Back-compat alias for single-source-of-truth imports (tests import this).
REQUIRED_DOMAINS = REQUIRED_DOMAINS_R4_00
EXPECTED_PINS = {
    "ti_sdk_sha": "3615ad5d3f4f271258d18a2f5ce1785064ff9a58",
    "ti_sdk_release": "lpf2-8.33.00.16",
    "ti_examples_sha": "87ff5b638b632050228a7504f35cf3b95581c278",
    "ti_examples_release": "lpf2-8.33.00.16",
    "sdk_version": "8.33",
    "herdsman_sha": "0968f979d558874b17396c96b66382d4236bbdcd",
    "herdsman_version": "10.9.1",
    "ccs": "12.8.0.00012",
    "ti_arm_clang": "3.2.2.LTS",
    "sysconfig": "1.21.1.3772",
    "vendor_20260310_sha256": "f18011d2652651e36d5e1e7e1cb1f7cbcb99e9493eacbbf8e404a036c626afbe",
    "vendor_20240710_sha256": "1e257bc066e7a8db9c12e0b826791cc81d8744b9453355af0f4efce194060d6b",
}
EXPECTED_DONOR_REPOS = {
    "ti_lowpower_f2_sdk": "TexasInstruments/simplelink-lowpower-f2-sdk",
    "zstack_examples": "TexasInstruments/simplelink-zstack-examples",
    "koenkk_zstack_firmware": "Koenkk/Z-Stack-firmware",
    "zigbee_herdsman": "Koenkk/zigbee-herdsman",
}
# "R4-00-fixture" marks synthetic fixtures under fixtures/; it is never
# valid for the real manifests, which must carry phase "R4-00".
ALLOWED_PHASES = {"R4-00", "R4-00-fixture"}
PROVENANCE_TOP_KEYS = {
    "schema", "phase", "issue", "sdk_version", "donors",
    "toolchain", "vendor_images", "unknowns", "verification_scope",
    "catalog_labels_note",
}
MATRIX_TOP_KEYS = {"schema", "phase", "issue", "entries", "status_notes"}
MATRIX_ENTRY_KEYS = {"id", "domain", "claim", "status", "evidence", "verification"}
MATRIX_ENTRY_REQUIRED = ("id", "domain", "claim", "status", "evidence", "verification")
VENDOR_IMAGE_KEYS = {
    "id", "rev", "sha256", "provenance", "source_unproven",
    "baud", "catalog_sdk", "container_bytes_observed", "filename", "url",
}
VENDOR_URL_PREFIX = "https://updates.smlight.tech/"


def _err(errors, msg):
    errors.append(msg)


def _no_duplicate_keys(pairs):
    """object_pairs_hook rejecting duplicate JSON keys (else json.load
    silently keeps the last value and guards below see a clean dict)."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate key %r" % (key,))
        obj[key] = value
    return obj


def loads_strict(text):
    """Parse JSON, rejecting duplicate keys at any nesting level."""
    return json.loads(text, object_pairs_hook=_no_duplicate_keys)


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return loads_strict(handle.read())


def _check_top_keys(errors, prefix, doc, allowed, required):
    for key in required:
        if key not in doc:
            _err(errors, "%s: missing key %r" % (prefix, key))
    for key in doc:
        if key not in allowed:
            _err(errors, "%s: unexpected top-level key %r" % (prefix, key))


def _check_phase_issue(errors, prefix, doc):
    if doc.get("phase") not in ALLOWED_PHASES:
        _err(errors, "%s: phase %r not allowed (want R4-00)" % (prefix, doc.get("phase")))
    if doc.get("issue") != 85:
        _err(errors, "%s: issue %r not allowed (want 85)" % (prefix, doc.get("issue")))


def _is_hex40(value):
    return isinstance(value, str) and bool(HEX40.match(value))


def _is_hex64(value):
    return isinstance(value, str) and bool(HEX64.match(value))


def validate_provenance(doc):
    errors = []
    if not isinstance(doc, dict):
        return ["provenance: top-level object required"]
    _check_top_keys(errors, "provenance", doc, PROVENANCE_TOP_KEYS,
                    ("schema", "phase", "issue", "sdk_version", "donors",
                     "toolchain", "vendor_images", "unknowns"))
    if errors:
        return errors
    if doc.get("schema") != "r4-source-provenance-v1":
        _err(errors, "provenance: unexpected schema %r" % doc.get("schema"))
    _check_phase_issue(errors, "provenance", doc)
    if doc.get("sdk_version") != EXPECTED_PINS["sdk_version"]:
        _err(errors, "provenance: sdk_version %r mismatch (want %r)"
              % (doc.get("sdk_version"), EXPECTED_PINS["sdk_version"]))
    donors = doc["donors"]
    if not isinstance(donors, dict):
        _err(errors, "provenance: donors must be an object")
        donors = {}
    for donor_key, want_repo in EXPECTED_DONOR_REPOS.items():
        entry = donors.get(donor_key)
        if not isinstance(entry, dict):
            _err(errors, "provenance: donors.%s must be an object" % donor_key)
            continue
        if entry.get("repo") != want_repo:
            _err(errors, "provenance: donors.%s repo %r mismatch (want %r)"
                  % (donor_key, entry.get("repo"), want_repo))
    sdk = donors.get("ti_lowpower_f2_sdk")
    if isinstance(sdk, dict):
        if sdk.get("sha") != EXPECTED_PINS["ti_sdk_sha"]:
            _err(errors, "provenance: ti_lowpower_f2_sdk sha mismatch")
        if not _is_hex40(sdk.get("sha")):
            _err(errors, "provenance: ti sdk sha not 40-hex")
        if sdk.get("release") != EXPECTED_PINS["ti_sdk_release"]:
            _err(errors, "provenance: ti_lowpower_f2_sdk release %r mismatch (want %r)"
                  % (sdk.get("release"), EXPECTED_PINS["ti_sdk_release"]))
    examples = donors.get("zstack_examples")
    if isinstance(examples, dict):
        if examples.get("sha") != EXPECTED_PINS["ti_examples_sha"]:
            _err(errors, "provenance: zstack_examples sha mismatch")
        if not _is_hex40(examples.get("sha")):
            _err(errors, "provenance: zstack examples sha not 40-hex")
        if examples.get("release") != EXPECTED_PINS["ti_examples_release"]:
            _err(errors, "provenance: zstack_examples release %r mismatch (want %r)"
                  % (examples.get("release"), EXPECTED_PINS["ti_examples_release"]))
    if (isinstance(sdk, dict) and isinstance(examples, dict)
            and (sdk.get("release") != examples.get("release")
                 or sdk.get("release") != EXPECTED_PINS["ti_sdk_release"]
                 or doc.get("sdk_version") not in (sdk.get("release") or ""))):
        # Cross-version consistency: both TI donors must name the same
        # release, and sdk_version must be that release's version. A mixed
        # pair (e.g. 8.33 examples against an 8.32 SDK) fails closed here
        # even when each SHA is individually well-formed.
        _err(errors, "provenance: donor pair incoherent: sdk release %r vs "
                     "examples release %r vs sdk_version %r (want coherent %s/%s)"
              % (sdk.get("release") if isinstance(sdk, dict) else None,
                 examples.get("release") if isinstance(examples, dict) else None,
                 doc.get("sdk_version"),
                 EXPECTED_PINS["ti_sdk_release"], EXPECTED_PINS["sdk_version"]))
    koenkk = donors.get("koenkk_zstack_firmware")
    if isinstance(koenkk, dict):
        if koenkk.get("identical_to_20260310") is not False:
            _err(errors, "provenance: koenkk donor must state identical_to_20260310=false")
        if not koenkk.get("patch") or not koenkk.get("changelog"):
            _err(errors, "provenance: koenkk patch+changelog paths required")
    herd = donors.get("zigbee_herdsman")
    if isinstance(herd, dict):
        if herd.get("sha") != EXPECTED_PINS["herdsman_sha"]:
            _err(errors, "provenance: herdsman sha mismatch")
        if herd.get("version") != EXPECTED_PINS["herdsman_version"]:
            _err(errors, "provenance: herdsman version mismatch")
    tc = doc["toolchain"]
    if not isinstance(tc, dict):
        _err(errors, "provenance: toolchain must be an object")
    else:
        for field in ("ccs", "ti_arm_clang", "sysconfig"):
            if tc.get(field) != EXPECTED_PINS[field]:
                _err(errors, "provenance: toolchain %s mismatch" % field)
    images = doc["vendor_images"]
    if not isinstance(images, list):
        _err(errors, "provenance: vendor_images must be a list")
        images = []
    revs = []
    by_rev = {}
    for idx, img in enumerate(images):
        where = "provenance.vendor_images[%d]" % idx
        if not isinstance(img, dict):
            _err(errors, "%s: object required" % where)
            continue
        for key in img:
            if key not in VENDOR_IMAGE_KEYS:
                _err(errors, "%s: unexpected vendor key %r" % (where, key))
        rev = img.get("rev")
        if not isinstance(rev, str) or not rev:
            _err(errors, "%s: rev must be a non-empty string" % where)
            continue
        revs.append(rev)
        by_rev.setdefault(rev, img)
        url = img.get("url")
        if not isinstance(url, str) or not url.startswith(VENDOR_URL_PREFIX):
            _err(errors, "%s: url must start with %r" % (where, VENDOR_URL_PREFIX))
    if len(revs) != len(set(revs)):
        _err(errors, "provenance: duplicate vendor rev (each rev must appear once; last-wins shadowing of UNKNOWN is not allowed)")
    img10 = by_rev.get("20260310")
    img407 = by_rev.get("20240710")
    if img10 is None:
        _err(errors, "provenance: vendor 20260310 entry missing")
    else:
        if img10.get("sha256") != EXPECTED_PINS["vendor_20260310_sha256"]:
            _err(errors, "provenance: vendor 20260310 sha256 mismatch")
        if not _is_hex64(img10.get("sha256")):
            _err(errors, "provenance: vendor 20260310 sha256 not 64-hex")
        if img10.get("provenance") != "UNKNOWN":
            _err(errors, "provenance: vendor 20260310 provenance must stay UNKNOWN")
        if img10.get("source_unproven") is not True:
            _err(errors, "provenance: vendor 20260310 source_unproven must be true")
    if img407 is None:
        _err(errors, "provenance: vendor 20240710 entry missing")
    else:
        if img407.get("sha256") != EXPECTED_PINS["vendor_20240710_sha256"]:
            _err(errors, "provenance: vendor 20240710 sha256 mismatch")
        if not _is_hex64(img407.get("sha256")):
            _err(errors, "provenance: vendor 20240710 sha256 not 64-hex")
        # 20240710 is catalog history, not a fitted-unit claim: its
        # container digest is catalogued vendor history, so
        # source_unproven=false is explicit and intended here (it marks
        # "vendor-origin catalog artifact", NOT "source proven"). Only
        # 20260310 carries source_unproven=true.
        if img407.get("source_unproven") is not False:
            _err(errors, "provenance: vendor 20240710 source_unproven must be false (catalog history, not a fitted-unit claim)")
        if img407.get("provenance") != "CATALOG_HISTORICAL":
            _err(errors, "provenance: vendor 20240710 provenance must stay CATALOG_HISTORICAL")
    unknowns = doc["unknowns"]
    if not isinstance(unknowns, list) or not unknowns:
        _err(errors, "provenance: unknowns must be a non-empty list")
    else:
        for idx, item in enumerate(unknowns):
            if not isinstance(item, str) or not item.strip():
                _err(errors, "provenance: unknowns[%d] must be a non-empty string" % idx)
        substance = [item for item in unknowns
                     if isinstance(item, str) and "20260310" in item]
        if not substance:
            _err(errors, "provenance: unknowns must substantively record the 20260310 source-unknown gap (no entry mentions 20260310)")
    return errors


def validate_matrix(doc):
    errors = []
    if not isinstance(doc, dict):
        return ["matrix: top-level object required"]
    _check_top_keys(errors, "matrix", doc, MATRIX_TOP_KEYS,
                    ("schema", "phase", "issue", "entries"))
    if errors:
        return errors
    if doc.get("schema") != "r4-parity-matrix-v1":
        _err(errors, "matrix: unexpected schema %r" % doc.get("schema"))
    _check_phase_issue(errors, "matrix", doc)
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
        for key in entry:
            if key not in MATRIX_ENTRY_KEYS:
                _err(errors, "%s: unexpected entry key %r" % (where, key))
        for key in MATRIX_ENTRY_REQUIRED:
            if not entry.get(key):
                _err(errors, "%s: missing/empty %r" % (where, key))
        eid = entry.get("id")
        if not isinstance(eid, str) or not eid:
            _err(errors, "%s: id must be a non-empty string" % where)
        else:
            if eid in seen_ids:
                _err(errors, "%s: duplicate id %r" % (where, eid))
            seen_ids.add(eid)
        domain = entry.get("domain")
        if not isinstance(domain, str) or not domain:
            _err(errors, "%s: domain must be a non-empty string" % where)
        else:
            if domain in seen_domains:
                _err(errors, "%s: duplicate domain %r (one entry per domain at R4-00)" % (where, domain))
            seen_domains.add(domain)
        status = entry.get("status")
        if not isinstance(status, str) or status not in ALLOWED_STATUS:
            _err(errors, "%s: status %r not permitted at R4-00 (only SOURCE_CONFIRMED/PHYSICAL_UNVERIFIED)" % (where, status))
    # Exact equality against the frozen R4-00 snapshot (see B1 growth
    # procedure on REQUIRED_DOMAINS_R4_00). Holds for the R4-00 phase gate.
    missing = REQUIRED_DOMAINS_R4_00 - seen_domains
    if missing:
        _err(errors, "matrix: missing domains: %s" % sorted(missing))
    extra = seen_domains - REQUIRED_DOMAINS_R4_00
    if extra:
        _err(errors, "matrix: unexpected domains (exact R4-00 domain-set equality required): %s" % sorted(extra))
    return errors


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
