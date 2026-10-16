"""R4-00 manifest-consistency checks (stdlib only, offline).

Validates firmware/slzb-06p7u/r4/SOURCE_PROVENANCE.json and
firmware/slzb-06p7u/r4/PARITY_MATRIX.json against the EXPECTED_*
constants compiled into THIS file. Exit 0 on success, exit 1 with
clean error lines on failure (never a traceback: every malformed
shape, including nulls, wrong container types, unhashable ids/domains
and duplicate JSON keys, maps to an error line).

These are manifest-CONSISTENCY checks, not external source-integrity
proof: the EXPECTED_* constants live in the same checkout as the
manifests, so a coherent in-PR mutation of pins plus constants passes
them by construction. The phrase "source-integrity proof" is reserved
for the hosted r4-00-upstream-attestation job
(tools/r4_upstream_attest.py), which re-verifies every pin against
upstream over the network and fails closed when upstream is
unreachable. Never describe this validator's green run as upstream
proof in docs, packets, or reviews.

Donor coherence (issue #85): the pinned simplelink-zstack-examples
commit 87ff5b63 carries the message "SimpleLink LPF2 8.33.00.16
zstack examples update" and a cc13xx_cc26xx_sdk gitlink of 3615ad5d,
which is the simplelink-lowpower-f2-sdk commit "SimpleLink
lpf2-8.33.00.16 update". The coherent pair is therefore SDK 3615ad5d +
examples 87ff5b6 at release lpf2-8.33.00.16. Toolchain compat
re-checked against the upstream 8.33.00.16 release notes at the pinned
SDK commit: CCS-12.8.0, TI ARM Clang 3.2.2.LTS, SysConfig 1.21.1 -- the
pinned 12.8.0.00012 / 3.2.2.LTS / 1.21.1.3772 stand unchanged.
Installer/download digests for those toolchain components were never
sourced, so the manifest records them explicitly as UNKNOWN (never a
fabricated digest); the validator requires the UNKNOWN marker.

Koenkk comparison donor (issue #85 R4-D01): exact commit
5e4db67e550d41ea6dc6cd86ceeb04d82ffe1bfb (tag
Z-Stack_3.x.0_coordinator_20250321, 20250321-era comparison donor,
never a build input). The firmware.patch and CHANGELOG.md blob SHAs
below were read from the public GitHub contents API at that commit.
Distinct comparison donor only; identical_to_20260310 is false.
"""
import json
import re
import sys
from pathlib import Path

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40_SEARCH = re.compile(r"[0-9a-f]{40}")
HEX64_SEARCH = re.compile(r"[0-9a-f]{64}")
# A path-like traceability token: contains a slash and a dotted suffix,
# e.g. coordinator/Z-Stack_3.x.0/firmware.patch or .supervisor/x.yaml.
UPSTREAM_PATH_SEARCH = re.compile(r"\S+/\S*\.\S+")
# SOURCE_CONFIRMED-only path token (issue #85 re-review): a real
# multi-segment upstream path (at least two slashes), e.g.
# coordinator/Z-Stack_3.x.0/firmware.patch. A trivial "a/b.c" does
# not qualify. Used ONLY for the SOURCE_CONFIRMED anchor rule; the
# general evidence taxonomy above stays permissive.
SC_PATH_SEARCH = re.compile(r"\S+/\S+/\S*\.\S+")
# Claim/evidence/verification length bound (trimmed). Real R4-00 strings
# are a few hundred chars; the bound only rejects runaway pastes.
TEXT_MAX_LEN = 2000
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
    "koenkk_sha": "5e4db67e550d41ea6dc6cd86ceeb04d82ffe1bfb",
    "koenkk_patch_blob": "e015d9a9020e08d049515664693b22a9ce0e1fdb",
    "koenkk_changelog_blob": "25f8bb3fb3bafe22b860d9a00134a2d722272650",
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
KOENKK_PATCH_PATH = "coordinator/Z-Stack_3.x.0/firmware.patch"
KOENKK_CHANGELOG_PATH = "coordinator/Z-Stack_3.x.0/CHANGELOG.md"
# Toolchain installer/download digests were never sourced: the manifest
# must carry each of these fields with the literal value "UNKNOWN".
TOOLCHAIN_DOWNLOAD_DIGEST_FIELDS = (
    "ccs_download_sha256",
    "ti_arm_clang_download_sha256",
    "sysconfig_download_sha256",
)
# Full vendor artifact identity tuples (issue #85 R4-D06). Every listed
# field is bound: repoint/resize/rebaud/re-id/relabel of either image
# fails. vendor_catalog records the vendor-channel listing status;
# binary_source_equivalence records binary-to-source proof and must stay
# UNKNOWN for both images (no equivalence established at R4-00).
EXPECTED_VENDOR_IMAGES = {
    "20260310": {
        "id": "P7U_VENDOR_20260310_115200",
        "rev": "20260310",
        "model": "SLZB-06P7U",
        "filename": "znp-SLZB-06P7U-115200-20260310.bin",
        "baud": 115200,
        "container_bytes_observed": 273894,
        "url": "https://updates.smlight.tech/firmware/slzb06x/zigbee/slzb06p7v2/20260310/znp-SLZB-06P7U-115200-20260310.bin",
        "sha256": EXPECTED_PINS["vendor_20260310_sha256"],
        "provenance": "UNKNOWN",
        "vendor_catalog": "LISTED",
        "binary_source_equivalence": "UNKNOWN",
        "catalog_sdk": "8.32.00.07",
    },
    "20240710": {
        "id": "P7U_VENDOR_20240710_115200",
        "rev": "20240710",
        "model": "SLZB-06P7U",
        "filename": "CC1352P7_coordinator_20240710.bin",
        "baud": 115200,
        "container_bytes_observed": 179804,
        "url": "https://updates.smlight.tech/firmware/slzb06x/zigbee/slzb06p7v2/CC1352P7_coordinator_20240710.bin",
        "sha256": EXPECTED_PINS["vendor_20240710_sha256"],
        "provenance": "CATALOG_HISTORICAL",
        "vendor_catalog": "LISTED",
        "binary_source_equivalence": "UNKNOWN",
        "catalog_sdk": "7.41",
    },
}
VENDOR_TUPLE_FIELDS = (
    "id", "rev", "model", "filename", "baud",
    "container_bytes_observed", "url", "sha256", "provenance",
    "vendor_catalog", "catalog_sdk",
)
# "R4-00-fixture" marks synthetic fixtures under fixtures/; it is never
# valid for the real manifests, which must carry phase "R4-00". The
# production CLI (main) always enforces allow_fixture=False; hosted
# tests pass allow_fixture=True explicitly for fixture docs.
ALLOWED_FIXTURE_PHASE = "R4-00-fixture"
PRODUCTION_PHASE = "R4-00"
PROVENANCE_TOP_KEYS = {
    "schema", "phase", "issue", "sdk_version", "donors",
    "toolchain", "vendor_images", "unknowns", "verification_scope",
    "catalog_labels_note",
}
MATRIX_TOP_KEYS = {"schema", "phase", "issue", "entries", "status_notes"}
MATRIX_ENTRY_KEYS = {"id", "domain", "claim", "status", "evidence", "verification"}
MATRIX_ENTRY_REQUIRED = ("id", "domain", "claim", "status", "evidence", "verification")
VENDOR_IMAGE_KEYS = {
    "id", "rev", "model", "sha256", "provenance", "vendor_catalog",
    "binary_source_equivalence", "baud", "catalog_sdk",
    "container_bytes_observed", "filename", "url",
}


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


def _check_phase_issue(errors, prefix, doc, allow_fixture):
    # Type-first: set-membership on an unhashable phase (list/dict) would
    # raise TypeError, so compare with == chains only. Every JSON type
    # maps to a clean error line, never a traceback.
    phase = doc.get("phase")
    if not isinstance(phase, str):
        _err(errors, "%s: phase must be a string (got %s)"
              % (prefix, type(phase).__name__))
    elif phase != PRODUCTION_PHASE and not (
            allow_fixture and phase == ALLOWED_FIXTURE_PHASE):
        _err(errors, "%s: phase %r not allowed (want R4-00)" % (prefix, phase))
    if doc.get("issue") != 85:
        _err(errors, "%s: issue %r not allowed (want 85)" % (prefix, doc.get("issue")))


def _is_hex40(value):
    return isinstance(value, str) and bool(HEX40.match(value))


def _has_traceable_anchor(text):
    """Traceability taxonomy (issue #85 R4-D05): an evidence string must
    carry at least one traceable anchor -- an upstream commit/blob
    digest, an http(s) URL, an issue reference, or an upstream path.
    Returns False for non-strings (callers report the type error)."""
    if not isinstance(text, str):
        return False
    lowered = text.lower()
    return bool(
        HEX40_SEARCH.search(text)
        or HEX64_SEARCH.search(text)
        or "https://" in lowered
        or "http://" in lowered
        or "#85" in lowered
        or UPSTREAM_PATH_SEARCH.search(text)
    )


def _has_pinned_digest(text):
    """True when text contains a full 40- or 64-hex digest equal to one of
    the EXPECTED_PINS digest values (TI/herdsman/koenkk commits, koenkk
    blobs, vendor image sha256s). A coincidental 40-hex run such as
    all-zeros is NOT sufficient: it must equal a reviewed pin (issue
    #85 R4-R3; the SOURCE_CONFIRMED anchor binds the entry to a pin)."""
    candidates = set(HEX40_SEARCH.findall(text))
    candidates.update(HEX64_SEARCH.findall(text))
    pinned = {
        EXPECTED_PINS["ti_sdk_sha"],
        EXPECTED_PINS["ti_examples_sha"],
        EXPECTED_PINS["herdsman_sha"],
        EXPECTED_PINS["koenkk_sha"],
        EXPECTED_PINS["koenkk_patch_blob"],
        EXPECTED_PINS["koenkk_changelog_blob"],
        EXPECTED_PINS["vendor_20260310_sha256"],
        EXPECTED_PINS["vendor_20240710_sha256"],
    }
    return bool(candidates & pinned)


def _check_text(errors, where, name, value, need_anchor):
    """Claim/evidence/verification guard (R4-D05): nonempty TRIMMED
    strings within documented length bounds; evidence additionally needs
    a traceable anchor. Structured values (dict/list), whitespace-only
    strings, and overlong pastes each yield exactly one clean error."""
    if not isinstance(value, str):
        _err(errors, "%s: %s must be a string (got %s)"
              % (where, name, type(value).__name__))
        return
    stripped = value.strip()
    if not stripped:
        _err(errors, "%s: %s must be a non-empty trimmed string" % (where, name))
        return
    if len(stripped) > TEXT_MAX_LEN:
        _err(errors, "%s: %s exceeds %d chars" % (where, name, TEXT_MAX_LEN))
    if need_anchor and not _has_traceable_anchor(stripped):
        _err(errors, "%s: %s must carry a traceable anchor "
                     "(upstream path/blob/commit, issue ref, or URL)"
              % (where, name))


def validate_provenance(doc, allow_fixture=False):
    errors = []
    if not isinstance(doc, dict):
        return ["provenance: top-level object required"]
    _check_top_keys(errors, "provenance", doc, PROVENANCE_TOP_KEYS,
                    ("schema", "phase", "issue", "sdk_version", "donors",
                     "toolchain", "vendor_images", "unknowns"))
    # Phase/issue BEFORE the top-keys early return (issue #85 R4-R6):
    # a shape error must never silently drop the phase/issue lines;
    # both are reported together and the CLI still exits nonzero.
    # Missing/extra keys make deeper checks unsafe, so only that shape
    # class returns early (with the phase/issue lines preserved).
    had_shape_errors = bool(errors)
    _check_phase_issue(errors, "provenance", doc, allow_fixture)
    if had_shape_errors:
        return errors
    if doc.get("schema") != "r4-source-provenance-v1":
        _err(errors, "provenance: unexpected schema %r" % doc.get("schema"))
    sdk_version = doc.get("sdk_version")
    if not isinstance(sdk_version, str):
        _err(errors, "provenance: sdk_version must be a string (got %s)"
              % type(sdk_version).__name__)
    elif sdk_version != EXPECTED_PINS["sdk_version"]:
        _err(errors, "provenance: sdk_version %r mismatch (want %r)"
              % (sdk_version, EXPECTED_PINS["sdk_version"]))
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
    sdk_rel = sdk.get("release") if isinstance(sdk, dict) else None
    ex_rel = examples.get("release") if isinstance(examples, dict) else None
    if (isinstance(sdk_rel, str) and isinstance(ex_rel, str)
            and isinstance(sdk_version, str)
            and (sdk_rel != ex_rel
                 or sdk_rel != EXPECTED_PINS["ti_sdk_release"]
                 or sdk_version not in sdk_rel)):
        # Cross-version consistency: both TI donors must name the same
        # release, and sdk_version must be that release's version. A mixed
        # pair (e.g. 8.33 examples against an 8.32 SDK) fails closed here
        # even when each SHA is individually well-formed. The isinstance
        # gate above keeps non-string releases/sdk_version on the
        # mismatch/type guards instead of raising TypeError here.
        _err(errors, "provenance: donor pair incoherent: sdk release %r vs "
                     "examples release %r vs sdk_version %r (want coherent %s/%s)"
              % (sdk_rel, ex_rel, sdk_version,
                 EXPECTED_PINS["ti_sdk_release"], EXPECTED_PINS["sdk_version"]))
    koenkk = donors.get("koenkk_zstack_firmware")
    if isinstance(koenkk, dict):
        if koenkk.get("identical_to_20260310") is not False:
            _err(errors, "provenance: koenkk donor must state identical_to_20260310=false")
        if koenkk.get("patch") != KOENKK_PATCH_PATH:
            _err(errors, "provenance: koenkk patch path mismatch (want %r)"
                  % KOENKK_PATCH_PATH)
        if koenkk.get("changelog") != KOENKK_CHANGELOG_PATH:
            _err(errors, "provenance: koenkk changelog path mismatch (want %r)"
                  % KOENKK_CHANGELOG_PATH)
        if koenkk.get("commit") != EXPECTED_PINS["koenkk_sha"]:
            _err(errors, "provenance: koenkk commit mismatch (want %s)"
                  % EXPECTED_PINS["koenkk_sha"])
        if not _is_hex40(koenkk.get("commit")):
            _err(errors, "provenance: koenkk commit not 40-hex")
        if koenkk.get("patch_blob") != EXPECTED_PINS["koenkk_patch_blob"]:
            _err(errors, "provenance: koenkk firmware.patch blob mismatch")
        if koenkk.get("changelog_blob") != EXPECTED_PINS["koenkk_changelog_blob"]:
            _err(errors, "provenance: koenkk CHANGELOG.md blob mismatch")
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
        for field in TOOLCHAIN_DOWNLOAD_DIGEST_FIELDS:
            if tc.get(field) != "UNKNOWN":
                _err(errors, "provenance: toolchain %s must be explicitly "
                             "UNKNOWN (unsourced download digest; never fabricated)"
                      % field)
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
    if len(revs) != len(set(revs)):
        _err(errors, "provenance: duplicate vendor rev (each rev must appear once; last-wins shadowing of UNKNOWN is not allowed)")
    for rev in sorted(set(revs)):
        if rev not in EXPECTED_VENDOR_IMAGES:
            _err(errors, "provenance: unexpected vendor rev %r" % (rev,))
    for rev, want in EXPECTED_VENDOR_IMAGES.items():
        img = by_rev.get(rev)
        if img is None:
            _err(errors, "provenance: vendor %s entry missing" % rev)
            continue
        for field in VENDOR_TUPLE_FIELDS:
            if img.get(field) != want[field]:
                _err(errors, "provenance: vendor %s %s mismatch (want %r)"
                      % (rev, field, want[field]))
        # Split formerly carried by the misleading source_unproven
        # boolean: vendor_catalog is the vendor-channel listing status,
        # binary_source_equivalence is binary-to-source proof and must
        # stay UNKNOWN for BOTH images (no equivalence established).
        if img.get("binary_source_equivalence") != "UNKNOWN":
            _err(errors, "provenance: vendor %s binary_source_equivalence "
                         "must stay UNKNOWN (no binary-to-source "
                         "equivalence established)" % rev)
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


def validate_matrix(doc, allow_fixture=False):
    errors = []
    if not isinstance(doc, dict):
        return ["matrix: top-level object required"]
    _check_top_keys(errors, "matrix", doc, MATRIX_TOP_KEYS,
                    ("schema", "phase", "issue", "entries"))
    # Phase/issue BEFORE either early return (issue #85 R4-R6): the
    # entries-shape error is appended to already-accumulated phase/issue
    # lines instead of replacing them, and the top-keys return likewise
    # preserves them. Fail-closed still holds (nonzero exit).
    # Missing/extra keys make deeper checks unsafe, so only that shape
    # class returns early (with the phase/issue lines preserved); other
    # errors accumulate through the entries checks below.
    had_shape_errors = bool(errors)
    _check_phase_issue(errors, "matrix", doc, allow_fixture)
    if had_shape_errors:
        return errors
    if doc.get("schema") != "r4-parity-matrix-v1":
        _err(errors, "matrix: unexpected schema %r" % doc.get("schema"))
    entries = doc.get("entries")
    if not isinstance(entries, list) or not entries:
        _err(errors, "matrix: entries must be a non-empty list")
        return errors
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
        eid = entry.get("id")
        if not isinstance(eid, str) or not eid.strip():
            _err(errors, "%s: id must be a non-empty string" % where)
        else:
            if eid in seen_ids:
                _err(errors, "%s: duplicate id %r" % (where, eid))
            seen_ids.add(eid)
        domain = entry.get("domain")
        if not isinstance(domain, str) or not domain.strip():
            _err(errors, "%s: domain must be a non-empty string" % where)
        else:
            if domain in seen_domains:
                _err(errors, "%s: duplicate domain %r (one entry per domain at R4-00)" % (where, domain))
            seen_domains.add(domain)
        status = entry.get("status")
        # isinstance first: membership of an unhashable status in the
        # allowed set would raise TypeError.
        if not isinstance(status, str) or status not in ALLOWED_STATUS:
            _err(errors, "%s: status %r not permitted at R4-00 (only SOURCE_CONFIRMED/PHYSICAL_UNVERIFIED)" % (where, status))
        _check_text(errors, where, "claim", entry.get("claim"), False)
        _check_text(errors, where, "evidence", entry.get("evidence"), True)
        _check_text(errors, where, "verification", entry.get("verification"), False)
        if status == "SOURCE_CONFIRMED":
            evidence = entry.get("evidence")
            if isinstance(evidence, str) and not (
                    _has_pinned_digest(evidence)
                    and SC_PATH_SEARCH.search(evidence)):
                _err(errors, "%s: SOURCE_CONFIRMED requires an exact upstream "
                             "anchor (repo + commit/blob + path); retag future "
                             "intent as PHYSICAL_UNVERIFIED" % where)
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
    provenance = None
    matrix = None
    try:
        provenance = load_json(prov_path)
    except (OSError, ValueError) as exc:
        errors.append("provenance: unreadable %s (%s)" % (prov_path, exc))
    try:
        matrix = load_json(matrix_path)
    except (OSError, ValueError) as exc:
        errors.append("parity: unreadable %s (%s)" % (matrix_path, exc))
    # Production CLI: fixture phases are never accepted here (explicit
    # allow_fixture=False). Hosted tests pass allow_fixture=True only to
    # the validate_* functions for fixture docs, never to main().
    if provenance is not None:
        errors += ["provenance: " + e
                   for e in validate_provenance(provenance, allow_fixture=False)]
    if matrix is not None:
        errors += ["parity: " + e
                   for e in validate_matrix(matrix, allow_fixture=False)]
    if isinstance(provenance, dict) and isinstance(matrix, dict):
        # Cross-document identity: the pair must identify the same phase
        # and issue. A mixed production/fixture pair fails closed here
        # even if each document were individually consistent. Plain !=
        # comparisons (never set membership) keep array/object phases on
        # the clean-error path instead of raising TypeError.
        if provenance.get("phase") != matrix.get("phase"):
            errors.append("cross: phase mismatch (provenance %r vs parity %r; "
                          "documents must identify the same phase)"
                          % (provenance.get("phase"), matrix.get("phase")))
        if provenance.get("issue") != matrix.get("issue"):
            errors.append("cross: issue mismatch (provenance %r vs parity %r; "
                          "documents must identify the same issue)"
                          % (provenance.get("issue"), matrix.get("issue")))
    if errors:
        sys.stdout.write("\n".join(errors) + "\n")
        return 1
    sys.stdout.write("R4-00 provenance+parity OK\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

