"""R4-B0 overlay validator (offline, stdlib only, never unittest-network).

Validates firmware/slzb-06p7u/r4/b0/B0_DONOR_INVENTORY.json and
B0_BOARD_CONTRACT.json for manifest-consistency against the pinned
R4-B0 literals below. This is manifest-consistency, not external
source-integrity proof; proof lives only in the hosted
`r4-b0-upstream-inventory` CI job, which re-derives every donor
file name against upstream with git ls-tree at the pinned SHAs.

Usage: python b0_overlay_validate.py validate <b0-base-dir>
Exit 0 on OK, 1 on manifest error. Never prints a traceback.
"""
import json
import sys
from collections import Counter
from pathlib import Path

EXPECTED_DONOR_REPOS = {
    "zstack_examples": "TexasInstruments/simplelink-zstack-examples",
    "ti_lowpower_f2_sdk": "TexasInstruments/simplelink-lowpower-f2-sdk",
}

EXPECTED_PINS = {
    "ti_examples_sha": "87ff5b638b632050228a7504f35cf3b95581c278",
    "ti_sdk_sha": "3615ad5d3f4f271258d18a2f5ce1785064ff9a58",
    "ccs": "12.8.0.00012",
    "ti_arm_clang": "3.2.2.LTS",
    "sysconfig": "1.21.1.3772",
}

# Closed allowlist: exact upstream paths verified present with
# `git ls-tree -r FETCH_HEAD` at the pinned SHAs (issue #90).
# Nothing may be added here without a hosted ls-tree re-derivation.
# The linked linker script is the projectspec-linked board .cmd
# (projectspec blob 4d05569e line 566 -> SDK blob 1e5777c2), NOT
# the ancillary source/ti/devices/.../linker_files/cc13x2x7.cmd.
EXPECTED_INVENTORY_PATHS = frozenset([
    "examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec",
    "examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/znp.syscfg",
    "source/ti/zstack/startup/main.c",
    "source/ti/zstack/npi/npi_task.c",
    "source/ti/zstack/mt/mt_sys.c",
    "source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd",
    "source/ti/devices/cc13x2x7_cc26x2x7/startup_files/startup_ticlang.c",
    "cc13xx_cc26xx_sdk",
    "README.md",
])

REPO_FOR_PATH = {
    "examples/": "zstack_examples",
    "cc13xx_cc26xx_sdk": "zstack_examples",
    "README.md": "zstack_examples",
    "source/": "ti_lowpower_f2_sdk",
}

REPO_SHA_KEY = {
    "zstack_examples": "ti_examples_sha",
    "ti_lowpower_f2_sdk": "ti_sdk_sha",
}

ALLOWED_CLAIM_STATUS = ("SOURCE_CONFIRMED", "HARDWARE_OPERATIONALLY_PROVEN", "PHYSICAL_UNVERIFIED", "OPEN")

EXPECTED_UART = {"rx": "DIO12", "tx": "DIO13", "baud": 115200, "flow": "OFF"}

# Reconciliation of the TOOLCHAIN_DOWNLOAD_DIGEST_FIELDS finding
# (issue #90 comment 6213411102): this single canonical constant is
# the validator allowlist; the inventory document records UNKNOWN in
# all three fields (never fabricated digests); hosted proof lives
# only in the `r4-b0-upstream-inventory` CI job (upstream ls-tree
# re-derivation) plus the provision receipt. UNKNOWN here is an
# explicitly recorded gap, never a pass.
TOOLCHAIN_DOWNLOAD_DIGEST_FIELDS = (
    "ccs_download_sha256",
    "ti_arm_clang_download_sha256",
    "sysconfig_download_sha256",
)


def loads_strict(text):
    """JSON parse that rejects duplicate object keys."""
    def reject_dupes(pairs):
        keys = [key for key, _ in pairs]
        dupes = [key for key, count in Counter(keys).items() if count > 1]
        if dupes:
            raise ValueError("duplicate key: %s" % sorted(dupes)[0])
        return dict(pairs)
    return json.loads(text, object_pairs_hook=reject_dupes)


def _is_hex40(value):
    return (isinstance(value, str) and len(value) == 40
            and all(c in "0123456789abcdef" for c in value))


def _repo_for(path):
    for prefix, repo in REPO_FOR_PATH.items():
        if path == prefix or path.startswith(prefix):
            return repo
    return None


def validate_inventory(doc):
    """Returns a list of error strings (empty means OK)."""
    errors = []
    if not isinstance(doc, dict):
        return ["inventory must be an object"]
    for key in ("schema", "phase", "issue", "donor_files", "toolchain"):
        if key not in doc:
            errors.append("inventory missing key: %s" % key)
    if errors:
        return errors
    if doc["schema"] != "r4-b0-donor-inventory-v1":
        errors.append("inventory schema mismatch")
    if doc["phase"] != "R4-B0":
        errors.append("inventory phase must be R4-B0")
    if doc["issue"] != 90:
        errors.append("inventory issue must be 90")
    tool = doc["toolchain"]
    if not isinstance(tool, dict):
        return errors + ["inventory toolchain must be an object"]
    for field, pin in (("ccs", "ccs"), ("ti_arm_clang", "ti_arm_clang"),
                       ("sysconfig", "sysconfig")):
        if tool.get(field) != EXPECTED_PINS[pin]:
            errors.append("inventory toolchain %s mismatch" % field)
    for field in TOOLCHAIN_DOWNLOAD_DIGEST_FIELDS:
        expected = {
            "ccs_download_sha256": "fa807c9ea3bc8a558c4c9bef64c37261c1146d0b9da96ae7867e1b5e3046e06d",
            "sysconfig_download_sha256": "0c1674f82a53b187f60e376de3da2b719f003187c7437998c2ce3f975504d1d5",
            "ti_arm_clang_download_sha256": "2864bb1013ec60b1290f92ff723a4fc222653db1278c08ad81af6063f698dec9",
        }[field]
        if tool.get(field) != expected:
            errors.append("inventory toolchain %s must match TI-published SHA-256" % field)
    files = doc["donor_files"]
    if not isinstance(files, list) or not files:
        return errors + ["inventory donor_files must be a nonempty list"]
    seen = set()
    for entry in files:
        if not isinstance(entry, dict):
            errors.append("inventory entry must be an object")
            continue
        for key in ("repo", "sha", "path", "kind", "status", "evidence"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                errors.append("inventory entry missing/nonempty key: %s" % key)
        path = entry.get("path")
        if not isinstance(path, str):
            continue
        if path in seen:
            errors.append("inventory duplicate path: %s" % path)
        seen.add(path)
        if path not in EXPECTED_INVENTORY_PATHS:
            errors.append("inventory path not upstream-verified: %s" % path)
        repo_key = _repo_for(path)
        if repo_key is None:
            errors.append("inventory path has no donor repo: %s" % path)
            continue
        if entry.get("repo") != EXPECTED_DONOR_REPOS[repo_key]:
            errors.append("inventory repo mismatch for %s" % path)
        if entry.get("sha") != EXPECTED_PINS[REPO_SHA_KEY[repo_key]]:
            errors.append("inventory sha mismatch for %s" % path)
        if not _is_hex40(entry.get("sha", "")):
            errors.append("inventory sha not 40-hex for %s" % path)
        if entry.get("status") not in ("SOURCE_CONFIRMED", "OPEN"):
            errors.append("inventory bad status for %s" % path)
    if set(seen) != set(EXPECTED_INVENTORY_PATHS):
        errors.append("inventory must list exactly the verified donor set (missing=%s extra=%s)"
                      % (sorted(set(EXPECTED_INVENTORY_PATHS) - seen),
                         sorted(seen - set(EXPECTED_INVENTORY_PATHS))))
    for bad in doc.get("forbidden_statuses", []):
        joined = json.dumps(files)
        if bad in joined:
            errors.append("inventory claims forbidden status: %s" % bad)
    return errors


def validate_board(doc):
    """Returns a list of error strings (empty means OK)."""
    errors = []
    if not isinstance(doc, dict):
        return ["board contract must be an object"]
    for key in ("schema", "phase", "issue", "claims", "open_items"):
        if key not in doc:
            errors.append("board contract missing key: %s" % key)
    if errors:
        return errors
    if doc["schema"] != "r4-b0-board-contract-v1":
        errors.append("board contract schema mismatch")
    if doc["phase"] != "R4-B0":
        errors.append("board contract phase must be R4-B0")
    if doc["issue"] != 90:
        errors.append("board contract issue must be 90")
    claims = doc["claims"]
    if not isinstance(claims, list) or not claims:
        return errors + ["board contract claims must be a nonempty list"]
    by_id = {}
    for claim in claims:
        if not isinstance(claim, dict):
            errors.append("board claim must be an object")
            continue
        cid = claim.get("id")
        if not isinstance(cid, str) or not cid.strip():
            errors.append("board claim id must be a nonempty string")
            continue
        if cid in by_id:
            errors.append("board duplicate claim id: %s" % cid)
        by_id[cid] = claim
        if claim.get("status") not in ALLOWED_CLAIM_STATUS:
            errors.append("board claim bad status: %s" % cid)
    for cid, want in (("uart-rx", EXPECTED_UART["rx"]),
                      ("uart-tx", EXPECTED_UART["tx"]),
                      ("uart-baud", EXPECTED_UART["baud"]),
                      ("uart-flow", EXPECTED_UART["flow"])):
        got = by_id.get(cid, {}).get("value")
        if got != want:
            errors.append("board %s must be %r" % (cid, want))
    # Historical fitted P7U facts have been proven, not merely
    # conjectured. R2 ELF UART pinmux matched vendor 20240710, and
    # the original board answered stock ZNP across its USB bridge.
    # These checks never qualify the newly compiled R4 image.
    for cid in ("uart-rx", "uart-tx", "uart-baud", "uart-flow", "target-part"):
        claim = by_id.get(cid, {})
        if claim.get("status") != "HARDWARE_OPERATIONALLY_PROVEN":
            errors.append("board %s must be HARDWARE_OPERATIONALLY_PROVEN per issue #80" % cid)
        if "6198198498" not in str(claim.get("evidence", "")) and cid != "target-part":
            errors.append("board %s lacks actual UART source evidence #80/6198198498" % cid)
    if doc.get("board", {}).get("status") != "HARDWARE_OPERATIONALLY_PROVEN":
        errors.append("fitted P7U board identity evidence not acknowledged")
    hardware = doc.get("hardware_evidence", {})
    if not isinstance(hardware, dict) or hardware.get("status") != "HARDWARE_OPERATIONALLY_PROVEN":
        errors.append("board historical hardware evidence missing")
    else:
        ref = hardware.get("manufacturer_esp_board_def", {})
        if not isinstance(ref, dict) or any(ref.get(k) != v for k, v in (
            ("repo", "smlight-tech/slzb-esphome"),
            ("commit", "3397f6ffe7b0a58cf1546c8293bfa644235a9769"),
            ("esp_tx_to_radio_rx", "GPIO17 -> radio DIO12"),
            ("radio_tx_to_esp_rx", "radio DIO13 -> GPIO18")
        )):
            errors.append("SMLIGHT fitted board UART evidence pin mismatch")
    vendor = doc.get("vendor_20240710_ccfg", {})
    if not isinstance(vendor, dict) or (vendor.get("vendor_digest_sha256") !=
            "1defedbd2f474ee8b7385476801a63de95f55c3dd51115e29f97c69196049af7"
            or vendor.get("syscfg_override") != "device.enableDCDC = false;"):
        errors.append("vendor 20240710 CCFG DC/DC evidence mismatch")
    image = doc.get("r4_image", {})
    if not isinstance(image, dict) or image.get("status") != "R4_IMAGE_UNVERIFIED":
        errors.append("new R4 image must remain explicitly UNVERIFIED")
    elif image.get("flash_authorized") is not False:
        errors.append("new R4 image must not authorize flash")
    if by_id.get("nv-pages", {}).get("value") != 2:
        errors.append("board nv-pages must be 2 (donor NVOCMP_NVPAGES=2)")
    if not isinstance(doc.get("open_items"), list) or len(doc["open_items"]) < 4:
        errors.append("board open_items must list at least the four known gaps")
    else:
        for item in doc["open_items"]:
            if not isinstance(item, str) or not item.strip():
                errors.append("board open_items entries must be nonempty strings")
                break
    abi = doc.get("abi", {})
    for cmd in ("SYS_PING", "SYS_VERSION"):
        if cmd not in json.dumps(abi):
            errors.append("board abi must retain %s" % cmd)
    if abi.get("extra_serial_owner") is not False:
        errors.append("board abi must keep single NPI owner (extra_serial_owner=false)")
    return errors


def validate_pair(base):
    """Validate both B0 overlay documents under base. Returns errors."""
    errors = []
    try:
        inv_text = (base / "B0_DONOR_INVENTORY.json").read_text(encoding="utf-8")
        board_text = (base / "B0_BOARD_CONTRACT.json").read_text(encoding="utf-8")
    except OSError as exc:
        return ["unreadable B0 overlay document (%s)" % exc]
    try:
        inv = loads_strict(inv_text)
    except ValueError as exc:
        return ["inventory JSON error (%s)" % exc]
    try:
        board = loads_strict(board_text)
    except ValueError as exc:
        return ["board contract JSON error (%s)" % exc]
    return validate_inventory(inv) + validate_board(board)


def main(argv):
    # argv follows the repo test convention: argv[0] is the command
    # (callers pass sys.argv[1:]); `if __name__` strips the prog name.
    try:
        if len(argv) != 2 or argv[0] != "validate":
            print("usage: b0_overlay_validate.py validate <b0-base-dir>")
            return 2
        errors = validate_pair(Path(argv[1]))
    except Exception as exc:  # noqa: BLE001 -- fail closed, never traceback
        print("b0 overlay error (%s)" % exc)
        return 1
    if errors:
        print("b0 overlay invalid: %s" % errors[0])
        return 1
    print("R4-B0 overlay OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
