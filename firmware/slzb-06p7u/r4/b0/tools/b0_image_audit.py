"""R4-B0 image/map/CCFG/NV/ISR-stack audit (offline, stdlib only).

Audits a native-build artifacts directory produced by the hosted
CCS build: a manifest binding logical artifacts (elf/map/hex/bin)
to SHA256 digests, the CCS build log (must show a real SysConfig +
linker + objcopy pipeline, never a bare `echo pass`), and a linker
map excerpt carrying MEMORY regions, C/IRQ stack size, CCFG and
vector markers.

Usage:
  python b0_image_audit.py audit <b0-base-dir> --artifacts <dir>

Exit 0 audit OK, 1 audit mismatch, 2 BLOCKED (no artifacts: native
toolchain unprovisioned, no binary claim). Never prints a traceback.
"""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

REQUIRED_LOGICALS = ("elf", "map", "hex", "bin")

# Build-log evidence markers: a genuine CCS headless build leaves all
# three. A log with none of them (e.g. a bare `echo pass` workflow)
# is rejected as `no actual linker invocation`.
LOG_MARKERS = {
    "syscfg generation": "syscfg",
    "linker invocation": "tiarmclang",
    "hex emission": "tiarmobjcopy",
}

DONOR_NVS_BASE = 0xAA000
DONOR_NVS_SIZE = 0x4000
DONOR_CSTACK = 1024


def loads_strict(text):
    def reject_dupes(pairs):
        keys = [key for key, _ in pairs]
        dupes = [key for key, count in Counter(keys).items() if count > 1]
        if dupes:
            raise ValueError("duplicate key: %s" % sorted(dupes)[0])
        return dict(pairs)
    return json.loads(text, object_pairs_hook=reject_dupes)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_map(text):
    """Parse the minimal map excerpt format.

    Lines: `REGION <name> <base_hex> <size_hex>`,
    `CSTACK <size_dec>`, `VECTORS <base_hex>`.
    Returns (regions, cstack, vectors, errors).
    """
    regions = {}
    cstack = None
    vectors = None
    errors = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "REGION" and len(parts) == 4:
            try:
                regions[parts[1]] = (int(parts[2], 16), int(parts[3], 16))
            except ValueError:
                errors.append("map line %d malformed region" % lineno)
        elif parts[0] == "CSTACK" and len(parts) == 2:
            try:
                cstack = int(parts[1], 10)
            except ValueError:
                errors.append("map line %d malformed CSTACK" % lineno)
        elif parts[0] == "VECTORS" and len(parts) == 2:
            try:
                vectors = int(parts[1], 16)
            except ValueError:
                errors.append("map line %d malformed VECTORS" % lineno)
        else:
            errors.append("map line %d unrecognized" % lineno)
    return regions, cstack, vectors, errors


def audit(base, artifacts):
    """Returns (exit_code, message). Never raises."""
    try:
        manifest_text = (artifacts / "manifest.json").read_text(encoding="utf-8")
    except OSError:
        return 2, ("B0-AUDIT-BLOCKED: no native build artifacts "
                   "(toolchain unprovisioned; no binary claim)")
    try:
        manifest = loads_strict(manifest_text)
    except ValueError as exc:
        return 1, "audit manifest JSON error (%s)" % exc
    if not isinstance(manifest, dict):
        return 1, "audit manifest must be an object"
    if manifest.get("schema") != "r4-b0-artifact-manifest-v1":
        return 1, "audit manifest schema mismatch"
    files = manifest.get("files")
    if not isinstance(files, dict):
        return 1, "audit manifest files must be an object"
    for logical in REQUIRED_LOGICALS:
        entry = files.get(logical)
        if not isinstance(entry, dict):
            return 1, "audit manifest missing logical artifact: %s" % logical
        name = entry.get("file")
        want = entry.get("sha256")
        if not isinstance(name, str) or not name.strip():
            return 1, "audit manifest %s has no file name" % logical
        if (not isinstance(want, str) or len(want) != 64
                or any(c not in "0123456789abcdef" for c in want)):
            return 1, "audit manifest %s has no 64-hex sha256" % logical
        target = artifacts / name
        if not target.is_file():
            return 1, "audit artifact missing on disk: %s" % name
        try:
            got = _sha256(target)
        except OSError as exc:
            return 1, "audit artifact unreadable: %s (%s)" % (name, exc)
        if got != want:
            return 1, "audit sha256 mismatch for %s" % logical
    log_name = manifest.get("build_log")
    if not isinstance(log_name, str) or not (artifacts / log_name).is_file():
        return 1, "audit build log missing (no actual linker invocation)"
    try:
        log_text = (artifacts / log_name).read_text(encoding="utf-8",
                                                   errors="replace")
    except OSError as exc:
        return 1, "audit build log unreadable (%s)" % exc
    lowered = log_text.lower()
    for label, marker in LOG_MARKERS.items():
        if marker not in lowered:
            return 1, ("audit no actual linker invocation "
                       "(build log lacks %s)" % label)
    map_name = files["map"]["file"]
    try:
        map_text = (artifacts / map_name).read_text(encoding="utf-8",
                                                   errors="replace")
    except OSError as exc:
        return 1, "audit map unreadable (%s)" % exc
    regions, cstack, vectors, map_errors = _parse_map(map_text)
    if map_errors:
        return 1, "audit map error: %s" % map_errors[0]
    if vectors is None:
        return 1, "audit missing .cmd/vector table marker"
    if "CCFG" not in regions:
        return 1, "audit missing CCFG region (invalid ELF/map symbols)"
    if "NVS" not in regions:
        return 1, "audit missing NVS region"
    nvs_base, nvs_size = regions["NVS"]
    if nvs_base != DONOR_NVS_BASE or nvs_size != DONOR_NVS_SIZE:
        return 1, ("audit NVS geometry differs from donor "
                   "(want base 0xAA000 size 0x4000)")
    ccfg_base, ccfg_size = regions["CCFG"]
    nvs_end = nvs_base + nvs_size
    ccfg_end = ccfg_base + ccfg_size
    if nvs_base < ccfg_end and ccfg_base < nvs_end:
        return 1, "audit NV/CCFG overlap"
    if cstack is None:
        return 1, "audit missing C/IRQ stack size"
    if cstack != DONOR_CSTACK:
        return 1, ("audit wrong C/IRQ stack expectation "
                   "(want donor 1024; 4096 needs native map proof)")
    return 0, "R4-B0 image audit OK"


def main(argv):
    # argv follows the repo test convention: argv[0] is the command
    # (callers pass sys.argv[1:]); `if __name__` strips the prog name.
    try:
        if (len(argv) != 4 or argv[0] != "audit"
                or argv[2] != "--artifacts"):
            print("usage: b0_image_audit.py audit <b0-base-dir> "
                  "--artifacts <dir>")
            return 2
        code, message = audit(Path(argv[1]), Path(argv[3]))
    except Exception as exc:  # noqa: BLE001 -- fail closed, never traceback
        print("b0 audit error (%s)" % exc)
        return 1
    print(message)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
