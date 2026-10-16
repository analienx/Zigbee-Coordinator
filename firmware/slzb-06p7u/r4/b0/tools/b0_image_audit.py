"""R4-B0 image audit: genuine TI linker XML + ELF cross-check (offline, stdlib only).

Audits a native-build artifacts directory produced by the hosted
CCS build: a manifest binding logical artifacts (elf/xml/hex/bin)
to SHA256 digests, the CCS build log (must show a real SysConfig +
headless CCS projectBuild + tiarmclang --xml_link_info + objcopy
pipeline, never a bare `echo pass`), the genuine TI-ARM-CLANG
3.2.2 `--xml_link_info` XML document, and an actual ELF cross-check.

Authoritative memory layout comes from the pinned TI objects
(issue #90 comments 6213312663 / 6213411102 / 6213447363):
  projectspec blob 4d05569e (device Cortex M.CC1352P7, cgt 3.2.2)
  links source/ti/zstack/boards/cc13x2x7_cc26x2x7/
  cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd, SDK blob 1e5777c2, which
  declares FLASH app 0x00000..0xA9FFF, FLASH_NV 0xAA000..0xADFFF,
  FLASH_LAST 0xAE000..0xAFFFF, `.ccfg` section mapped into
  FLASH_LAST at HIGH, `.resetVecs`, and `--stack_size=1024`.

The invented REGION/CSTACK/VECTORS text summary format is
explicitly REJECTED as synthetic. Any partial/fake XML or fake
ELF fails closed. Exit 0 audit OK, 1 audit mismatch, 2 BLOCKED
(no artifacts: native toolchain unprovisioned, no binary claim).
Never prints a traceback.
"""
import hashlib
import json
import re
import struct
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

REQUIRED_LOGICALS = ("elf", "xml", "hex", "bin")

# Build-log evidence markers: a genuine CCS headless build leaves all
# of them, including the exact headless application id and the XML
# evidence channel flag. A log with any missing (e.g. a bare
# `echo pass` workflow) is rejected as `no actual linker invocation`.
LOG_MARKERS = {
    "CCS headless projectBuild": "com.ti.ccstudio.apps.projectbuild",
    "linker invocation": "tiarmclang",
    "XML link info channel": "--xml_link_info",
    "hex emission": "tiarmobjcopy",
    "syscfg generation": "syscfg",
}

# Donor geometry from the genuine linked .cmd (SDK blob 1e5777c2).
DONOR_NVS_BASE = 0xAA000
DONOR_NVS_SIZE = 0x4000
DONOR_FLASH_LAST_BASE = 0xAE000
DONOR_CSTACK = 1024

XML_SIZE_CAP = 2 * 1024 * 1024

_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


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


def _safe_artifact(artifacts, name):
    """Resolve a manifest file name strictly inside artifacts.

    Returns (Path, error). Rejects absolute paths, separators,
    dot-segments and names outside the artifact directory.
    """
    if not isinstance(name, str) or not name or len(name) > 128:
        return None, "audit artifact name is not a safe basename"
    if "/" in name or "\\" in name or name not in (Path(name).name,):
        return None, "audit artifact path traversal rejected"
    if not _SAFE_NAME.fullmatch(name) or name in (".", ".."):
        return None, "audit artifact path traversal rejected"
    if name.startswith("."):
        return None, "audit artifact path traversal rejected"
    target = artifacts / name
    try:
        resolved = target.resolve()
        base = artifacts.resolve()
    except OSError as exc:
        return None, "audit artifact unreadable: %s (%s)" % (name, exc)
    if resolved != base / name:
        return None, "audit artifact path traversal rejected"
    return target, None


def _parse_elf(path):
    """Minimal ELF cross-check. Returns (entry, error).

    Verifies ELF magic, 32/64-bit little-endian ARM executable and
    returns the entry address. Anything else fails closed.
    """
    try:
        with open(path, "rb") as handle:
            header = handle.read(64)
    except OSError as exc:
        return None, "audit ELF unreadable (%s)" % exc
    if len(header) < 52 or header[:4] != b"\x7fELF":
        return None, "audit invalid ELF (bad magic; fake ELF rejected)"
    ei_class, ei_data = header[4], header[5]
    if ei_class not in (1, 2) or ei_data != 1:
        return None, "audit invalid ELF (not 32/64-bit little-endian)"
    e_machine = struct.unpack_from("<H", header, 18)[0]
    if e_machine != 40:
        return None, "audit invalid ELF (machine is not ARM; fake ELF rejected)"
    if ei_class == 1:
        if len(header) < 28:
            return None, "audit invalid ELF (truncated header)"
        entry = struct.unpack_from("<I", header, 24)[0]
    else:
        entry = struct.unpack_from("<Q", header, 24)[0]
    return entry, None


def _int_maybe(text):
    text = (text or "").strip()
    try:
        return int(text, 0)
    except ValueError:
        return None


def _parse_link_xml(text, elf_name, elf_entry):
    """Validate the genuine TI --xml_link_info document.

    Returns an error string or None on OK. Checks root/banner/
    output/entry/placement/logical-group geometry against the
    donor .cmd facts, plus ELF entry agreement.
    """
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return "audit XML uses a forbidden DTD/entity declaration"
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return "audit XML parse error (%s)" % exc
    if root.tag != "link_info":
        return ("audit XML is not a TI link_info document "
                "(synthetic summary rejected)")
    banner = root.findtext("banner") or ""
    if "3.2.2" not in banner:
        return "audit XML banner lacks TI-ARM-CLANG 3.2.2"
    output = (root.findtext("output_file") or "").strip()
    if Path(output).name != elf_name:
        return "audit XML output_file does not match the audited ELF"
    entry_text = ""
    entry_node = root.find("entry_point")
    if entry_node is not None:
        entry_text = (entry_node.findtext("address") or "").strip()
    entry = _int_maybe(entry_text)
    if entry is None:
        return "audit XML missing entry_point address"
    if entry != elf_entry:
        return "audit XML entry_point disagrees with ELF e_entry"
    areas = {}
    for area in root.findall("./placement_map/memory_area"):
        name = (area.findtext("name") or "").strip()
        origin = _int_maybe(area.findtext("origin"))
        length = _int_maybe(area.findtext("length"))
        if not name or origin is None or length is None:
            return "audit XML memory_area malformed"
        areas[name] = (origin, length)
    for need in ("FLASH", "FLASH_NV", "FLASH_LAST", "SRAM"):
        if need not in areas:
            return "audit XML missing %s memory area" % need
    nvs_base, nvs_size = areas["FLASH_NV"]
    if nvs_base != DONOR_NVS_BASE or nvs_size != DONOR_NVS_SIZE:
        return ("audit NVS geometry differs from donor "
                "(want base 0xAA000 size 0x4000)")
    fl_base, fl_len = areas["FLASH_LAST"]
    if fl_base != DONOR_FLASH_LAST_BASE:
        return "audit FLASH_LAST base differs from donor (want 0xAE000)"
    nvs_end = nvs_base + nvs_size
    fl_end = fl_base + fl_len
    if nvs_base < fl_end and fl_base < nvs_end:
        return "audit NV/CCFG overlap"
    sections = {}
    for section in root.findall("./logical_group_list//section"):
        name = ((section.findtext("name") or "").strip()
                or (section.get("name") or "").strip())
        load = _int_maybe(section.findtext("load_address")
                           or section.get("load_address"))
        size = _int_maybe(section.findtext("size") or section.get("size"))
        if name:
            sections[name] = (load, size)
    if ".resetVecs" not in sections:
        return "audit missing .resetVecs/vector table marker"
    ccfg = sections.get(".ccfg")
    if ccfg is None:
        return "audit missing CCFG section (invalid ELF/map symbols)"
    ccfg_load, ccfg_size = ccfg
    if ccfg_load is None or ccfg_size is None:
        return "audit CCFG section lacks load address/size"
    if nvs_base < ccfg_load + ccfg_size and ccfg_load < nvs_end:
        return "audit NV/CCFG overlap"
    if not (fl_base <= ccfg_load
            and ccfg_load + ccfg_size <= fl_end):
        return "audit CCFG not mapped into FLASH_LAST at HIGH"
    stack_size = None
    stack = sections.get(".stack")
    if stack is not None and stack[1] is not None:
        stack_size = stack[1]
    if stack_size is None:
        for symbol in root.findall("./logical_group_list//symbol"):
            sname = ((symbol.findtext("name") or "").strip()
                     or (symbol.get("name") or "").strip())
            if sname in ("__STACK_SIZE", "__stack_size", "C_STACK_SIZE"):
                stack_size = _int_maybe(symbol.findtext("value")
                                        or symbol.get("value"))
                break
    if stack_size is None:
        return "audit missing C/IRQ stack size"
    if stack_size != DONOR_CSTACK:
        return ("audit wrong C/IRQ stack expectation "
                "(want donor 1024; 4096 needs native map proof)")
    return None


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
    if "map" in str(manifest.get("files", {}).keys()) and "xml" not in manifest.get("files", {}):
        return 1, ("audit synthetic map format rejected "
                   "(require TI --xml_link_info XML + ELF cross-check)")
    files = manifest.get("files")
    if not isinstance(files, dict):
        return 1, "audit manifest files must be an object"
    targets = {}
    for logical in REQUIRED_LOGICALS:
        entry = files.get(logical)
        if not isinstance(entry, dict):
            return 1, "audit manifest missing logical artifact: %s" % logical
        name = entry.get("file")
        want = entry.get("sha256")
        target, err = _safe_artifact(artifacts, name)
        if err:
            return 1, err
        if (not isinstance(want, str) or len(want) != 64
                or any(c not in "0123456789abcdef" for c in want)):
            return 1, "audit manifest %s has no 64-hex sha256" % logical
        if not target.is_file():
            return 1, "audit artifact missing on disk: %s" % name
        try:
            got = _sha256(target)
        except OSError as exc:
            return 1, "audit artifact unreadable: %s (%s)" % (name, exc)
        if got != want:
            return 1, "audit sha256 mismatch for %s" % logical
        targets[logical] = target
    log_name = manifest.get("build_log")
    log_target, err = _safe_artifact(artifacts, log_name)
    if err or not log_target.is_file():
        return 1, "audit build log missing (no actual linker invocation)"
    try:
        log_text = log_target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return 1, "audit build log unreadable (%s)" % exc
    lowered = log_text.lower()
    for label, marker in LOG_MARKERS.items():
        if marker not in lowered:
            return 1, ("audit no actual linker invocation "
                       "(build log lacks %s)" % label)
    try:
        if targets["xml"].stat().st_size > XML_SIZE_CAP:
            return 1, "audit XML exceeds size cap (synthetic summary rejected)"
        xml_text = targets["xml"].read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return 1, "audit XML unreadable (%s)" % exc
    if "REGION " in xml_text and "CSTACK " in xml_text:
        return 1, ("audit synthetic map format rejected "
                   "(require TI --xml_link_info XML + ELF cross-check)")
    elf_entry, err = _parse_elf(targets["elf"])
    if err:
        return 1, err
    err = _parse_link_xml(xml_text, targets["elf"].name, elf_entry)
    if err:
        return 1, err
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
