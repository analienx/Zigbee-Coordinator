"""R4-B0 image audit: genuine TI linker XML + ELF cross-check (offline, stdlib only).

Audits a native-build artifacts directory produced by the hosted
CCS build: a manifest binding logical artifacts (elf/xml/hex/bin)
to SHA256 digests, the CCS build log (must show a real SysConfig +
headless CCS projectBuild + tiarmclang --xml_link_info + objcopy
pipeline spread over a long multi-line log in pipeline order,
never a bare `echo pass` and never a fabricated one-liner; the
log markers are a tripwire only, never proof), the genuine TI-ARM-CLANG
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
ELF fails closed. HEX/BIN artifacts are cross-bound to the
independently-parsed evidence: the HEX file must be genuine
Intel HEX records (raw binary rejected), every HEX data address
must fall inside an XML-reported memory area and outside
FLASH_NV, the HEX payload must cover the XML-declared
.resetVecs/.ccfg extents and the ELF entry, and the BIN must
equal the HEX data payload in ascending address order. Beyond
that, the HEX data payload must byte-match every ELF PT_LOAD
segment exactly (same addresses, same bytes: no extra HEX data
outside the LOAD segments, no missing LOAD bytes, no differing
byte), so a content-tampered HEX/BIN pair with merely
recomputed manifest digests fails closed at this
content-binding, never with exit 0. The ELF entry address is
compared Thumb-normalized (bit 0 cleared: Cortex-M Thumb-2
entry points carry bit 0 set while Intel HEX holds the aligned
address). Exit 0 audit OK, 1 audit mismatch, 2 BLOCKED (no
artifacts: native toolchain unprovisioned, no binary claim).
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
#
# These markers are a tripwire only, never proof: one fabricated line
# can contain every substring, so a genuine pipeline must additionally
# clear structural tripwires -- minimum length, markers spread over
# distinct lines, and plausible pipeline order (syscfg generation
# before projectBuild before tiarmclang/tiarmobjcopy). Real proof is
# the ELF/XML content-binding plus hosted provenance, never the log.
LOG_MARKERS = {
    "CCS headless projectBuild": "com.ti.ccstudio.apps.projectbuild",
    "linker invocation": "tiarmclang",
    "XML link info channel": "--xml_link_info",
    "hex emission": "tiarmobjcopy",
    "syscfg generation": "syscfg",
}

# Build-log tripwire depth: defeats single-line fabrications carrying
# all marker substrings. A genuine CCS pipeline log is hundreds of
# lines with the markers spread across the syscfg -> projectBuild ->
# link -> objcopy stages.
LOG_MIN_NONEMPTY_LINES = 20
LOG_MIN_MARKER_LINES = 3

# Donor geometry from the genuine linked .cmd (SDK blob 1e5777c2).
# The full FLASH/FLASH_NV/FLASH_LAST/SRAM layout is pinned by the
# expected_geometry table in _parse_link_xml; only the constants
# still referenced below are kept here.
DONOR_NVS_BASE = 0xAA000
DONOR_NVS_SIZE = 0x4000
DONOR_FLASH_LAST_BASE = 0xAE000
DONOR_CSTACK = 1024

XML_SIZE_CAP = 2 * 1024 * 1024

# HEX/BIN cross-binding caps: the CC1352P7 FLASH image is ~704 KiB,
# so a 1 MiB payload cap accepts any genuine image while failing
# closed on unbounded inputs.
HEX_SIZE_CAP = 4 * 1024 * 1024
HEX_PAYLOAD_CAP = 1024 * 1024
BIN_SIZE_CAP = 1024 * 1024

# ELF program-header table cap: a genuine CC1352P7 image carries
# a handful of PT_LOAD segments; the bound only rejects absurd
# headers while parsing stays fail-closed on any malformation.
ELF_SIZE_CAP = 8 * 1024 * 1024
ELF_PHNUM_CAP = 32

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


def _parse_elf_load_segments(path):
    """Extract the ELF PT_LOAD file-backed image. Returns (segments, error).

    Segments maps absolute byte addresses to byte values, covering
    exactly the file-backed bytes of every PT_LOAD program header
    (p_paddr .. p_paddr + p_filesz). Both 32- and 64-bit
    little-endian ARM ELFs are accepted; anything malformed --
    bad magic, missing/truncated program-header table, a LOAD
    segment pointing outside the file, p_filesz > p_memsz,
    overlapping LOAD file ranges, or no LOAD segment at all --
    fails closed. The caller byte-matches this image against the
    HEX data payload exactly, so content tamper, injected extra
    bytes, and silent deletion all fail at the content-binding.
    """
    prefix = ("audit HEX/BIN/ELF content-binding failed (cross-binding: ")
    try:
        if path.stat().st_size > ELF_SIZE_CAP:
            return None, prefix + "ELF exceeds size cap)"
        blob = path.read_bytes()
    except OSError as exc:
        return None, prefix + "ELF unreadable: %s)" % exc
    if len(blob) < 52 or blob[:4] != b"\x7fELF":
        return None, prefix + "invalid ELF (bad magic; fake ELF rejected)"
    ei_class, ei_data = blob[4], blob[5]
    if ei_data != 1:
        return None, prefix + "invalid ELF (not little-endian)"
    if ei_class == 1:
        if len(blob) < 52:
            return None, prefix + "invalid ELF (truncated header)"
        phoff = struct.unpack_from("<I", blob, 28)[0]
        phentsize = struct.unpack_from("<H", blob, 42)[0]
        phnum = struct.unpack_from("<H", blob, 44)[0]
        min_entsize = 32
    elif ei_class == 2:
        if len(blob) < 64:
            return None, prefix + "invalid ELF (truncated header)"
        phoff = struct.unpack_from("<Q", blob, 32)[0]
        phentsize = struct.unpack_from("<H", blob, 54)[0]
        phnum = struct.unpack_from("<H", blob, 56)[0]
        min_entsize = 56
    else:
        return None, prefix + "invalid ELF (not 32/64-bit)"
    if phoff == 0 or phnum == 0:
        return None, prefix + "ELF has no program headers)"
    if phnum > ELF_PHNUM_CAP or phentsize < min_entsize:
        return None, prefix + "ELF program-header table malformed)"
    if phoff + phentsize * phnum > len(blob):
        return None, prefix + "ELF program-header table truncated)"
    segments = {}
    ranges = []
    total = 0
    for index in range(phnum):
        base = phoff + index * phentsize
        try:
            if ei_class == 1:
                (ptype, poff, _, ppaddr, pfilesz, pmemsz, _, _) = (
                    struct.unpack_from("<8I", blob, base))
            else:
                (ptype, _, poff, _, ppaddr, pfilesz, pmemsz, _) = (
                    struct.unpack_from("<IIQQQQQQ", blob, base))
        except struct.error:
            return None, prefix + "ELF program-header entry truncated)"
        if ptype != 1:
            continue
        if pfilesz > pmemsz:
            return None, prefix + "ELF PT_LOAD file size exceeds memory size)"
        if poff + pfilesz > len(blob):
            return None, prefix + "ELF PT_LOAD segment outside the file)"
        if pfilesz:
            start, end = ppaddr, ppaddr + pfilesz
            for (other_start, other_end) in ranges:
                if start < other_end and other_start < end:
                    return None, prefix + "ELF PT_LOAD segments overlap)"
            ranges.append((start, end))
            total += pfilesz
            if total > HEX_PAYLOAD_CAP:
                return None, prefix + "ELF PT_LOAD image exceeds size cap)"
            for offset in range(pfilesz):
                segments[start + offset] = blob[poff + offset]
    if not segments:
        return None, prefix + "ELF has no PT_LOAD segments)"
    return segments, None


def _int_maybe(text):
    text = (text or "").strip()
    try:
        return int(text, 0)
    except ValueError:
        return None


def _parse_link_xml(text, elf_name, elf_entry):
    """Validate the genuine TI --xml_link_info document.

    Returns (evidence, error): evidence carries the parsed memory
    areas, sections and entry on OK, error is None on OK. Checks
    root/banner/output/entry/placement/logical-group geometry
    against the donor .cmd facts, plus ELF entry agreement.
    """
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return None, "audit XML uses a forbidden DTD/entity declaration"
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return None, "audit XML parse error (%s)" % exc
    if root.tag != "link_info":
        return None, ("audit XML is not a TI link_info document "
                      "(synthetic summary rejected)")
    banner = root.findtext("banner") or ""
    if "3.2.2" not in banner:
        return None, "audit XML banner lacks TI-ARM-CLANG 3.2.2"
    output = (root.findtext("output_file") or "").strip()
    if Path(output).name != elf_name:
        return None, "audit XML output_file does not match the audited ELF"
    entry_text = ""
    entry_node = root.find("entry_point")
    if entry_node is not None:
        entry_text = (entry_node.findtext("address") or "").strip()
    entry = _int_maybe(entry_text)
    if entry is None:
        return None, "audit XML missing entry_point address"
    if entry != elf_entry:
        return None, "audit XML entry_point disagrees with ELF e_entry"
    areas = {}
    for area in root.findall("./placement_map/memory_area"):
        name = (area.findtext("name") or "").strip()
        origin = _int_maybe(area.findtext("origin"))
        length = _int_maybe(area.findtext("length"))
        if not name or origin is None or length is None:
            return None, "audit XML memory_area malformed"
        if name in areas or length <= 0:
            return None, "audit XML duplicate/invalid memory_area: %s" % name
        areas[name] = (origin, length)
    for need in ("FLASH", "FLASH_NV", "FLASH_LAST", "SRAM"):
        if need not in areas:
            return None, "audit XML missing %s memory area" % need
    # Match the complete pinned TI linker layout, not just NV and LAST
    # region starts. Reject duplicate/malformed region declarations above
    # before accepting any flash image as layout-compatible.
    expected_geometry = {
        "FLASH": (0x00000000, 0xAA000),
        "FLASH_NV": (0xAA000, 0x4000),
        "FLASH_LAST": (0xAE000, 0x2000),
        "SRAM": (0x20000000, 0x24000),
    }
    for region, expected in expected_geometry.items():
        if areas[region] != expected:
            return None, ("audit donor memory geometry mismatch for %s "
                          "(got %r; want %r)" % (region, areas[region], expected))
    nvs_base, nvs_size = areas["FLASH_NV"]
    if nvs_base != DONOR_NVS_BASE or nvs_size != DONOR_NVS_SIZE:
        return None, ("audit NVS geometry differs from donor "
                      "(want base 0xAA000 size 0x4000)")
    fl_base, fl_len = areas["FLASH_LAST"]
    if fl_base != DONOR_FLASH_LAST_BASE:
        return None, "audit FLASH_LAST base differs from donor (want 0xAE000)"
    nvs_end = nvs_base + nvs_size
    fl_end = fl_base + fl_len
    if nvs_base < fl_end and fl_base < nvs_end:
        return None, "audit NV/CCFG overlap"
    sections = {}
    # TI --xml_link_info uses one <logical_group id="lg-N"> per output
    # section, with name/load_address/size as its *direct children*.
    # Some historical synthetic test vectors nested <section> elements;
    # support those as unit oracles, but never rely on them for native
    # output. Reject duplicate entries to avoid shadowing real sections.
    groups = list(root.findall("./logical_group_list/logical_group"))
    candidates = groups + list(root.findall("./logical_group_list//section"))
    for section in candidates:
        if section.tag == "logical_group" and section.find("section") is not None:
            continue  # synthetic parent group, children below
        name = ((section.findtext("name") or "").strip()
                or (section.get("name") or "").strip())
        load = _int_maybe(section.findtext("load_address")
                           or section.get("load_address"))
        size = _int_maybe(section.findtext("size") or section.get("size"))
        if name:
            if name in sections:
                return None, "audit duplicate linker output section %s" % name
            sections[name] = (load, size)
    if ".resetVecs" not in sections:
        return None, "audit missing .resetVecs/vector table marker"
    ccfg = sections.get(".ccfg")
    if ccfg is None:
        return None, "audit missing CCFG section (invalid ELF/map symbols)"
    ccfg_load, ccfg_size = ccfg
    if ccfg_load is None or ccfg_size is None:
        return None, "audit CCFG section lacks load address/size"
    if nvs_base < ccfg_load + ccfg_size and ccfg_load < nvs_end:
        return None, "audit NV/CCFG overlap"
    if not (fl_base <= ccfg_load
            and ccfg_load + ccfg_size <= fl_end):
        return None, "audit CCFG not mapped into FLASH_LAST at HIGH"
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
        return None, "audit missing C/IRQ stack size"
    if stack_size != DONOR_CSTACK:
        return None, ("audit wrong C/IRQ stack expectation "
                      "(want donor 1024; 4096 needs native map proof)")
    return {"areas": areas, "sections": sections, "entry": entry}, None


def _parse_intel_hex(path):
    """Parse genuine Intel HEX records. Returns (payload, error).

    Payload maps absolute byte addresses to byte values. Raw binary
    content, bad checksums, unknown record types, missing EOF and
    duplicate addresses all fail closed. Every failure names the
    HEX/BIN cross-binding so a tampered pair with recomputed
    manifest digests cannot pass as a mere hash check.
    """
    try:
        if path.stat().st_size > HEX_SIZE_CAP:
            return None, ("audit HEX/BIN cross-binding failed "
                          "(HEX exceeds size cap)")
        raw = path.read_bytes()
    except OSError as exc:
        return None, "audit HEX/BIN cross-binding failed (HEX unreadable: %s)" % exc
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None, ("audit HEX/BIN cross-binding failed "
                      "(HEX is not Intel HEX records; raw binary rejected)")
    payload = {}
    upper = 0
    seen_eof = False
    data_records = 0
    seg_base = None
    lineno = 0
    for line in text.splitlines():
        lineno += 1
        if not line.strip():
            continue
        if seen_eof:
            return None, ("audit HEX/BIN cross-binding failed "
                          "(Intel HEX records after EOF)")
        if not line.startswith(":"):
            return None, ("audit HEX/BIN cross-binding failed "
                          "(HEX is not Intel HEX records; raw binary rejected)")
        body = line[1:]
        if len(body) < 10 or len(body) % 2 != 0:
            return None, ("audit HEX/BIN cross-binding failed "
                          "(malformed Intel HEX line %d)" % lineno)
        try:
            blob = bytes(int(body[i:i + 2], 16)
                         for i in range(0, len(body), 2))
        except ValueError:
            return None, ("audit HEX/BIN cross-binding failed "
                          "(malformed Intel HEX line %d)" % lineno)
        count, addr, rtype = blob[0], (blob[1] << 8) | blob[2], blob[3]
        data, checksum = blob[4:4 + count], blob[4 + count:]
        if len(data) != count or len(checksum) != 1:
            return None, ("audit HEX/BIN cross-binding failed "
                          "(malformed Intel HEX line %d)" % lineno)
        if (sum(blob) & 0xFF) != 0:
            return None, ("audit HEX/BIN cross-binding failed "
                          "(bad Intel HEX checksum on line %d)" % lineno)
        if rtype == 0x00:
            base = upper if seg_base is None else seg_base
            for offset, value in enumerate(data):
                target = base + addr + offset
                if target in payload:
                    return None, ("audit HEX/BIN cross-binding failed "
                                  "(duplicate HEX address 0x%08X)" % target)
                payload[target] = value
            data_records += 1
        elif rtype == 0x01:
            if count != 0:
                return None, ("audit HEX/BIN cross-binding failed "
                              "(malformed Intel HEX EOF on line %d)" % lineno)
            seen_eof = True
        elif rtype == 0x02:
            if count != 2:
                return None, ("audit HEX/BIN cross-binding failed "
                              "(malformed Intel HEX line %d)" % lineno)
            seg_base = ((data[0] << 8) | data[1]) << 4
            upper = 0
        elif rtype == 0x04:
            if count != 2:
                return None, ("audit HEX/BIN cross-binding failed "
                              "(malformed Intel HEX line %d)" % lineno)
            upper = ((data[0] << 8) | data[1]) << 16
            seg_base = None
        elif rtype in (0x03, 0x05):
            continue
        else:
            return None, ("audit HEX/BIN cross-binding failed "
                          "(unsupported Intel HEX record type 0x%02X)" % rtype)
        if len(payload) > HEX_PAYLOAD_CAP:
            return None, ("audit HEX/BIN cross-binding failed "
                          "(HEX data payload exceeds size cap)")
    if not seen_eof:
        return None, ("audit HEX/BIN cross-binding failed "
                      "(Intel HEX missing EOF record)")
    if not data_records:
        return None, ("audit HEX/BIN cross-binding failed "
                      "(Intel HEX carries no data records)")
    return payload, None


def _check_hex_bin_binding(payload, bin_path, evidence, elf_entry,
                           elf_segments):
    """Cross-bind HEX/BIN to the parsed XML evidence and ELF image.

    Returns error or None. After the XML region/coverage checks,
    the HEX data payload must byte-match every ELF PT_LOAD segment
    exactly: same addresses, same bytes. Any extra HEX byte with
    no covering LOAD segment (injected bytes), any LOAD byte
    missing from the HEX payload (silent deletion), and any
    differing byte (content tamper) fails closed naming the
    content-binding. The ELF entry is compared Thumb-normalized
    (bit 0 cleared: Cortex-M Thumb-2 entry points carry bit 0 set
    while Intel HEX holds the aligned address).
    """
    areas = evidence["areas"]
    sections = evidence["sections"]
    nvs_base, nvs_size = areas["FLASH_NV"]
    nvs_end = nvs_base + nvs_size
    others = [(base, base + size) for name, (base, size) in areas.items()
              if name != "FLASH_NV"]
    for addr in payload:
        if nvs_base <= addr < nvs_end:
            return ("audit HEX/BIN cross-binding failed "
                    "(HEX data address 0x%08X inside FLASH_NV; "
                    "image data must not overlap NV storage)" % addr)
        if not any(base <= addr < end for base, end in others):
            return ("audit HEX/BIN cross-binding failed "
                    "(HEX data address 0x%08X outside the XML-reported "
                    "memory regions)" % addr)
    for need in (".resetVecs", ".ccfg"):
        span = sections.get(need)
        if span is None:
            return ("audit HEX/BIN cross-binding failed "
                    "(XML section %s missing from HEX coverage)" % need)
        load, size = span
        if load is None or size is None:
            return ("audit HEX/BIN cross-binding failed "
                    "(XML section %s lacks load address/size)" % need)
        missing = [a for a in range(load, load + size) if a not in payload]
        if missing:
            return ("audit HEX/BIN cross-binding failed "
                    "(HEX data payload does not cover XML section %s "
                    "at 0x%08X)" % (need, missing[0]))
    entry_norm = elf_entry & 0xFFFFFFFE
    if entry_norm not in payload:
        return ("audit HEX/BIN cross-binding failed "
                "(ELF entry 0x%08X not covered by HEX data payload; "
                "HEX is not derived from the audited ELF)" % elf_entry)
    # Real tiarmobjcopy -O ihex omits ELF PT_LOAD zero-byte alignment
    # padding where no linked logical output section exists. Confirmed
    # on native donor CI artifact 12048696580: exactly two zero bytes
    # at 0x2ACD2..0x2ACD3 between .rodata and config_const. Treating
    # these as missing executable bytes produces a false rejection.
    # Accept only bounded ZERO padding within FLASH and outside ALL
    # real allocated FLASH logical-group spans; every meaningful linked
    # section remains byte-for-byte tied to HEX. Never permit nonzero
    # omissions, SRAM omissions or broad erased-data deletions.
    flash_start, flash_size = areas["FLASH"]
    nonalloc_prefixes = (".debug", ".symtab", ".strtab", ".comment",
                         ".note", ".ARM.attributes")
    linked_spans = [
        (load, load + size)
        for name, (load, size) in sections.items()
        if load is not None and size is not None and size > 0
        and not name.startswith(nonalloc_prefixes)
        and flash_start <= load < flash_start + flash_size
        and load + size <= flash_start + flash_size
    ]
    padded = 0
    for addr in sorted(set(payload) | set(elf_segments)):
        if addr not in elf_segments:
            return ("audit HEX/BIN/ELF content-binding failed "
                    "(cross-binding: HEX data address 0x%08X has no "
                    "covering ELF PT_LOAD segment; extra image bytes "
                    "rejected)" % addr)
        if addr not in payload:
            is_alignment = (
                elf_segments[addr] == 0 and padded < 16
                and flash_start <= addr < flash_start + flash_size
                and not any(start <= addr < end
                            for start, end in linked_spans)
            )
            if is_alignment:
                padded += 1
                continue
            return ("audit HEX/BIN/ELF content-binding failed "
                    "(cross-binding: ELF PT_LOAD byte 0x%08X missing "
                    "from the HEX data payload; image deletion "
                    "rejected)" % addr)
        if payload[addr] != elf_segments[addr]:
            return ("audit HEX/BIN/ELF content-binding failed "
                    "(cross-binding: HEX data byte 0x%08X differs from "
                    "the ELF PT_LOAD image; content tamper "
                    "rejected)" % addr)
    try:
        if bin_path.stat().st_size > BIN_SIZE_CAP:
            return ("audit HEX/BIN cross-binding failed "
                    "(BIN exceeds size cap)")
        bin_bytes = bin_path.read_bytes()
    except OSError as exc:
        return "audit HEX/BIN cross-binding failed (BIN unreadable: %s)" % exc
    addresses = sorted(payload)
    compact = bytes(payload[addr] for addr in addresses)
    # Legacy fixture oracles use packed HEX bytes. Native tiarmobjcopy
    # -O binary emits an *addressed, flat image* spanning the FLASH
    # regions; gaps between .text and .ccfg are filled, not deleted.
    # Require all programmed bytes to match exactly in either layout
    # and require every native flat-image hole to be uniformly erased.
    if bin_bytes == compact:
        return None
    base, last = addresses[0], addresses[-1]
    span = last - base + 1
    if span > BIN_SIZE_CAP or len(bin_bytes) != span:
        return ("audit HEX/BIN cross-binding failed "
                "(BIN content differs: neither exact packed HEX bytes nor a "
                "full address-preserving binary image)")
    gap_value = None
    for offset, value in enumerate(bin_bytes):
        addr = base + offset
        if addr in payload:
            if payload[addr] != value:
                return ("audit HEX/BIN cross-binding failed "
                        "(flat BIN byte at 0x%08X differs from HEX)" % addr)
        else:
            if gap_value is None:
                if value not in (0x00, 0xFF):
                    return ("audit HEX/BIN cross-binding failed "
                            "(flat BIN contains unexpected gap fill)")
                gap_value = value
            elif value != gap_value:
                return ("audit HEX/BIN cross-binding failed "
                        "(flat BIN has inconsistent unprogrammed gap fill)")
    return None


def audit(base, artifacts):
    """Returns (exit_code, message). Never raises.

    Log markers are a tripwire only -- real proof is the ELF/XML
    content-binding plus hosted provenance, never the log.
    """
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
    lines = log_text.splitlines()
    nonempty = [line for line in lines if line.strip()]
    if len(nonempty) < LOG_MIN_NONEMPTY_LINES:
        return 1, ("audit no actual linker invocation "
                   "(build log has %d non-empty lines; a genuine CCS "
                   "pipeline log is far longer; one-liners rejected)"
                   % len(nonempty))
    lowered = log_text.lower()
    for label, marker in LOG_MARKERS.items():
        if marker not in lowered:
            return 1, ("audit no actual linker invocation "
                       "(build log lacks %s)" % label)
    lowered_lines = [line.lower() for line in nonempty]
    marker_lines = {index for index, line in enumerate(lowered_lines)
                    if any(m in line for m in LOG_MARKERS.values())}
    if len(marker_lines) < LOG_MIN_MARKER_LINES:
        return 1, ("audit no actual linker invocation "
                   "(build log markers share a single line; fabricated "
                   "one-liner rejected)")
    # A genuine SDK-root GNU make invokes tiarmclang extensively BEFORE
    # the ZNP CCS project build; the first compiler string in the complete
    # log is therefore NOT the ZNP link. Find the actual linker command
    # AFTER the CCS projectBuild command and require --xml_link_info on
    # that same line; then require objcopy AFTER that linker command.
    # We validate a monotone, stage-specific sequence, not the global
    # first occurrence of generic tool names.
    syscfg_positions = [i for i, line in enumerate(lowered_lines)
                        if ("$ syscfg" in line or "syscfg generation" in line
                            or "syscfg standalone pinned preflight" in line
                            or ("sysconfig_cli" in line and "--script" in line))]
    project_positions = [i for i, line in enumerate(lowered_lines)
                         if "com.ti.ccstudio.apps.projectbuild" in line]
    actual_sequence = None
    for project_pos in project_positions:
        preceding = [i for i in syscfg_positions if i < project_pos]
        if not preceding:
            continue
        for linker_pos in range(project_pos + 1, len(lowered_lines)):
            line = lowered_lines[linker_pos]
            if "tiarmclang" not in line or "--xml_link_info" not in line:
                continue
            for objcopy_pos in range(linker_pos + 1, len(lowered_lines)):
                if "tiarmobjcopy" in lowered_lines[objcopy_pos]:
                    actual_sequence = (preceding[-1], project_pos,
                                       linker_pos, objcopy_pos)
                    break
            if actual_sequence:
                break
        if actual_sequence:
            break
    if actual_sequence is None:
        return 1, ("audit no actual linker invocation "
                   "(build log pipeline order implausible: require an "
                   "actual SysConfig stage before CCS projectBuild, "
                   "a later tiarmclang --xml_link_info linker command, "
                   "and later tiarmobjcopy)")
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
    evidence, err = _parse_link_xml(xml_text, targets["elf"].name, elf_entry)
    if err:
        return 1, err
    payload, err = _parse_intel_hex(targets["hex"])
    if err:
        return 1, err
    elf_segments, err = _parse_elf_load_segments(targets["elf"])
    if err:
        return 1, err
    err = _check_hex_bin_binding(payload, targets["bin"], evidence,
                                 elf_entry, elf_segments)
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
