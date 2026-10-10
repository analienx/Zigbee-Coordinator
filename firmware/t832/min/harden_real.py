"""Verify actual TI ZNP source and linked image, not the planning model.

All use is GitHub-hosted CI, offline only. PASS never authorizes flashing.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

FLASH_END = 0x100000
NVS_BEGIN = 0xFD800
CCFG_BEGIN = 0x50000000
CCFG_END = 0x50000800
REVISION = 20261010
H_STD = "src/adapter/z-stack/znp/definition.ts"


def version_bytes(sdk: Path) -> list[int]:
    text = (sdk / "source/ti/zstack/mt/mt_version.c").read_text(encoding="utf-8")
    m = re.search(r"const\s+uint8_t\s+MTVersionString\s*\[\s*\]\s*=\s*\{(.*?)\};",
                  text, flags=re.S)
    if not m:
        raise ValueError("linked TI version source: MTVersionString absent")
    body = re.sub(r"/\*.*?\*/|//[^\n]*", "", m.group(1), flags=re.S)
    pieces = [p.strip() for p in body.split(",") if p.strip()]
    if not all(re.fullmatch(r"\d+", p) for p in pieces):
        raise ValueError("nonliteral/unknown SYS_VERSION source bytes: " + repr(pieces))
    return [int(p) for p in pieces]


def check_version(sdk: Path, herdsman: Path) -> dict:
    actual = version_bytes(sdk)
    expected = [2, 1, 2, 7, 1] + list(REVISION.to_bytes(4, "little"))
    if actual != expected:
        raise ValueError(f"SYS_VERSION source mismatch: expected 9 bytes {expected}, got {actual}")
    definition = (herdsman / H_STD).read_text(encoding="utf-8")
    m = re.search(r'name:\s*"version".*?response:\s*\[(.*?)\]', definition, re.S)
    if not m:
        raise ValueError("pinned Herdsman definition lacks SYS/version response")
    fields = re.findall(r'name:\s*"([^"]+)"\s*,\s*parameterType:\s*ParameterType\.(UINT\d+)', m.group(1))
    wanted = [
        ("transportrev", "UINT8"), ("product", "UINT8"), ("majorrel", "UINT8"),
        ("minorrel", "UINT8"), ("maintrel", "UINT8"), ("revision", "UINT32"),
    ]
    if fields != wanted:
        raise ValueError(f"Herdsman SYS_VERSION field layout changed: {fields}")
    return {"status": "PASS_TI_SOURCE_WIRE_ABI", "payload_length": len(actual),
            "payload": actual, "revision": REVISION,
            "herdsman_sys_version_layout": fields, "hardware_verified": False}


def memory_map(path: Path) -> dict[str, dict[str, int]]:
    pat = re.compile(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+"
        r"([0-9A-Fa-f]{8,})\s+([0-9A-Fa-f]{8,})\s+"
        r"([0-9A-Fa-f]{8,})\s+([0-9A-Fa-f]{8,})(?:\s|$)"
    )
    rows = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = pat.match(line)
        if m:
            rows[m.group(1)] = dict(zip(("origin", "length", "used", "unused"),
                                       (int(x, 16) for x in m.groups()[1:])))
    return rows


def hex_spans(path: Path) -> dict:
    upper = 0
    eof = False
    records = 0
    ccfglocs = set()
    occupied = set()
    for lineno, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if eof:
            raise ValueError(f"Intel HEX data after EOF at line {lineno}")
        if not line.startswith(":"):
            raise ValueError(f"not Intel HEX at line {lineno}")
        try:
            raw = bytes.fromhex(line[1:])
        except ValueError as e:
            raise ValueError(f"invalid HEX digits at line {lineno}") from e
        if len(raw) < 5 or len(raw) != raw[0] + 5 or sum(raw) % 256:
            raise ValueError(f"bad Intel HEX length/checksum at line {lineno}")
        count = raw[0]
        address = int.from_bytes(raw[1:3], "big")
        typ = raw[3]
        payload = raw[4:-1]
        if typ == 0:
            start = upper + address
            stop = start + count
            if address + count > 0x10000 or start < 0:
                raise ValueError(f"HEX record crosses 64 KiB window at {lineno}")
            in_main = 0 <= start < FLASH_END and stop <= FLASH_END
            in_ccfg = CCFG_BEGIN <= start < CCFG_END and stop <= CCFG_END
            if not (in_main or in_ccfg):
                raise ValueError(f"HEX writes outside main flash and separate CC26x4 CCFG at {lineno}: {start:#x}-{stop:#x}")
            if in_main and stop > NVS_BEGIN:
                raise ValueError(f"HEX writes NVS data at {lineno}: {start:#x}-{stop:#x}")
            for pos in range(start, stop):
                if pos in occupied:
                    raise ValueError(f"HEX duplicate flash byte at {pos:#x}")
                occupied.add(pos)
                if in_ccfg:
                    ccfglocs.add(pos)
            records += 1
        elif typ == 4:
            if address != 0 or count != 2:
                raise ValueError("bad Intel HEX extended linear address record")
            upper = int.from_bytes(payload, "big") << 16
        elif typ == 2:
            if address != 0 or count != 2:
                raise ValueError("bad Intel HEX extended segment address record")
            upper = int.from_bytes(payload, "big") << 4
        elif typ == 1:
            if address or count:
                raise ValueError("invalid Intel HEX EOF")
            eof = True
        elif typ in (3, 5):
            if count != 4:
                raise ValueError("bad Intel HEX start address")
        else:
            raise ValueError(f"unexpected Intel HEX type {typ}")
    if not eof or records == 0:
        raise ValueError("HEX lacks data or EOF")
    # CCFG bytes are a hardware-critical part of the generated image. This is
    # presence and separation only; backdoor/boot config is NOT yet proved.
    if not ccfglocs:
        raise ValueError("CCFG address range absent from linked HEX")
    return {"data_records": records, "total_bytes": len(occupied),
            "ccfg_bytes": len(ccfglocs), "ccfg_address_min": hex(min(ccfglocs))}


def linked(map_file: Path, hex_file: Path, projectspec: Path, syscfg: Path,
           sdk_linker: Path) -> dict:
    rows = memory_map(map_file)
    if not {"FLASH", "FLASH_NV", "SRAM", "CCFG"}.issubset(rows):
        raise ValueError(f"missing real TI linker memory rows: {sorted(rows)}")
    nv = rows["FLASH_NV"]
    if nv["origin"] != NVS_BEGIN or nv["length"] != FLASH_END - NVS_BEGIN:
        raise ValueError(f"linked NV geometry mismatch: {nv}")
    flash = rows["FLASH"]
    if flash["origin"] != 0 or flash["length"] != NVS_BEGIN:
        raise ValueError(f"linked application FLASH span mismatch: {flash}")
    ccfg = rows["CCFG"]
    if ccfg["origin"] != CCFG_BEGIN or ccfg["length"] != CCFG_END - CCFG_BEGIN:
        raise ValueError(f"CC26x4 CCFG must be outside main flash: {ccfg}")
    if rows["SRAM"]["unused"] < 8192:
        raise ValueError(f"less than 8 KiB unallocated SRAM: {rows['SRAM']}")
    proj = projectspec.read_text(encoding="utf-8")
    for item in ("-DNVOCMP_NVPAGES=5", "--define=NVOCMP_NVPAGES=5"):
        if proj.count(item) != 1:
            raise ValueError(f"effective project NV compiler/linker option missing: {item}")
    link = sdk_linker.read_text(encoding="utf-8")
    if link.count("#define NVOCMP_NVPAGES          5") != 1:
        raise ValueError("SDK linker NV page count is not 5")
    cfg = syscfg.read_text(encoding="utf-8")
    if cfg.count("NVS1.internalFlash.regionBase = 0xFD800;") != 1 or (
        cfg.count("NVS1.internalFlash.regionSize = 0x2800;") != 1
    ):
        raise ValueError("P10 SysConfig NV region differs from verified map")
    evidence = hex_spans(hex_file)
    return {"status": "PASS_REAL_LINK_GEOMETRY",
            "linked_memory": {k: rows[k] for k in ("FLASH", "FLASH_NV", "SRAM", "CCFG")},
            "hex": evidence, "flash_authorized": False,
            "warning": ("CC26x4 separate CCFG address region validated; NVS occupies " 
                        "entire upper five pages in main flash. The true generated "
                        "NVS driver configuration, physical pinmap, ROM BSL, oscillator, "
                        "PA and flash erase/write effects still require verification.")}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["source", "linked"])
    p.add_argument("--sdk", type=Path)
    p.add_argument("--herdsman", type=Path)
    p.add_argument("--map", type=Path)
    p.add_argument("--hex", type=Path)
    p.add_argument("--projectspec", type=Path)
    p.add_argument("--syscfg", type=Path)
    p.add_argument("--linker", type=Path)
    p.add_argument("--out", type=Path)
    a = p.parse_args()
    if a.mode == "source":
        if not a.sdk or not a.herdsman:
            p.error("source requires --sdk and --herdsman")
        result = check_version(a.sdk, a.herdsman)
    else:
        if not all((a.map, a.hex, a.projectspec, a.syscfg, a.linker)):
            p.error("linked requires --map --hex --projectspec --syscfg --linker")
        result = linked(a.map, a.hex, a.projectspec, a.syscfg, a.linker)
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
