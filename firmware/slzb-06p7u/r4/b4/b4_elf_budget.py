"""Measure B0 versus B4 *linked ELF allocated sections* (not runtime stack).

Requires two independently built, hash-bound ARM32 little-endian ELFs.
Only reports source-proven allocated section delta; does NOT infer heap
fragmentation, RTOS task-stack high-water, radio delivery or flash approval.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

CAP_BYTES = 12 * 1024 * 1024
SHF_ALLOC = 0x2

def _find_elf(root):
    manifests = list(Path(root).rglob("manifest.json"))
    if len(manifests) != 1 or manifests[0].is_symlink():
        raise ValueError("expected exactly one native artifact manifest")
    m = json.loads(manifests[0].read_text(encoding="utf-8"))
    if m.get("schema") != "r4-b0-artifact-manifest-v1":
        raise ValueError("unverified native artifact manifest")
    f = m.get("files", {}).get("elf", {})
    name = f.get("file")
    if type(name) is not str or Path(name).name != name:
        raise ValueError("unsafe ELF file name")
    target = manifests[0].parent / name
    if target.is_symlink() or not target.is_file() or target.stat().st_size > CAP_BYTES:
        raise ValueError("ELF missing, symlinked or oversized")
    data = target.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != f.get("sha256"):
        raise ValueError("ELF SHA mismatch with manifest")
    return data, sha

def _sections(data):
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError("requires genuine 32-bit little-endian TI ELF")
    if struct.unpack_from("<H", data, 18)[0] != 40:
        raise ValueError("ELF target is not ARM")
    e_shoff = struct.unpack_from("<I", data, 32)[0]
    e_shentsize, e_shnum, e_shstr = struct.unpack_from("<HHH", data, 46)
    if (not 1 <= e_shnum <= 512 or e_shentsize < 40 or e_shstr >= e_shnum
            or e_shoff + e_shentsize * e_shnum > len(data)):
        raise ValueError("invalid ELF section-header geometry")
    records = []
    for i in range(e_shnum):
        pos = e_shoff + i * e_shentsize
        name_offset, sh_type, flags, address, offset, size, *_ = struct.unpack_from("<10I", data, pos)
        if sh_type != 8 and offset + size > len(data):  # SHT_NOBITS has no file data
            raise ValueError("ELF section exceeds file bounds")
        records.append((name_offset, flags, address, size, offset))
    offset = records[e_shstr][4]
    size = records[e_shstr][3]
    if offset + size > len(data):
        raise ValueError("ELF name table out of range")
    names = data[offset:offset + size]
    out = {}
    for name_offset, flags, addr, length, _ in records:
        if not (flags & SHF_ALLOC):
            continue
        if name_offset >= len(names):
            raise ValueError("ELF section name outside string table")
        end = names.find(b"\x00", name_offset)
        if end == -1:
            raise ValueError("unterminated ELF section name")
        name = names[name_offset:end].decode("ascii", "strict")
        if name in out:
            raise ValueError("ambiguous repeated allocated section name")
        region = ("FLASH_APP" if 0 <= addr < 0xAA000
                  else "RAM" if 0x20000000 <= addr < 0x20040000
                  else "OTHER")
        out[name] = {"region":region,"address":addr,"bytes":length}
    return out

def compare(base, candidate):
    bdata, bsha = _find_elf(base)
    cdata, csha = _find_elf(candidate)
    b = _sections(bdata)
    c = _sections(cdata)
    def sum_region(m, area):
        return sum(x["bytes"] for x in m.values() if x["region"] == area)
    delta = {}
    for name in sorted(set(b)|set(c)):
        before = b.get(name,{}).get("bytes",0)
        after = c.get(name,{}).get("bytes",0)
        if before != after:
            delta[name] = after-before
    return {
        "schema":"b4-elf-linked-section-budget-v1",
        "evidence":"HOSTED_LINKED_ELF_SECTIONS_NOT_RTOS_RUNTIME",
        "b0_elf_sha256":bsha,
        "b4_elf_sha256":csha,
        "flash_app_allocated_bytes": [sum_region(b,"FLASH_APP"),sum_region(c,"FLASH_APP")],
        "ram_allocated_bytes": [sum_region(b,"RAM"),sum_region(c,"RAM")],
        "flash_app_delta_bytes":sum_region(c,"FLASH_APP")-sum_region(b,"FLASH_APP"),
        "ram_delta_bytes":sum_region(c,"RAM")-sum_region(b,"RAM"),
        "changed_section_sizes":delta,
        "rtos_stack_high_water":"NOT_MEASURED",
        "heap_fragmentation":"NOT_MEASURED",
        "flash_authorized":False,
        "physical_verified":False,
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--b0", type=Path, required=True)
    p.add_argument("--b4", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(compare(a.b0,a.b4),sort_keys=True))

if __name__ == "__main__":
    main()
