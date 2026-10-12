#!/usr/bin/env python3
"""Prove every programmed TI P7 HEX byte matches a real ELF PT_LOAD byte.

Strictly offline; only the pristine LP_CC1352P7_4 reference shape is accepted.
No radio access, programmer, firmware upload, BSL, or hardware actions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

APP_END = 0xAA000
NV_START = 0xAA000
NV_END = 0xAE000
LAST_START = 0xAE000
FLASH_END = 0xB0000
CCFG_START = 0xAFFA8
ELF_HEADER = 52
ELF_PHDR = 32


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def read_elf(data: bytes) -> tuple[dict[int, int], dict]:
    require(len(data) >= ELF_HEADER, "ELF_TOO_SHORT")
    require(data[:7] == b"\x7fELF\x01\x01\x01", "NOT_ELF32_LITTLE_ENDIAN_V1")
    require(data[7] == 0, "ELF_OSABI_UNEXPECTED")
    (etype, machine, version, entry, phoff, shoff, flags,
     ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
        "<HHIIIIIHHHHHH", data, 16)
    require((etype, machine, version) == (2, 40, 1), "ELF_NOT_ARM_EXEC_V1")
    require((flags & 0xFF000000) == 0x05000000, "NOT_ARM_EABI5")
    require(ehsize == ELF_HEADER and phentsize == ELF_PHDR, "BAD_ELF_HEADER_SIZE")
    require(2 <= phnum <= 64 and phoff >= ELF_HEADER, "BAD_ELF_PHDR_COUNT")
    require(phoff + phentsize * phnum <= len(data), "ELF_PHDR_OUT_OF_FILE")
    require((entry & 1) == 1 and 0 <= (entry & ~1) < APP_END,
            "RESET_ENTRY_NOT_THUMB_APP")
    memory: dict[int, int] = {}
    loaded = []
    nv_reservations = []
    for i in range(phnum):
        (ptype, off, vaddr, paddr, file_bytes, mem_bytes,
         access_flags, align) = struct.unpack_from(
            "<IIIIIIII", data, phoff + i * phentsize)
        if ptype != 1:
            continue
        require(file_bytes <= mem_bytes, "ELF_LOAD_FILE_GT_MEMORY")
        require(off + file_bytes <= len(data), "ELF_LOAD_OUTSIDE_FILE")
        # All PT_LOAD memory ranges in the P7 reference must be in the
        # verified flash or SRAM address map (or GPRAM, unused by G2).
        require(mem_bytes > 0 and paddr + mem_bytes <= 0xFFFFFFFF,
                "ELF_LOAD_EMPTY_OR_WRAP")
        if NV_START <= paddr < NV_END:
            require((paddr, mem_bytes, file_bytes) ==
                    (NV_START, NV_END - NV_START, 0),
                    "ELF_NV_SEGMENT_NOT_PURE_RESERVATION")
            nv_reservations.append(i)
        elif 0 <= paddr < APP_END:
            require(paddr + mem_bytes <= APP_END, "ELF_APP_LOAD_CROSSES_NV")
        elif LAST_START <= paddr < FLASH_END:
            require(paddr + mem_bytes <= FLASH_END, "ELF_CCFG_SEGMENT_CROSSES_FLASH")
        elif 0x20000000 <= paddr < 0x20024000:
            require(paddr + mem_bytes <= 0x20024000, "ELF_SRAM_OVERFLOW")
            require(file_bytes == 0, "ELF_LOAD_PROGRAMS_SRAM")
        else:
            raise ValueError(f"ELF_UNEXPECTED_PT_LOAD_ADDRESS_{paddr:#x}")
        if not file_bytes:
            continue
        # Only application and CCFG bytes are allowed in the programmed HEX.
        require((0 <= paddr < APP_END and paddr + file_bytes <= APP_END) or
                (LAST_START <= paddr and paddr + file_bytes <= FLASH_END),
                "ELF_FILE_BYTES_OUTSIDE_APP_CCFG")
        payload = data[off:off + file_bytes]
        for delta, v in enumerate(payload):
            absolute = paddr + delta
            require(absolute not in memory, "ELF_DUPLICATE_PROGRAM_BYTE")
            memory[absolute] = v
        loaded.append({"start": f"0x{paddr:x}", "bytes": file_bytes})
    require(len(nv_reservations) == 1, "ELF_NV_RESERVATION_COUNT")
    require(any(addr < APP_END for addr in memory), "ELF_APPLICATION_ABSENT")
    ccfg = [p for p in memory if LAST_START <= p < FLASH_END]
    require(len(ccfg) == FLASH_END - CCFG_START, "ELF_CCFG_SIZE_NOT_88")
    require(min(ccfg) == CCFG_START and max(ccfg) == FLASH_END - 1,
            "ELF_CCFG_NOT_FINAL_88_BYTES")
    require(set(ccfg) == set(range(CCFG_START, FLASH_END)), "ELF_CCFG_HAS_HOLES")
    return memory, {"entry_point_thumb": f"0x{entry:x}",
                    "programmed_bytes": len(memory),
                    "nv_uninitialized_reserved_bytes": NV_END - NV_START,
                    "ccfg_bytes": len(ccfg), "load_segments": loaded}


def read_hex(text: str) -> dict[int, int]:
    upper = 0
    eof = False
    memory: dict[int, int] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        require(not eof, "HEX_DATA_AFTER_EOF")
        require(line.startswith(":") and len(line) % 2 == 1,
                "HEX_MALFORMED_TEXT")
        try:
            raw = bytes.fromhex(line[1:])
        except ValueError as e:
            raise ValueError("HEX_INVALID_HEX_DIGIT") from e
        require(len(raw) >= 5 and len(raw) == raw[0] + 5 and
                sum(raw) % 256 == 0, "HEX_BAD_RECORD_OR_CHECKSUM")
        length, offset, record_type = raw[0], int.from_bytes(raw[1:3], "big"), raw[3]
        payload = raw[4:-1]
        if record_type == 0:
            require(length > 0 and offset + length <= 0x10000,
                    "HEX_DATA_CROSSES_64K_PAGE")
            address = upper + offset
            require((0 <= address < APP_END and address + length <= APP_END) or
                    (LAST_START <= address < FLASH_END and
                     address + length <= FLASH_END), "HEX_WRITES_RESERVED_FLASH")
            for j, value in enumerate(payload):
                key = address + j
                require(key not in memory, "HEX_DUPLICATE_BYTE")
                memory[key] = value
        elif record_type == 1:
            require(length == 0 and offset == 0, "HEX_INVALID_EOF")
            eof = True
        elif record_type in (2, 4):
            require(length == 2 and offset == 0, "HEX_INVALID_EXTENSION")
            upper = int.from_bytes(payload, "big") << (4 if record_type == 2 else 16)
        elif record_type in (3, 5):
            require(length == 4 and offset == 0, "HEX_INVALID_START_ADDRESS")
        else:
            raise ValueError("HEX_UNSUPPORTED_RECORD")
    require(eof and memory, "HEX_MISSING_EOF_OR_DATA")
    return memory


def audit(elf_blob: bytes, hex_text: str) -> dict:
    elf_mem, meta = read_elf(elf_blob)
    hex_mem = read_hex(hex_text)
    require(len(elf_mem) == len(hex_mem), "ELF_HEX_BYTE_COUNT_MISMATCH")
    for address, value in elf_mem.items():
        require(address in hex_mem, f"ELF_HEX_MISSING_ADDRESS_{address:#x}")
        require(hex_mem[address] == value, f"ELF_HEX_CONTENT_MISMATCH_{address:#x}")
    require(len(hex_mem) == len(elf_mem), "ELF_HEX_EXTRA_ADDRESS")
    return {
        "status": "ELF_HEX_EXACT_PROGRAM_BYTES_MATCH",
        "qualification": "REFERENCE_ONLY_NOT_FLASHABLE",
        "elf_sha256": digest(elf_blob),
        "hex_program_memory_sha256": hashlib.sha256(
            b"".join(a.to_bytes(4, "little") + bytes([elf_mem[a]])
                     for a in sorted(elf_mem))).hexdigest(),
        "hex_sha256": digest(hex_text.encode("ascii")),
        "exact_programmed_addresses_and_values": len(elf_mem),
        "original_smlight_ccfg_verified": False,
        "flash_authorized": False,
        "elf": meta,
    }


def hex_record(typ: int, payload: bytes = b"", offset: int = 0) -> str:
    raw = bytes([len(payload), (offset >> 8) & 255, offset & 255, typ]) + payload
    return ":" + (raw + bytes([(-sum(raw)) & 255])).hex().upper()


def fixture() -> tuple[bytes, str]:
    data = bytearray(240)
    data[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HHIIIIIHHHHHH", data, 16,
                     2, 40, 1, 0x101, 52, 0, 0x5000000, 52, 32, 3, 40, 0, 0)
    phdrs = [
        (1, 148, 0x100, 0x100, 2, 2, 5, 4),
        (1, 150, CCFG_START, CCFG_START, 88, 88, 4, 4),
        (1, 238, NV_START, NV_START, 0, NV_END - NV_START, 6, 1),
    ]
    for idx, values in enumerate(phdrs):
        struct.pack_into("<IIIIIIII", data, 52 + idx * 32, *values)
    data[148:150] = b"\x01\x02"
    data[150:238] = bytes(range(88))
    hexfile = "\n".join([
        hex_record(4, b"\x00\x00"),
        hex_record(0, b"\x01\x02", 0x100),
        hex_record(4, b"\x00\x0a"),
        hex_record(0, bytes(range(88)), 0xffa8),
        hex_record(1),
    ])
    return bytes(data), hexfile


def selftest() -> None:
    elf, hex_text = fixture()
    require(audit(elf, hex_text)["exact_programmed_addresses_and_values"] == 90,
            "POSITIVE_ELF_HEX_FIXTURE")
    cases = []
    # Crucial attack: valid checksummed HEX data changed, still same addresses.
    cases.append((elf, hex_text.replace(
        hex_record(0, b"\x01\x02", 0x100),
        hex_record(0, b"\x01\x03", 0x100))))
    cases.append((elf, hex_text.replace(
        hex_record(0, bytes(range(88)), 0xffa8),
        hex_record(0, bytes(range(87)) + b"\xFF", 0xffa8))))
    cases.append((elf, hex_text.replace(
        hex_record(0, b"\x01\x02", 0x100), "")))
    cases.append((elf, hex_text.replace(
        hex_record(0, b"\x01\x02", 0x100),
        hex_record(0, b"\x01\x02", 0x100) + "\n" +
        hex_record(0, b"\x01\x02", 0x100))))
    cases.append((elf, hex_text.replace(
        hex_record(0, bytes(range(88)), 0xffa8),
        hex_record(0, bytes(range(88)), 0xa000))))
    bad = bytearray(elf); bad[150] ^= 1; cases.append((bytes(bad), hex_text))
    bad = bytearray(elf); bad[18] = 62; cases.append((bytes(bad), hex_text))
    bad = bytearray(elf); bad[24] &= 0xfe; cases.append((bytes(bad), hex_text))
    bad = bytearray(elf); struct.pack_into("<I", bad, 52 + 16, 0); cases.append((bytes(bad), hex_text))
    bad = bytearray(elf); struct.pack_into("<I", bad, 52 + 2 * 32 + 16, 2); cases.append((bytes(bad), hex_text))
    cases.append((elf, hex_text.rsplit("\n",1)[0]))
    for idx, pair in enumerate(cases):
        try:
            audit(*pair)
        except (ValueError, UnicodeError):
            continue
        raise AssertionError(f"ELF_HEX_NEGATIVE_CASE_{idx}_UNDETECTED")
    print(f"PASS G2 ELF↔HEX exact payload binding; {len(cases)} attack/corruption negatives")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--elf", type=Path)
    p.add_argument("--hex", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--selftest", action="store_true")
    opts = p.parse_args()
    if opts.selftest:
        selftest()
    if opts.elf or opts.hex or opts.out:
        require(bool(opts.elf and opts.hex and opts.out), "ALL_ARGS_REQUIRED")
        result = audit(opts.elf.read_bytes(), opts.hex.read_text(encoding="ascii"))
        opts.out.parent.mkdir(parents=True, exist_ok=True)
        opts.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
