#!/usr/bin/env python3
"""Build/audit one owner-controlled current-layout reset stage; no transport.

Hosted native qualification only. This is NOT a manufacturer-signed MCUboot
image, a demonstration of stock-loader policy, or hardware boot proof. Its
separate 8-KiB payload requires a private same-unit rollback binding and fresh
authorization before a protected-boot-area write. CCFG and NV stay excluded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "qualification"))
import full_nv4_profile as profiles
from r4_native_bundle import capture_native

BOOT, END, SECTOR = 0xAC000, 0xAE000, 0x2000
APP_END = 0xA0000
SCHEMA = "r4-p7u-stock20260311-compiled-handoff-v1"
BIN = "P7U-STOCK20260311-AC000-HANDOFF-UNQUALIFIED.bin"
EXPECTED_MMIO = [
    (0xE000ED08, BOOT),
    (0xE000E010, 0), (0xE000E014, 0), (0xE000E018, 0),
    (0xE000E180, 0xFFFFFFFF), (0xE000E184, 0xFFFFFFFF),
    (0xE000E280, 0xFFFFFFFF), (0xE000E284, 0xFFFFFFFF),
    (0xE000ED04, 0x0A000000), (0xE000ED08, 0),
]


def deny(reason):
    raise ValueError("R4_CURRENT_HANDOFF_DENIED_" + reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def elf_loads(raw):
    """Return real file-backed ARM ELF32 PT_LOAD spans; reject malformed ELF."""
    if (len(raw) < 52 or raw[:6] != b"\x7fELF\x01\x01" or
            struct.unpack_from("<HH", raw, 16) != (2, 40)):
        deny("ARM_ELF32_REQUIRED")
    offset = struct.unpack_from("<I", raw, 28)[0]
    size, count = struct.unpack_from("<HH", raw, 42)
    if not offset or size < 32 or not 0 < count <= 32 or offset + size * count > len(raw):
        deny("ELF_PROGRAM_HEADERS")
    result = []
    for i in range(count):
        kind, pos, run, load, n, memory, flags, _ = struct.unpack_from("<8I", raw, offset + size*i)
        if kind != 1:
            continue
        if n > memory or pos + n > len(raw):
            deny("ELF_LOAD_EXTENT")
        if n:
            result.append((run, raw[pos:pos+n], flags, load))
    if not result:
        deny("ELF_LOADS_MISSING")
    return result


def app_vectors(elf, binary):
    loads = elf_loads(elf)
    vectors = [(addr, raw, flags) for addr, raw, flags, load in loads
               if addr == load == 0 and len(raw) >= 0x3C]
    if len(vectors) != 1 or len(binary) < 0x3C or vectors[0][1][:0x3C] != binary[:0x3C]:
        deny("NATIVE_VECTOR_ELF_BIN_BINDING")
    sp, reset = struct.unpack_from("<II", binary)
    pc = reset & ~1
    if not (0x20000000 < sp <= 0x20024000 and sp % 8 == 0):
        deny("NATIVE_STACK")
    if not (reset & 1 and 0x3C <= pc < APP_END):
        deny("NATIVE_RESET")
    executable = [(addr, raw) for addr, raw, flags, load in loads
                  if addr == load and flags & 1 and 0 <= addr <= pc < pc+2 <= addr+len(raw) <= APP_END]
    if len(executable) != 1:
        deny("RESET_NOT_IN_UNIQUE_EXECUTABLE_APP_LOAD")
    addr, raw = executable[0]
    if len(binary) < addr+len(raw) or binary[addr:addr+len(raw)] != raw:
        deny("NATIVE_EXECUTABLE_ELF_BIN_BINDING")
    return sp, reset


def audit_stage(elf, emitted, sp):
    """Independently derive the padded sector from actual linked PT_LOADs."""
    loads = elf_loads(elf)
    sector = bytearray(b"\xff" * SECTOR)
    touched = set()
    for addr, raw, flags, load in loads:
        if addr != load or not BOOT <= addr < addr+len(raw) <= END or not flags & 4:
            deny("STAGE_LOAD_OUTSIDE_SINGLE_SECTOR")
        for i, value in enumerate(raw):
            pos = addr - BOOT + i
            if pos in touched:
                deny("OVERLAPPING_STAGE_LOADS")
            touched.add(pos)
            sector[pos] = value
    if not set(range(54*4)).issubset(touched):
        deny("STAGE_VECTOR_TABLE_MISSING")
    words = struct.unpack_from("<54I", sector)
    entry, hold = words[1], words[2]
    if (words[0] != sp or not entry & 1 or not hold & 1 or entry == hold or
            not BOOT+54*4 <= (entry & ~1) < END or
            not BOOT+54*4 <= (hold & ~1) < END or
            set(words[2:]) != {hold}):
        deny("STAGE_VECTOR_TABLE")
    if struct.unpack_from("<I", elf, 24)[0] & ~1 != entry & ~1:
        deny("STAGE_ELF_ENTRY")
    low, high = min(touched), max(touched)+1
    if low != 0 or emitted != bytes(sector[:high]):
        deny("STAGE_ELF_OBJCOPY_BINDING")
    return bytes(sector), entry, hold


def execute_stage(sector, sp, reset, entry, hold):
    """Execute the compiled M4F bytes, stopping BEFORE executing native APP.

    Unicorn checks core instructions/registers and observed MMIO writes only;
    it does not model TI ROM, analog/peripheral behavior or interrupt arrival.
    """
    import unicorn
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn import arm_const as a
    if unicorn.__version__ != "2.1.4":
        deny("UNPINNED_EXECUTION_ENGINE")
    cases = []
    for mutation in ("matching", "changed_stack", "changed_reset"):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        uc.ctl_set_cpu_model(a.UC_CPU_ARM_CORTEX_M4)
        uc.mem_map(0, 0xB0000)
        uc.mem_map(0x20000000, 0x24000)
        uc.mem_map(0xE000E000, 0x1000)
        uc.mem_write(BOOT, sector)
        uc.mem_write(0, struct.pack("<II", sp ^ (8 if mutation == "changed_stack" else 0),
                                    reset ^ (2 if mutation == "changed_reset" else 0)))
        # A dirty but privileged thread-mode transfer must be normalized.
        uc.reg_write(a.UC_ARM_REG_MSP, sp)
        uc.reg_write(a.UC_ARM_REG_PSP, sp-0x100)
        uc.reg_write(a.UC_ARM_REG_CONTROL, 2)
        uc.reg_write(a.UC_ARM_REG_BASEPRI, 0x80)
        uc.reg_write(a.UC_ARM_REG_PRIMASK, 1)
        uc.reg_write(a.UC_ARM_REG_FAULTMASK, 1)
        writes, arrived = [], []
        def on_write(engine, access, address, size, value, data):
            if size != 4 or address not in {item[0] for item in EXPECTED_MMIO}:
                deny("UNEXPECTED_EXECUTED_WRITE_" + hex(address))
            writes.append((address, value))
        def on_code(engine, address, size, data):
            if address in (reset & ~1, hold & ~1):
                arrived.append(address)
                engine.emu_stop()
        uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
        uc.hook_add(UC_HOOK_CODE, on_code)
        uc.emu_start(entry, END, count=256)
        if mutation == "matching":
            regs = {"msp": (a.UC_ARM_REG_MSP, sp), "psp": (a.UC_ARM_REG_PSP, 0),
                    "control": (a.UC_ARM_REG_CONTROL, 0), "basepri": (a.UC_ARM_REG_BASEPRI, 0),
                    "faultmask": (a.UC_ARM_REG_FAULTMASK, 0), "primask": (a.UC_ARM_REG_PRIMASK, 0),
                    "ipsr": (a.UC_ARM_REG_IPSR, 0)}
            if (arrived != [reset & ~1] or writes != EXPECTED_MMIO or
                    any(uc.reg_read(reg) != want for reg, want in regs.values()) or
                    struct.unpack("<I", uc.mem_read(0xE000ED08, 4))[0] != 0):
                deny("COMPILED_RESET_TRANSFER_SEMANTICS")
        elif arrived != [hold & ~1] or writes != EXPECTED_MMIO[:1]:
            deny("COMPILED_VECTOR_MISMATCH_DID_NOT_HOLD")
        cases.append({"case": mutation, "result": "APP_RESET" if mutation == "matching" else "LOCAL_HOLD",
                      "instruction_execution": True, "writes": [[hex(addr), hex(value)] for addr, value in writes]})
    return {"engine": "Unicorn 2.1.4 Cortex-M4", "cases": cases,
            "no_ram_or_flash_writes": True, "ti_rom_or_hardware_emulated": False}


def build(artifacts, manifest_sha256, profile, clang, out):
    if out.exists() or out.is_symlink():
        deny("OUTPUT_EXISTS")
    selected = profiles.validate_profile(profile)
    if selected["profile_id"] != profiles.STOCK_20260311_ID:
        deny("CURRENT_PROFILE_REQUIRED")
    compiler, objcopy, objdump = (clang / "bin" / tool for tool in ("tiarmclang", "tiarmobjcopy", "tiarmobjdump"))
    version = subprocess.check_output([str(compiler), "--version"], text=True)
    if "3.2.2.LTS" not in version:
        deny("PINNED_TI_COMPILER_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="r4-current-handoff-") as temp:
        frozen = Path(temp)
        manifest = capture_native(artifacts, frozen, manifest_sha256)
        raw = {kind: (frozen / manifest["files"][kind]["file"]).read_bytes() for kind in ("elf", "bin")}
        sp, reset = app_vectors(raw["elf"], raw["bin"])
        out.mkdir(parents=True)
        target = out / "handoff.out"
        command = [str(compiler), "-mcpu=cortex-m4", "-mthumb", "-mfloat-abi=soft", "-nostdlib",
                   "-DEXPECTED_APP_SP=" + hex(sp), "-DEXPECTED_APP_RESET=" + hex(reset),
                   str(HERE / "r4_stock20260311_handoff.S"), "-o", str(target),
                   "-Wl,--map_file=" + str(out / "handoff.map"),
                   "-Wl,--xml_link_info=" + str(out / "handoff.xml"),
                   "-Wl," + str(HERE / "r4_stock20260311_handoff.cmd")]
        run = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (out / "build.log").write_text(run.stdout)
        if run.returncode:
            deny("NATIVE_BUILD_FAILED\n" + run.stdout)
        compact = out / "handoff.compact.bin"
        subprocess.run([str(objcopy), "-O", "binary", str(target), str(compact)], check=True)
        subprocess.run([str(objcopy), "-O", "ihex", str(target), str(out / "handoff.hex")], check=True)
        sector, entry, hold = audit_stage(target.read_bytes(), compact.read_bytes(), sp)
        execution = execute_stage(sector, sp, reset, entry, hold)
        disassembly = subprocess.check_output([str(objdump), "--disassemble", "--mcpu=cortex-m4", str(target)], text=True)
        if "psplim" in disassembly.lower() or "msplim" in disassembly.lower():
            deny("ARMV8_STACK_LIMIT_IN_STAGE")
        (out / "disassembly.txt").write_text(disassembly)
        (out / BIN).write_bytes(sector)
        receipt = {"schema": SCHEMA, "status": "COMPILED_M4F_SINGLE_SECTOR_TRANSFER_AUDITED",
                   "profile_id": selected["profile_id"], "profile_sha256": sha(profile.read_bytes()),
                   "source_native_manifest_sha256": manifest_sha256,
                   "source_native_artifact_sha256": {k: v["sha256"] for k, v in manifest["files"].items()},
                   "app_initial_sp": hex(sp), "app_reset_thumb": hex(reset), "app_vector_address": "0x0",
                   "resident_vector_address": hex(BOOT), "stage_reset_thumb": hex(entry), "stage_hold_thumb": hex(hold),
                   "stage_sector_range": [hex(BOOT), hex(END)], "stage_vector_count": 54,
                   "sector_bin": BIN, "sector_sha256": sha(sector), "sector_bytes": len(sector),
                   "source_sha256": {p.name: sha(p.read_bytes()) for p in
                                     (Path(__file__), HERE / "r4_stock20260311_handoff.S", HERE / "r4_stock20260311_handoff.cmd")},
                   "execution": execution, "ccfg_changed": False, "nv_changed": False,
                   "manufacturer_signature_verification": False, "manufacturer_boot_trust_boundary_replaced": True,
                   "hardware_boot_qualified": False, "private_same_unit_rollback_binding_required": True,
                   "flash_authorized": False}
        receipt["files"] = {p.name: {"sha256": sha(p.read_bytes()), "bytes": p.stat().st_size}
                            for p in sorted(out.iterdir()) if p.is_file()}
        (out / "handoff-receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.artifacts, args.manifest_sha256, args.profile, args.clang, args.out_dir), sort_keys=True))


if __name__ == "__main__":
    main()
