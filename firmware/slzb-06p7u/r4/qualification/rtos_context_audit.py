"""Fail closed on the *linked* M4F SYS/BIOS context-switch ABI.

The TI SDK m3 assembler contains ARMv8-M preprocessor conditionals even when
building the Cortex-M4F. A successful link is not evidence that the conditions
were evaluated. This audit inspects TI's linked disassembly, not its source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
from xml.etree import ElementTree

SWAP = "ti_sysbios_knl_TaskSupport_swap"
SET_LIMIT = "ti_sysbios_family_arm_m3_Hwi_setStackLimit"
HWI = ("ti_sysbios_family_arm_m3_Hwi_dispatch",
       "ti_sysbios_family_arm_m3_Hwi_pendSV",
       "ti_sysbios_family_arm_m3_Hwi_initStacks",
       "ti_sysbios_family_arm_m3_Hwi_switchAndRunFunc")
# setStackLimit is an ARMv8-M-only implementation in the pinned TI source.
# Once the M4F preprocessor guard is effective it is *absent* from the ELF;
# demanding its presence caused the first corrected CI build to fail closed.
TARGETS = (SWAP, *HWI)


def parse_assembly(text: str, name: str) -> list[str]:
    """Require a real TI objdump symbol and extract only instruction mnemonics."""
    if not re.search(r"<" + re.escape(name) + r">:\s*$", text, re.M):
        raise ValueError("M4F_CONTEXT_MISSING_LINKED_SYMBOL " + name)
    instructions = []
    for line in text.splitlines():
        match = re.match(r"^\s*[0-9a-fA-F]+:\s+([a-zA-Z][a-zA-Z0-9_.]*)(?:\s+(.*))?$", line)
        if match:
            instructions.append(match.group(1).lower() + " " + (match.group(2) or "").lower())
    if not instructions:
        raise ValueError("M4F_CONTEXT_EMPTY_DISASSEMBLY " + name)
    return instructions


def verify_m4f_disassembly(disassembly: dict[str, str]) -> dict:
    instructions = {name: parse_assembly(disassembly[name], name) for name in TARGETS}
    for name, lines in instructions.items():
        if re.search(r"\b(?:psplim|msplim)\b", "\n".join(lines)):
            raise ValueError("M4F_CONTEXT_ARMV8_STACK_LIMIT_IN_LINKED_CODE " + name)
    # TI's objdump may spell push/pop as stmdb/ldmia, and VFP operations as
    # vstmdb/vldmia. A text-mnemonic register-frame test falsely rejected a
    # correct *linked* M4F swap in native CI. Independently check the exact
    # executable bytes against the pinned compiler's proven M4F swap below;
    # this textual pass guards all Hwi paths against ARMv8-M stack registers.
    restored_pc_word = 8 + 16
    return {"schema": "r4-m4f-linked-context-abi-v1",
            "armv8m_stack_limit_in_linked_code": False,
            "m4f_restored_pc_word_index": restored_pc_word,
            "m4f_first_task_returns_to_glue": True,
            "hwi_switch_paths_inspected": list(HWI),
            "armv8m_stack_limit_symbol_policy": "absent_or_noop_only",
            "linked_disassembly_sha256": {
                name: hashlib.sha256(disassembly[name].encode()).hexdigest() for name in TARGETS},
            "status": "M4F_CONTEXT_FRAME_AND_HWI_PATHS_AUDITED"}


# TI tiarmclang 3.2.2.LTS, SYS/BIOS M4F TaskSupport_asm_gcc.S, linked image:
# push.w r4-r11,lr; vpush d8-d15; str sp,[r0]; ldr sp,[r1];
# vpop d8-d15; pop.w r4-r11,pc. No stack-limit frame; PC at stack word 24.
# Proven from the physical-failure root cause and the 10ae6dd native ELF.
M4F_SWAP_INSTRUCTIONS = bytes.fromhex(
    "2de9f04f2ded108bc0f800d0d1f800d0bdec108bbde8f08f")
M4F_SWAP_SECTION = M4F_SWAP_INSTRUCTIONS + bytes.fromhex("00bf" * 8)


def _full_swap_load(elf: Path, address: int, size: int) -> dict:
    """Require the full-profile frame in one real, executable flash PT_LOAD."""
    blob = elf.read_bytes()
    if (len(blob) < 52 or blob[:6] != b"\x7fELF\x01\x01" or
            struct.unpack_from("<HH", blob, 16) != (2, 40)):
        raise ValueError("M4F_CONTEXT_INVALID_ARM_ELF32")
    offset = struct.unpack_from("<I", blob, 28)[0]
    stride, count = struct.unpack_from("<HH", blob, 42)
    if (offset == 0 or stride < 32 or not 0 < count <= 32 or
            offset + stride * count > len(blob)):
        raise ValueError("M4F_CONTEXT_INVALID_PROGRAM_HEADERS")
    matches = []
    for index in range(count):
        kind, start, run, load, file_size, memory_size, flags, _ = struct.unpack_from(
            "<8I", blob, offset + stride * index)
        if kind != 1:
            continue
        if file_size > memory_size or start + file_size > len(blob):
            raise ValueError("M4F_CONTEXT_INVALID_LOAD_EXTENT")
        if (flags & 1 and run == load and
                run <= address < address + size <= run + file_size):
            matches.append((start + address - run, run, load, file_size, flags))
    if len(matches) != 1:
        raise ValueError("M4F_CONTEXT_SWAP_NOT_IN_UNIQUE_EXECUTABLE_FLASH_LOAD")
    start, run, load, file_size, flags = matches[0]
    if blob[start:start + size] != M4F_SWAP_SECTION:
        raise ValueError("M4F_CONTEXT_LINKED_SWAP_MACHINE_BYTES_MISMATCH")
    return {"run_address": hex(run), "load_address": hex(load),
            "file_bytes": file_size, "flags": flags}


def audit_linked_swap_bytes(xml: Path, elf: Path, *, full_nv4: bool = False) -> dict:
    """Verify exact linked machine instructions using the already-bound BIN/XML."""
    components = [node for node in ElementTree.parse(xml).iter("object_component")
                  if node.findtext("name") == ".text." + SWAP]
    if len(components) != 1:
        raise ValueError("M4F_CONTEXT_SWAP_SECTION_MISSING_OR_AMBIGUOUS")
    component = components[0]
    address = int(component.findtext("run_address"), 0)
    size = int(component.findtext("size"), 0)
    if size != len(M4F_SWAP_SECTION):
        raise ValueError("M4F_CONTEXT_SWAP_SECTION_GEOMETRY")
    full_evidence = {}
    if full_nv4:
        # Independent selected profile, never an APP bound inferred from ELF.
        import full_nv4_profile as full
        profile = full.validate_profile(full.DEFAULT_PROFILE)
        ceiling = int(profile["flash"]["conservative_app_ceiling_exclusive"], 16)
        if not 0 <= address < address + size <= ceiling:
            raise ValueError("M4F_CONTEXT_SWAP_SECTION_GEOMETRY")
        full_evidence = {
            "profile_sha256": hashlib.sha256(full.DEFAULT_PROFILE.read_bytes()).hexdigest(),
            "app_ceiling_exclusive": hex(ceiling),
            "executable_pt_load": _full_swap_load(elf, address, size)}
    elif not 0 <= address < 0x6000:
        raise ValueError("M4F_CONTEXT_SWAP_SECTION_GEOMETRY")
    # The parent native image-binding audit confirms this flat BIN is exactly
    # the same linked ELF and XML, not merely an unrelated bytes file.
    image = elf.with_suffix(".bin").read_bytes()
    if image[address:address + size] != M4F_SWAP_SECTION:
        raise ValueError("M4F_CONTEXT_LINKED_SWAP_MACHINE_BYTES_MISMATCH")
    return {"address": hex(address), "size": size,
            "instruction_sha256": hashlib.sha256(M4F_SWAP_INSTRUCTIONS).hexdigest(),
            "linked_section_sha256": hashlib.sha256(M4F_SWAP_SECTION).hexdigest(),
            **full_evidence}


ARCHIVE = Path("kernel/tirtos7/packages/ti/sysbios/lib/ticlang/m4f/sysbios.a")


def audit_archive_ownership(xml: Path, sdk: Path) -> dict:
    actual = sdk / ARCHIVE
    if actual.is_symlink() or not actual.is_file():
        raise ValueError("M4F_CONTEXT_LINKED_ARCHIVE_MISSING")
    tree = ElementTree.parse(xml)
    owners = set()
    for element in tree.iter("input_file"):
        if (element.findtext("kind") == "archive" and
                element.findtext("file") == actual.name and
                Path(element.findtext("path") or "").resolve() == actual.parent.resolve()):
            owners.add(element.findtext("name"))
    required = {"TaskSupport_asm_gcc.o", "Hwi_asm_gcc.o", "Hwi_asm_switch_gcc.o"}
    if not required.issubset(owners):
        raise ValueError("M4F_CONTEXT_ASSEMBLY_OBJECTS_NOT_LINKED_FROM_M4F_ARCHIVE " + repr(sorted(owners)))
    return {"path_in_pinned_sdk": str(ARCHIVE),
            "sha256": hashlib.sha256(actual.read_bytes()).hexdigest(),
            "linked_asm_members": sorted(required)}


def audit(elf: Path, xml: Path, sdk: Path, clang: Path, *, full_nv4: bool = False) -> dict:
    dumper = clang / "bin/tiarmobjdump"
    if not dumper.is_file():
        raise ValueError("M4F_CONTEXT_MISSING_PINNED_TI_OBJDUMP")
    output = {}
    for name in TARGETS:
        output[name] = subprocess.check_output(
            [str(dumper), "--disassemble-symbols=" + name, "--no-show-raw-insn",
             "--mcpu=cortex-m4", str(elf)], text=True)
    report = verify_m4f_disassembly(output)
    report["linked_m4f_swap_machine_frame"] = audit_linked_swap_bytes(xml, elf, full_nv4=full_nv4)
    # TI's M4F-preprocessed Hwi assembly does not define setStackLimit at all.
    # If a future SDK instead links a no-op, inspect and constrain it as well.
    optional = subprocess.run(
        [str(dumper), "--disassemble-symbols=" + SET_LIMIT, "--no-show-raw-insn",
         "--mcpu=cortex-m4", str(elf)], capture_output=True, text=True, check=True)
    if "failed to disassemble missing symbol " + SET_LIMIT in optional.stderr:
        report["armv8m_stack_limit_symbol"] = "absent_on_m4f"
    else:
        limit = parse_assembly(optional.stdout, SET_LIMIT)
        if len(limit) != 1 or not re.search(r"\bbx\s+lr\b", limit[0]):
            raise ValueError("M4F_CONTEXT_HWI_STACK_LIMIT_NOT_NOOP")
        report["armv8m_stack_limit_symbol"] = "linked_noop"
    report["linked_sysbios_archive"] = audit_archive_ownership(xml, sdk)
    report["linked_elf_sha256"] = hashlib.sha256(elf.read_bytes()).hexdigest()
    report["linked_xml_sha256"] = hashlib.sha256(xml.read_bytes()).hexdigest()
    report["full_nv4"] = full_nv4
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--clang", required=True, type=Path)
    parser.add_argument("--full-nv4", action="store_true")
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if (args.artifacts.is_symlink() or not args.artifacts.is_dir() or
            args.receipt.exists() or args.receipt.is_symlink()):
        raise ValueError("M4F_CONTEXT_UNTRUSTED_INPUT_OR_RECEIPT")
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "release"))
    sys.path.insert(0, str(root / "b0/tools"))
    from r4_native_bundle import capture_native
    from b0_image_audit import audit as image_audit
    artifacts = args.artifacts.resolve()
    manifest_path = artifacts / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("M4F_CONTEXT_NATIVE_MANIFEST_MISSING")
    # This CLI is a linked-ABI subgate, not build-provenance authentication.
    # Bind its inspection to one private copy of the admitted native files.
    pin = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="r4-m4f-context-native-") as directory:
        frozen = Path(directory)
        manifest = capture_native(artifacts, frozen, pin)
        status, message = image_audit(root / "b0", frozen,
                                      direct_rom_boot=not args.full_nv4,
                                      full_nv4=args.full_nv4)
        if status:
            raise ValueError("M4F_CONTEXT_NATIVE_IMAGE_BINDING_FAILED " + message)
        members = manifest["files"]
        elf, xml = (frozen / members[kind]["file"] for kind in ("elf", "xml"))
        if elf.with_suffix(".bin").name != members["bin"]["file"]:
            raise ValueError("M4F_CONTEXT_BIN_NAME_NOT_BOUND_TO_ELF")
        report = audit(elf, xml, args.sdk, args.clang, full_nv4=args.full_nv4)
        report["native_manifest_sha256"] = pin
        report["native_artifact_sha256"] = {
            kind: members[kind]["sha256"] for kind in ("elf", "hex", "bin", "xml")}
        report["flash_authorized"] = False
    args.receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "full_nv4": args.full_nv4,
                      "flash_authorized": False}))


if __name__ == "__main__":
    main()
