"""Fail closed on the *linked* M4F SYS/BIOS context-switch ABI.

The TI SDK m3 assembler contains ARMv8-M preprocessor conditionals even when
building the Cortex-M4F. A successful link is not evidence that the conditions
were evaluated. This audit inspects TI's linked disassembly, not its source.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
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

    swap = instructions[SWAP]

    def has_exact_frame(opcode: str, last: str) -> bool:
        expected = {*(f"r{number}" for number in range(4, 12)), last}
        for instruction in swap:
            match = re.search(r"\b" + opcode + r"(?:\.w)?\s+\{([^}]+)\}", instruction)
            if match:
                # Both ABI register names and objdump's sb/sl/fp aliases are
                # legitimate spellings of registers 9, 10 and 11.
                aliases = {"sb": "r9", "sl": "r10", "fp": "r11"}
                actual = {aliases.get(item.strip(), item.strip()) for item in match.group(1).split(",")}
                if actual == expected:
                    return True
        return False

    has_general_save = has_exact_frame("push", "lr")
    has_general_restore = has_exact_frame("pop", "pc")
    vfp_save = sum(bool(re.search(r"\bvpush\b", x)) for x in swap)
    vfp_restore = sum(bool(re.search(r"\bvpop\b", x)) for x in swap)
    if not all((has_general_save, has_general_restore, vfp_save == 1, vfp_restore == 1)):
        raise ValueError("M4F_CONTEXT_REGISTER_FRAME_INCOMPLETE")
    # Pinned TaskSupport_buildTaskStack() creates exactly eight r4-r11
    # words, 16 d8-d15 words and then the glue return PC. M4F must consume
    # precisely those first 24 words before popping PC from word 24.
    # No ARMv8-M 2-word stack-limit frame or extra pop is permitted.
    saved_words = 8 + 16
    restored_pc_word = saved_words
    if restored_pc_word != 24:
        raise ValueError("M4F_CONTEXT_PC_OFFSET_MISMATCH")

    hwi_checks = {
        HWI[0]: ("basepri", "psp", "fpscr"),
        HWI[1]: ("psp", "bx lr"),
        HWI[2]: ("psp", "msp", "control"),
        HWI[3]: ("control", "blx"),
    }
    for name, required in hwi_checks.items():
        program = "\n".join(instructions[name])
        if not all(x in program for x in required):
            raise ValueError("M4F_CONTEXT_HWI_PATH_INCOMPLETE " + name)
    return {"schema": "r4-m4f-linked-context-abi-v1",
            "armv8m_stack_limit_in_linked_code": False,
            "m4f_restored_pc_word_index": restored_pc_word,
            "m4f_first_task_returns_to_glue": True,
            "hwi_switch_paths_inspected": list(HWI),
            "armv8m_stack_limit_symbol_policy": "absent_or_noop_only",
            "linked_disassembly_sha256": {
                name: hashlib.sha256(disassembly[name].encode()).hexdigest() for name in TARGETS},
            "status": "M4F_CONTEXT_FRAME_AND_HWI_PATHS_AUDITED"}


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


def audit(elf: Path, xml: Path, sdk: Path, clang: Path) -> dict:
    dumper = clang / "bin/tiarmobjdump"
    if not dumper.is_file():
        raise ValueError("M4F_CONTEXT_MISSING_PINNED_TI_OBJDUMP")
    output = {}
    for name in TARGETS:
        output[name] = subprocess.check_output(
            [str(dumper), "--disassemble-symbols=" + name, "--no-show-raw-insn",
             "--mcpu=cortex-m4", str(elf)], text=True)
    report = verify_m4f_disassembly(output)
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
    return report
