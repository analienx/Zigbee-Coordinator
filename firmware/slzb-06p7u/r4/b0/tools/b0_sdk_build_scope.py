"""Scope pinned TI-RTOS to M4F and make its ASM guards effective.

The upstream 8.33 full-architecture make builds generic M4 as well as M4F;
its generic M4 target compiles the arm/m3 TaskSupport ASM with FP instructions,
which clang 3.2.2 correctly rejects on a non-FPU architecture.
The SDK lists assembler sources with lowercase .s although they contain C
preprocessor #if guards. TI Clang assembles those guards as comments, leaving
ARMv8-M PSPLIM save/restore in the M4F context switch. This disposable SDK
change selects .S copies *only* for M4F, forcing the C preprocessor. It also
omits unrelated generic M4 and leaves the pinned TI donor repository intact.
"""
import argparse
import hashlib
from pathlib import Path

RELATIVE = Path("kernel/tirtos7/packages/ti/sysbios/CMakeLists.txt")
BEFORE = "set(TIRTOS_SUPPORTED_ARCHITECTURES m0p m4 m4f m33f)"
AFTER = "set(TIRTOS_SUPPORTED_ARCHITECTURES m0p m4f m33f)"
SOURCE_LIST = "    list(TRANSFORM SOURCES_${TI_TOOLCHAIN_NAME} PREPEND ${PREPEND_STR} OUTPUT_VARIABLE SOURCES_${TI_ARCH})"
PREPROCESS_M4F = """    # .s bypasses the TI Clang preprocessor; .S evaluates the architecture guards.
    if (TI_ARCH STREQUAL m4f AND TI_TOOLCHAIN_NAME STREQUAL ticlang)
        list(TRANSFORM SOURCES_m4f REPLACE "\\\\.s$" ".S")
    endif ()"""
M4F_ASM = ("TaskSupport_asm_gcc.s", "Hwi_asm_gcc.s", "Hwi_asm_switch_gcc.s")


def scope(sdk: Path) -> dict:
    source = sdk / RELATIVE
    original = source.read_bytes()
    text = original.decode("utf-8")
    if (text.count(BEFORE) != 1 or AFTER in text or
            text.count(SOURCE_LIST) != 1 or PREPROCESS_M4F in text):
        raise ValueError("SDK architecture source differs from pinned baseline; refuse patch")
    result = text.replace(BEFORE, AFTER).replace(SOURCE_LIST, SOURCE_LIST + "\n" + PREPROCESS_M4F)
    asm_sources = {}
    for name in M4F_ASM:
        original_asm = sdk / "kernel/tirtos7/packages/ti/sysbios/family/arm/m3" / name
        if original_asm.is_symlink() or not original_asm.is_file():
            raise ValueError("Missing pinned M4F ASM: " + name)
        promoted_asm = original_asm.with_suffix(".S")
        if promoted_asm.exists() or promoted_asm.is_symlink():
            raise ValueError("Refuse to overwrite existing preprocessed ASM: " + name)
        asm_sources[name] = hashlib.sha256(original_asm.read_bytes()).hexdigest()
    # No original SDK source file is modified, only the disposable CMake file
    # and three byte-identical .S copies compiled by TIClang.
    for name in M4F_ASM:
        original_asm = sdk / "kernel/tirtos7/packages/ti/sysbios/family/arm/m3" / name
        original_asm.with_suffix(".S").write_bytes(original_asm.read_bytes())
    source.write_text(result, encoding="utf-8")
    return {
        "reason": "Preprocess M4F SYSBIOS ASM guards and exclude unrelated generic M4 target",
        "path": str(RELATIVE),
        "before_sha256": hashlib.sha256(original).hexdigest(),
        "after_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "target_preserved": "m4f",
        "m4f_preprocessed_asm_source_sha256": asm_sources,
        "asm_input_suffix": ".S",
        "scope": "TEMPORARY_HOSTED_SDK_BUILD_ONLY",
    }


def main():
    import json
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    receipt = scope(args.sdk)
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
