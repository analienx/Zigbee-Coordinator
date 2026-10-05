#!/usr/bin/env python3
"""Hosted linked-image fatal-hook proof; consumes TI objdump, never guesses.

Keep raw disassembly in the bundle for independent review. Fatal latch bodies
must have no call instructions. Kernel paths must contain calls to the latch,
and the original exception assembly / Error self-loop must remain linked.
"""
import argparse
import json
import re
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--disassembly", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    text = args.disassembly.read_text()
    labels = list(re.finditer(r"^\s*([0-9a-fA-F]+) <([^>]+)>:\s*$", text, re.M))
    # TI objdump prints ARM mapping symbols, local asm branch labels and
    # literal-pool labels as headings too. They are not function boundaries:
    # notably Hwi's original spin is under lab$3, after lab$4.
    matches = [m for m in labels if not m[2].startswith(("$", "lab$", ".L"))
               and m[2] not in {"excHandlerAddr", "svcHandlerAddr"}]
    functions = {match[2]: text[match.end():matches[i + 1].start() if i + 1 < len(matches) else len(text)]
                 for i, match in enumerate(matches)}
    proof = {}

    def body(suffix):
        candidates = [value for name, value in functions.items() if name == suffix or name.endswith("_" + suffix)]
        assert len(candidates) == 1, f"linked function ambiguous/missing: {suffix}"
        return candidates[0]

    for name in ("T832Diag_fatalError", "T832Diag_fatalException"):
        code = body(name)
        assert not re.search(r"\bblx?(?:\.w)?\b", code), f"fatal function calls something: {name}"
        proof[name] = {"linked": True, "call_instructions": 0}
    error = body("Error_raiseX")
    assert "T832Diag_fatalError" in error, "Error path does not call RAM latch"
    # Decode the branch address and require a self-targeting unconditional
    # branch. A generic branch somewhere in the function is not spin proof.
    def self_spins(code):
        offsets = []
        for line in code.splitlines():
            branch = re.search(r"^\s*([0-9a-fA-F]+):.*?\bb(?:\.[nw])?\s+(?:0x)?([0-9a-fA-F]+)\b", line)
            if branch and int(branch[1], 16) == int(branch[2], 16):
                offsets.append(code.index(line))
        return offsets

    spins = self_spins(error)
    assert spins and error.index("T832Diag_fatalError") < max(spins), "original Error_SPIN after latch not proven"
    proof["error_before_original_spin"] = True
    hwi = body("Hwi_excHandler")
    assert "T832Diag_fatalException" in hwi, "default Hwi path does not call RAM latch"
    asm = body("Hwi_excHandlerAsm")
    assert re.search(r"\bblx?\b", asm), "exception handler assembly call absent"
    assert self_spins(asm), "original exception assembly spin absent"
    handler = [m for m in matches if m[2] == "Hwi_excHandler" or m[2].endswith("_Hwi_excHandler")]
    pool = re.search(r"^\s*[0-9a-fA-F]+ <excHandlerAddr>:\s*\n.*?\.word\s+0x([0-9a-fA-F]+)", asm, re.M)
    assert len(handler) == 1 and pool, "default Hwi handler pointer absent/ambiguous"
    assert (int(pool[1], 16) & ~1) == int(handler[0][1], 16), "assembly targets a different exception handler"
    proof["default_exception_path_calls_latch"] = True
    proof["original_exception_assembly_spin_linked"] = True
    proof["default_exception_handler_pointer_verified"] = True
    proof["raw_disassembly_sha_source"] = args.disassembly.name
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print("R5 linked fatal hooks + no calls + preserved Error_SPIN: PASS")


if __name__ == "__main__":
    main()
