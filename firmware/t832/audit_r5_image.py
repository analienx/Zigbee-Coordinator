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
    matches = list(re.finditer(r"^\s*([0-9a-fA-F]+) <([^>]+)>:\s*$", text, re.M))
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
    spins = []
    for line in error.splitlines():
        branch = re.search(r"^\s*([0-9a-fA-F]+):.*?\bb(?:\.w)?\s+(?:0x)?([0-9a-fA-F]+)\b", line)
        if branch and int(branch[1], 16) == int(branch[2], 16):
            spins.append(error.index(line))
    assert spins and error.index("T832Diag_fatalError") < max(spins), "original Error_SPIN after latch not proven"
    proof["error_before_original_spin"] = True
    hwi = body("Hwi_excHandler")
    assert "T832Diag_fatalException" in hwi, "default Hwi path does not call RAM latch"
    asm = body("Hwi_excHandlerAsm")
    assert re.search(r"\bblx?\b", asm), "exception handler assembly call absent"
    proof["default_exception_path_calls_latch"] = True
    proof["raw_disassembly_sha_source"] = args.disassembly.name
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print("R5 linked fatal hooks + no calls + preserved Error_SPIN: PASS")


if __name__ == "__main__":
    main()
