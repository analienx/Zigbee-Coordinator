"""Restrict pinned SDK's TI-RTOS libraries to the actual CC2652P7 M4F CPU.

The upstream 8.33 full-architecture make builds generic M4 as well as M4F;
its generic M4 target compiles the arm/m3 TaskSupport ASM with FP instructions,
which clang 3.2.2 correctly rejects on a non-FPU architecture.
This *hosted temporary checkout-only* workaround drops the unrelated M4 target,
not the M4F target, and leaves committed TI donors and live hardware intact.
"""
import argparse
import hashlib
from pathlib import Path

RELATIVE = Path("kernel/tirtos7/packages/ti/sysbios/CMakeLists.txt")
BEFORE = "set(TIRTOS_SUPPORTED_ARCHITECTURES m0p m4 m4f m33f)"
AFTER = "set(TIRTOS_SUPPORTED_ARCHITECTURES m0p m4f m33f)"


def scope(sdk: Path) -> dict:
    source = sdk / RELATIVE
    original = source.read_bytes()
    text = original.decode("utf-8")
    if text.count(BEFORE) != 1 or AFTER in text:
        raise ValueError("SDK architecture source differs from pinned baseline; refuse patch")
    result = text.replace(BEFORE, AFTER)
    source.write_text(result, encoding="utf-8")
    return {
        "reason": "Exclude broken generic M4 target, retain CC2652P7 M4F",
        "path": str(RELATIVE),
        "before_sha256": hashlib.sha256(original).hexdigest(),
        "after_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "target_preserved": "m4f",
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
