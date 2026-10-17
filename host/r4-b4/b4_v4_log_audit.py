"""Guard against DEBUG payload leakage from the pinned B4 v4 ZNP/UNPI stack.

Source-level only; does not claim global app or installed host privacy.
"""
import argparse
import hashlib
import json
from pathlib import Path

BASE = "src/adapter/z-stack"
ZNP = BASE + "/znp/znp.ts"
PARSER = BASE + "/unpi/parser.ts"
WRITER = BASE + "/unpi/writer.ts"

def verify(root, receipt):
    root = Path(root)
    if not root.is_dir() or root.is_symlink() or not str(root.resolve()).startswith("/tmp/"):
        raise ValueError("only disposable source")
    evidence = json.loads(Path(receipt).read_text(encoding="utf-8"))
    if (evidence.get("schema") != "r4-b4-v4-herdsman-source-v1" or
            evidence.get("stage") != "PINNED_DISPOSABLE_SOURCE_ONLY" or
            evidence.get("unpi_raw_debug_payload_logging") is not False or
            evidence.get("installed") is not False or
            evidence.get("original_znp_owner") is not True):
        raise ValueError("source receipt lacks privacy or owner guarantees")
    source = {}
    for name in (ZNP, PARSER, WRITER):
        file = root / name
        if not file.is_file() or file.is_symlink():
            raise ValueError("missing/symlinked source")
        raw = file.read_bytes()
        expected = evidence.get("files", {}).get(name, {}).get("sha256_after")
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("patched source SHA mismatch: " + name)
        source[name] = raw.decode("utf-8")
    znp = source[ZNP]
    for marker in ("r4DiagReadOnly", "r4DiagReadOnlyV4",
                   "B4 SYS SRSP (diagnostic body redacted)",
                   "B4 SYS SREQ (diagnostic nonce redacted)"):
        if marker not in znp:
            raise ValueError("ZNP diagnostic redaction missing")
    # Ordinary ZNP request and response debug paths are retained inside else.
    if znp.count("logger.debug(() =>") != 2:
        raise ValueError("ZNP DEBUG control flow changed")
    if any(fragment in source[WRITER] for fragment in
           ("[...buffer]", "frame [", "buffer [")):
        raise ValueError("raw outgoing UNPI frame/buffer logging")
    if any(fragment in source[PARSER] for fragment in
           ("[...chunk]", "[...this.buffer]", "parsed " + chr(36) + "{frame}")):
        raise ValueError("raw incoming UNPI chunk/frame logging")
    for name, markers in (
        (WRITER, ("payload redacted", "frame ", "buffer ")),
        (PARSER, ("payload redacted", "subsystem=", "command=")),
    ):
        for marker in markers:
            if marker not in source[name]:
                raise ValueError("metadata-only UNPI logging missing: " + name)
    return {
        "schema": "b4-v4-unpi-debug-source-audit-v1",
        "raw_unpi_debug_bytes": False, "v3_v4_high_level_payload_debug": False,
        "ordinary_znp_debug_preserved": True, "installed": False,
        "physical_verified": False,
        "verified_source_shas": {name: hashlib.sha256(text.encode()).hexdigest()
                                 for name, text in source.items()},
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.checkout, args.receipt), sort_keys=True))

if __name__ == "__main__":
    main()
