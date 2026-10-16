"""R4-00 parity audit generator (stdlib only, offline).

Reads PARITY_MATRIX.json (+ optionally SOURCE_PROVENANCE.json unknowns)
and writes a short human-readable audit report. Never touches hardware.
Exits nonzero with clean error lines on unreadable/invalid input
(duplicate JSON keys, malformed entries, or a matrix the R4-00
validator rejects).
"""
import importlib.util
import json
import sys
from pathlib import Path


def _no_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate key %r" % (key,))
        obj[key] = value
    return obj


def loads_strict(text):
    return json.loads(text, object_pairs_hook=_no_duplicate_keys)


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return loads_strict(handle.read())


def _load_validator():
    tool_path = Path(__file__).resolve().parent / "r4_provenance_validate.py"
    spec = importlib.util.spec_from_file_location("r4_provenance_validate", tool_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def audit_matrix(matrix, provenance=None):
    entries = matrix.get("entries", [])
    if not isinstance(entries, list):
        entries = []
    by_status = {}
    for entry in entries:
        if not isinstance(entry, dict):
            by_status.setdefault("?", []).append({})
            continue
        status = entry.get("status", "?")
        if not isinstance(status, str):
            status = "?"
        by_status.setdefault(status, []).append(entry)
    lines = []
    lines.append("# R4-00 parity audit (generated, source-only)")
    lines.append("")
    lines.append("Entries: %d" % len(entries))
    for status in sorted(by_status, key=str):
        lines.append("- %s: %d" % (status, len(by_status[status])))
    unverified = [e for e in entries
                  if isinstance(e, dict) and e.get("status") == "PHYSICAL_UNVERIFIED"]
    lines.append("")
    lines.append("## PHYSICAL_UNVERIFIED gaps (%d)" % len(unverified))
    for entry in unverified:
        lines.append("- %s [%s]: %s" % (entry.get("id"), entry.get("domain"), str(entry.get("claim", ""))[:120]))
    if isinstance(provenance, dict):
        unknowns = provenance.get("unknowns", [])
        if not isinstance(unknowns, list):
            unknowns = []
        lines.append("")
        lines.append("## Explicit unknowns (%d)" % len(unknowns))
        for item in unknowns:
            lines.append("- %s" % item)
    lines.append("")
    lines.append("Hardware gates: all OPEN (no HARDWARE_PROVEN permitted at R4-00).")
    return "\n".join(lines) + "\n"


def main(argv):
    base = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[1]
    out = Path(argv[2]) if len(argv) > 2 else None
    try:
        matrix = load_json(base / "PARITY_MATRIX.json")
    except (OSError, ValueError) as exc:
        sys.stdout.write("audit: unreadable matrix (%s)\n" % exc)
        return 1
    validator = _load_validator()
    matrix_errors = validator.validate_matrix(matrix)
    if matrix_errors:
        for err in matrix_errors:
            sys.stdout.write("audit: invalid matrix: %s\n" % err)
        return 1
    prov_path = base / "SOURCE_PROVENANCE.json"
    provenance = None
    if prov_path.exists():
        try:
            provenance = load_json(prov_path)
        except (OSError, ValueError) as exc:
            sys.stdout.write("audit: unreadable provenance (%s)\n" % exc)
            return 1
        prov_errors = validator.validate_provenance(provenance)
        if prov_errors:
            for err in prov_errors:
                sys.stdout.write("audit: invalid provenance: %s\n" % err)
            return 1
    report = audit_matrix(matrix, provenance)
    if out:
        out.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
