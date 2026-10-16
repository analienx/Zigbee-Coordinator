"""R4-00 parity audit generator (stdlib only, offline).

Reads PARITY_MATRIX.json (+ optionally SOURCE_PROVENANCE.json unknowns)
and writes a short human-readable audit report. Never touches hardware.
"""
import json
import sys
from pathlib import Path


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def audit_matrix(matrix, provenance=None):
    entries = matrix.get("entries", [])
    by_status = {}
    for entry in entries:
        by_status.setdefault(entry.get("status", "?"), []).append(entry)
    lines = []
    lines.append("# R4-00 parity audit (generated, source-only)")
    lines.append("")
    lines.append("Entries: %d" % len(entries))
    for status in sorted(by_status):
        lines.append("- %s: %d" % (status, len(by_status[status])))
    unverified = [e for e in entries if e.get("status") == "PHYSICAL_UNVERIFIED"]
    lines.append("")
    lines.append("## PHYSICAL_UNVERIFIED gaps (%d)" % len(unverified))
    for entry in unverified:
        lines.append("- %s [%s]: %s" % (entry.get("id"), entry.get("domain"), entry.get("claim", "")[:120]))
    if provenance:
        unknowns = provenance.get("unknowns", [])
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
    matrix = load_json(base / "PARITY_MATRIX.json")
    prov_path = base / "SOURCE_PROVENANCE.json"
    provenance = load_json(prov_path) if prov_path.exists() else None
    report = audit_matrix(matrix, provenance)
    if out:
        out.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
