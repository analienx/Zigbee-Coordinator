"""R4-00 parity audit generator (stdlib only, offline).

Reads PARITY_MATRIX.json and the REQUIRED SOURCE_PROVENANCE.json
unknowns and writes a short human-readable audit report. Never touches
hardware. Exits nonzero with clean error lines on unreadable/invalid
input (duplicate JSON keys, malformed entries, a matrix the R4-00
validator rejects, a missing provenance manifest, a refused output
path, or an unwritable report path). This is a manifest-consistency
reporter, not source-integrity proof (see r4_provenance_validate.py).
"""
import importlib.util
import json
import os
import sys
import tempfile
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
    # Dict guard (issue #85 R4-R6): a non-object matrix yields a clean
    # INVALID INPUT report string, never an AttributeError traceback.
    if not isinstance(matrix, dict):
        return ("INVALID INPUT: matrix must be an object "
                "(got %s)\n" % type(matrix).__name__)
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


def _same_path(left, right):
    try:
        return left.resolve() == right.resolve()
    except (OSError, ValueError, RuntimeError):
        # RuntimeError covers symlink loops (Path.resolve recursion).
        return False


def _write_report_atomic(out, report):
    """Atomic report write (temp file in the destination dir + os.replace)
    with clean nonzero handling of output IO errors (never a traceback)."""
    try:
        parent = out.parent
        handle, tmp_name = tempfile.mkstemp(
            dir=str(parent), prefix=".r4_audit_", suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as tmp:
                tmp.write(report)
            os.replace(tmp_name, out)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
    except (OSError, ValueError) as exc:
        sys.stdout.write("audit: cannot write report %s (%s)\n" % (out, exc))
        return 1
    return 0


def main(argv):
    base = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[1]
    out = Path(argv[2]) if len(argv) > 2 else None
    matrix_path = base / "PARITY_MATRIX.json"
    prov_path = base / "SOURCE_PROVENANCE.json"
    try:
        matrix = load_json(matrix_path)
    except (OSError, ValueError) as exc:
        sys.stdout.write("audit: unreadable matrix (%s)\n" % exc)
        return 1
    validator = _load_validator()
    # Production CLI: fixture phases are never accepted here.
    matrix_errors = validator.validate_matrix(matrix, allow_fixture=False)
    if matrix_errors:
        for err in matrix_errors:
            sys.stdout.write("audit: invalid matrix: %s\n" % err)
        return 1
    # Certification requires the provenance manifest: a matrix-only run
    # would silently omit the explicit unknowns, so fail closed here.
    # (The audit_matrix() function itself stays lenient for unit use.)
    if not prov_path.exists():
        sys.stdout.write("audit: missing provenance %s "
                         "(certification requires it; matrix-only output refused)\n"
                         % prov_path)
        return 1
    try:
        provenance = load_json(prov_path)
    except (OSError, ValueError) as exc:
        sys.stdout.write("audit: unreadable provenance (%s)\n" % exc)
        return 1
    prov_errors = validator.validate_provenance(provenance, allow_fixture=False)
    if prov_errors:
        for err in prov_errors:
            sys.stdout.write("audit: invalid provenance: %s\n" % err)
        return 1
    # Cross-document identity gate (issue #85 R4-R7), mirroring
    # validator main(): the pair must identify the same phase/issue.
    # (Unreachable when both docs validate strictly -- phase must be
    # R4-00 and issue 85 on each side -- kept as defense in depth.)
    if provenance.get("phase") != matrix.get("phase"):
        sys.stdout.write("audit: cross phase mismatch (provenance %r vs parity %r; "
                         "documents must identify the same phase)\n"
                         % (provenance.get("phase"), matrix.get("phase")))
        return 1
    if provenance.get("issue") != matrix.get("issue"):
        sys.stdout.write("audit: cross issue mismatch (provenance %r vs parity %r; "
                         "documents must identify the same issue)\n"
                         % (provenance.get("issue"), matrix.get("issue")))
        return 1
    report = audit_matrix(matrix, provenance)
    if out is not None:
        # Never allow the report to overwrite either input manifest.
        if _same_path(out, matrix_path) or _same_path(out, prov_path):
            sys.stdout.write("audit: refusing to overwrite input manifest %s\n" % out)
            return 1
        result = _write_report_atomic(out, report)
        if result != 0:
            return result
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
