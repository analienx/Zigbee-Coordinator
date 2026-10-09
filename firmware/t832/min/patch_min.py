"""T832-MIN v4 M1 deterministic patcher — NOT_PRODUCTION_QUALIFIED.

Builds ONE minimal candidate image tree from pristine pinned TI source staged in a
throwaway directory (populated by hosted CI from the pinned upstream refs).

Rules (enforced by tests + hosted CI T2):
  - Deterministic: patches apply in sorted order; manifest is sorted JSON with
    SHA-256 digests; running twice yields identical bytes.
  - Anchors are interface-definition placeholders defined by M1 (not claims
    about TI source text): every patch requires its placeholder literal to
    occur EXACTLY ONCE in the staged target file; otherwise the patcher fails
    closed. TI-side citation of each placeholder against the pinned TI refs
    (TI SDK 6499c3f53fc5fb5806213be695450a7b43fbaf3d and P10 ZNP example
    87ff5b638b632050228a7504f35cf3b95581c278) is pending TI-side confirmation.
  - Provenance: patches pristine TI source only. No R10 code is imported,
    vendored, or invoked. In particular this module never calls ``apply_r6.base``
    and never imports any ``r6``/``apply_r6``/R10 helper.
  - No flash, no hardware, no HA/Z2M changes. Offline file transform only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

STATUS = "NOT_PRODUCTION_QUALIFIED"

MIN_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MIN_ROOT.parents[3]

# (relative_path, anchor_literal, replacement_literal, reason)
PATCHES: list[tuple[str, str, str, str]] = [
    (
        "example/znp/coordinator/app.c",
        "/* TI-SEED-DEVICE-ID: CC2674R10 */",
        "/* T832-MIN-M1: device-id reconciled as CC2674P10; TOOLCHAIN label, see design doc */",
        "TOOLCHAIN-labeled device-id reconciliation; seed CC2674R10 text is not P10 proof.",
    ),
    (
        "example/znp/coordinator/config.h",
        "/* TI-SEED-PRODUCT: product=0 */",
        "/* T832-MIN-M1: product-id left at seed value; host ABI handles product=0 explicitly */",
        "Record product=0 seed value instead of counterfeiting an unsupported feature.",
    ),
    (
        "example/znp/coordinator/nv_config.h",
        "/* TI-SEED-NV-INDEX0 */",
        "/* T832-MIN-M1: NV index0 base agreed by compiler/linker/SysConfig/backend views */",
        "NV integrity: genuine index0 agreement, no app/NVS/CCFG overlap.",
    ),
]

FORBIDDEN_IMPORT_TOKENS = ("apply_r6",)


def _fail(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    from typing import NoReturn

    print(f"patch_min: FAIL: {msg}", file=sys.stderr)
    raise SystemExit(2)


def check_no_r10_imports(tree: Path) -> list[str]:
    """Scan M1 tree for real R10 imports/calls. Returns violations.

    Only executable references count: import/from statements naming an R10
    helper, an actual ``apply_r6.base(...)`` invocation, or a dynamic-loader
    call (``import_module`` / ``__import__`` / ``getattr``) whose target
    resolves to the forbidden token. Matching is fragment-insensitive: quotes,
    plus signs, backticks, and whitespace are stripped before comparing, so
    ``"apply_" + "r6"`` still counts. Docstring prose, comments, and string
    literals that merely NAME the forbidden token (including this scanner's
    own reference table) are not violations — ``*.py`` files are analyzed
    with the ``tokenize`` module and STRING/COMMENT tokens are excluded from
    the code view before matching, while ``*.cjs``/``*.c``/``*.h`` files are
    scanned as raw text.
    """
    import io
    import re
    import tokenize

    violations: list[str] = []
    import_stmt = re.compile(r"^\s*(import|from)\s+.*(apply_r6|\br6\b)")
    call_expr = re.compile(r"apply_r6\s*\.\s*base\s*\(")
    frag_strip = re.compile(r"""['"`\s\+]""")
    loader_names = ("import_module", "__import__", "getattr")
    skip_types = {tokenize.STRING, tokenize.COMMENT, tokenize.NL,
                  tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
                  tokenize.ENDMARKER}
    for path in sorted(tree.rglob("*.py")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        raw_lines = text.splitlines()
        try:
            toks = tokenize.generate_tokens(io.StringIO(text).readline)
            code_lines: dict[int, list[str]] = {}
            for tok in toks:
                if tok.type in skip_types:
                    continue
                code_lines.setdefault(tok.start[0], []).append(tok.string)
        except (tokenize.TokenError, IndentationError, SyntaxError):
            violations.append(f"{path}: UNPARSEABLE")
            continue
        file_hits = 0
        for lineno, parts in sorted(code_lines.items()):
            code = " ".join(parts)
            if import_stmt.search(code) or call_expr.search(code):
                violations.append(f"{path}:{lineno}: {code.strip()}")
                file_hits += 1
                continue
            if any(loader in parts for loader in loader_names):
                raw = raw_lines[lineno - 1] if 0 < lineno <= len(raw_lines) else code
                if "apply_r6" in frag_strip.sub("", raw):
                    violations.append(f"{path}:{lineno}: {code.strip()}")
                    file_hits += 1
        if file_hits == 0:
            all_code = {tok for parts in code_lines.values() for tok in parts}
            if any(loader in all_code for loader in loader_names):
                if "apply_r6" in frag_strip.sub("", text):
                    violations.append(f"{path}: CROSS_LINE_FRAGMENT")
    for ext in ("*.cjs", "*.c", "*.h"):
        for path in sorted(tree.rglob(ext)):
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            hit = False
            for lineno, line in enumerate(text.splitlines(), start=1):
                if "apply_r6" in frag_strip.sub("", line):
                    violations.append(f"{path}:{lineno}: {line.strip()}")
                    hit = True
            if not hit and "apply_r6" in frag_strip.sub("", text):
                violations.append(f"{path}: CROSS_LINE_FRAGMENT")
    return violations


def apply_patches(pristine_dir: Path, out_dir: Path) -> dict:
    pristine_dir = pristine_dir.resolve()
    out_dir = out_dir.resolve()
    if not pristine_dir.is_dir():
        _fail(f"STAGING_MISSING: pristine dir not found: {pristine_dir}")
    manifest_entries: list[dict] = []
    for rel, anchor, replacement, reason in sorted(PATCHES, key=lambda p: p[0]):
        src = pristine_dir / rel
        if not src.is_file():
            _fail(f"ANCHOR_FILE_MISSING: {rel}")
        text = src.read_text(encoding="utf-8")
        count = text.count(anchor)
        if count != 1:
            _fail(f"ANCHOR_NOT_UNIQUE: {rel} anchor occurs {count}x (need exactly 1)")
        patched = text.replace(anchor, replacement)
        dest = out_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(patched, encoding="utf-8")
        digest = hashlib.sha256(patched.encode("utf-8")).hexdigest()
        manifest_entries.append(
            {"file": rel, "anchor_sha256": hashlib.sha256(anchor.encode()).hexdigest(),
             "output_sha256": digest, "reason": reason}
        )
    manifest = {
        "status": STATUS,
        "patcher": "patch_min.py",
        "patches": sorted(manifest_entries, key=lambda e: e["file"]),
    }
    (out_dir / "patch_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def selftest() -> dict:
    """Offline determinism + anchor selftest on synthetic staging. No TI source needed."""
    with tempfile.TemporaryDirectory(prefix="min-pristine-") as p, tempfile.TemporaryDirectory(
        prefix="min-out-a-"
    ) as a, tempfile.TemporaryDirectory(prefix="min-out-b-") as b:
        pristine = Path(p)
        for rel, anchor, _repl, _reason in PATCHES:
            target = pristine / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"header\n{anchor}\nfooter\n", encoding="utf-8")
        man_a = apply_patches(pristine, Path(a))
        man_b = apply_patches(pristine, Path(b))
        if man_a != man_b:
            _fail("NONDETERMINISTIC: two runs disagree")
        # Anchor uniqueness enforcement: duplicate anchor must fail closed.
        dup = pristine / PATCHES[0][0]
        dup.write_text(f"{PATCHES[0][1]}\n{PATCHES[0][1]}\n", encoding="utf-8")
        try:
            apply_patches(pristine, Path(a))
        except SystemExit as exc:
            if exc.code != 2:
                raise
        else:
            _fail("ANCHOR check did not fail closed on duplicate anchor")
    violations = check_no_r10_imports(MIN_ROOT)
    if violations:
        _fail(f"R10_ABSENCE violated: {violations}")
    return man_a


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T832-MIN M1 deterministic patcher (offline).")
    parser.add_argument("--pristine-dir", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--check-r10-absence", action="store_true")
    args = parser.parse_args(argv)
    if args.check_r10_absence:
        violations = check_no_r10_imports(MIN_ROOT)
        if violations:
            print(json.dumps({"status": "FAIL", "violations": violations}, indent=2))
            return 1
        print(json.dumps({"status": "PASS_R10_ABSENT", "qualifier": STATUS}, indent=2))
        return 0
    if args.selftest or (args.pristine_dir is None and args.out_dir is None):
        manifest = selftest()
        print(json.dumps({"status": "PASS_SELFTEST", "qualifier": STATUS,
                           "patches": len(manifest["patches"])}, indent=2))
        return 0
    if not args.pristine_dir or not args.out_dir:
        parser.error("--pristine-dir and --out-dir are both required")
    manifest = apply_patches(args.pristine_dir, args.out_dir)
    print(json.dumps({"status": "PATCHED", "qualifier": STATUS,
                       "patches": len(manifest["patches"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
