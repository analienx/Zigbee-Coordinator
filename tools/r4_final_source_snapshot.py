#!/usr/bin/env python3
"""Publish the *final* reviewable TI C source delta used by the R4 native build.

The R4 build composes several immutable overlays.  This tool captures their
combined effect after the last overlay, including new C/H files that ordinary
``git diff`` would otherwise omit.  Running it again after linking detects a
source mutation between the review snapshot and the native build.

This is provenance, not a hardware, NV or security qualification gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess


TI_PIN = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
PATCH = "r4-final-ti-source.patch"
MANIFEST = "r4-final-ti-source-manifest.json"
SOURCE_SUFFIXES = {".c", ".h", ".s", ".S", ".asm", ".inc"}
MANDATORY = {
    "source/ti/common/nv/nvocmp.c",
    "source/ti/common/nv/b1_management.c",
    "source/ti/common/nv/b1_management.h",
    "source/ti/common/nv/b1_admission.c",
    "source/ti/common/nv/b1_admission.h",
    "source/ti/common/nv/nv4_readonly_admission.c",
    "source/ti/common/nv/nv4_readonly_admission.h",
    "source/ti/zstack/stack/zdo/zd_app.c",
    "source/ti/zstack/stack/zdo/zd_sec_mgr.c",
    "source/ti/zstack/stack/api/zstacktask.c",
    "source/ti/zstack/npi/npi_task.c",
    "source/ti/zstack/npi/npi_tl_uart.c",
    "source/ti/zstack/mt/mt_sys.c",
}


def deny(message: str) -> None:
    raise ValueError("R4_FINAL_SOURCE_SNAPSHOT_" + message)


def git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(["git", "-C", str(root), *args],
                                       stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        raise ValueError("R4_FINAL_SOURCE_SNAPSHOT_GIT_FAILED") from exc


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def paths(raw: bytes, *, ignore_non_source: bool = False) -> list[str]:
    result = [part.decode("utf-8") for part in raw.split(b"\0") if part]
    if ignore_non_source:
        result = [name for name in result if Path(name).suffix in SOURCE_SUFFIXES]
    for name in result:
        if (not name.startswith("source/ti/") or ".." in Path(name).parts or
                Path(name).suffix not in SOURCE_SUFFIXES):
            deny("UNEXPECTED_SOURCE_PATH_" + name)
    return result


def capture(sdk: Path, source_sha: str, *, required: set[str] = MANDATORY,
            sdk_pin: str = TI_PIN):
    sdk = sdk.resolve(strict=True)
    if (git(sdk, "rev-parse", "HEAD").decode().strip() != sdk_pin or
            not re.fullmatch(r"[0-9a-f]{40}", source_sha)):
        deny("SOURCE_OR_TI_COMMIT_DRIFT")
    # Include generated B1/NV4 C/H translation units in the SAME patch as the
    # edits to tracked TI files.  Intent-to-add affects only this disposable
    # checkout's index; it does not stage content or modify source bytes.
    untracked = paths(git(sdk, "ls-files", "--others", "--exclude-standard", "-z",
                          "--", "source/ti"), ignore_non_source=True)
    if untracked:
        git(sdk, "add", "-N", "--", *untracked)
    deleted = git(sdk, "diff", "--name-only", "-z", "--diff-filter=D", "--",
                  "source/ti")
    if deleted:
        deny("SOURCE_DELETION")
    changed = paths(git(sdk, "diff", "--name-only", "-z", "--", "source/ti"))
    if len(changed) > 80 or not required.issubset(changed):
        deny("EXPECTED_SOURCE_FILES_MISSING_OR_SCOPE_TOO_LARGE")
    entries = []
    for name in sorted(changed):
        target = sdk / name
        mode = target.lstat().st_mode
        if not stat.S_ISREG(mode) or target.is_symlink() or target.stat().st_nlink != 1:
            deny("NOT_PRIVATE_REGULAR_SOURCE_" + name)
        data = target.read_bytes()
        if len(data) > 2_000_000:
            deny("SOURCE_FILE_TOO_LARGE")
        original = subprocess.run(["git", "-C", str(sdk), "cat-file", "-e", "HEAD:" + name],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        entries.append({"path": name, "sha256": digest(data), "bytes": len(data),
                        "new_file": original.returncode != 0})
    patch = git(sdk, "diff", "--binary", "--no-ext-diff", "--", "source/ti")
    if not patch or len(patch) > 8_000_000:
        deny("PATCH_EMPTY_OR_TOO_LARGE")
    report = {
        "schema": "r4-p7u-final-ti-source-snapshot-v1",
        "firmware_source_sha": source_sha,
        "ti_sdk_sha": sdk_pin,
        "patch_filename": PATCH,
        "patch_sha256": digest(patch),
        "changed_files": entries,
        "source_changed_files_count": len(entries),
        "source_reviewable": True,
        "compiled_source_unchanged_after_snapshot": "REQUIRES_POST_LINK_VERIFICATION",
        "flash_authorized": False,
    }
    return patch, report


def run(sdk: Path, output: Path, source_sha: str, verify: Path | None = None, *,
        required: set[str] = MANDATORY, sdk_pin: str = TI_PIN):
    patch, report = capture(sdk, source_sha, required=required, sdk_pin=sdk_pin)
    if verify is not None:
        if (verify.is_symlink() or not verify.is_file() or
                verify.name != MANIFEST or not (verify.parent / PATCH).is_file()):
            deny("VERIFICATION_INPUT_INVALID")
        prior = json.loads(verify.read_bytes())
        if prior != report or digest((verify.parent / PATCH).read_bytes()) != report["patch_sha256"]:
            deny("SOURCE_CHANGED_SINCE_SNAPSHOT")
        return report
    if (output.is_symlink() or not output.is_dir() or
            (output / PATCH).exists() or (output / MANIFEST).exists()):
        deny("OUTPUT_MUST_BE_UNUSED_EXISTING_DIRECTORY")
    (output / PATCH).write_bytes(patch)
    (output / MANIFEST).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--verify-manifest", type=Path)
    args = parser.parse_args()
    receipt = run(args.sdk, args.out_dir, args.source_sha, args.verify_manifest)
    print(json.dumps({"patch_sha256": receipt["patch_sha256"],
                      "files": receipt["source_changed_files_count"],
                      "flash_authorized": False}))


if __name__ == "__main__":
    main()
