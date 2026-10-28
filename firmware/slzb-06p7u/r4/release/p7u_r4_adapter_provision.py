"""Offline provisioner for one-use, reviewed, source-bound P7U R4 adapters.

It never talks to the radio or HA. Caller supplies a privately reviewed,
hash-pinned recipe and a directory containing independently reviewed old
templates. All four generated outputs are verified BEFORE writing anything.
Never regenerate over hardware receipts, a one-shot lock or an existing file.
Private templates, board IDs, counters and backups are never copied into Git.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

STAGES = ("capture", "prepare", "flash", "startup")
NAMES = {
    "capture": "capture_current_once.py",
    "prepare": "prepare_upgrade_once.py",
    "flash": "flash_upgrade_once.py",
    "startup": "startup_once.py",
}
SENTINELS = ("capture-bsl-request.json", "readback-1",
             "security-receipt-validated.json", "frozen-plan.json",
             "admission.json", "admission-input.json", "owner-request.json",
             "programming-bsl-entry.json", "flash-journal.jsonl",
             "flash-result.json", "app-boot-request.json",
             "retained-startup-request.json", "startup-result.json",
             ".r4-operator-one-shot-lock", "operator-adapters.json")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


class ProvisionHold(RuntimeError):
    pass


def check(ok, why):
    if not ok:
        raise ProvisionHold(why)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def render(private: Path, template_dir: Path, recipe_path: Path,
           expected_recipe_sha: str, source: str, candidate: dict):
    """Return fully validated candidate bytes; no private output yet."""
    check(bool(HEX64.fullmatch(expected_recipe_sha)), "REVIEWED_RECIPE_HASH_REQUIRED")
    check(bool(HEX40.fullmatch(source)), "EXACT_SOURCE_REQUIRED")
    source_recipe = recipe_path.read_bytes()
    check(digest(source_recipe) == expected_recipe_sha, "REVIEWED_RECIPE_CHANGED")
    recipe = json.loads(source_recipe)
    check(type(recipe) is dict and recipe.get("schema") == "p7u-r4-one-use-adapters-v1",
          "UNSUPPORTED_ADAPTER_RECIPE")
    check(recipe.get("source_sha") == source and
          recipe.get("github_run_id") == candidate["github_run_id"] and
          recipe.get("candidate_sha256") == digest(canonical(candidate)),
          "ADAPTER_CANDIDATE_BINDING_MISMATCH")
    stages = recipe.get("stages")
    check(type(stages) is dict and set(stages) == set(STAGES),
          "ALL_FOUR_REVIEWED_TEMPLATES_REQUIRED")
    check(private.is_dir() and template_dir.is_dir(), "PRIVATE_OR_TEMPLATE_DIR_MISSING")
    check(not any((private / name).exists() for name in SENTINELS),
          "PRIVATE_TRANSACTION_OR_SEAL_ALREADY_EXISTS")
    check(not any((private / name).exists() for name in NAMES.values()),
          "PRIVATE_SCRIPT_ALREADY_EXISTS_NO_OVERWRITE")
    rendered = {}
    for stage in STAGES:
        entry = stages[stage]
        check(type(entry) is dict, "REVIEWED_STAGE_ENTRY_INVALID")
        before = entry.get("template_sha256")
        after = entry.get("output_sha256")
        edits = entry.get("replacements")
        check(bool(HEX64.fullmatch(before or "")) and
              bool(HEX64.fullmatch(after or "")) and
              type(edits) is list and 1 <= len(edits) <= 16,
              "REVIEWED_STAGE_DIGEST_OR_REPLACEMENTS_INVALID")
        template = template_dir / NAMES[stage]
        check(template.resolve().is_relative_to(template_dir.resolve()) and
              template.is_file() and not template.is_symlink(),
              "UNSAFE_TEMPLATE_PATH")
        raw = template.read_bytes()
        check(digest(raw) == before, "TEMPLATE_SHA256_CHANGED_" + stage)
        try:
            updated = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProvisionHold("TEMPLATE_NOT_UTF8_" + stage) from exc
        for change in edits:
            check(type(change) is dict and set(change) == {"old", "new", "count"} and
                  isinstance(change["old"], str) and len(change["old"]) > 0 and
                  isinstance(change["new"], str) and
                  type(change["count"]) is int and 1 <= change["count"] <= 16,
                  "TEMPLATE_REPLACEMENT_INVALID_" + stage)
            check(updated.count(change["old"]) == change["count"],
                  "TEMPLATE_REPLACEMENT_ANCHOR_CHANGED_" + stage)
            updated = updated.replace(change["old"], change["new"])
        output = updated.encode("utf-8")
        check(source.encode() in output and digest(output) == after,
              "REVIEWED_ADAPTER_OUTPUT_MISMATCH_" + stage)
        rendered[NAMES[stage]] = output
    return rendered


def provision(private: Path, template_dir: Path, recipe_path: Path,
              expected_recipe_sha: str, source: str, candidate: dict):
    outputs = render(private, template_dir, recipe_path, expected_recipe_sha,
                     source, candidate)
    seal = {
        "schema": "p7u-r4-operator-adapters-v1",
        "source_sha": source,
        "candidate_sha256": digest(canonical(candidate)),
        "reviewed_recipe_sha256": expected_recipe_sha,
        "scripts_sha256": {name: digest(blob) for name, blob in outputs.items()},
    }
    # Every output is prevalidated, and O_EXCL refuses existing paths. A
    # mid-write interruption leaves partial files: never replace them in place.
    for name, blob in outputs.items():
        with (private / name).open("xb") as file:
            file.write(blob)
            file.flush()
            os.fsync(file.fileno())
    with (private / "operator-adapters.json").open("xb") as file:
        file.write(canonical(seal))
        file.flush()
        os.fsync(file.fileno())
    return seal


def verify_seal(private: Path, source: str, candidate: dict | None = None):
    path = private / "operator-adapters.json"
    if not path.exists():
        return None  # Historical, manually audited operations remain valid.
    seal = json.loads(path.read_bytes())
    check(seal.get("schema") == "p7u-r4-operator-adapters-v1" and
          seal.get("source_sha") == source, "ADAPTER_SEAL_SOURCE_CHANGED")
    if candidate is not None:
        check(seal.get("candidate_sha256") == digest(canonical(candidate)),
              "ADAPTER_SEAL_CANDIDATE_CHANGED")
    expected = seal.get("scripts_sha256")
    check(type(expected) is dict and set(expected) == set(NAMES.values()),
          "ADAPTER_SEAL_INCOMPLETE")
    for name, expected_sha in expected.items():
        check(bool(HEX64.fullmatch(expected_sha)) and
              digest((private / name).read_bytes()) == expected_sha,
              "REVIEWED_ONE_SHOT_SCRIPT_CHANGED_" + name)
    return seal
