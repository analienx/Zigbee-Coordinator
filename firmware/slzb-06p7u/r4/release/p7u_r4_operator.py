"""Fail-closed SLZB-06P7U R4 deployment orchestrator.

A single CLI for GitHub artifacts, private read-only capture, offline security
preflight, bounded sector flash and a one-shot startup. Hardware primitives
remain the audited scripts/ROM writer; this tool NEVER implements flash I/O.
No WSL, no retry/resume of incomplete hardware work and no MQTT auto-start.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

FLASH_BYTES = 720896
BOOT = 0xAC000
STAGES = ("capture", "prepare", "flash", "startup")
SCRIPTS = {
    "capture": "capture_current_once.py",
    "prepare": "prepare_upgrade_once.py",
    "flash": "flash_upgrade_once.py",
    "startup": "startup_once.py",
}

class Stop(RuntimeError):
    pass

def require(ok: bool, message: str) -> None:
    if not ok:
        raise Stop(message)

def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()

def read_json(path: Path) -> dict:
    require(path.is_file(), "MISSING_RECEIPT: " + path.name)
    result = json.loads(path.read_bytes())
    require(type(result) is dict, "INVALID_RECEIPT: " + path.name)
    return result

def candidate_verify(folder: Path, expected_source: str) -> dict:
    require(folder.is_dir(), "MISSING_CANDIDATE_DIRECTORY")
    c = read_json(folder / "candidate.json")
    require(c.get("source_sha") == expected_source and
            len(expected_source) == 40, "CANDIDATE_SOURCE_MISMATCH")
    require(c.get("flash_authorized") is False and
            c.get("hardware_boot_qualified") is False,
            "PUBLIC_CANDIDATE_IS_NOT_A_FLASH_APPROVAL")
    require(len(c.get("replicas", [])) == 2, "TWO_NATIVE_REPLICAS_REQUIRED")
    require(c["replicas"][0]["app_hex_sha256"] ==
            c["replicas"][1]["app_hex_sha256"] == c["app_hex_sha256"],
            "NONREPRODUCIBLE_NATIVE_APP")
    require(c["replicas"][0]["handoff_sha256"] ==
            c["replicas"][1]["handoff_sha256"] == c["handoff_sha256"],
            "NONREPRODUCIBLE_BOOT_HANDOFF")
    for name, digest in c["files"].items():
        p = folder / name
        require(p.resolve().is_relative_to(folder.resolve()) and p.is_file(),
                "MISSING_OR_UNSAFE_ARTIFACT: " + name)
        require(sha(p.read_bytes()) == digest, "ARTIFACT_HASH_CHANGED: " + name)
    return c

def capture_verify(private: Path) -> dict:
    p = private / "readback-1"
    c = read_json(p / "capture-receipt.json")
    require(c.get("schema") == "r4-p7u-capture-pair-v1" and
            c.get("status") == "DUPLICATE_READBACK_MATCH" and
            c.get("flash_bytes") == FLASH_BYTES and
            c.get("capture_origin") ==
                "SUPPLIED_ROM_ADAPTER_REQUIRES_OPERATOR_PROVENANCE" and
            all(c.get(k) is False for k in
                ("nv_compatibility_verified", "reset_issued",
                 "flash_performed", "return_to_stock_verified")),
            "CAPTURE_RECEIPT_FAILED")
    first = (p / "current-pass1.bin").read_bytes()
    second = (p / "current-pass2.bin").read_bytes()
    require(len(first) == FLASH_BYTES and first == second,
            "CAPTURE_PASSES_DIFFER")
    require(sha(first) == c.get("pass1_sha256") == c.get("pass2_sha256"),
            "CAPTURE_HASH_CHANGED")
    return c

def prepare_verify(private: Path, candidate: dict) -> dict:
    capture = capture_verify(private)
    receipt = read_json(private / "security-receipt-validated.json")
    require(receipt.get("status") == "PASS_RETAINED_SECURITY_OFFLINE_ONLY" and
            receipt.get("flash_authorized") is False,
            "RETAINED_SECURITY_NOT_ADMITTED")
    require(receipt.get("capture_sha256") == capture["pass1_sha256"],
            "SECURITY_CAPTURE_STALE")
    plan = read_json(private / "frozen-plan.json")
    admission = read_json(private / "admission-input.json")
    require(admission.get("new_source_sha") == candidate["source_sha"] and
            admission.get("plan_sha256") == plan.get("plan_sha256") and
            admission.get("current_capture_sha256") == capture["pass1_sha256"],
            "PREPARE_INPUTS_CHANGED")
    order = plan.get("program_order")
    require(type(order) is list and len(order) <= 25 and len(order) >= 2 and
            len(set(order)) == len(order) and
            order[-2:] == [0, BOOT] and
            all(type(a) is int and (0 <= a < 0xA4000 or a == BOOT) and
                a % 8192 == 0 for a in order),
            "UNSAFE_OR_CHANGED_SECTOR_ALLOWLIST")
    require(admission.get("nv_touched") is False, "NV_WRITE_PROHIBITED")
    return plan

def flash_verify(private: Path, candidate: dict) -> dict:
    plan = prepare_verify(private, candidate)
    result = read_json(private / "flash-result.json")
    require(result.get("status") == "APP_AND_AC000_VERIFIED_STILL_IN_BSL" and
            result.get("nv_touched") is False and
            result.get("ccfg_touched") is False and
            result.get("reset_issued") is False and
            result.get("automatic_rollback") is False,
            "FLASH_VERIFICATION_MISSING")
    verified = result.get("written_sectors")
    require(type(verified) is list and len(set(verified)) == len(verified) and
            set(verified).issubset(set(plan["program_order"])) and
            BOOT in verified,
            "FLASH_RESULT_SECTOR_MISMATCH")
    return result

def startup_verify(private: Path, candidate: dict) -> dict:
    flash_verify(private, candidate)
    result = read_json(private / "startup-result.json")
    require(result.get("source") == candidate["source_sha"] and
            result.get("status") == "COORDINATOR_STATE9_MARKER_PASS" and
            result.get("post_state") == 9 and
            result.get("attempts") == 1,
            "COORDINATOR_STATE9_NOT_CONFIRMED")
    return result

def stage_state(private: Path, candidate: dict) -> dict[str, str]:
    result = {}
    checks = {
        "capture": lambda: capture_verify(private),
        "prepare": lambda: prepare_verify(private, candidate),
        "flash": lambda: flash_verify(private, candidate),
        "startup": lambda: startup_verify(private, candidate),
    }
    sentinels = {
        "capture": "capture-bsl-request.json",
        "prepare": "security-receipt-validated.json",
        "flash": "flash-journal.jsonl",
        "startup": "app-boot-request.json",
    }
    for stage in STAGES:
        try:
            checks[stage]()
            result[stage] = "PASS"
        except (Stop, OSError, ValueError, KeyError, TypeError) as error:
            if (private / sentinels[stage]).exists():
                result[stage] = "INCOMPLETE_NO_AUTOMATIC_RETRY: " + str(error)
            else:
                result[stage] = "NOT_COMPLETED: " + str(error)
    return result

def script_check(private: Path, stage: str, source: str) -> Path:
    p = private / SCRIPTS[stage]
    require(p.is_file(), "MISSING_PRIVATE_ONE_SHOT_SCRIPT: " + p.name)
    # Each private script embeds the source pin, rather than resolving HEAD.
    require(source in p.read_text(encoding="utf-8"),
            "PRIVATE_SCRIPT_SOURCE_NOT_PINNED: " + p.name)
    return p

def run_through(private: Path, folder: Path, source: str, target: str,
                *, allow_bsl: bool, allow_flash: bool, allow_boot: bool) -> None:
    c = candidate_verify(folder, source)
    progress = stage_state(private, c)
    for step in STAGES[:STAGES.index(target) + 1]:
        if progress[step] == "PASS":
            print("SKIP_VERIFIED", step, flush=True)
            continue
        require(progress[step].startswith("NOT_COMPLETED:"),
                "STOP_INCOMPLETE_ONE_SHOT: " + step + " " + progress[step])
        idx = STAGES.index(step)
        if idx:
            prior = STAGES[idx - 1]
            require(progress[prior] == "PASS",
                    "PREREQUISITE_UNVERIFIED: " + prior)
        if step == "capture":
            require(allow_bsl, "EXPLICIT_BSL_MODE_ENTRY_REQUIRED")
        if step == "flash":
            require(allow_flash, "EXPLICIT_APP_AC000_FLASH_APPROVAL_REQUIRED")
            prepare_verify(private, c)
            require((private / "owner-request.json").is_file(),
                    "FROZEN_OWNER_APPROVAL_MISSING")
        if step == "startup":
            require(allow_boot, "EXPLICIT_BOOT_AND_ONE_START_APPROVAL_REQUIRED")
            flash_verify(private, c)
        script = script_check(private, step, source)
        print("RUN_ONE_SHOT", step, script.name, flush=True)
        completed = subprocess.run([sys.executable, "-u", str(script)],
                                   cwd=private, check=False)
        require(completed.returncode == 0,
                "STOP_AFTER_FAILED_STAGE_NO_RETRY: " + step)
        progress = stage_state(private, c)
        require(progress[step] == "PASS",
                "STOP_STAGE_RETURNED_WITHOUT_RECEIPT: " + step + " " + progress[step])
        print("VERIFIED", step, flush=True)
    print("REQUESTED_STAGES_COMPLETED", target, flush=True)

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--private", required=True, type=Path)
    parser.add_argument("--source", required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("status")
    run = commands.add_parser("run")
    run.add_argument("--through", required=True, choices=STAGES)
    run.add_argument("--allow-bsl", action="store_true")
    run.add_argument("--allow-flash", action="store_true")
    run.add_argument("--allow-boot", action="store_true")
    args = parser.parse_args(argv)
    try:
        c = candidate_verify(args.candidate, args.source)
        require(args.private.is_dir(), "MISSING_PRIVATE_WORKSPACE")
        if args.action == "status":
            print(json.dumps({"source_sha": args.source, "github_run_id": c["github_run_id"],
                              "stages": stage_state(args.private, c)}, indent=2))
        else:
            run_through(args.private, args.candidate, args.source, args.through,
                        allow_bsl=args.allow_bsl, allow_flash=args.allow_flash,
                        allow_boot=args.allow_boot)
        return 0
    except (Stop, OSError, KeyError, ValueError, TypeError) as error:
        print("R4_OPERATOR_HOLD:", str(error), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
