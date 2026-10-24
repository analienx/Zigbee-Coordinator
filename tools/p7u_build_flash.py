#!/usr/bin/env python3
"""P7U exact-source build/flash clock and fail-closed transaction orchestrator.

T0 is BEFORE tests/compile. Already pinned immutable dependencies are allowed;
every requested APP must be freshly compiled once with clean objects.
No cache aliases and no fake hosted workflow IDs. The hardware dispatcher is an
explicit separate operator, never a shell string or automatic fallback.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
R4 = ROOT / "firmware/slzb-06p7u/r4"
SCOPE = "P7U_R4_KNOWN_INSTALLED_FULL_FINAL_SHA_V1"
BUDGET = {"build":60., "stage":5., "owner_bsl":8., "protected":14.,
          "security":3., "write":55., "final_read":75.,
          "startup_handoff":45., "traffic":10., "margin":15.}
TARGET_SECONDS = sum(BUDGET.values())
# CI source tests are mandatory for every clean build; runtime config must
# not turn acceptance into a no-op Python command.
REQUIRED_SOURCE_TESTS = [
    ["python","-m","pytest","-q",
     "tests/test_p7u_known_r4_fastpath.py",
     "tests/test_p7u_subfive_controller.py",
     "tests/test_p7u_single_candidate_packager.py",
     "tests/test_p7u_ha_fast_preflight.py",
     "tests/test_r4_stock20260311_transition.py",
     "tests/test_p7u_usb_sparse_transition.py",
     "tests/test_p7u_stock20260311_rom_adapter.py",
     "tests/test_p7u_r4_startup_observer.py",
     "tests/test_p7u_r4_operator.py",
     "tests/test_p7u_strict_sector_writer.py"],
]

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class Hold(RuntimeError):
    pass


def require(ok, why):
    if not ok:
        raise Hold("P7U_SUB5_HOLD_" + why)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),allow_nan=False).encode()


def argv_value(argv, flag):
    """Return exactly one nonempty value; no last-argument IndexError."""
    if type(argv) is not list or argv.count(flag)!=1:
        return None
    index=argv.index(flag)
    if index+1>=len(argv) or type(argv[index+1]) is not str:
        return None
    return argv[index+1] or None


def resolve_within(parent, name):
    p = (Path(parent) / name).resolve()
    require(p.is_relative_to(Path(parent).resolve()) and p.is_file(),
            "BUILD_OUTPUT_MISSING_OR_OUTSIDE_WORKER")
    return p


def run_command(argv, *, cwd, seconds, env=None):
    require(type(argv) is list and bool(argv) and
            all(type(v) is str and v for v in argv) and not any(
                "\x00" in v or "\n" in v for v in argv),
            "ARGV_NOT_AN_EXPLICIT_EXECUTABLE_ARRAY")
    start = time.monotonic()
    try:
        p = subprocess.run(argv,cwd=cwd,text=True,capture_output=True,
                           timeout=seconds,env=env,check=False,errors="replace")
    except subprocess.TimeoutExpired as ex:
        raise Hold("COMMAND_TIMEOUT_" + Path(argv[0]).name) from ex
    require(p.returncode == 0, "COMMAND_FAILED_" + Path(argv[0]).name)
    return {"elapsed":round(time.monotonic()-start,3),
            "stdout_tail":p.stdout[-200:], "exit":p.returncode}


def validate_worker(worker, source):
    from p7u_prepared_deps import verify_manifest
    require(worker.get("source_sha") == source and
            worker.get("worker") == "build-1",
            "WORKER_SOURCE_OR_IDENTITY")
    manifest_path = Path(worker["prepared_manifest"])
    receipt = verify_manifest(manifest_path)
    require(worker.get("prepared_identity_sha256") == receipt["identity_sha256"],
            "DEPENDENCY_PIN_CHANGED")
    # Hashes controlled by the runtime configuration are NOT independent
    # trust anchors. Only roots explicitly pinned in a reviewed repository
    # revision may reach compilation or flashing.
    approval=json.loads((ROOT/"tools/p7u_prepared_ti_approved.json").read_bytes())
    require(approval.get("schema")=="p7u-reviewed-ti-prepared-root-v1" and
            type(approval.get("approved")) is list and
            receipt["identity_sha256"] in approval["approved"] and
            all(type(x) is str and HEX64.fullmatch(x)
                for x in approval["approved"]),
            "DEPENDENCY_ROOT_NOT_EXTERNALLY_APPROVED")
    writable=Path(worker["out_dir"]).resolve()
    require(writable.is_dir() and
            str(writable)!=str(manifest_path.parent.resolve()) and
            not writable.is_relative_to(Path(receipt["immutable_root"]).resolve()),
            "WORKER_OUTPUT_MUST_BE_NEW_WRITABLE_LAYER")
    return receipt


def run_worker(worker, source, deadline):
    # Source-specific build is always executed; no prior APP result is reusable.
    prepared=validate_worker(worker,source)
    started=time.monotonic()
    env={**os.environ,"P7U_EXACT_SOURCE_SHA":source,
         "P7U_CLEAN_APP_REQUIRED":"1",
         "P7U_PREPARED_MANIFEST":str(Path(worker["prepared_manifest"]).resolve())}
    command=worker["command"]
    remaining=deadline-started
    require(remaining>0, "CLEAN_BUILD_DEADLINE_EXCEEDED")
    result=run_command(command,cwd=worker["cwd"],
                       seconds=remaining,env=env)
    out=Path(worker["out_dir"])
    artifact=worker["artifacts"]
    a={name:sha(resolve_within(out,rel)) for name,rel in artifact.items()}
    require(set(("app","handoff","elf","source_manifest")) <= set(a),
            "CLEAN_ARTIFACT_SET_INCOMPLETE")
    report=json.loads(resolve_within(out,worker["receipt"]).read_bytes())
    require(report.get("source_sha")==source and
            report.get("prepared_identity_sha256")==prepared["identity_sha256"] and
            report.get("clean_app_build") is True and
            report.get("reused_app_objects") is False and
            report.get("dependency_reuse") == "PINNED_VERIFIED_LIBRARIES_ONLY" and
            report.get("worker")==worker["worker"] and
            all(report.get("hashes",{}).get(k)==v for k,v in a.items()),
            "CLEAN_BUILD_RECEIPT_OR_ARTIFACT_HASH")
    attestation={"worker":worker["worker"],"origin":"PREPARED_LOCAL_LINUX_NOT_GITHUB_RUN",
            "source_sha":source,"dependency_identity":prepared["identity_sha256"],
            "artifact_hashes":a,"compile_time":result["elapsed"],
            "clean_app_build":True,"reused_app_objects":False}
    receipt_path=out/"single-clean-build-attestation.json"
    require(not receipt_path.exists(), "BUILD_ATTESTATION_ALREADY_EXISTS")
    with receipt_path.open("xb") as f:
        f.write(canonical(attestation));f.flush();os.fsync(f.fileno())
    return attestation


def check_clean_build(report):
    require(type(report) is dict and report.get("worker")=="build-1" and
            report.get("clean_app_build") is True and
            type(report.get("dependency_identity")) is str and
            HEX64.fullmatch(report["dependency_identity"]),
            "FRESH_CLEAN_APP_BUILD_REQUIRED")
    hashes=report.get("artifact_hashes",{})
    require(type(hashes) is dict and all(
        type(hashes.get(k)) is str and HEX64.fullmatch(hashes[k])
        for k in ("app","handoff","elf","source_manifest")),
        "BUILT_ARTIFACT_HASHES_REQUIRED")
    return hashes


def verify_operation_result(receipt, source):
    # Only the actual HA executor may assert this; source build is not enough.
    require(receipt.get("schema")=="p7u-sub5-live-result-v1" and
            receipt.get("source_sha")==source and
            receipt.get("installed_source_sha")==source and
            receipt.get("flash_verification")=="ALL88_ROM_SHA" and
            receipt.get("protected_nv_writes")==0 and
            receipt.get("ccfg_writes")==0 and
            receipt.get("state")==9 and receipt.get("owner")=="ORIGINAL_Z2M" and
            receipt.get("exclusive_uart_owner") is True and
            receipt.get("fresh_nonretained_device_reports",0)>=1 and
            receipt.get("observation_seconds",0)>=10 and
            receipt.get("startup_errors",1)==0 and
            receipt.get("owner_start_attempts")==1,
            "LIVE_END_TO_END_ACCEPTANCE_INCOMPLETE")
    return True


def run(config, *, execute=False, clock=time.monotonic):
    t0=clock()
    stage="verify"
    timings={}
    config=dict(config)
    if execute:
        raise Hold("HA_HARDWARE_EXECUTOR_NOT_YET_QUALIFIED")
    source=config.get("source_sha")
    require(isinstance(source,str) and HEX40.fullmatch(source),
            "EXACT_SOURCE_REQUIRED")
    exact=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,
                         capture_output=True,check=True).stdout.strip()
    require(exact==source,"SOURCE_TREE_NOT_SELECTED_COMMIT")
    require(not subprocess.run(["git","status","--porcelain"],cwd=ROOT,
                               text=True,capture_output=True,check=True).stdout,
            "UNCOMMITTED_SOURCE_CANNOT_BE_LABELED_EXACT")
    require(config.get("scope")==SCOPE and
            type(config.get("worker")) is dict, "PROFILE_OR_WORKER_NOT_READY")
    start=clock()
    tests=REQUIRED_SOURCE_TESTS
    require("required_tests" not in config or
            config["required_tests"]==REQUIRED_SOURCE_TESTS,
            "REQUIRED_SOURCE_TESTS_CANNOT_BE_REPLACED")
    with concurrent.futures.ThreadPoolExecutor(max_workers=1+len(tests)) as pool:
        work=pool.submit(run_worker,config["worker"],source,t0+BUDGET["build"])
        test_futures=[pool.submit(run_command,argv,cwd=ROOT,seconds=180.) for argv in tests]
        report=work.result()
        [f.result() for f in test_futures]
    hashes=check_clean_build(report)
    timings["build"] = round(clock()-start,3)
    require(timings["build"]<=BUDGET["build"], "BUILD_BUDGET_EXCEEDED")
    elapsed=clock()-t0
    print(json.dumps({"phase":"SOURCE_QUALIFIED","elapsed":round(elapsed,3),
                      "source":source,"scope":SCOPE,"hashes":hashes},sort_keys=True),flush=True)
    # Bundle and candidate validation run inside T0-T1. The dispatcher is
    # separate and cannot be triggered by a build-only request.
    package_cmd=config.get("package_command")
    accepted_script=str((ROOT/"tools/p7u_single_candidate_packager.py").resolve())
    require(type(package_cmd) is list and len(package_cmd)>=12 and
            package_cmd[0] in ("python","python3") and
            str(Path(package_cmd[1]).resolve())==accepted_script and
            argv_value(package_cmd,"--source")==source and
            argv_value(package_cmd,"--dependency-identity")==report["dependency_identity"] and
            argv_value(package_cmd,"--build-receipt") is not None and
            Path(argv_value(package_cmd,"--build-receipt")).resolve() ==
                (Path(config["worker"]["out_dir"])/"single-clean-build-attestation.json").resolve() and
            argv_value(package_cmd,"--out") is not None and
            Path(argv_value(package_cmd,"--out")).resolve() ==
                Path(config["candidate_bundle"]).resolve(),
            "PACKAGE_COMMAND_NOT_SINGLE_CLEAN_PINNED_BUILDER")
    package_start=clock()
    run_command(package_cmd,cwd=ROOT,seconds=BUDGET["stage"])
    bundle=Path(config["candidate_bundle"])
    sys.path.insert(0,str(R4/"release"))
    from p7u_r4_operator import candidate_verify_fast_single
    candidate_verify_fast_single(bundle,source,hashes,
                                 report["dependency_identity"])
    timings["stage"]=round(clock()-t0-elapsed,3)
    require(timings["stage"]<=BUDGET["stage"],"STAGING_BUDGET_EXCEEDED")
    if not execute:
        return {"status":"OFFLINE_ONE_CLEAN_BUILD_QUALIFIED_NO_FLASH",
                "source_sha":source,"timings":timings,"t0_to_stage":round(clock()-t0,3),
                "under_5_minute_hardware_qualified":False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",required=True,type=Path)
    parser.add_argument("--execute",action="store_true",
                        help="only after separately provisioned, approved HA operator is validated")
    args=parser.parse_args(argv)
    try:
        result=run(json.loads(args.config.read_bytes()),execute=args.execute)
        print(json.dumps(result,indent=2))
        return 0
    except (Hold,ValueError,OSError,KeyError) as e:
        print(json.dumps({"status":"HOLD","reason":str(e)[:250]}))
        return 2


if __name__=="__main__":
    sys.exit(main())
