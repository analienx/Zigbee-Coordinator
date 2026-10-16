"""Compile pinned, patched TI bodies on a hosted runner with synthetic hardware.

Mutants are applied AFTER extraction so a lexical extraction guard cannot serve
as the mutation oracle. No hardware or household data is accessed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

from apply_b1 import overlay, HERDSMAN_FILE
from patch_management import PINS, EXTRA_PINS, HERDSMAN_PIN, HERDSMAN_PATH
from make_security_harness import SCENARIOS as SECURITY_SCENARIOS, MUTANTS as SECURITY_MUTANTS
from make_management_harness import SCENARIOS as MANAGEMENT_SCENARIOS
from make_boot_harness import SCENARIOS as BOOT_SCENARIOS

SDK_COMMIT = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
SOURCE_PATHS = (
    "source/ti/common/nv/nvocmp.c",
    "source/ti/zstack/startup/main.c",
    "source/ti/zstack/zmac/f8w/zmac.c",
    "source/ti/zstack/stack/zdo/zd_app.c",
    "source/ti/zstack/stack/zdo/zd_sec_mgr.c",
    "source/ti/zstack/stack/sys/zglobals.c",
    "source/ti/common/nv/crc.c",
    "source/ti/zstack/startup/zstackstartup.c",
    "source/ti/zstack/osal/osal_nv.c",
)


def fetch_sources(root):
    for relative in dict.fromkeys((*SOURCE_PATHS, *PINS, *EXTRA_PINS)):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        url = ("https://raw.githubusercontent.com/TexasInstruments/"
               f"simplelink-lowpower-f2-sdk/{SDK_COMMIT}/{relative}")
        for attempt in range(3):
            try:
                with urllib.request.urlopen(url, timeout=60) as response:
                    target.write_bytes(response.read())
                break
            except Exception:
                if attempt == 2:
                    raise
    target = root / HERDSMAN_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    url = (f"https://raw.githubusercontent.com/Koenkk/zigbee-herdsman/{HERDSMAN_PIN}/"
           + HERDSMAN_PATH)
    with urllib.request.urlopen(url, timeout=60) as response:
        target.write_bytes(response.read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Hosted acceptance requires GitHub Actions")
    b1 = Path(__file__).resolve().parents[1]
    work = args.out.resolve()
    work.mkdir(parents=True, exist_ok=True)
    sdk = work / "sdk"
    fetch_sources(sdk)
    receipt = overlay(sdk, b1)
    source_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True).strip()
    if source_sha != os.environ["B1_SOURCE_SHA"]:
        raise RuntimeError("Checked-out HEAD differs from requested source SHA")
    receipt.update(source_sha=source_sha, classification="HOSTED_SYNTHETIC")
    (work / "overlay.json").write_text(json.dumps(receipt, indent=2) + "\n")
    results = []
    environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                       UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")

    def run(command, **kwargs):
        return subprocess.run([str(arg) for arg in command], env=environment,
                              text=True, timeout=120, **kwargs)

    def compile_c(source, name, *, admission=True, management=False):
        binary = work / name
        flags = (["-DB1_MANAGEMENT_ENABLED", "-DB1_MANAGEMENT_HOST",
                  "-DB1_BUILD_DIGEST_BYTES=0x12,0x34,0x56,0x78"] if management else [])
        run(["gcc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-parameter", "-fsanitize=address,undefined",
             "-fno-omit-frame-pointer", "-fno-pie", "-no-pie", "-I", b1,
             *flags, source, *([b1 / "b1_admission.c"] if admission else []),
             *([b1 / "b1_management.c"] if management else []),
             "-o", binary], check=True)
        return binary

    def positive(binary, arguments=()):
        completed = run([binary, *arguments], capture_output=True)
        print(completed.stdout, end="", flush=True)
        if completed.returncode:
            print(completed.stderr, file=sys.stderr)
            raise RuntimeError(f"Healthy/fault oracle failed: {binary.name} {arguments}")
        results.append({"test": binary.name, "arguments": arguments,
                        "result": "PASS", "stdout": completed.stdout.strip()})

    def mutation(source, old, new, name, evidence, arguments=(), *, admission=True, management=False):
        text = source.read_text()
        if text.count(old) != 1:
            raise RuntimeError(f"Mutation anchor is not unique: {name}")
        mutated = work / f"{name}.c"
        mutated.write_text(text.replace(old, new, 1))
        binary = compile_c(mutated, name, admission=admission, management=management)
        completed = run([binary, *arguments], capture_output=True)
        if completed.returncode == 0 or evidence not in completed.stderr:
            raise RuntimeError(f"Mutant did not fail its intended oracle: {name}: "
                               + completed.stdout + completed.stderr)
        print(f"B1_COMPILED_MUTANT_REJECTED {name}", flush=True)
        results.append({"test": name, "result": "MUTANT_REJECTED",
                        "intended_failure": evidence,
                        "generated_c_sha256": hashlib.sha256(mutated.read_bytes()).hexdigest()})

    positive(compile_c(b1 / "tests/test_admission.c", "admission"))
    harnesses = (
        ("nvocmp_init", "make_nvocmp_init_harness.py", SOURCE_PATHS[0], ((),)),
        ("zmac", "make_zmac_harness.py", SOURCE_PATHS[2], ((),)),
        ("zdapp", "make_zdapp_harness.py", SOURCE_PATHS[3], tuple((name,) for name in (
            "new_empty", "positive", "generic", "missing_key", "zero_key",
            "missing_row", "overflow", "write_fail", "readback", "read_fail",
            "wrong_generic_identity"))),
        ("security", "make_security_harness.py", SOURCE_PATHS[4],
         tuple((name,) for name in SECURITY_SCENARIOS)),
        ("startup_security", "make_startup_security_harness.py", SOURCE_PATHS[7], ((),)),
        ("osal_nv", "make_osal_nv_harness.py", SOURCE_PATHS[8], ((),)),
    )
    generated = {}
    for name, generator, relative, scenarios in harnesses:
        source = work / f"actual_{name}.c"
        run([sys.executable, b1 / "tools" / generator,
             "--source", sdk / relative, "--output", source], check=True)
        generated[name] = source
        binary = compile_c(source, name, admission=(name != "security"))
        for scenario in scenarios:
            positive(binary, scenario)

    for variant in ("sem", "posix"):
        name = "nvocmp_init_" + variant
        source = work / f"actual_{name}.c"
        run([sys.executable, b1 / "tools/make_nvocmp_init_harness.py",
             "--source", sdk / SOURCE_PATHS[0], "--output", source,
             "--rtos", variant], check=True)
        generated[name] = source
        positive(compile_c(source, name))

    for name, generator, flag, input_path, scenarios in (
        ("management", "make_management_harness.py", "--sdk", sdk, MANAGEMENT_SCENARIOS),
        ("boot", "make_boot_harness.py", "--source", sdk / SOURCE_PATHS[1], BOOT_SCENARIOS),
    ):
        source = work / f"actual_{name}.c"
        run([sys.executable, b1 / "tools" / generator,
             flag, input_path, "--output", source], check=True)
        generated[name] = source
        binary = compile_c(source, name, admission=(name == "management"), management=True)
        for scenario in scenarios:
            positive(binary, (scenario,))

    backend_scenarios = ("healthy", "write_ok", "erase_ok", "crc_corrupt", "header_corrupt",
        "init_read_fail", "init_repair", "init_scan_corrupt", "init_page_signature",
        "init_page_version", "init_page_state", "read_fail", "read_bounds",
        "write_fail", "write_positive_error", "write_bounds", "low_write", "erase_fail",
        "erase_positive_error", "erase_bounds", "low_erase", "scan_corrupt", "scan_length", "runtime_crc")
    for variant in ("slow", "fast"):
        name = "nv_backend_" + variant
        source = work / f"actual_{name}.c"
        run([sys.executable, b1 / "tools/make_nv_backend_harness.py",
             "--source", sdk / SOURCE_PATHS[0], "--crc-source", sdk / SOURCE_PATHS[6],
             "--output", source, *(["--fast-item"] if variant == "fast" else [])], check=True)
        generated[name] = source
        binary = compile_c(source, name)
        for scenario in backend_scenarios:
            positive(binary, (scenario,))

    source = work / "actual_nv_authorized_blank.c"
    run([sys.executable, b1 / "tools/make_nv_backend_harness.py",
         "--source", sdk / SOURCE_PATHS[0], "--crc-source", sdk / SOURCE_PATHS[6],
         "--output", source, "--factory-authorized"], check=True)
    generated["nv_authorized_blank"] = source
    positive(compile_c(source, "nv_authorized_blank"), ("authorized_blank",))

    # Real TI startup/OSAL wrappers: genuine compiled bypass mutations.
    # A missing pre-MAC gate must reach the MAC boundary and violate the
    # healthy/fault ordering assertion, not merely fail a text regex.
    mutation(generated["startup_security"],
             "if (!b1_sec_validate_restored()) return;",
             "if (!b1_sec_validate_restored() && 0) return;", "mutant_startup_pre_mac",
             "checks==1 && mac_calls==0 && sem_calls==0")
    # Regression to the donor's only-check-NVINTF_FAILURE would silently
    # accept other non-success read statuses as valid data.
    mutation(generated["osal_nv"],
             "if ( pZStackCfg->nvFps.readItem( nvId, ndx, len, buf ) != NVINTF_SUCCESS )",
             "if ( pZStackCfg->nvFps.readItem( nvId, ndx, len, buf ) == NVINTF_FAILURE )",
             "mutant_osal_nv_nonzero_status",
             "osal_nv_read(7,0,1,&value)==NV_OPER_FAILED")

    mutation(generated["zmac"],
             "if (b1_nv_runtime_hold_active()) return MAC_NO_RESOURCES;",
             "if (0) return MAC_NO_RESOURCES;", "mutant_zmac_data_hold",
             "ZMacDataReqSec(&req, NULL) == MAC_NO_RESOURCES")
    mutation(generated["zmac"],
             "if (b1_nv_runtime_hold_active()) return;",
             "if (0) return;", "mutant_zmac_no_data_hold", "mock_mac_submissions == 2")
    mutation(generated["nvocmp_init"],
             "if (NVOCMP_nvsHandle == NULL)", "if (0)",
             "mutant_nvs_null", "handle != NULL")
    mutation(generated["nvocmp_init"],
             "NVOCMP_nvsAttrs.sectorSize != B1_NV2_PAGE_SIZE ||\n"
             "            NVOCMP_nvsAttrs.regionSize != B1_NV2_REGION_SIZE ||",
             "0 ||\n            NVOCMP_nvsAttrs.regionSize != B1_NV2_REGION_SIZE ||",
             "mutant_nvs_zero_sector", "division by zero")
    mutation(generated["nvocmp_init"],
             "if (NVOCMP_gMutexPri == NULL)", "if (0)",
             "mutant_nvs_mutex", "NVOCMP_initNvApi(NULL) == NVINTF_FAILURE")
    mutation(generated["management"],
             "uint8_t b1_action = b1_management_mt_filter(pBuf, b1_reply, &b1_error);",
             "uint8_t b1_action = b1_management_mt_filter(pBuf, b1_reply, &b1_error);\n"
             "    b1_action = B1_MT_CONTINUE;", "mutant_hold_command_dispatch",
             "sent==count && forwarded==0 && mutations==0", ("hold_nv",), management=True)
    mutation(generated["boot"],
             "goto b1_start_npi; /* no stack task, original NPI owner */",
             "; /* mutant permits unsafe stack initialization */", "mutant_boot_stack_hold",
             "stack_calls==", ("nv_failure",), admission=False, management=True)
    for name, (scenario, before, after) in SECURITY_MUTANTS.items():
        evidence = {"aps_publish": "ApsLinkKeyRAMEntry[0].txFrmCntr==0",
                    "checkpoint_pending": "held && pending", "counter_wrap": "result==ZSecNoKey",
                    "readback": "ApsLinkKeyRAMEntry[0].txFrmCntr==0"}[name]
        mutation(generated["security"], before, after, "mutant_security_" + name,
                 evidence, (scenario,), admission=False)
    report = {"schema": "r4-b1-hosted-source-tests-v1", "source_sha": source_sha,
              "sdk_commit": SDK_COMMIT, "classification": "HOSTED_SYNTHETIC",
              "generated_c": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for name, path in generated.items()}, "results": results,
              "physical_rf": "NOT_MEASURED", "production_nv": "STOCK_NV_LAYOUT_UNKNOWN"}
    (work / "test-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print("B1_HOSTED_SOURCE_AND_COMPILED_MUTATION_TESTS_PASS", flush=True)


if __name__ == "__main__":
    main()
