"""Independent review probes; execute only on GitHub-hosted Actions.

These prove adverse cases accepted by PR44 eb850bf. They are not release
acceptance tests and do not qualify or modify a real device.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
R6 = ROOT / "firmware/t832/r6"
R7 = ROOT / "firmware/t832/r7"
sys.path[:0] = [str(R6), str(R7)]
from nv_recovery_fix import apply_fix
from test_t832_hw_qual import Bundle, verify_small


def qualification_probes(out):
    results = []
    for case in ("rx_decrease_with_tx_increase", "cross_phase_counter_reset",
                 "changed_ieee", "missing_write_hashes", "missing_manifest",
                 "later_unsealed_flash"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write(counters=((7, 10), (8, 9))
                                     if case == "rx_decrease_with_tx_increase"
                                     else ((7, 9), (7, 10)))
            transcript = Path(root) / "transcript.jsonl"
            events = [json.loads(x) for x in transcript.read_text().splitlines()]
            if case == "changed_ieee":
                identities = [x for x in events if x["type"] == "identity"]
                identities[-1]["ieee_sha256"] = hashlib.sha256(b"different-ieee").hexdigest()
            elif case == "missing_write_hashes":
                for event in events:
                    if event["type"] == "neutral_write":
                        event.pop("write_sha256")
                        event.pop("readback_sha256")
            elif case == "later_unsealed_flash":
                events.append({"seq": len(events) + 1, "type": "flash", "phase": "base",
                               "image_sha256": "0" * 64})
            transcript.write_text("".join(json.dumps(x) + "\n" for x in events))
            if case == "missing_manifest":
                assert not (Path(root) / "T832-BUILD-MANIFEST.json").exists()
            verdict = verify_small(root)["verdict"]
            assert verdict == "PASS", (case, verdict)
            results.append({"case": case, "actual_verdict": verdict,
                            "review_expectation": "reject incomplete or contradictory evidence"})
    (out / "qualification-counterexamples.json").write_text(json.dumps(results, indent=2) + "\n")


def driver_probes(sdk, out):
    folder = out / "driver"
    folder.mkdir()
    nv = folder / "nvocmp.c"
    shutil.copy2(sdk / "source/ti/common/nv/nvocmp.c", nv)
    apply_fix(nv)
    source = ROOT / "review/pr44_driver_probe.c"
    results = {}
    for policy in ("lab", "production_assert"):
        build = folder / policy
        build.mkdir()
        if policy == "production_assert":
            header = (R6 / "nv_linux.h").read_text()
            old = '#define NVOCMP_ASSERT(cond,message) do {if(!(cond)){fprintf(stderr,"NV invariant: %s\\n",message);exit(80);}} while(0);'
            assert old in header
            # Match embedded !NVDEBUG: NVOCMP_ASSERT is empty. Change the
            # host assertion policy only, never the recovery algorithm.
            header = header.replace(old, '#define NVOCMP_ASSERT(cond,message) ((void)(cond));')
            (build / "nv_linux.h").write_text(header)
        exe = build / "driver-probe"
        subprocess.run(["gcc", "-std=c11", "-O1", "-g", "-D_GNU_SOURCE", "-DNV_LINUX",
                        "-DNVOCMP_POSIX_MUTEX", "-DDeviceFamily_CC26X4", "-DNVOCMP_NVPAGES=15",
                        "-I" + str(build), "-I" + str(folder), "-I" + str(R6),
                        "-I" + str(sdk / "source"), "-I" + str(sdk / "source/ti/common/nv"),
                        str(source), str(sdk / "source/ti/common/nv/crc.c"),
                        str(R6 / "nv_linux.c"), "-pthread", "-o", str(exe)], check=True)
        if policy == "lab":
            env = dict(os.environ, NVLAB_IMAGE=str(build / "duplicate.bin"))
            result = subprocess.run([str(exe), "duplicate"], env=env, capture_output=True, text=True, check=True)
            duplicate = json.loads(result.stdout)
            assert duplicate["source_crc_status"] != 0
            assert duplicate["destination_crc_status"] == 0
            assert duplicate["destination_active_before"] and not duplicate["destination_active_after"]
            assert duplicate["read_status_after"] != 0
            results["bad_crc_original_disables_good_copy"] = duplicate
        image = build / "unknown-topology.bin"
        env = dict(os.environ, NVLAB_IMAGE=str(image))
        subprocess.run([str(exe), "seed"], env=env, capture_output=True, text=True, check=True)
        raw = bytearray(image.read_bytes())
        assert raw[14 * 2048] == 0xFE
        raw[2048] = 0xFE  # A second structurally valid XDST page: ambiguous topology.
        image.write_bytes(raw)
        before = hashlib.sha256(raw).hexdigest()
        result = subprocess.run([str(exe), "read"], env=env, capture_output=True, text=True)
        after = hashlib.sha256(image.read_bytes()).hexdigest()
        row = {"exit": result.returncode, "nv_changed": before != after,
               "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
        results[policy + "_unknown_topology"] = row
        (out / "driver-counterexamples.json").write_text(json.dumps(results, indent=2) + "\n")
        if policy == "lab":
            assert result.returncode == 80 and before == after
        else:
            state = json.loads(result.stdout)
            assert result.returncode == 0 and before != after
            assert state["init_status"] == 0 and state["read_status"] != 0
    (out / "driver-counterexamples.json").write_text(json.dumps(results, indent=2) + "\n")


def gate_probe(sdk, out):
    original = subprocess.run
    injected = []

    def run(*args, **kwargs):
        command = args[0] if args else kwargs.get("args")
        image = kwargs.get("env", {}).get("NVLAB_IMAGE", "")
        if isinstance(command, list) and len(command) == 2 and command[1] == "write-proof" and image.endswith("/write-proof-1.bin"):
            injected.append(image)
            return subprocess.CompletedProcess(command, 21, "", "review-injected post-cut write rejection\n")
        return original(*args, **kwargs)

    subprocess.run = run
    before_argv = sys.argv[:]
    cli_exit = 0
    capture = io.StringIO()
    try:
        sys.argv = [str(R6 / "run_nv_lab.py"), "--sdk", str(sdk), "--out", str(out / "failed-gate-lab"),
                    "--profiles", "vendor-20240716"]
        with contextlib.redirect_stdout(capture):
            try:
                runpy.run_path(str(R6 / "run_nv_lab.py"), run_name="__main__")
            except SystemExit as error:
                cli_exit = error.code
    finally:
        subprocess.run = original
        sys.argv = before_argv
    report = json.loads(capture.getvalue())
    assert injected and report["all_power_cut_recovery_passed"] is False
    assert cli_exit == 0
    result = {"injected_post_cut_write_rejections": len(injected), "actual_cli_exit": cli_exit,
              "all_power_cut_recovery_passed": report["all_power_cut_recovery_passed"],
              "review_expectation": "nonzero exit for R8 required recovery gate"}
    (out / "gate-counterexample.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True)
    qualification_probes(args.out)
    driver_probes(args.sdk.resolve(), args.out)
    gate_probe(args.sdk.resolve(), args.out)
    print("PR44 review counterexamples reproduced; no release acceptance claimed")
