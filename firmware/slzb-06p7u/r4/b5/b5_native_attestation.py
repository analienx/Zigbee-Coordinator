"""R4 B5 OFFLINE composite image/source attestation (not on-device identity).

Runs only AFTER B0 native image/CCFG audit, B1 native ELF seal and B4 F0/F2
real ELF symbol audits. Does not parse secrets, NV content, or open a device.
A SHA-256 receipt is evidence of CI provenance, NOT authentication/attestation
by radio firmware and NOT approval for installation/flashing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

B1_SHA = "a514c194ea0d94b5d38b28c7b07ca5caba9aeffd"
TI_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
MT = "source/ti/zstack/mt/mt.c"
SYS = "source/ti/zstack/mt/mt_sys.c"
NPI = "source/ti/zstack/npi/npi_task.c"
UART = "source/ti/zstack/npi/npi_tl_uart.c"
B1_NATIVE = (
    "source/ti/common/nv/nvocmp.c",
    "source/ti/zstack/startup/main.c",
    "source/ti/zstack/zmac/f8w/zmac.c",
    "source/ti/zstack/stack/zdo/zd_app.c",
    "source/ti/zstack/stack/zdo/zd_sec_mgr.c",
    "source/ti/zstack/stack/sys/zglobals.c",
    "source/ti/zstack/startup/zstackstartup.c",
    "source/ti/zstack/osal/osal_nv.c",
)
B1_COPIED = tuple(
    "source/ti/common/nv/" + name for name in
    ("b1_admission.c", "b1_admission.h", "b1_management.c", "b1_management.h")
)
ALL_SOURCES = (MT, SYS, NPI, UART, *B1_NATIVE, *B1_COPIED)
HEXDIGEST = re.compile(r"[0-9a-f]{64}\Z")


def check(cond, label):
    if not cond:
        raise ValueError("B5 COMPOSITE ATTESTATION BLOCKED: " + label)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    obj = json.loads(path.read_text(encoding="utf-8"))
    check(type(obj) is dict, "receipt JSON object expected: " + path.name)
    return obj


def git_head(path):
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True,
        stderr=subprocess.DEVNULL).strip()


def verify(sdk: Path, artifacts: Path, b1: Path, source_head: str):
    sdk, artifacts, b1 = sdk.resolve(), artifacts.resolve(), b1.resolve()
    check(all(str(p).startswith("/tmp/") for p in (sdk, artifacts, b1)),
          "only temporary CI workspaces")
    check(re.fullmatch(r"[0-9a-f]{40}", source_head) is not None,
          "exact full composite source SHA")
    check(git_head(sdk) == TI_SHA and git_head(b1) == B1_SHA,
          "actual pinned SDK/B1 checkout HEAD")
    prefix = "source/ti/"
    sources = {}
    for relative in ALL_SOURCES:
        check(relative.startswith(prefix) and ".." not in Path(relative).parts,
              "unsafe source path")
        f = sdk / relative
        check(f.is_file() and not f.is_symlink(), "source path unavailable: " + relative)
        sources[relative] = digest(f.read_bytes())
    def j(name):
        return read_json(artifacts / name)

    compose = j("b5-source-compose.json")
    b1_overlay = j("b1-overlay.json")
    v3 = j("b4-native-overlay.json")
    v4 = j("b4-v4-overlay.json")
    manifest = j("manifest.json")
    b1_native = j("b1-native-seal.json")
    b4_native = j("b4-native-linked.json")
    b4_v4_native = j("b4-v4-native-linked.json")

    check(compose.get("schema") == "b5-b1-management-b4-sources-v1"
          and compose.get("stage") == "FULL_B1_B4_SOURCE_COMPOSE_NOT_NATIVE_LINKED"
          and compose.get("b1_sha") == B1_SHA
          and compose.get("ti_sha") == TI_SHA
          and compose.get("b4_sha") == source_head
          and compose.get("full_b1_nv_security_source_applied") is True
          and compose.get("public_build_digest_is_b1_only_not_composite") is True
          and compose.get("flash_authorized") is False
          and compose.get("physical_verified") is False
          and compose.get("native_linked") is False
          and compose.get("b1_hold_allows_f2") is False
          and compose.get("commands") == {"B4_F0":240,"B1_F1":241,"B4_F2":242},
          "composition provenance, boundaries, or command ownership")
    check(set(compose.get("files", {})) == {MT, NPI, UART},
          "unrecognized B1 management file set")
    for p in (MT, NPI, UART):
        check(compose["files"][p]["after"] == sources[p],
              "actual combined NPI/UART/MT source drift: " + p)
    check(compose.get("mt_sys_sha256") == sources[SYS],
          "actual B4 F0/F2 dispatcher drift")

    check(b1_overlay.get("schema") == "r4-b1-admission-overlay-v2"
          and b1_overlay.get("source_sha") == B1_SHA
          and b1_overlay.get("management", {}).get("collision", {}).get("command") == "MT SYS 0xF1",
          "B1 overlay source/ABI")
    binding = {
        "modified_nv_sha256": B1_NATIVE[0],
        "modified_main_sha256": B1_NATIVE[1],
        "modified_zmac_sha256": B1_NATIVE[2],
        "modified_zdapp_sha256": B1_NATIVE[3],
        **b1_overlay.get("additional_source_bindings", {}),
    }
    check(set(binding.values()) == set(ALL_SOURCES) - {SYS, *B1_COPIED},
          "incomplete/extra B1 linked source bindings")
    for key, p in binding.items():
        check(p in sources and b1_overlay.get(key) == sources[p],
              "B1 final modified source mismatch: " + key)

    check(v3.get("stage") == "PATCHED_DISPOSABLE_SDK_NOT_LINKED"
          and v3.get("ti_sha") == TI_SHA
          and v3.get("valid_counter_indices") == [0,1,2,3,4,5]
          and set(v3.get("written", {})) == {SYS, NPI, UART},
          "canonical B4 v3 receipt")
    check(v4.get("schema") == "r4-b4-v4-native-overlay-v1"
          and v4.get("command") == "SYS_F2"
          and v4.get("sdk_sha") == TI_SHA
          and v4.get("trng_timeout_cancellation") ==
              "CANCEL_QUEUED_JOB_BEFORE_SEMAPHORE_DESTRUCT"
          and v4.get("trng_timeout_bound_us") == 100000
          and v4.get("flash_authorized") is False
          and set(v4.get("files", {})) == {SYS, NPI},
          "canonical B4 v4 receipt")
    for p in (SYS, NPI):
        check(v3["written"][p]["after_sha256"] == v4["files"][p]["before_sha256"],
              "B4 v3->v4 exact chained preimages: " + p)
    check(v3["written"][UART]["after_sha256"] == compose["files"][UART]["before"],
          "B4 native UART -> B1 source preimage")
    check(v4["files"][NPI]["after_sha256"] == compose["files"][NPI]["before"],
          "B4 v4 NPI -> B1 preimage")
    check(v4["files"][SYS]["after_sha256"] == sources[SYS],
          "B4 v4 SYS F2 source")

    check(manifest.get("schema") == "r4-b0-artifact-manifest-v1",
          "real TI native artifact manifest")
    output_hashes = {}
    for kind in ("elf","bin","hex","xml"):
        entry = manifest.get("files", {}).get(kind, {})
        name = entry.get("file")
        check(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name),
              "unsafe native artifact basename " + kind)
        f = artifacts / name
        check(f.is_file() and f.resolve().parent == artifacts
              and HEXDIGEST.fullmatch(str(entry.get("sha256","")))
              and entry["sha256"] == digest(f.read_bytes()),
              "actual native artifact mismatch: " + kind)
        output_hashes[kind] = entry["sha256"]
    check((artifacts / manifest["files"]["elf"]["file"]).read_bytes()[:4] == b"\x7fELF",
          "genuine ELF magic")
    check(b1_native.get("schema") == "r4-b1-native-seal-v1"
          and b1_native.get("classification") == "HOSTED_NATIVE_LINKED"
          and b1_native.get("source_sha") == B1_SHA
          and b1_native.get("artifacts", {}).get("elf", {}).get("sha256") ==
              output_hashes["elf"]
          and b1_native.get("b1_source_ready") is False
          and len(b1_native.get("linked_functions", {})) >= 8,
          "B1 exact executable-linked image proof")
    check(b4_native.get("schema") == "b4-native-link-proof-v1"
          and b4_native.get("elf_sha256") == output_hashes["elf"]
          and b4_native.get("f0_native_handler_linked") is True,
          "B4 F0 actual ELF link proof")
    check(b4_v4_native.get("schema") == "r4-b4-v4-native-symbol-link-proof-v1"
          and b4_v4_native.get("elf_sha256") == output_hashes["elf"]
          and b4_v4_native.get("v4_sys_f2_linked") is True
          and b4_v4_native.get("trng_runtime_verified") is False
          and "B4_V4BootInitialize" in b4_v4_native.get("symbols", {})
          and b4_v4_native.get("symbols", {}).get("B4_V4BootInitAttempted", {}).get("section_type") in ("b","d"),
          "B4 F2 actual ELF boot guard proof")

    # Deterministic canonical JSON binds *final* TI C sources to the actual
    # native output, both upstream pins and the checked-out B5 commit. This
    # off-device receipt is NOT an embedded firmware digest or radio signature.
    material = {
        "schema": "r4-b5-composite-material-v1",
        "b5_source_sha": source_head, "b1_source_sha": B1_SHA,
        "ti_sdk_sha": TI_SHA, "source_sha256": dict(sorted(sources.items())),
        "native_sha256": output_hashes,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",",":"),
                           ensure_ascii=True).encode()
    return {
        "schema": "r4-b5-native-offline-provenance-v1",
        "classification": "HOSTED_NATIVE_LINKED_SOURCE_BOUND",
        "composite_sha256": digest(canonical),
        "material": material,
        "b1_public_status_digest_is_not_composite": True,
        "b1_native_symbol_seal": True, "b4_f0_native_symbol_seal": True,
        "b4_f2_native_symbol_seal": True,
        "full_b1_nv_security_composed": True, "b2_routing_integrated": False,
        "b3_persistence_integrated": False,
        "hardware_entropy_verified": False, "physical_verified": False,
        "host_installed": False, "flash_authorized": False,
        "runtime_radio_attestation": False,
    }


def main():
    p = argparse.ArgumentParser()
    for field in ("sdk","artifacts","b1","output"):
        p.add_argument("--"+field,required=True,type=Path)
    p.add_argument("--source-head",required=True)
    a = p.parse_args()
    report = verify(a.sdk,a.artifacts,a.b1,a.source_head)
    a.output.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps({key:report[key] for key in (
        "schema","classification","composite_sha256","flash_authorized",
        "physical_verified")},sort_keys=True))


if __name__ == "__main__":
    main()
