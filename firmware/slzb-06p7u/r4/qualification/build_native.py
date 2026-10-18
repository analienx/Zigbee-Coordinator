"""Build a real TI transport diagnostic in a disposable native workspace.

Public historical power references exercise generation and linking only.
This command has no radio transport and cannot qualify the current board.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from contextlib import contextmanager
import shlex
from make_transport_harness import SCENARIOS
from board_profile import REFERENCES

EXAMPLES = "87ff5b638b632050228a7504f35cf3b95581c278"
SDK = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
PROJECT = "znp_LP_CC1352P7_4_tirtos7_ticlang"
CMAKE_VERSION = "3.31.6"
REPO = Path(__file__).resolve().parents[4]
R4 = REPO / "firmware/slzb-06p7u/r4"


@contextmanager
def native_workspace():
    # Separate CI machines use the same path: TI sources contain __FILE__.
    # Refuse reuse rather than deleting an unknown existing workspace.
    root = Path("/tmp/r4-p7u-qualified-native")
    root.mkdir(exist_ok=False)
    try:
        yield root
    finally:
        # This exact directory was created above by this invocation.
        shutil.rmtree(root)


def build(output: Path, reference: str, source_sha: str, profile: str = "transport-only"):
    if profile not in ("transport-only", "uart-smoke", "uart-poll"):
        raise ValueError("QUALIFICATION_UNKNOWN_PROFILE")
    if output.exists():
        raise ValueError("QUALIFICATION_OUTPUT_MUST_BE_NEW")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    if source_sha != actual:
        raise ValueError("QUALIFICATION_SOURCE_SHA_MISMATCH")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO, text=True).strip():
        raise ValueError("QUALIFICATION_REQUIRES_CLEAN_CHECKOUT")
    required = {key: os.environ[key] for key in
                ("CCS_ECLIPSE", "TICLANG_ARMCOMPILER", "SYSCONFIG_CLI", "SYSCONFIG_TOOL")}
    output.mkdir(parents=True)
    log = output / "build.log"

    def run(*argv, cwd=None):
        args = [str(x) for x in argv]
        print("$ " + " ".join(args), flush=True)
        with log.open("a", encoding="utf-8") as stream:
            stream.write("$ " + " ".join(args) + "\n")
            stream.flush()
            result = subprocess.run(args, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT)
        if result.returncode:
            # Public build source only; no private captures enter this job.
            print(log.read_text(errors="replace")[-18000:], flush=True)
            raise subprocess.CalledProcessError(result.returncode, args)

    def tool(relative, *argv):
        run(sys.executable, R4 / relative, *argv)

    if reference == "vendor-20240716":
        tool("qualification/vendor_stock.py", "--download", "--receipt", output / "vendor-stock-reference.json")

    with native_workspace() as temp:
        examples = temp / "examples"
        workspace = temp / "workspace"
        eclipse = Path(required["CCS_ECLIPSE"])
        compiler = Path(required["TICLANG_ARMCOMPILER"])
        syscfg = Path(required["SYSCONFIG_CLI"])
        run("git", "init", "-q", examples)
        run("git", "-C", examples, "remote", "add", "origin",
            "https://github.com/TexasInstruments/simplelink-zstack-examples.git")
        run("git", "-C", examples, "fetch", "--depth", "1", "origin", EXAMPLES)
        run("git", "-C", examples, "checkout", "--detach", EXAMPLES)
        run("git", "-C", examples, "submodule", "update", "--init", "cc13xx_cc26xx_sdk")
        sdk = examples / "cc13xx_cc26xx_sdk"
        if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=sdk, text=True).strip() != SDK:
            raise ValueError("QUALIFICATION_SDK_PIN_MISMATCH")
        if "1.21.1+3772" not in subprocess.check_output([str(syscfg), "--version"], text=True):
            raise ValueError("QUALIFICATION_SYSCONFIG_PIN_MISMATCH")
        version = subprocess.check_output([str(compiler / "bin/tiarmclang"), "--version"], text=True)
        if "3.2.2" not in version:
            raise ValueError("QUALIFICATION_COMPILER_PIN_MISMATCH")
        cmake_version = subprocess.check_output(["cmake", "--version"], text=True).splitlines()[0]
        if cmake_version != "cmake version " + CMAKE_VERSION:
            raise ValueError("QUALIFICATION_CMAKE_PIN_MISMATCH: " + cmake_version)
        with (sdk / "imports.mak").open("a", encoding="utf-8") as stream:
            stream.write(f"\nSYSCONFIG_TOOL := {syscfg}\nTICLANG_ARMCOMPILER := {compiler}\n"
                         f"CMAKE := {shutil.which('cmake')}\nPYTHON := {sys.executable}\n"
                         "GCC_ARMCOMPILER :=\nIAR_ARMCOMPILER :=\n")
        tool("b0/tools/b0_sdk_build_scope.py", "--sdk", sdk,
             "--receipt", output / "sdk-scope-receipt.json")
        os.environ["CMAKE_EXPORT_COMPILE_COMMANDS"] = "ON"
        run("make", "-j2", cwd=sdk)
        commands_file = sdk / "build/ticlang/compile_commands.json"
        if not commands_file.is_file():
            raise ValueError("QUALIFICATION_NATIVE_ASM_COMMANDS_NOT_RECORDED")
        commands = json.loads(commands_file.read_text())
        expected_asm = {"TaskSupport_asm_gcc.S", "Hwi_asm_gcc.S", "Hwi_asm_switch_gcc.S"}
        m4f_asm = {}
        for entry in commands:
            file_path = Path(entry["file"])
            if (file_path.name in expected_asm and
                    file_path.as_posix().endswith("/family/arm/m3/" + file_path.name)):
                command = entry.get("command", "")
                args = shlex.split(command) if command else entry.get("arguments", [])
                if (not any("tiarmclang" in Path(arg).name for arg in args[:1]) or
                        any(args[i + 1] != "assembler-with-cpp" for i, arg in enumerate(args[:-1]) if arg == "-x")):
                    raise ValueError("QUALIFICATION_ASM_PREPROCESSOR_OVERRIDDEN " + file_path.name)
                if file_path.name in m4f_asm:
                    raise ValueError("QUALIFICATION_AMBIGUOUS_ASM_COMPILE_COMMAND")
                m4f_asm[file_path.name] = entry
        if set(m4f_asm) != expected_asm:
            raise ValueError("QUALIFICATION_M4F_ASM_NOT_COMPILED_WITH_CPP " + repr(sorted(m4f_asm)))
        (output / "native-asm-compile-commands.json").write_text(json.dumps({
            "cmake_version": cmake_version, "tiarmclang_version": version.splitlines()[0],
            "m4f_asm_compile_commands": m4f_asm}, indent=2) + "\n")
        if profile == "transport-only":
            os.environ["R4_NVOCMP_SOURCE"] = str(sdk / "source/ti/common/nv/nvocmp.c")
            os.environ["R4_CRC_SOURCE"] = str(sdk / "source/ti/common/nv/crc.c")
            run(sys.executable, "-m", "unittest", "-v", "tests.test_r4_nv_compatibility", cwd=REPO)
            tool("qualification/transport_profile.py", "--sdk", sdk, "--source-sha", source_sha,
                 "--receipt", output / "transport-profile-source.json")
            tool("qualification/make_transport_harness.py", "--sdk", sdk,
                 "--profile-receipt", output / "transport-profile-source.json",
                 "--output", output / "transport-profile-host.c")
            run("cc", "-std=c11", "-O1", "-g", "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                "-DR4_TRANSPORT_HOST", "-Wno-incompatible-pointer-types", "-I", R4 / "qualification",
                output / "transport-profile-host.c", "-o", temp / "transport-host")
            for scenario in SCENARIOS:
                run(temp / "transport-host", scenario)
        elif profile == "uart-smoke":
            tool("qualification/uart_smoke_profile.py", "--sdk", sdk, "--source-sha", source_sha,
                 "--receipt", output / "uart-smoke-source.json")
        else:
            tool("qualification/uart_poll_profile.py", "--sdk", sdk, "--source-sha", source_sha,
                 "--receipt", output / "uart-poll-source.json")
        run(eclipse, "-noSplash", "-data", workspace,
            "-application", "com.ti.common.core.initialize",
            "-ccs.toolDiscoveryPath", compiler)
        run(eclipse, "-noSplash", "-data", workspace,
            "-application", "com.ti.common.core.initialize",
            "-ccs.productDiscoveryPath", f"{sdk};{required['SYSCONFIG_TOOL']}")
        projectspec = examples / f"examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/{PROJECT}.projectspec"
        run(eclipse, "-noSplash", "-data", workspace,
            "-application", "com.ti.ccstudio.apps.projectImport", "-ccs.location", projectspec)
        project = workspace / PROJECT
        source_config = project / "znp.syscfg"
        board_args = ("--reference-power", reference, "--transport-only")
        tool("qualification/board_profile.py", "--syscfg", source_config, *board_args,
             "--receipt", output / "board-source.json")
        tool("release/r4_prepare_direct_rom_boot.py", "--syscfg", source_config,
             "--linker", sdk / "source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd",
             "--receipt", output / "direct-source.json")
        preflight = output / "preflight-syscfg"
        run(syscfg, "--script", source_config, "-o", preflight,
            "-s", sdk / ".metadata/product.json", "--compiler", "ticlang")
        tool("qualification/board_profile.py", "--generated", preflight, *board_args,
             "--receipt", output / "board-preflight.json")
        run(eclipse, "-noSplash", "-data", workspace,
            "-application", "com.ti.ccstudio.apps.projectBuild", "-ccs.projects", PROJECT)
        shutil.copyfile(project / "Stack/Config/znp_cnf.opts", output / "znp_cnf.opts")
        tool("b0/tools/b0_collect_native.py", "--workspace", workspace, "--out", output,
             "--clang", compiler, "--build-log", log)
        # Keep actual compiled SysConfig outputs for independent artifact review.
        shutil.copytree(project / "default/syscfg", output / "compiled-syscfg")
        tool("qualification/board_profile.py", "--generated", output / "compiled-syscfg",
             "--binary", output / (PROJECT + ".bin"), *board_args,
             "--receipt", output / "board-native.json")
        if profile == "transport-only":
            tool("qualification/native_profile_audit.py", "--artifacts", output, "--sdk", sdk,
                 "--profile-receipt", output / "transport-profile-source.json",
                 "--expected-sha", source_sha, "--receipt", output / "transport-profile-native.json")
        elif profile == "uart-smoke":
            tool("qualification/uart_smoke_native_audit.py", "--artifacts", output, "--sdk", sdk,
                 "--clang", compiler,
                 "--profile-receipt", output / "uart-smoke-source.json",
                 "--expected-sha", source_sha, "--receipt", output / "uart-smoke-native.json")
        else:
            tool("qualification/uart_poll_native_audit.py", "--artifacts", output, "--sdk", sdk,
                 "--profile-receipt", output / "uart-poll-source.json",
                 "--expected-sha", source_sha, "--receipt", output / "uart-poll-native.json")
        receipt = {"schema": "r4-p7u-qualification-build-v1", "profile": profile,
                   "source_sha": source_sha, "sdk_sha": SDK, "examples_sha": EXAMPLES,
                   "reference_power": reference, "current_board_qualified": False,
                   "replica": os.environ.get("R4Q_REPLICA"),
                   "run_id": os.environ.get("GITHUB_RUN_ID"),
                   "nv_compatibility_verified": False, "flash_authorized": False,
                   "firmware": {ext: hashlib.sha256((output / (PROJECT + ext)).read_bytes()).hexdigest()
                                for ext in (".hex", ".bin")}}
        (output / "qualification-build.json").write_text(json.dumps(receipt, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--reference-power", required=True,
                        choices=REFERENCES)
    parser.add_argument("--profile", choices=("transport-only", "uart-smoke", "uart-poll"),
                        default="transport-only")
    args = parser.parse_args()
    build(args.output.resolve(), args.reference_power, args.source_sha, args.profile)


if __name__ == "__main__":
    main()
