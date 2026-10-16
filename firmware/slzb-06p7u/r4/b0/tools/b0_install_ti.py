"""Unattended TI tool bootstrap for disposable Linux GitHub runners only.

Requires out-of-band publisher-verified hashes passed through workflow secrets.
No live-device access and no source checkout mutation.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tarfile
from b0_fetch_ti import acquire


def checked(argv, cwd=None):
    subprocess.run(argv, cwd=cwd, check=True, timeout=1800)


def contained_extract(tar_path, destination):
    destination = destination.resolve()
    with tarfile.open(tar_path, "r:gz") as archive:
        for item in archive.getmembers():
            target = (destination / item.name).resolve()
            if not target.is_relative_to(destination):
                raise RuntimeError("unsafe CCS archive traversal")
            if not (item.isfile() or item.isdir()):
                raise RuntimeError("unsupported CCS archive link/device member")
        archive.extractall(destination, filter="data")


def install(destination, hashes):
    destination.mkdir(parents=True, exist_ok=True)
    packages = destination / "downloads"
    roots = destination / "installed"
    roots.mkdir(exist_ok=True)
    for component in ("ccs", "sysconfig", "clang"):
        acquire(component, hashes[component], packages)
    ccs_dist = packages / "CCS12.8.0.00012_linux-x64.tar.gz"
    unpack = destination / "ccs-unpack"
    unpack.mkdir(exist_ok=True)
    contained_extract(ccs_dist, unpack)
    installers = list(unpack.rglob("ccs_setup*.run"))
    if len(installers) != 1:
        raise RuntimeError("CCS offline tarball must expose one ccs_setup installer")
    ccs_dir = roots / "ccs"
    installers[0].chmod(installers[0].stat().st_mode | 0o100)
    checked([str(installers[0]), "--mode", "unattended", "--prefix", str(ccs_dir)])
    syscfg_dir = roots / "sysconfig"
    (packages / "sysconfig-1.21.1_3772-setup.run").chmod(0o755)
    checked([str(packages / "sysconfig-1.21.1_3772-setup.run"),
             "--mode", "unattended", "--prefix", str(syscfg_dir)])
    clang_dir = roots / "clang"
    (packages / "ti_cgt_armllvm_3.2.2.LTS_linux-x64_installer.bin").chmod(0o755)
    checked([str(packages / "ti_cgt_armllvm_3.2.2.LTS_linux-x64_installer.bin"),
             "--mode", "unattended", "--prefix", str(clang_dir)])
    eclipse = list(ccs_dir.rglob("eclipse"))
    eclipse = [p for p in eclipse if p.is_file() and os.access(p, os.X_OK)]
    syscfg = list(syscfg_dir.rglob("sysconfig_cli.sh"))
    clang = list(clang_dir.rglob("tiarmclang"))
    if len(eclipse) != 1 or len(syscfg) != 1 or len(clang) != 1:
        raise RuntimeError("installed TI binaries missing or ambiguous")
    checked([str(syscfg[0]), "--version"])
    checked([str(clang[0]), "--version"])
    return {"CCS_ECLIPSE": str(eclipse[0]), "SYSCONFIG_TOOL": str(syscfg[0].parent.parent),
            "TICLANG_ARMCOMPILER": str(clang[0].parent.parent)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--github-env", required=True, type=Path)
    args = parser.parse_args()
    names = {"ccs": "TI_CCS_SHA256", "sysconfig": "TI_SYSCONFIG_SHA256",
             "clang": "TI_CLANG_SHA256"}
    hashes = {key: os.getenv(name, "") for key, name in names.items()}
    if any(not value for value in hashes.values()):
        raise RuntimeError("BLOCKED: publisher verified TI SHA-256 pins not configured")
    exports = install(args.root, hashes)
    with args.github_env.open("a", encoding="utf-8") as output:
        for key, value in exports.items():
            output.write(f"{key}={value}\n")
    print("TI installation complete: discovered exact native executable paths")


if __name__ == "__main__":
    main()
