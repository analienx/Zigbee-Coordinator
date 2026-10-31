"""Route CCS 12.8's bundled SysConfig launcher to verified standalone 1.21.1.

This modifies ONLY the disposable, installed CCS directory on the hosted
Ubuntu runner. It does not edit the TI SDK, projectspec, product metadata,
source repo, Home Assistant, or hardware.

CCS 12.8 keeps generating a make rule invoking
ccs/utils/sysconfig_1.21.0/sysconfig_cli.sh despite a separately
discovered standalone SysConfig 1.21.1. Replacing that runner-local
launcher (not the tool itself) is a deterministic, auditable solution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


PIN = "1.21.1+3772"
BUNDLED_RELATIVE = Path("utils/sysconfig_1.21.0/sysconfig_cli.sh")


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _version(path):
    result = subprocess.run([str(path), "--version"], capture_output=True,
                            text=True, timeout=30, check=True)
    return (result.stdout + result.stderr).strip()


def bind(ccs_eclipse: Path, standalone_cli: Path):
    ccs_eclipse = ccs_eclipse.resolve(strict=True)
    standalone_cli = standalone_cli.resolve(strict=True)
    if ccs_eclipse.name != "eclipse" or ccs_eclipse.parent.name != "eclipse":
        raise RuntimeError("CCS Eclipse path does not match pinned CCS 12.8 layout")
    if not standalone_cli.is_file() or not os.access(standalone_cli, os.X_OK):
        raise RuntimeError("standalone SysConfig CLI missing or not executable")
    standalone_version = _version(standalone_cli)
    if PIN not in standalone_version:
        raise RuntimeError("standalone SysConfig version does not match 1.21.1+3772")

    ccs_root = ccs_eclipse.parent.parent
    legacy = ccs_root / BUNDLED_RELATIVE
    if legacy.is_symlink() or not legacy.is_file():
        raise RuntimeError("CCS bundled SysConfig launcher absent or symlink")
    backup = legacy.with_name("sysconfig_cli.sh.vendor-original")
    if backup.exists():
        raise RuntimeError("CCS SysConfig launcher already modified")
    old_version = _version(legacy)
    if "1.21.0" not in old_version:
        raise RuntimeError("unexpected CCS bundled SysConfig version")
    original_hash = _sha(legacy)

    wrapper = '#!/bin/sh\nexec "' + str(standalone_cli) + '" "$@"\n'
    if '"' in str(standalone_cli) or "\n" in str(standalone_cli):
        raise RuntimeError("unsafe standalone SysConfig CLI path")
    old_mode = legacy.stat().st_mode
    legacy.rename(backup)
    try:
        legacy.write_text(wrapper, encoding="utf-8")
        legacy.chmod(old_mode)
        effective = _version(legacy)
        if PIN not in effective:
            raise RuntimeError("CCS SysConfig launcher did not invoke pinned CLI")
    except BaseException:
        legacy.unlink(missing_ok=True)
        backup.rename(legacy)
        raise

    return {
        "schema": "r4-b0-ccs-sysconfig-binding-v1",
        "scope": "DISPOSABLE_HOSTED_CCS_INSTALL_ONLY",
        "ccs_launcher": str(legacy),
        "standalone_cli": str(standalone_cli),
        "bundled_version_before": old_version,
        "standalone_version": standalone_version,
        "effective_version_after": effective,
        "original_launcher_sha256": original_hash,
        "new_launcher_sha256": _sha(legacy),
        "preserved_original": str(backup),
        "status": "PINNED_1_21_1_VERIFIED",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ccs-eclipse", type=Path, required=True)
    parser.add_argument("--standalone-cli", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    result = bind(args.ccs_eclipse, args.standalone_cli)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
