"""R4-B0 toolchain provision verifier (offline check, stdlib only).

Inspects the current machine for the pinned native build toolchain
(CCS 12.8.0.00012 headless eclipse, SysConfig 1.21.1.3772 CLI,
TI-ARM-CLANG 3.2.2.LTS) and writes a dated receipt. READY only when
all three are present with pinned versions; otherwise BLOCKED with
the precise missing piece and the official TI acquisition points.
Installer/download SHA256 digests are recorded UNKNOWN (never
fabricated) until sourced from TI distribution channels.

The verifier never downloads, installs, or fabricates firmware.
A BLOCKED receipt is a hard stop for the native build, not a pass.

Usage: python b0_provision.py provision [--toolchain-dir <dir>] [--out <receipt.json>]
Exit 0 READY, 1 BLOCKED, 2 usage error. Never prints a traceback.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

EXPECTED = {
    "ccs": "12.8.0.00012",
    "sysconfig": "1.21.1.3772",
    "ti_arm_clang": "3.2.2.LTS",
}

# Official TI acquisition points (informational; installer binaries
# and their digests are NOT pinned here because no verified direct
# headless download URL/SHA has been sourced -- see UNKNOWN below).
# SysConfig 1.21.1.3772 must be installed EXPLICITLY external:
# CCS 12.8.0.00012 officially bundles SysConfig 1.21.0.3721, which
# is NOT equal to the coherent SDK donor pin (see CCS 12.8.0
# release notes). Never rely on the CCS bundle for the version pin.
ACQUIRE = {
    "ccs": "https://www.ti.com/tool/CCSTUDIO (CCS 12.8.0.00012, Linux; TI account/export approval may apply)",
    "sysconfig": "https://www.ti.com/tool/SYSCONFIG (standalone 1.21.1.3772 explicitly external; CCS 12.8 bundles only 1.21.0.3721 -- never rely on the bundle)",
    "ti_arm_clang": "https://www.ti.com/tool/TI-ARM-CLANG (3.2.2.LTS, via CCS update or standalone)",
    "cli_reference": "https://software-dl.ti.com/ccs/esd/documents/ccs_projects-command-line.html",
}

# Exact version fingerprints required for READY. Presence of an
# executable name alone never yields READY (a stub or wrong-version
# binary must BLOCK). Each probe output must contain its pin.
VERSION_PINS = {
    "ccs": "12.8.0.00012",
    "sysconfig": "1.21.1.3772",
    "ti_arm_clang": "3.2.2",
}

BINARIES = {
    "ccs": ("eclipse", "eclipsec"),
    "sysconfig": ("sysconfig_cli",),
    "ti_arm_clang": ("tiarmclang",),
}


def _which(names, tool_dir):
    if tool_dir:
        for name in names:
            candidate = os.path.join(tool_dir, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _version(binary, key):
    flags = {"ccs": ["-noSplash", "-application",
                     "com.ti.ccstudio.apps.projectBuild", "-ccs.help"],
             "sysconfig": ["--version"],
             "ti_arm_clang": ["--version"]}[key]
    try:
        proc = subprocess.run([binary] + flags, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=120,
                              check=False)
        return proc.stdout.decode("utf-8", "replace")[:2000]
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return "version probe failed (%s)" % exc


def _sha256(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return "UNKNOWN"
    return digest.hexdigest()


def provision(tool_dir=None):
    """Returns (exit_code, receipt_dict). Never raises."""
    found = {}
    missing = []
    for key in ("ccs", "sysconfig", "ti_arm_clang"):
        binary = _which(BINARIES[key], tool_dir)
        if binary is None:
            missing.append(key)
            found[key] = {"present": False, "expected": EXPECTED[key],
                          "acquire": ACQUIRE[key]}
            continue
        version_output = _version(binary, key)
        if VERSION_PINS[key] not in version_output:
            missing.append(key)
            found[key] = {"present": False, "expected": EXPECTED[key],
                          "binary": binary,
                          "version_output": version_output,
                          "version_mismatch": True,
                          "acquire": ACQUIRE[key]}
        else:
            found[key] = {"present": True, "binary": binary,
                          "expected": EXPECTED[key],
                          "binary_sha256": _sha256(binary),
                          "version_output": version_output,
                          "version_match": True,
                          "acquire": ACQUIRE[key]}
    status = "READY" if not missing else "BLOCKED"
    receipt = {
        "schema": "r4-b0-provision-receipt-v1",
        "phase": "R4-B0",
        "issue": 90,
        "status": status,
        "emitted_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expected_toolchain": dict(EXPECTED),
        "installer_download_sha256": {
            "ccs": "UNKNOWN",
            "sysconfig": "UNKNOWN",
            "ti_arm_clang": "UNKNOWN",
        },
        "official_acquisition_points": dict(ACQUIRE),
        "components": found,
    }
    if missing:
        receipt["blocker"] = ("external dependency unavailable: TI toolchain "
                              "not provisioned (missing: %s); no dummy "
                              "firmware produced" % ", ".join(missing))
    return (0 if status == "READY" else 1), receipt


def main(argv):
    # argv follows the repo test convention: argv[0] is the command
    # (callers pass sys.argv[1:]); `if __name__` strips the prog name.
    try:
        if not argv or argv[0] != "provision":
            print("usage: b0_provision.py provision "
                  "[--toolchain-dir <dir>] [--out <receipt.json>]")
            return 2
        rest = argv[1:]
        tool_dir = None
        out = None
        i = 0
        while i < len(rest):
            if rest[i] == "--toolchain-dir" and i + 1 < len(rest):
                tool_dir = rest[i + 1]
                i += 2
            elif rest[i] == "--out" and i + 1 < len(rest):
                out = rest[i + 1]
                i += 2
            else:
                print("usage: b0_provision.py provision "
                      "[--toolchain-dir <dir>] [--out <receipt.json>]")
                return 2
        code, receipt = provision(tool_dir)
    except Exception as exc:  # noqa: BLE001 -- fail closed, never traceback
        print("b0 provision error (%s)" % exc)
        return 1
    text = json.dumps(receipt, indent=2, sort_keys=True)
    if out:
        try:
            with open(out, "w", encoding="utf-8") as handle:
                handle.write(text + "\n")
        except OSError as exc:
            print("b0 provision error (receipt unwritable: %s)" % exc)
            return 1
    print(text)
    print("B0 provision status: %s" % receipt["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
