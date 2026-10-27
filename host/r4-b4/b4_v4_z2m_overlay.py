"""Optional Zigbee2MQTT 2.14.0 SYS F2 v4 manual existing-owner bridge.

Runs after b4_z2m_ota_overlay.py against source-pinned disposable checkout;
same OTAUpdate.#inProgress getter/Controller, no new serial owner/timer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from safe_checkout_files import validate_sources, read_source_text, write_source_text

PIN = "62b02e2aa1997c574223b80c196677b63a25f4a7"
CONTROLLER = "lib/controller.ts"
MARKER = "B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE"

def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)

def plan(root):
    root = Path(root)
    validate_sources(root, (CONTROLLER,))
    if git(root, "rev-parse", "HEAD").decode().strip() != PIN:
        raise ValueError("wrong pinned Zigbee2MQTT 2.14.0")
    src = read_source_text(root, CONTROLLER)
    if MARKER in src:
        raise ValueError("already applied")
    if src.count("    public async b4ProbeReadOnlyDiagnostics(enabled = false) {") != 1:
        raise ValueError("missing prior source-verified v3 OTA owner bridge")
    anchor = "    public async b4ProbeReadOnlyDiagnostics(enabled = false) {"
    added = """    /** B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE: explicit manual opt-in.
     *  Same private real OTA gate; no fallback to F0 on v4 errors.
     */
    public async b4ProbeReadOnlyDiagnosticsV4(enabled = false, reserveAtBoundary = false) {
        const herdsman = this.zigbee.zhController;
        if (enabled !== true || this.#startAbortController?.signal.aborted !== false ||
            !herdsman || herdsman.isStopping() || herdsman.isAdapterDisconnected()) {
            return undefined;
        }
        const ota = [...this.extensions].find(
            (extension): extension is ExtensionOTAUpdate =>
                extension instanceof ExtensionOTAUpdate,
        );
        if (!ota) {
            return undefined;
        }
        const stillAllowed = (): boolean =>
            ota.b4CanAcceptReadOnlyDiagnostics() &&
            this.#startAbortController?.signal.aborted === false &&
            !herdsman.isStopping() && !herdsman.isAdapterDisconnected();
        if (!stillAllowed()) {
            return undefined;
        }
        return await herdsman.b4ReadOnlyDiagnosticsV4FromExistingOwner({
            enabled: true, hostIdle: true, otaActive: false, stillAllowed, reserveAtBoundary,
        });
    }

"""
    return src, src.replace(anchor, added + anchor, 1)

def apply(root):
    before, after = plan(root)
    write_source_text(root, CONTROLLER, after)
    return {
        "schema": "r4-b4-v4-z2m-source-overlay-v1",
        "stage": "DISPOSABLE_SOURCE_ONLY", "installed": False,
        "default_enabled": False, "serial_owners_added": 0,
        "sha256_before": hashlib.sha256(before.encode()).hexdigest(),
        "sha256_after": hashlib.sha256(after.encode()).hexdigest(),
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--checkout", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    a = p.parse_args()
    result = apply(a.checkout)
    a.receipt.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
