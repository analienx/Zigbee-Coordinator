"""Source-pinned Zigbee2MQTT 2.14.0 B4 OTA admission patch, disposable only.

OTAUpdate already owns #inProgress for scheduled/manual/automatic update
checks and transfers. We expose only a boolean, never a device address.
A manually invoked Controller API consults it twice: on entry and through
a live callback inside herdsman's existing Znp AsyncMutex before F0 UART TX.
No timer, MQTT request, second serial port, auto-sampling or installation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from safe_checkout_files import validate_sources, write_source_text

PIN = "62b02e2aa1997c574223b80c196677b63a25f4a7"
OTA = "lib/extension/otaUpdate.ts"
CONTROLLER = "lib/controller.ts"
PACKAGE = "package.json"
MARKER = "B4_EXPERIMENTAL_Z2M_OTA_OWNER"

def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)

def once(data, anchor, replacement):
    if data.count(anchor) != 1:
        raise ValueError("Z2M source anchor drift: " + anchor[:80])
    return data.replace(anchor, replacement, 1)

def plan(root):
    root = Path(root)
    validate_sources(root, (OTA, CONTROLLER, PACKAGE))
    if git(root, "rev-parse", "HEAD").decode().strip() != PIN:
        raise ValueError("wrong pinned Z2M source")
    originals = {}
    for path in (OTA, CONTROLLER, PACKAGE):
        f = root / path
        if not f.is_file() or f.is_symlink():
            raise ValueError("Z2M source absent/symlinked: " + path)
        raw = f.read_bytes()
        if raw != git(root, "show", PIN + ":" + path):
            raise ValueError("dirty Z2M upstream source: " + path)
        originals[path] = raw.decode("utf-8")
    manifest = json.loads(originals[PACKAGE])
    if (manifest.get("version") != "2.14.0" or
            manifest.get("dependencies", {}).get("zigbee-herdsman") != "10.9.1"):
        raise ValueError("Z2M/herdsman version mismatch")
    if any(MARKER in x for x in originals.values()):
        raise ValueError("already applied source overlay")

    ota = once(originals[OTA],
               "    #inProgress = new Set<string>();",
               "    #inProgress = new Set<string>();\n"
               "    #b4Started = false; // B4_EXPERIMENTAL_Z2M_OTA_OWNER")
    ota = once(ota,
               "        }\n    }\n\n    // mostly intended for testing",
               """        }
        // Mark ready only after OTA listeners and old-progress cleanup.
        this.#b4Started = true;
    }

    /** B4_EXPERIMENTAL_Z2M_OTA_OWNER: real OTA admission, no identifiers. */
    public b4CanAcceptReadOnlyDiagnostics(): boolean {
        return this.#b4Started && this.#inProgress.size === 0;
    }

    override async stop(): Promise<void> {
        this.#b4Started = false;
        await super.stop();
    }

    // mostly intended for testing""")
    controller = once(originals[CONTROLLER],
                      "    async start(): Promise<void> {",
                      """    /** B4_EXPERIMENTAL_Z2M_OTA_OWNER: manual source-only admission.
     *  Existing herdsman Controller→ZStackAdapter→Znp transport only.
     *  No auto-polling and no direct access to private adapter/serial.
     */
    public async b4ProbeReadOnlyDiagnostics(enabled = false) {
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
        // Never trust caller OTA flags. This predicate is also reevaluated
        // inside the already-existing ZNP mutex immediately BEFORE writeFrame.
        const stillAllowed = (): boolean =>
            ota.b4CanAcceptReadOnlyDiagnostics() &&
            this.#startAbortController?.signal.aborted === false &&
            !herdsman.isStopping() && !herdsman.isAdapterDisconnected();
        if (!stillAllowed()) {
            return undefined;
        }
        return await herdsman.b4ReadOnlyDiagnosticsFromExistingOwner({
            enabled: true, hostIdle: true, otaActive: false, stillAllowed,
        });
    }

    async start(): Promise<void> {""")
    return {OTA: (originals[OTA], ota), CONTROLLER: (originals[CONTROLLER], controller)}

def apply(root):
    changes = plan(root)
    result = {
        "schema": "b4-z2m-ota-source-overlay-v1",
        "source_sha": PIN,
        "stage": "DISPOSABLE_PINNED_SOURCE_ONLY",
        "ota_state": "NATIVE_PRIVATE_INPROGRESS_SET",
        "prewrite_admission": "CALLBACK_RECHECK_WITHIN_EXISTING_ZNP_MUTEX",
        "no_secondary_serial_owner": True,
        "enabled_by_default": False,
        "host_installed": False,
        "files": {},
    }
    for path, (old, new) in changes.items():
        write_source_text(root, path, new)
        result["files"][path] = {
            "before_sha256": hashlib.sha256(old.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(new.encode()).hexdigest(),
        }
    return result

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--checkout", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    a = p.parse_args()
    evidence = apply(a.checkout)
    a.receipt.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, sort_keys=True))

if __name__ == "__main__":
    main()
