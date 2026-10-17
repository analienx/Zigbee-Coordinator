"""Add v4 manual entry to source-pinned Z2M after validated v3 OTA overlay.

Reuses SAME private OTAUpdate.#inProgress getter and the SAME herdsman
Controller/Adapter/Znp owner. This does not install, enable or poll anything.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from b4_z2m_ota_overlay import PIN, CONTROLLER, OTA, PACKAGE

MARKER = "B4_V4_NONCE_AND_BOOT"

def _git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)

def plan(root, v3_receipt):
    root = Path(root)
    if not root.is_dir() or root.is_symlink() or not str(root.resolve()).startswith("/tmp/"):
        raise ValueError("source-only disposable Z2M checkout required")
    if _git(root, "rev-parse", "HEAD").decode().strip() != PIN:
        raise ValueError("Z2M pin mismatch")
    receipt = json.loads(Path(v3_receipt).read_text())
    if (receipt.get("schema") != "b4-z2m-ota-source-overlay-v1" or
        receipt.get("source_sha") != PIN or
        receipt.get("enabled_by_default") is not False or
        receipt.get("host_installed") is not False or
        CONTROLLER not in receipt.get("files", {})):
        raise ValueError("source-qualified Z2M v3 OTA baseline required")
    f = root / CONTROLLER
    if not f.is_file() or f.is_symlink():
        raise ValueError("Z2M controller path missing")
    content = f.read_bytes()
    metadata = receipt["files"][CONTROLLER]
    if (hashlib.sha256(content).hexdigest() != metadata["after_sha256"]
        or hashlib.sha256(_git(root, "show", PIN+":"+CONTROLLER)).hexdigest() != metadata["before_sha256"]):
        raise ValueError("Z2M v3 OTA controller changed")
    src = content.decode()
    if MARKER in src:
        raise ValueError("v4 already present")
    insert = """    /** B4_V4_NONCE_AND_BOOT: optional v4 F2, no automatic polling.
     *  Same actual OTA extension, existing controller, one ZNP owner.
     */
    public async b4ProbeReadOnlyDiagnosticsV4(enabled = false) {
        const herdsman = this.zigbee.zhController;
        if (enabled !== true || this.#startAbortController?.signal.aborted !== false ||
            !herdsman || herdsman.isStopping() || herdsman.isAdapterDisconnected()) {
            return undefined;
        }
        const ota = [...this.extensions].find(
            (extension): extension is ExtensionOTAUpdate =>
                extension instanceof ExtensionOTAUpdate,
        );
        if (!ota) return undefined;
        const stillAllowed = (): boolean =>
            ota.b4CanAcceptReadOnlyDiagnostics() &&
            this.#startAbortController?.signal.aborted === false &&
            !herdsman.isStopping() && !herdsman.isAdapterDisconnected();
        if (!stillAllowed()) return undefined;
        return await herdsman.b4ReadOnlyDiagnosticsV4FromExistingOwner({
            enabled: true, hostIdle: true, otaActive: false, stillAllowed,
        });
    }

"""
    anchor = "    async start(): Promise<void> {"
    if src.count(anchor) != 1 or "b4ProbeReadOnlyDiagnostics(enabled = false)" not in src:
        raise ValueError("real Z2M v3 manual owner entry drift")
    src = src.replace(anchor, insert+anchor, 1)
    return {CONTROLLER: (content.decode(), src)}

def apply(root, v3_receipt):
    files = plan(root, v3_receipt)
    receipt = {"schema":"b4-v4-z2m-addon-v1",
               "pin":PIN,"stage":"PINNED_SOURCE_NOT_INSTALLED",
               "manual_by_default":True,
               "ota_owner":"SAME_NATIVE_PRIVATE_INPROGRESS_SET",
               "serial_owner":"SAME_HERDSMAN_ZNP",
               "files":{}}
    for p,(before,after) in files.items():
        (Path(root)/p).write_text(after,encoding="utf-8",newline="")
        receipt["files"][p]={"before_sha256":hashlib.sha256(before.encode()).hexdigest(),
                             "after_sha256":hashlib.sha256(after.encode()).hexdigest()}
    return receipt

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--checkout",type=Path,required=True)
    p.add_argument("--v3-receipt",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    result=apply(a.checkout,a.v3_receipt)
    a.receipt.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":
    main()
