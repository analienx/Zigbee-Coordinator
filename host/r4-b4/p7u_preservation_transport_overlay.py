"""Pinned existing-Znp one-read preservation mode, after protected startup overlay.

Default normal behavior is unchanged. Explicit mode admits exactly one B1/F1
op0 and never uses normal stack startup, bootloader fallback, reset or NV APIs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from safe_checkout_files import validate_sources, read_source_text, write_source_text

PIN = "0968f979d558874b17396c96b66382d4236bbdcd"
FILE = "src/adapter/z-stack/znp/znp.ts"
MARKER = "P7U_PRESERVATION_SINGLE_F1_V1"


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("PRESERVATION_PINNED_SOURCE_DRIFT")
    return text.replace(old, new, 1)


def apply(root):
    validate_sources(root, (FILE,))
    if subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip() != PIN:
        raise ValueError("PRESERVATION_WRONG_HERDSMAN")
    before = read_source_text(root, FILE)
    if MARKER in before or "P7U_SAFE_PING_NO_BOOTLOADER_SIGNALS" not in before:
        raise ValueError("PRESERVATION_WRONG_COMPOSITION")
    text = once(before, 'import assert from "node:assert";',
                'import assert from "node:assert";\nimport {execFileSync} from "node:child_process"; // ' + MARKER)
    text = once(text, "    private initialized: boolean;", """    private initialized: boolean;
    private p7uPreservationOnly = false;
    private p7uPreservationReadConsumed = false;

    /** Same fixed serial owner; no second port, socket or Controller.start(). */
    public async p7uOpenPreservationOnly(): Promise<{hupclDisabled: true}> {
        if (process.platform !== "linux" || this.initialized || this.serialPort || this.socketPort || this.p7uPreservationOnly ||
            this.path !== "/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00" ||
            this.baudRate !== 115200 || this.rtscts !== false) {
            throw new Error("P7U_PRESERVATION_OWNER_NOT_FRESH_OR_PINNED");
        }
        // Check the fixed binary before opening serial. No user command/argv.
        execFileSync("/bin/stty", ["--help"], {timeout: 2000, stdio: "ignore"});
        this.p7uPreservationOnly = true;
        await this.open();
        return {hupclDisabled: true};
    }
""")
    text = once(text, "const options = {path: this.path, baudRate: this.baudRate, rtscts: this.rtscts, autoOpen: false};",
                "const options = {path: this.path, baudRate: this.baudRate, rtscts: this.rtscts, autoOpen: false, ...(this.p7uPreservationOnly ? {hupcl: false} : {})};")
    text = once(text, "    private async skipBootloader(): Promise<void> {", """    private async skipBootloader(): Promise<void> {
        if (this.p7uPreservationOnly) {
            // The pinned native binding doesn't clear inherited HUPCL when
            // hupcl:false. Pass the OWNED fd as stdin: stty opens no port and
            // sends no serial bytes. Only hangup-on-close policy is changed.
            const fd = (this.serialPort?.port as unknown as {fd?: number} | undefined)?.fd;
            if (!Number.isSafeInteger(fd) || (fd as number) < 0) throw new Error("P7U_PRESERVATION_FD_UNAVAILABLE");
            execFileSync("/bin/stty", ["-hupcl"], {timeout: 2000, stdio: [fd as number, "ignore", "pipe"]});
            const flags = execFileSync("/bin/stty", ["-a"], {timeout: 2000, stdio: [fd as number, "pipe", "pipe"]}).toString();
            if (!/(?:^|\s)-hupcl(?:[;\s]|$)/.test(flags)) throw new Error("P7U_PRESERVATION_HUPCL_NOT_CLEARED");
            return; // No SYS ping, 0xEF byte, reset or explicit modem toggles.
        }
""")
    text = once(text, "        const object = ZpiObject.createRequest(subsystem, command, payload);", """        if (this.p7uPreservationOnly) {
            const query = payload?.query;
            if (subsystem !== Subsystem.SYS || command !== "p7uRetainedStatus" ||
                !Buffer.isBuffer(query) || !query.equals(Buffer.from([0x42,0x31,0x51,0x31,1,8,0,0])) ||
                this.p7uPreservationReadConsumed || typeof timeout !== "number" || timeout <= 0 || timeout > 2000) {
                throw new Error("P7U_PRESERVATION_ONLY_ONE_FIXED_F1_READ");
            }
            this.p7uPreservationReadConsumed = true; // before an uncertain TX
        }
        const object = ZpiObject.createRequest(subsystem, command, payload);""")
    text = once(text, "    public requestZdo(clusterId: ZdoClusterId, payload: Buffer, waiterID?: number): Promise<void> {", """    public requestZdo(clusterId: ZdoClusterId, payload: Buffer, waiterID?: number): Promise<void> {
        if (this.p7uPreservationOnly) throw new Error("P7U_PRESERVATION_ZDO_DISABLED");""")
    write_source_text(root, FILE, text)
    return {"schema":"p7u-preservation-transport-source-v1", "serial_owners_added":0, "default_enabled":False,
            "source_before":hashlib.sha256(before.encode()).hexdigest(), "source_after":hashlib.sha256(text.encode()).hexdigest()}


if __name__ == "__main__":
    p=argparse.ArgumentParser();p.add_argument("--checkout",type=Path,required=True);p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args();a.receipt.write_text(json.dumps(apply(a.checkout),sort_keys=True)+"\n")
