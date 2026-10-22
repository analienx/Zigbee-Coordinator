"""Pinned post-v4 source overlay: real single-owner 60s F2 sampler and lifecycle.

Applies ONLY after b4_z2m_ota_overlay.py and b4_v4_z2m_overlay.py in a
disposable Zigbee2MQTT 2.14.0 checkout, never to a running add-on's modules.
Opt-in environment variable P7U_B4_COLLECTOR=1; default OFF.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from safe_checkout_files import validate_sources, read_source_text, write_source_text

PIN = "62b02e2aa1997c574223b80c196677b63a25f4a7"
CONTROLLER = "lib/controller.ts"
MARKER = "P7U_B4_SAMPLED_SINGLE_OWNER_R4_V1"

METHOD = r"""
    /** P7U_B4_SAMPLED_SINGLE_OWNER_R4_V1:
     *  All queries reuse the normal herdsman Controller/Znp queue. An SRSP
     *  timeout poisons the v4 diagnostic session, never the production radio.
     */
    #b4Schedule(delay = 60_000): void {
        if (!this.#b4Operational || process.env.P7U_B4_COLLECTOR !== "1") {
            return;
        }
        this.#b4Timer = setTimeout(() => { void this.#b4Sample(); }, delay);
    }

    #b4SaveAtomic(target: string, value: object): void {
        const root = b4Data.getPath();
        const dir = b4Path.join(root, "p7u-b4-diagnostics");
        b4Fs.mkdirSync(dir, {recursive: true, mode: 0o700});
        if ((b4Fs.statSync(dir).mode & 0o077) !== 0) {
            throw new Error("B4_PRIVATE_STORAGE_PERMISSIONS");
        }
        const path = b4Path.join(dir, target);
        const tmp = b4Path.join(dir, ".pending-" + randomBytes(12).toString("hex"));
        const fd = b4Fs.openSync(tmp, "wx", 0o600);
        try {
            b4Fs.writeFileSync(fd, JSON.stringify(value) + "\n", "utf8");
            b4Fs.fsyncSync(fd);
        } finally {
            b4Fs.closeSync(fd);
        }
        try {
            b4Fs.renameSync(tmp, path);
            const dfd = b4Fs.openSync(dir, "r");
            try { b4Fs.fsyncSync(dfd); } finally { b4Fs.closeSync(dfd); }
        } finally {
            if (b4Fs.existsSync(tmp)) { b4Fs.unlinkSync(tmp); }
        }
    }

    #b4Persist(sample: Record<string, unknown>): void {
        const dir = b4Path.join(b4Data.getPath(), "p7u-b4-diagnostics");
        const historyPath = b4Path.join(dir, "history.json");
        let history: Array<Record<string, unknown>> = [];
        if (b4Fs.existsSync(historyPath)) {
            const size = b4Fs.statSync(historyPath).size;
            if (size > 16 * 1024 * 1024) { throw new Error("B4_HISTORY_OVERSIZED"); }
            const decoded: unknown = JSON.parse(b4Fs.readFileSync(historyPath, "utf8"));
            if (!decoded || typeof decoded !== "object" ||
                (decoded as {schema?: string}).schema !== "p7u-b4-native-history-v1" ||
                !Array.isArray((decoded as {rows?: unknown}).rows)) {
                throw new Error("B4_HISTORY_CORRUPT_NO_OVERWRITE");
            }
            history = (decoded as {rows: Array<Record<string, unknown>>}).rows;
        }
        const now = sample.utc as number;
        const rows = history.filter((x) => typeof x.utc === "number" &&
            x.utc <= now && x.utc >= now - 86_400_000).slice(-2047);
        rows.push(sample);
        // Commit the newest sample WITH the retained suffix, atomically.
        while (rows.length > 1 &&
               Buffer.byteLength(JSON.stringify(rows), "utf8") > 15 * 1024 * 1024) {
            rows.shift();
        }
        this.#b4SaveAtomic("history.json",
            {schema: "p7u-b4-native-history-v1", rows});
        if (sample.kind === "VALID") {
            this.#b4SaveAtomic("last-good.json", sample);
        }
    }

    async #b4Sample(): Promise<void> {
        if (!this.#b4Operational || process.env.P7U_B4_COLLECTOR !== "1" ||
            this.#b4InFlight) { return; }
        this.#b4InFlight = true;
        try {
            const result = await this.b4ProbeReadOnlyDiagnosticsV4(true);
            if (!this.#b4Operational) { return; }
            const utc = Date.now();
            if (!result) {
                this.#b4Persist({schema: "p7u-b4-native-sample-v1", kind: "SKIPPED",
                    utc, reason: "OWNER_BUSY_OTA_OR_DIAGNOSTIC_QUARANTINE",
                    sourceAbi: 4, imageRuntimeAttested: false});
                return;
            }
            const epochTag = result.radioBootId === null ? null :
                createHmac("sha256", this.#b4EpochKey)
                    .update(result.radioBootId, "utf8").digest("hex").slice(0, 24);
            this.#b4Persist({
                schema: "p7u-b4-native-sample-v1", kind: "VALID", utc,
                abi: result.abi, minor: result.minor,
                sequence: result.sequence, validityMask: result.validityMask,
                srspDepth: result.srspDepth, srspHighWater: result.srspHighWater,
                asyncDepth: result.asyncDepth, asyncHighWater: result.asyncHighWater,
                srspEnqueued: result.srspEnqueued,
                uartTxFinishedEvents: result.uartTxFinishedEvents,
                radioEpochTag: epochTag, radioEpochHardwareVerified: false,
                resetReason: result.resetReason,
                imageRuntimeAttested: false,
                hostPackage: "Zigbee2MQTT 2.14.0 / zigbee-herdsman 10.9.1",
                firmwareSourceClaim: "323949a95c9a07901c4ffc3d026fca414982c148"
            });
        } catch (error) {
            // A storage or source mismatch must stop optional sampling. It
            // must NOT reboot the radio or interfere with normal traffic.
            this.#b4SamplerDisabled = true;
            logger.error("P7U B4 sampler disabled: " +
                (error instanceof Error ? error.name : "UnknownError"));
        } finally {
            this.#b4InFlight = false;
            if (this.#b4Operational && !this.#b4SamplerDisabled) {
                this.#b4Schedule(60_000);
            }
        }
    }

"""


def once(s, before, after):
    if s.count(before) != 1:
        raise ValueError("B4 collector exact anchor drift: " + before[:110])
    return s.replace(before, after, 1)


def plan(root: Path):
    validate_sources(root, (CONTROLLER,))
    if subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip() != PIN:
        raise ValueError("wrong exact pinned Z2M")
    before = read_source_text(root, CONTROLLER)
    if MARKER in before:
        raise ValueError("already applied collector")
    if before.count("public async b4ProbeReadOnlyDiagnosticsV4(enabled = false)") != 1:
        raise ValueError("missing audited v4 bridge")
    # After normal start the upstream controller intentionally clears the
    # startup AbortController. BOTH prior methods would otherwise always skip.
    checks = {
        "this.#startAbortController?.signal.aborted !== false": "!this.#b4Operational",
        "this.#startAbortController?.signal.aborted === false": "this.#b4Operational",
    }
    src = before
    for old, new in checks.items():
        if src.count(old) != 2:
            raise ValueError("lifecycle check count drift: " + old)
        src = src.replace(old, new)
    src = once(src, 'import bind from "bind-decorator";',
        '''import bind from "bind-decorator";
import * as b4Fs from "node:fs";
import * as b4Path from "node:path";
import {createHmac, randomBytes} from "node:crypto";
import b4Data from "./util/data";''')
    src = once(src, "    #startAbortController: AbortController | undefined;",
        """    #startAbortController: AbortController | undefined;
    #b4Operational = false; // P7U_B4_SAMPLED_SINGLE_OWNER_R4_V1
    #b4Timer: NodeJS.Timeout | undefined;
    #b4InFlight = false;
    #b4SamplerDisabled = false;
    readonly #b4EpochKey = randomBytes(32);""")
    src = once(src, "        this.#startAbortController = new AbortController();",
        "        this.#b4Operational = false;\n        this.#startAbortController = new AbortController();")
    src = once(src, "        settings.setOnboarding(false);",
        """        settings.setOnboarding(false);
        // Only at steady state: startup AbortController is about to be GC'd.
        this.#b4Operational = true;
        this.#b4Schedule();""")
    src = once(src, '''        logger.info(`Stopping Zigbee2MQTT (restart=${restart}, code=${code}, signal=${signal})`);''',
        '''        this.#b4Operational = false;
        if (this.#b4Timer) { clearTimeout(this.#b4Timer); this.#b4Timer = undefined; }
        logger.info(`Stopping Zigbee2MQTT (restart=${restart}, code=${code}, signal=${signal})`);''')
    src = once(src, "    async start(): Promise<void> {", METHOD + "    async start(): Promise<void> {")
    if src.count(MARKER) != 2:
        raise ValueError("collector marker drift")
    return before, src


def apply(root: Path):
    before, after = plan(root)
    write_source_text(root, CONTROLLER, after)
    return {"schema": "p7u-b4-live-collector-source-v1",
            "stage": "DISPOSABLE_PINNED_SOURCE_ONLY",
            "z2m_pin": PIN, "opt_in": "P7U_B4_COLLECTOR=1",
            "default_enabled": False, "host_installed": False,
            "second_serial_owner": False, "radio_flash": False,
            "source_before": hashlib.sha256(before.encode()).hexdigest(),
            "source_after": hashlib.sha256(after.encode()).hexdigest()}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--checkout", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    args = p.parse_args()
    result = apply(args.checkout)
    args.receipt.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
