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

    /** F3 durable evidence writer runs in a separate NO-SERIAL worker.
     * IPC admission is bounded; main loop never calls sync read/fsync/rename.
     * ACK is durable manifest receipt only; no re-send on missing ACK.
     */
    #b4StartWorker(): void {
        if (this.#b4Worker || process.env.P7U_B4_COLLECTOR !== "1") { return; }
        const hostRun = randomUUID();
        this.#b4HostRunId = hostRun;
        this.#b4OwnerGeneration = randomUUID();
        const path = b4Path.join(__dirname, "p7u_diagnostic_worker.cjs");
        const root = b4Path.join(b4Data.getPath(), "p7u-b4-diagnostics");
        const worker = new Worker(path, {workerData: {
            schema: "p7u-f2-worker-v2", root,
        }});
        this.#b4Worker = worker;
        worker.on("message", (message: {type?: string; id?: number; reason?: string}) => {
            if (message.type === "ready") {
                this.#b4WorkerReady = true;
            } else if (message.type === "committed" && typeof message.id === "number") {
                this.#b4PendingIds.delete(message.id);
            } else if (message.type === "fatal") {
                this.#b4SamplerDisabled = true;
                this.#b4WorkerReady = false;
                logger.error("P7U B4 optional evidence writer halted: " + String(message.reason).slice(0, 120));
            }
        });
        worker.on("error", () => {
            this.#b4SamplerDisabled = true;
            this.#b4WorkerReady = false;
            logger.error("P7U B4 optional evidence worker error (radio untouched)");
        });
        worker.on("exit", () => {
            this.#b4WorkerReady = false;
            this.#b4SamplerDisabled = true;
            this.#b4PendingIds.clear();
        });
    }

    #b4Persist(sample: Record<string, unknown>): void {
        if (!this.#b4Worker || !this.#b4WorkerReady ||
            this.#b4SamplerDisabled || this.#b4PendingIds.size >= 4) {
            // Never queue unbounded diagnostics behind slow fsync; disable
            // optional collection without touching normal Zigbee traffic.
            this.#b4SamplerDisabled = true;
            throw new Error("B4_EVIDENCE_WORKER_UNAVAILABLE_OR_BACKPRESSURE");
        }
        const id = ++this.#b4RecordId;
        this.#b4PendingIds.add(id);
        const record = {
            ...sample,
            hostRunId: this.#b4HostRunId,
            ownerGeneration: this.#b4OwnerGeneration,
            processUptimeMs: Math.round(process.uptime() * 1000),
        };
        try {
            this.#b4Worker.postMessage({type: "append", id, record});
        } catch {
            this.#b4PendingIds.delete(id);
            this.#b4SamplerDisabled = true;
            throw new Error("B4_EVIDENCE_IPC_SEND_FAILED");
        }
    }

    async #b4Sample(): Promise<void> {
        if (!this.#b4Operational || process.env.P7U_B4_COLLECTOR !== "1" ||
            this.#b4InFlight || !this.#b4WorkerReady || this.#b4SamplerDisabled) { return; }
        this.#b4InFlight = true;
        const probeStarted = performance.now();
        try {
            const outcomeBefore = this.zigbee.zhController?.b4V4ReadOutcomeFromExistingOwner();
            const result = await this.b4ProbeReadOnlyDiagnosticsV4(true);
            const outcomeAfter = this.zigbee.zhController?.b4V4ReadOutcomeFromExistingOwner();
            const freshOutcome = outcomeAfter && outcomeBefore &&
                outcomeAfter.attempt > outcomeBefore.attempt ? outcomeAfter : null;
            const elapsedMs = Math.max(0, Math.round(performance.now() - probeStarted));
            if (!this.#b4Operational) { return; }
            const utc = Date.now();
            if (!result) {
                const outcome = freshOutcome;
                const kind = outcome?.kind === "FAILED" ? "FAILED"
                    : outcome?.kind === "QUARANTINED" ? "QUARANTINED" : "SKIPPED";
                this.#b4Persist({schema: "p7u-b4-native-sample-v1", kind,
                    utc, probeLatencyMs: elapsedMs,
                    monotonicReceiveNs: process.hrtime.bigint().toString(),
                    reason: outcome?.reason ?? "HOST_OR_OTA_ADMISSION_SKIPPED",
                    failureClass: kind === "FAILED" ? outcome?.reason : undefined,
                    submissionState: outcome?.submissionState ?? "NONE",
                    timingQuality: kind === "FAILED" ? "HOST_TIMING_UNCERTAIN" : "NOT_PROBED",
                    sourceAbi: 4, imageRuntimeAttested: false});
                // A sent, uncorrelated or malformed F2 permanently quarantines
                // only optional diagnostics; never reset or re-open the radio.
                if (kind === "FAILED" || kind === "QUARANTINED") {
                    this.#b4SamplerDisabled = true;
                }
                return;
            }
            const epochTag = result.radioBootId === null ? null :
                createHmac("sha256", this.#b4EpochKey)
                    .update(result.radioBootId, "utf8").digest("hex").slice(0, 24);
            this.#b4Persist({
                schema: "p7u-b4-native-sample-v1", kind: "VALID", utc,
                probeLatencyMs: elapsedMs,
                monotonicReceiveNs: process.hrtime.bigint().toString(),
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
import * as b4Path from "node:path";
import {createHmac, randomBytes, randomUUID} from "node:crypto";
import {Worker} from "node:worker_threads";
import b4Data from "./util/data";''')
    src = once(src, "    #startAbortController: AbortController | undefined;",
        """    #startAbortController: AbortController | undefined;
    #b4Operational = false; // P7U_B4_SAMPLED_SINGLE_OWNER_R4_V1
    #b4Timer: NodeJS.Timeout | undefined;
    #b4InFlight = false;
    #b4SamplerDisabled = false;
    readonly #b4EpochKey = randomBytes(32);
    #b4Worker: Worker | undefined;
    #b4WorkerReady = false;
    #b4HostRunId = "";
    #b4OwnerGeneration = "";
    #b4RecordId = 0;
    readonly #b4PendingIds = new Set<number>();""")
    src = once(src, "        this.#startAbortController = new AbortController();",
        "        this.#b4Operational = false;\n        this.#startAbortController = new AbortController();")
    src = once(src, "        settings.setOnboarding(false);",
        """        settings.setOnboarding(false);
        // Only at steady state: startup AbortController is about to be GC'd.
        this.#b4Operational = true;
        this.#b4StartWorker();
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
