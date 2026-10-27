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
     *  F2 timeouts gate later fresh nonce reads; hard failures quarantine
     *  optional probes, never the production radio or passive evidence.
     */
    #b4Schedule(delay = 60_000): void {
        if (!this.#b4Operational || process.env.P7U_B4_COLLECTOR !== "1") {
            return;
        }
        // Frequency never exceeds once a minute. Break 60s phase lock
        // without bypassing OTA, ZNP mutex or queue ownership.
        const nextDelay = delay === 60_000 ? randomInt(60_000, 90_001)
            : Math.max(60_000, delay);
        this.#b4Timer = setTimeout(() => { void this.#b4Sample(); }, nextDelay);
    }

    /** F3 durable evidence writer runs in a separate NO-SERIAL worker.
     * IPC admission is bounded; main loop never calls sync read/fsync/rename.
     * ACK is durable manifest receipt only; no re-send on missing ACK.
     */
    /** 30-minute native F2 objective, based on DURABLE worker commits only.
     *  This is an observability warning, never a radio recovery trigger.
     */
    #b4Native30mCheck(now = Date.now()): void {
        const origin = this.#b4LastNativeCommittedUtc || this.#b4NativeCollectionBeganUtc;
        if (!origin || now < origin || now - origin < 1_800_000) { return; }
        if (this.#b4Native30mWarnedAt && now - this.#b4Native30mWarnedAt < 1_800_000) { return; }
        this.#b4Native30mWarnedAt = now;
        logger.error("P7U F2 NATIVE_30M_MISSED: no durable VALID native snapshot within 1800s; " +
            "sampling remains subject to adapter queue, ZNP waiters and OTA gates; " +
            "DO NOT reset radio on F2 staleness");
    }

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
                if (this.#b4Operational && process.env.P7U_B4_COLLECTOR === "1") {
                    try {
                        const {createHostTimeoutSink} = require("./p7u_host_timeout_sink.cjs") as {
                            createHostTimeoutSink: (persist: (record: Record<string, unknown>) => void,
                                enabled: () => boolean) => (event: {at_ms: number; kind: "AF_SREQ_TIMEOUT" | "ZDO_SREQ_TIMEOUT" | "SYS_SREQ_TIMEOUT" | "UTIL_SREQ_TIMEOUT"; dropped: number}) => void;
                        };
                        this.zigbee.zhController?.b4SetHostTimeoutSinkFromExistingOwner(
                            createHostTimeoutSink((record) => this.#b4Persist(record),
                                () => this.#b4Operational && this.#b4WorkerReady &&
                                    process.env.P7U_B4_COLLECTOR === "1"));
                    } catch {
                        this.#b4SamplerDisabled = true;
                        this.#b4WorkerReady = false;
                        logger.error("P7U B4 passive timeout evidence unavailable (radio untouched)");
                    }
                }
            } else if (message.type === "committed" && typeof message.id === "number") {
                this.#b4PendingIds.delete(message.id);
                const nativeCommittedUtc = this.#b4PendingNativeValidUtc.get(message.id);
                this.#b4PendingNativeValidUtc.delete(message.id);
                if (nativeCommittedUtc !== undefined) {
                    this.#b4LastNativeCommittedUtc = nativeCommittedUtc;
                    this.#b4Native30mWarnedAt = 0;
                }
                clearTimeout(this.#b4AckTimers.get(message.id));
                this.#b4AckTimers.delete(message.id);
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
            this.#b4PendingNativeValidUtc.clear();
            for (const timer of this.#b4AckTimers.values()) { clearTimeout(timer); }
            this.#b4AckTimers.clear();
        });
    }

    // Optional F2 quarantine is NOT a persistence/worker quarantine. Healthy
    // owner-bound passive SRSP timeouts continue using this same worker.
    #b4Persist(sample: Record<string, unknown>): void {
        if (!this.#b4Worker || !this.#b4WorkerReady ||
            this.#b4PendingIds.size >= 4) {
            // Never queue unbounded diagnostics behind slow fsync; disable
            // optional collection without touching normal Zigbee traffic.
            this.#b4SamplerDisabled = true;
            throw new Error("B4_EVIDENCE_WORKER_UNAVAILABLE_OR_BACKPRESSURE");
        }
        const id = ++this.#b4RecordId;
        this.#b4PendingIds.add(id);
        if (sample.kind === "VALID" && typeof sample.utc === "number") {
            this.#b4PendingNativeValidUtc.set(id, sample.utc);
        }
        const timer = setTimeout(() => {
            this.#b4AckTimers.delete(id);
            this.#b4PendingIds.delete(id);
            this.#b4PendingNativeValidUtc.delete(id);
            this.#b4SamplerDisabled = true;
            this.#b4WorkerReady = false;
            logger.error("P7U B4 optional evidence ACK timed out; sampling halted (radio untouched)");
        }, 15_000);
        timer.unref();
        this.#b4AckTimers.set(id, timer);
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
            this.#b4PendingNativeValidUtc.delete(id);
            clearTimeout(this.#b4AckTimers.get(id));
            this.#b4AckTimers.delete(id);
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
            // Passive numeric-only evidence, even if F2 was not admitted.
            // This accessor MUST NOT attempt another ZNP request.
            const hostEvidence = this.zigbee.zhController?.b4NoWireOwnerSnapshotFromExistingOwner() ?? null;
            if (!this.#b4Operational) { return; }
            const utc = Date.now();
            if (!result) {
                const outcome = freshOutcome;
                const kind = outcome?.kind === "FAILED" ? "FAILED"
                    : outcome?.kind === "QUARANTINED" ? "QUARANTINED" : "SKIPPED";
                this.#b4Persist({schema: "p7u-b4-native-sample-v1", kind,
                    utc, probeLatencyMs: elapsedMs,
                    monotonicReceiveNs: process.hrtime.bigint().toString(),
                    reason: outcome?.reason ?? this.#b4BridgeGateReason,
                    failureClass: kind === "FAILED" ? outcome?.reason : undefined,
                    submissionState: outcome?.submissionState ?? "NONE",
                    timingQuality: kind === "FAILED" ? "HOST_TIMING_UNCERTAIN" : "NOT_PROBED",
                    sourceAbi: 4, imageRuntimeAttested: false, hostEvidence});
                // Znp owns nonce correlation, cooldown/progress admission and
                // hard quarantine. Keep recording its no-wire status even in
                // quarantine; worker/storage failure alone halts this timer.
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
                mtLifecycle: result.mtLifecycle,
                hostEvidence,
                radioEpochTag: epochTag, radioEpochHardwareVerified: false,
                resetReason: result.resetReason,
                imageRuntimeAttested: false,
                // F2 does not attest a firmware source revision. Installed
                // source is bound by the separate physical deployment receipt.
                hostPackage: "Zigbee2MQTT 2.14.0 / zigbee-herdsman 10.9.1"
            });
        } catch (error) {
            // A storage or source mismatch must stop optional sampling. It
            // must NOT reboot the radio or interfere with normal traffic.
            this.#b4SamplerDisabled = true;
            logger.error("P7U B4 sampler disabled: " +
                (error instanceof Error ? error.name : "UnknownError"));
        } finally {
            this.#b4InFlight = false;
            this.#b4Native30mCheck();
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
    # The v4 bridge is pinned before this overlay; preserve its actual
    # lifecycle rules but report WHY a no-wire probe was not admitted.
    # Scope only to F2: the predecessor F0 bridge deliberately has
    # identical !ota/stillAllowed syntax and MUST remain byte-identical.
    begin = src.index("    public async b4ProbeReadOnlyDiagnosticsV4(enabled = false)")
    end = src.index("    public async b4ProbeReadOnlyDiagnostics(enabled = false)", begin)
    v4bridge = src[begin:end]
    v4bridge = once(v4bridge, '''        if (enabled !== true || !this.#b4Operational ||
            !herdsman || herdsman.isStopping() || herdsman.isAdapterDisconnected()) {
            return undefined;
        }''', '''        const outerGate = enabled !== true ? "COLLECTOR_NOT_ENABLED"
            : !this.#b4Operational ? "HOST_NOT_OPERATIONAL"
            : !herdsman ? "HERDSMAN_UNAVAILABLE"
            : herdsman.isStopping() ? "HERDSMAN_STOPPING"
            : herdsman.isAdapterDisconnected() ? "ADAPTER_DISCONNECTED" : null;
        if (outerGate !== null) {
            this.#b4BridgeGateReason = outerGate;
            return undefined;
        }''')
    v4bridge = once(v4bridge, '''        if (!ota) {
            return undefined;
        }''', '''        if (!ota) {
            this.#b4BridgeGateReason = "OTA_EXTENSION_UNAVAILABLE";
            return undefined;
        }''')
    v4bridge = once(v4bridge, '''        if (!stillAllowed()) {
            return undefined;
        }
        return await herdsman.b4ReadOnlyDiagnosticsV4FromExistingOwner({''', '''        if (!stillAllowed()) {
            this.#b4BridgeGateReason = "OTA_OR_HOST_GUARD_BLOCKED";
            return undefined;
        }
        this.#b4BridgeGateReason = "ADAPTER_EVALUATING";
        return await herdsman.b4ReadOnlyDiagnosticsV4FromExistingOwner({''')
    src = src[:begin] + v4bridge + src[end:]
    src = once(src, 'import bind from "bind-decorator";',
        '''import bind from "bind-decorator";
import * as b4Path from "node:path";
import {createHmac, randomBytes, randomInt, randomUUID} from "node:crypto";
import {Worker} from "node:worker_threads";
import b4Data from "./util/data";''')
    src = once(src, "    #startAbortController: AbortController | undefined;",
        """    #startAbortController: AbortController | undefined;
    #b4Operational = false; // P7U_B4_SAMPLED_SINGLE_OWNER_R4_V1
    #b4Timer: NodeJS.Timeout | undefined;
    #b4InFlight = false;
    #b4SamplerDisabled = false;
    #b4BridgeGateReason = "NOT_ATTEMPTED";
    readonly #b4EpochKey = randomBytes(32);
    #b4Worker: Worker | undefined;
    #b4WorkerReady = false;
    #b4NativeCollectionBeganUtc = 0;
    #b4LastNativeCommittedUtc = 0;
    #b4Native30mWarnedAt = 0;
    readonly #b4PendingNativeValidUtc = new Map<number, number>();
    #b4HostRunId = "";
    #b4OwnerGeneration = "";
    #b4RecordId = 0;
    readonly #b4PendingIds = new Set<number>();
    readonly #b4AckTimers = new Map<number, NodeJS.Timeout>();""")
    src = once(src, "        this.#startAbortController = new AbortController();",
        "        this.#b4Operational = false;\n        this.#startAbortController = new AbortController();")
    src = once(src, "        settings.setOnboarding(false);",
        """        settings.setOnboarding(false);
        // Only at steady state: startup AbortController is about to be GC'd.
        this.#b4Operational = true;
        this.#b4NativeCollectionBeganUtc = Date.now();
        this.#b4LastNativeCommittedUtc = 0;
        this.#b4Native30mWarnedAt = 0;
        try { this.#b4StartWorker(); }
        catch {
            this.#b4SamplerDisabled = true;
            logger.error("P7U B4 optional evidence worker could not start (radio untouched)");
        }
        this.#b4Schedule();""")
    src = once(src, '''        logger.info(`Stopping Zigbee2MQTT (restart=${restart}, code=${code}, signal=${signal})`);''',
        '''        this.#b4Operational = false;
        this.zigbee.zhController?.b4SetHostTimeoutSinkFromExistingOwner(undefined);
        if (this.#b4Timer) { clearTimeout(this.#b4Timer); this.#b4Timer = undefined; }
        for (const timer of this.#b4AckTimers.values()) { clearTimeout(timer); }
        this.#b4AckTimers.clear();
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
