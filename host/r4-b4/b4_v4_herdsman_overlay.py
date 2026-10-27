"""Optional v4 SYS F2 existing-owner overlay ON TOP OF approved v3 source overlay.

No new serial owner, no timers, no auth claim: host crypto nonce echoes
verbatim so a delayed F2 SRSP can never impersonate a different request.
All source mutations confined to disposable pinned herdsman checkout.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from safe_checkout_files import validate_sources, read_source_text, write_source_text

PIN = "0968f979d558874b17396c96b66382d4236bbdcd"
DEFINITION = "src/adapter/z-stack/znp/definition.ts"
PARAM = "src/adapter/z-stack/znp/parameterType.ts"
BUFFALO = "src/adapter/z-stack/znp/buffaloZnp.ts"
ADAPTER = "src/adapter/z-stack/adapter/zStackAdapter.ts"
ZNP = "src/adapter/z-stack/znp/znp.ts"
WAITRESS = "src/utils/waitress.ts"
PARSER = "src/adapter/z-stack/unpi/parser.ts"
WRITER = "src/adapter/z-stack/unpi/writer.ts"
CONTROLLER = "src/controller/controller.ts"
MARKER = "B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE"

V4_ADAPTER_METHOD = r"""
    /** B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE: manually invoked, default OFF.
     * Uses the same existing ZNP owner and an unpredictable nonce to bind
     * each response to its request. A boot token is NOT a hardware attestation.
     */
    /** Sanitized outcome of latest optional F2 attempt; no nonce or device IDs. */
    public b4GetV4Outcome(): {attempt: number; kind: "VALID" | "SKIPPED" | "FAILED" | "QUARANTINED"; reason: string; submissionState: string} {
        return {...this.b4V4Outcome};
    }

    /** Passive in-process metrics ONLY. No UART or Zigbee SREQ. */
    public b4GetNoWireEvidence() {
        return {...this.znp.b4GetPassiveOwnerMetrics(),
            adapterQueuePending: this.queue?.count() ?? null,
            adapterClosing: this.closing, interpanLocked: !!this.interpanLock};
    }

    public async b4ReadOnlyDiagnosticsV4(input: {
        enabled: boolean; hostIdle: boolean; otaActive: boolean;
        stillAllowed: () => boolean;
    }): Promise<{
        abi: 4; minor: 1; validityMask: number; srspDepth: number | null;
        srspHighWater: number | null; asyncDepth: number; asyncHighWater: number;
        srspEnqueued: number | null; uartTxFinishedEvents: number;
        sequence: number; radioBootId: string | null; resetReason: number | null;
        buildImageDigest: null; radioEpochHardwareVerified: false;
    } | undefined> {
        this.b4V4Attempt = (this.b4V4Attempt ?? 0) + 1;
        this.b4V4Outcome = {attempt: this.b4V4Attempt, kind: "SKIPPED",
            reason: this.znp.b4IsDiagPoisoned?.() === true ? "DIAGNOSTIC_QUARANTINED" : "OUTER_ADMISSION_GATED",
            submissionState: "NONE"};
        if (this.znp.b4IsDiagPoisoned?.() === true) {
            this.b4V4Outcome.kind = "QUARANTINED";
            return undefined;
        }
        const recoveryGate = this.znp.b4F2ReadAdmissionReason();
        if (recoveryGate !== null) {
            this.b4V4Outcome.reason = recoveryGate;
            return undefined;
        }
        // One deterministic, privacy-safe reason for EACH no-wire admission
        // veto. Never attempt a diagnostic while the production owner is busy.
        const local = this.znp.b4GetPassiveOwnerMetrics();
        const gate = input?.enabled !== true ? "PROBE_NOT_ENABLED"
            : input?.hostIdle !== true ? "HOST_NOT_IDLE"
            : input?.otaActive !== false ? "OTA_ACTIVE_OR_UNKNOWN"
            : typeof input.stillAllowed !== "function" ? "OWNER_GUARD_UNAVAILABLE"
            : !input.stillAllowed() ? "OWNER_OR_OTA_GUARD_REVOKED"
            : this.closing ? "ADAPTER_CLOSING"
            : !this.queue ? "ADAPTER_QUEUE_UNAVAILABLE"
            : this.queue.count() !== 0 ? "ADAPTER_QUEUE_PENDING"
            : this.interpanLock ? "INTERPAN_LOCK"
            : !local.initialized ? "ZNP_NOT_INITIALIZED"
            : !local.mutexIdle ? "ZNP_MUTEX_BUSY"
            : !this.znp.b4F2NoBlockingWaiters() ? "ZNP_WAITRESS_PENDING"
            : !this.znp.b4CanProbeV4() ? "ZNP_OTHER_ADMISSION"
            : null;
        if (gate !== null) {
            this.b4V4Outcome.reason = gate;
            return undefined;
        }
        const now = performance.now();
        if (this.b4DiagInFlight || now < this.b4NextAllowedMs) {
            this.b4V4Outcome.reason = "COOLDOWN_OR_ALREADY_IN_FLIGHT";
            return undefined;
        }
        // Uses Node cryptographic random bytes, NOT radio/IEEE or a secret.
        // Returned nonce remains in the request/response only; never logged.
        const nonce = randomBytes(8);
        this.b4DiagInFlight = true;
        this.b4NextAllowedMs = now + 30_000;
        this.znp.b4SetProbeGuard(input.stillAllowed);
        try {
            this.b4V4Outcome = {attempt: this.b4V4Attempt, kind: "FAILED",
                reason: "SUBMISSION_OR_REPLY_UNCERTAIN", submissionState: "UNCERTAIN"};
            const response = await this.znp.requestWithReply(
                Subsystem.SYS, "r4DiagReadOnlyV4", {nonce}, undefined, 6000);
            const data = response.payload.diagnostic;
            if (!Buffer.isBuffer(data) || data.length !== 160 ||
                data.toString("ascii", 0, 4) !== "R4D4" ||
                data[4] !== 4 || data[5] !== 0 || data.readUInt16LE(6) !== 160 ||
                // v4 F2 echoes the REQUEST nonce. An old response is invalid.
                !nonce.equals(data.subarray(132, 140)) ||
                data.readUInt32LE(8) & ~0x01 ||
                data[157] !== 1 || data[158] & ~0x01 || data[159] !== 0 ||
                !data.subarray(140, 156).equals(Buffer.alloc(16)) ||
                data.readUInt32LE(24) !== 0 || data.readUInt32LE(28) === 0) {
                this.znp.b4PoisonDiagSession();
                this.b4V4Outcome = {attempt: this.b4V4Attempt, kind: "FAILED",
                    reason: "INVALID_NATIVE_RESPONSE", submissionState: "SENT_OR_UNCERTAIN"};
                return undefined;
            }
            const validity = data.readUInt32LE(12);
            if ((validity !== 0x3F && validity !== 0x2C) ||
                Array.from({length: 25}, (_, i) => i).some((i) =>
                    !(validity & (1 << i)) &&
                    data.readUInt32LE(32 + 4 * i) !== 0) ||
                (validity === 0x3F && data.readUInt32LE(32) > data.readUInt32LE(36)) ||
                data.readUInt32LE(40) > data.readUInt32LE(44)) {
                this.znp.b4PoisonDiagSession();
                this.b4V4Outcome = {attempt: this.b4V4Attempt, kind: "FAILED",
                    reason: "INVALID_NATIVE_RESPONSE", submissionState: "SENT_OR_UNCERTAIN"};
                return undefined;
            }
            const caps = data.readUInt32LE(8);
            const rawBoot = data.readBigUInt64LE(16);
            if ((caps === 0 && rawBoot !== 0n) ||
                (caps === 1 && rawBoot === 0n) ||
                (data[158] === 0 && data[156] !== 0xFF) ||
                (data[158] === 1 && data[156] === 0xFF)) {
                this.znp.b4PoisonDiagSession();
                this.b4V4Outcome = {attempt: this.b4V4Attempt, kind: "FAILED",
                    reason: "INVALID_NATIVE_RESPONSE", submissionState: "SENT_OR_UNCERTAIN"};
                return undefined;
            }
            const seq = data.readUInt32LE(28);
            // No cross-reboot counter delta: boot ID is probabilistic and
            // hardware qualification remains a separate physical gate.
            if (this.b4V4LastBoot === rawBoot &&
                this.b4V4LastSeq !== undefined && seq <= this.b4V4LastSeq) {
                this.znp.b4PoisonDiagSession();
                this.b4V4Outcome = {attempt: this.b4V4Attempt, kind: "FAILED",
                    reason: "INVALID_NATIVE_RESPONSE", submissionState: "SENT_OR_UNCERTAIN"};
                return undefined;
            }
            this.b4V4LastBoot = rawBoot;
            this.b4V4LastSeq = seq;
            this.znp.b4F2AcceptReply();
            this.b4V4Outcome = {attempt: this.b4V4Attempt, kind: "VALID",
                reason: "NATIVE_NONCE_MATCHED", submissionState: "RECEIVED"};
            return {
                abi: 4, minor: 1, validityMask: validity,
                srspDepth: validity & 1 ? data.readUInt32LE(32) : null,
                srspHighWater: validity & 2 ? data.readUInt32LE(36) : null,
                asyncDepth: data.readUInt32LE(40),
                asyncHighWater: data.readUInt32LE(44),
                srspEnqueued: validity & 16 ? data.readUInt32LE(48) : null,
                uartTxFinishedEvents: data.readUInt32LE(52),
                sequence: seq,
                radioBootId: caps === 1 ? data.subarray(16, 24).toString("hex") : null,
                resetReason: data[158] === 1 ? data[156] : null,
                buildImageDigest: null,
                radioEpochHardwareVerified: false,
            };
        } catch (error: unknown) {
            if (error instanceof Error && error.message === "B4 F2_REPLY_TIMEOUT") {
                this.b4V4Outcome = {attempt: this.b4V4Attempt, kind: "FAILED",
                    reason: this.znp.b4IsDiagPoisoned() ? "F2_TIMEOUT_BUDGET_EXHAUSTED" : "F2_REPLY_TIMEOUT",
                    submissionState: "SENT_OR_UNCERTAIN"};
                return undefined;
            }
            if (error instanceof Error &&
                (error.message === "B4 F2 runtime admission vetoed" ||
                 error.message === "B4 DIAG_NOT_SUBMITTED_BUSY" ||
                 error.message === "B4 F2_TIMEOUT_COOLDOWN" ||
                 error.message === "B4 F2_OWNER_PROGRESS_REQUIRED")) {
                this.b4V4Outcome = {attempt: this.b4V4Attempt, kind: "SKIPPED",
                    reason: error.message.startsWith("B4 F2_") ? error.message.slice(3) : "OWNER_OR_OTA_BUSY",
                    submissionState: "NONE"};
                return undefined;
            }
            // Only a classified nonce-bound reply timeout is recoverable.
            // Unknown transport/owner failures retain hard quarantine.
            this.znp.b4PoisonDiagSession();
            this.b4V4Outcome = {attempt: this.b4V4Attempt, kind: "FAILED",
                reason: "TRANSPORT_OR_WAIT_FAILURE",
                submissionState: "UNCERTAIN"};
            return undefined;
        } finally {
            this.znp.b4SetProbeGuard(undefined);
            this.b4DiagInFlight = false;
        }
    }

"""

def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)

def once(s, a, b):
    if s.count(a) != 1:
        raise ValueError("pinned v4 herdsman anchor drift: " + a[:72])
    return s.replace(a, b, 1)

def plan(root):
    root = Path(root)
    paths = (DEFINITION, PARAM, BUFFALO, ADAPTER, ZNP, WAITRESS, CONTROLLER, PARSER, WRITER)
    validate_sources(root, paths)
    if git(root, "rev-parse", "HEAD").decode().strip() != PIN:
        raise ValueError("herdsman HEAD drift")
    original = {p: read_source_text(root, p) for p in paths}
    # Raw UNPI logging paths were untouched by v3. Verify pristine blobs
    # before redaction; no second logger/transport or broad source guessing.
    for path in (PARSER, WRITER):
        if original[path].encode() != git(root, "show", PIN + ":" + path):
            raise ValueError("pinned UNPI parser/writer provenance drift")
    if any(MARKER in val for val in original.values()):
        raise ValueError("v4 already applied")
    if ("B4_EXPERIMENTAL_EXISTING_OWNER" not in original[ADAPTER] or
            "B4_EXPERIMENTAL_EXISTING_OWNER" not in original[ZNP] or
            "b4ReadOnlyDiagnosticsFromExistingOwner" not in original[CONTROLLER]):
        raise ValueError("v4 requires existing-owner v3 source overlay")
    definition = once(original[DEFINITION],
        '            name: "r4DiagReadOnly",',
        '''            name: "r4DiagReadOnly",''')
    # Replace the v3 definition's unique comment with an additional F2
    # definition. F0 remains untouched, preserving rollback and v3 ABI.
    definition = once(definition,
        "        // B4_EXPERIMENTAL_EXISTING_OWNER: read-only SYS F0; default disabled.",
        """        // B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE: independent SYS F2.
        {
            name: "r4DiagReadOnlyV4",
            ID: 242,
            type: CommandType.SREQ,
            request: [{name: "nonce", parameterType: ParameterType.BUFFER8}],
            response: [{name: "diagnostic", parameterType: ParameterType.BUFFER160}],
        },
        // B4_EXPERIMENTAL_EXISTING_OWNER: read-only SYS F0; default disabled.""")
    params = once(original[PARAM],
                  "    BUFFER132 = 19,",
                  "    BUFFER132 = 19,\n    BUFFER160 = 20, // B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE")
    buffalo = once(original[BUFFALO],
        """            case ParameterType.BUFFER132: {
                // B4_EXPERIMENTAL_EXISTING_OWNER: strict fixed-size
                // payload. Buffalo.readBuffer alone silently truncates.
                if (this.getBuffer().length - this.getPosition() !== 132) {
                    throw new Error("B4 diagnostic length must be exactly 132");
                }
                return this.readBuffer(132);
            }""",
        """            case ParameterType.BUFFER132: {
                // B4_EXPERIMENTAL_EXISTING_OWNER: strict fixed-size
                // payload. Buffalo.readBuffer alone silently truncates.
                if (this.getBuffer().length - this.getPosition() !== 132) {
                    throw new Error("B4 diagnostic length must be exactly 132");
                }
                return this.readBuffer(132);
            }
            case ParameterType.BUFFER160: {
                // B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE: no truncation.
                if (this.getBuffer().length - this.getPosition() !== 160) {
                    throw new Error("B4 v4 diagnostic length must be exactly 160");
                }
                return this.readBuffer(160);
            }""")
    adapter = once(original[ADAPTER],
        'import {performance} from "node:perf_hooks"; // B4 existing-owner monotonic cooldown',
        'import {performance} from "node:perf_hooks"; // B4 existing-owner monotonic cooldown\n'
        'import {randomBytes} from "node:crypto"; // B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE')
    adapter = once(adapter, "    private b4LastDiagSequence: number | undefined;",
        "    private b4LastDiagSequence: number | undefined;\n"
        "    private b4V4LastBoot: bigint | undefined;\n"
        "    private b4V4LastSeq: number | undefined;\n"
        "    private b4V4Attempt = 0;\n"
        '    private b4V4Outcome: {attempt: number; kind: "VALID" | "SKIPPED" | "FAILED" | "QUARANTINED"; reason: string; submissionState: string} = {attempt: 0, kind: "SKIPPED", reason: "NOT_ATTEMPTED", submissionState: "NONE"};')
    adapter = once(adapter, '    /** B4 source-only opt-in; no disk I/O, ZNP request, MQTT, or serial open. */',
        V4_ADAPTER_METHOD + '    /** B4 source-only opt-in; no disk I/O, ZNP request, MQTT, or serial open. */')
    controller = once(original[CONTROLLER],
        "    public isStopping(): boolean {",
        """    /** B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE: optional only,
     *  real owner and live OTA admission required.
     */
    public async b4ReadOnlyDiagnosticsV4FromExistingOwner(input: {
        enabled: boolean; hostIdle: boolean; otaActive: boolean;
        stillAllowed: () => boolean;
    }) {
        if (this.stopping || this.adapterDisconnected ||
            typeof input?.stillAllowed !== "function" ||
            !(this.adapter instanceof ZStackAdapter)) {
            return undefined;
        }
        return await this.adapter.b4ReadOnlyDiagnosticsV4(input);
    }

    /** No wire access: subscribe only to sanitized original-owner timeouts. */
    public b4SetHostTimeoutSinkFromExistingOwner(sink: Parameters<ZStackAdapter["b4SetHostTimeoutSink"]>[0]): void {
        if (this.adapter instanceof ZStackAdapter) {
            this.adapter.b4SetHostTimeoutSink(sink);
        }
    }

    /** Read numeric-only F2 outcome from original live ZStack owner. */
    public b4V4ReadOutcomeFromExistingOwner() {
        return this.adapter instanceof ZStackAdapter ? this.adapter.b4GetV4Outcome() : null;
    }

    /** No UART: snapshot adapter admission and host SRSP aggregates. */
    public b4NoWireOwnerSnapshotFromExistingOwner() {
        return this.adapter instanceof ZStackAdapter ? this.adapter.b4GetNoWireEvidence() : null;
    }

    public isStopping(): boolean {""")
    znp = original[ZNP]
    znp = once(znp, "    public b4PoisonDiagSession(): void {",
        """    public b4IsDiagPoisoned(): boolean {
        return this.b4DiagPoisoned;
    }

    public b4PoisonDiagSession(): void {""")
    # Both transport checks must also apply to F2, but ONLY the optional
    # diagnostic opcodes. All ordinary command handling remains unmodified.
    # The pinned v3 overlay inserts exactly TWO pre-write optional-only
    # checks (disconnected/Waitress and late OTA veto). Extend both.
    old_check = 'object.command.name === "r4DiagReadOnly" &&'
    if znp.count(old_check) != 2:
        raise ValueError("v3 diagnostic owner mutex guard count drift")
    znp = znp.replace(old_check,
        '(object.command.name === "r4DiagReadOnly" || object.command.name === "r4DiagReadOnlyV4") &&')
    # The F2 pre-write check runs under the existing ZNP mutex; it is a
    # second admission check, not a new serial owner. F0 remains all-waiter.
    znp = once(
        znp,
        '!this.waitress.b4IsIdle())) {',
        '!(object.command.name === "r4DiagReadOnlyV4" ? (this.b4F2NoBlockingWaiters() && this.b4F2ReadAdmissionReason() === null) : this.waitress.b4IsIdle()))) {',
    )
    znp = once(
        znp,
        'throw new Error("B4 F0 owner unavailable or poisoned inside ZNP mutex");',
        'throw new Error(object.command.name === "r4DiagReadOnlyV4" ? "B4 DIAG_NOT_SUBMITTED_BUSY" : "B4 F0 owner unavailable or poisoned inside ZNP mutex");',
    )
    # The v3 overlay's writer/timer cleanup previously applied only to F0.
    # F2 must use exactly the same tagged waiter's settlement and quarantine.
    znp = once(
        znp,
        'const isB4Diag = object.command.name === "r4DiagReadOnly";',
        'const isB4Diag = object.command.name === "r4DiagReadOnly" || object.command.name === "r4DiagReadOnlyV4";',
    )
    znp = once(
        znp,
        'subsystem === Subsystem.SYS && command === "r4DiagReadOnly" && this.b4DiagPoisoned',
        'subsystem === Subsystem.SYS && (command === "r4DiagReadOnly" || command === "r4DiagReadOnlyV4") && this.b4DiagPoisoned',
    )
    znp = once(
        znp,
        'throw new Error("B4 F0 runtime admission vetoed");',
        'throw new Error(object.command.name === "r4DiagReadOnlyV4" ? "B4 F2 runtime admission vetoed" : "B4 F0 runtime admission vetoed");',
    )
    # F0 has no nonce and retains its permanent timeout latch. F2 has a
    # per-request wire nonce: correlate it BEFORE resolving the waiter, then
    # permit only a later fresh read after both cooldown and owner SRSP progress.
    znp = once(znp, "    state?: number;", "    state?: number;\n    b4F2Nonce?: Buffer;")
    znp = once(znp, "    private b4DiagPoisoned = false;", """    private b4DiagPoisoned = false;
    private b4F2ConsecutiveTimeouts = 0;
    private readonly b4PassiveSrspStats: Record<"AF" | "ZDO" | "SYS" | "UTIL",
        {ok: number; timeout: number; maxLatencyMs: number; lastLatencyMs: number | null}> = {
        AF: {ok: 0, timeout: 0, maxLatencyMs: 0, lastLatencyMs: null},
        ZDO: {ok: 0, timeout: 0, maxLatencyMs: 0, lastLatencyMs: null},
        SYS: {ok: 0, timeout: 0, maxLatencyMs: 0, lastLatencyMs: null},
        UTIL: {ok: 0, timeout: 0, maxLatencyMs: 0, lastLatencyMs: null},
    };
    private b4F2NextAllowedMs = 0;
    private b4F2OwnerProgress = 0;
    private b4F2ProgressAtTimeout = 0;""")
    znp = once(znp, "    public b4IsDiagPoisoned(): boolean {", """    /** In-process, bounded, identity-free SRSP metrics. No extra requests,
     *  no wall-clock assumptions, no radio-epoch claim. */
    private b4PassiveSrspKey(subsystem: Subsystem): "AF" | "ZDO" | "SYS" | "UTIL" | null {
        return subsystem === Subsystem.AF ? "AF"
            : subsystem === Subsystem.ZDO ? "ZDO"
            : subsystem === Subsystem.SYS ? "SYS"
            : subsystem === Subsystem.UTIL ? "UTIL" : null;
    }

    private b4PassiveNoteAck(subsystem: Subsystem, elapsedMs: number): void {
        const key = this.b4PassiveSrspKey(subsystem);
        if (key === null || !Number.isFinite(elapsedMs) || elapsedMs < 0) { return; }
        const stats = this.b4PassiveSrspStats[key];
        const latency = Math.min(3600000, Math.floor(elapsedMs));
        stats.ok = Math.min(Number.MAX_SAFE_INTEGER, stats.ok + 1);
        stats.maxLatencyMs = Math.max(stats.maxLatencyMs, latency);
        stats.lastLatencyMs = latency;
    }

    private b4PassiveNoteTimeout(subsystem: Subsystem): void {
        const key = this.b4PassiveSrspKey(subsystem);
        if (key !== null) {
            const stats = this.b4PassiveSrspStats[key];
            stats.timeout = Math.min(Number.MAX_SAFE_INTEGER, stats.timeout + 1);
        }
    }

    /** F2-only: AF/ZDO completion AREQs may remain pending while a
     *  synchronous MT reply slot is free. SYS reset/unknown and all live
     *  SRSP waiters must block. Does not mutate stock Waitress state.
     */
    public b4F2NoBlockingWaiters(): boolean {
        return this.waitress.b4HasNoActiveBlockingWaiters((matcher) =>
            matcher.type === Type.AREQ &&
            (matcher.subsystem === Subsystem.AF || matcher.subsystem === Subsystem.ZDO));
    }

    public b4CanProbeV4(): boolean {
        return this.initialized && !this.b4DiagPoisoned &&
            this.queue.isIdle() && this.b4F2NoBlockingWaiters() &&
            this.b4F2ReadAdmissionReason() === null;
    }

    public b4GetPassiveOwnerMetrics() {
        return {
            initialized: this.initialized,
            mutexIdle: this.queue.isIdle(),
            mutexQueued: this.queue.count,
            waitressPending: this.waitress.b4PendingCount(),
            diagnosticQuarantined: this.b4DiagPoisoned,
            srsp: {
                AF: {...this.b4PassiveSrspStats.AF},
                ZDO: {...this.b4PassiveSrspStats.ZDO},
                SYS: {...this.b4PassiveSrspStats.SYS},
                UTIL: {...this.b4PassiveSrspStats.UTIL},
            },
            scope: "HOST_OWNER_LIFETIME_ONLY",
        };
    }

    /** Read-only nonce-bound F2 policy, never a reset or port reopen. */
    public b4F2ReadAdmissionReason(): string | null {
        if (this.b4F2ConsecutiveTimeouts >= 3) { return "F2_TIMEOUT_BUDGET_EXHAUSTED"; }
        if (this.b4F2ConsecutiveTimeouts > 0) {
            if (performance.now() < this.b4F2NextAllowedMs) { return "F2_TIMEOUT_COOLDOWN"; }
            if (this.b4F2OwnerProgress === this.b4F2ProgressAtTimeout) { return "F2_OWNER_PROGRESS_REQUIRED"; }
        }
        return null;
    }

    public b4F2AcceptReply(): void {
        this.b4F2ConsecutiveTimeouts = 0;
        this.b4F2NextAllowedMs = 0;
    }

    private b4F2RecordReplyTimeout(): void {
        this.b4F2ConsecutiveTimeouts = Math.min(3, this.b4F2ConsecutiveTimeouts + 1);
        this.b4F2NextAllowedMs = performance.now() + 60_000;
        this.b4F2ProgressAtTimeout = this.b4F2OwnerProgress;
        if (this.b4F2ConsecutiveTimeouts >= 3) { this.b4PoisonDiagSession(); }
    }

    public b4IsDiagPoisoned(): boolean {""")
    # F0 has no nonce: preserve the pristine conservative all-waiter gate.
    # The F2 timeout policy belongs only to b4CanProbeV4().
    if znp.count("this.queue.isIdle() && this.waitress.b4IsIdle();") != 1:
        raise ValueError("v3 F0 strict admission anchor drift")
    znp = once(znp, "            this.waitress.resolve(object);", """            const matched = this.waitress.resolve(object);
            if (matched && object.type === Type.SRSP &&
                !(object.subsystem === Subsystem.SYS &&
                  (object.command.name === "r4DiagReadOnly" || object.command.name === "r4DiagReadOnlyV4"))) {
                this.b4F2OwnerProgress = Math.min(Number.MAX_SAFE_INTEGER, this.b4F2OwnerProgress + 1);
            }""")
    znp = once(znp, "        const object = ZpiObject.createRequest(subsystem, command, payload);", """        if (subsystem === Subsystem.SYS && command === "r4DiagReadOnlyV4") {
            const reason = this.b4F2ReadAdmissionReason();
            if (reason !== null) { throw new Error("B4 " + reason); }
        }
        const object = ZpiObject.createRequest(subsystem, command, payload);""")
    # This source anchor is also used by the preservation-mode overlay; keep
    # the original createRequest statement unchanged and unique.
    znp = once(znp,
        "                const waiter = this.waitress.waitFor({type: Type.SRSP, subsystem: object.subsystem, command: object.command.name}, timeout || t);",
        """                const isB4F2 = object.subsystem === Subsystem.SYS && object.command.name === "r4DiagReadOnlyV4";
                const b4F2Nonce = isB4F2 ? Buffer.from(object.unpiFrame.data) : undefined;
                if (isB4F2 && b4F2Nonce?.length !== 8) { throw new Error("B4 F2_INVALID_REQUEST_NONCE"); }
                const waiter = this.waitress.waitFor({type: Type.SRSP, subsystem: object.subsystem,
                    command: object.command.name, ...(isB4F2 ? {b4F2Nonce} : {})}, timeout || t);""")
    znp = once(znp, "            (matcher.state === undefined || matcher.state === zpiObject.payload.state)", """            (matcher.state === undefined || matcher.state === zpiObject.payload.state) &&
            (!(matcher.type === Type.SRSP && matcher.subsystem === Subsystem.SYS &&
               matcher.command === "r4DiagReadOnlyV4") ||
                (Buffer.isBuffer(matcher.b4F2Nonce) && matcher.b4F2Nonce.length === 8 &&
                 Buffer.isBuffer(zpiObject.payload.diagnostic) && zpiObject.payload.diagnostic.length === 160 &&
                 matcher.b4F2Nonce.equals(zpiObject.payload.diagnostic.subarray(132, 140))))""")
    znp = once(znp, """                    if (isB4Diag) {
                        this.b4PoisonDiagSession();
                        this.waitress.b4Cancel(waiter.ID, "B4 diagnostic failed");
                    }
                    throw error;""", """                    if (isB4Diag) {
                        this.waitress.b4Cancel(waiter.ID, "B4 diagnostic failed");
                        if (isB4F2 && error instanceof Error && error.message ===
                            this.waitressTimeoutFormatter({type: Type.SRSP, subsystem: object.subsystem,
                                command: object.command.name}, timeout || t)) {
                            this.b4F2RecordReplyTimeout();
                            throw new Error("B4 F2_REPLY_TIMEOUT");
                        }
                        this.b4PoisonDiagSession();
                    }
                    throw error;""")
    znp = once(znp,
        "        const at_ms = Math.floor(performance.now());",
        """        this.b4PassiveNoteTimeout(subsystem);
        const at_ms = Math.floor(performance.now());""")
    znp = once(znp,
        "                const result = await waiter.start().promise.catch((error: unknown) => {",
        """                const b4NormalAckStart = performance.now();
                const result = await waiter.start().promise.then((response) => {
                    if (!isB4Diag) {
                        this.b4PassiveNoteAck(object.subsystem, performance.now() - b4NormalAckStart);
                    }
                    return response;
                }).catch((error: unknown) => {""")
    znp = once(znp,
        "            const result = await waiter.start().promise.catch((error: unknown) => {",
        """            const b4ZdoAckStart = performance.now();
            const result = await waiter.start().promise.then((response) => {
                this.b4PassiveNoteAck(Subsystem.ZDO, performance.now() - b4ZdoAckStart);
                return response;
            }).catch((error: unknown) => {""")
    # Redact v3/v4 host nonce and radio boot ID from ZNP DEBUG traces.
    znp = once(znp,
        "            logger.debug(() => `<-- ${object.toString(object.subsystem !== Subsystem.ZDO)}`, NS);",
        "            if (object.subsystem === Subsystem.SYS &&\n                (object.command.name === \"r4DiagReadOnly\" || object.command.name === \"r4DiagReadOnlyV4\")) {\n                logger.debug(\"B4 SYS SRSP (diagnostic body redacted)\", NS);\n            } else {\n                logger.debug(() => `<-- ${object.toString(object.subsystem !== Subsystem.ZDO)}`, NS);\n            }")
    znp = once(znp,
        "            logger.debug(() => `--> ${object}`, NS);",
        "            if (object.subsystem === Subsystem.SYS &&\n                (object.command.name === \"r4DiagReadOnly\" || object.command.name === \"r4DiagReadOnlyV4\")) {\n                logger.debug(\"B4 SYS SREQ (diagnostic nonce redacted)\", NS);\n            } else {\n                logger.debug(() => `--> ${object}`, NS);\n            }")
    # Passive existing-owner boundary observability: never open/reconfigure
    # UART. RX counts are inside the normal UNPI parser, TX counts are frames
    # offered to the existing stream (NOT a claim of physical TX completion).
    znp = once(znp,
        """    public b4GetPassiveOwnerMetrics() {
        return {""",
        """    public b4GetPassiveOwnerMetrics() {
        return {
            wire: {...this.unpiParser.b4NoWireIngress(),
                ...this.unpiWriter.b4NoWireEgress(),
                measurement: "EXISTING_OWNER_STREAM_ONLY"},""")
    # ZNP logging redaction alone is insufficient: pinned UNPI transport
    # DEBUG logging prints raw chunks/frame buffers, including boot token.
    writer = original[WRITER]
    writer = once(writer,
        "export class Writer extends stream.Readable {",
        """export class Writer extends stream.Readable {
    private b4TxQueuedBytes = 0;
    private b4TxQueuedFrames = 0;
    private b4TxQueuedRawBuffers = 0;

    public b4NoWireEgress() {
        return {txQueuedBytes: this.b4TxQueuedBytes,
            txQueuedFrames: this.b4TxQueuedFrames,
            txQueuedRawBuffers: this.b4TxQueuedRawBuffers};
    }
    private b4NoteQueued(bytes: number, frame: boolean): void {
        this.b4TxQueuedBytes = Math.min(Number.MAX_SAFE_INTEGER, this.b4TxQueuedBytes + bytes);
        if (frame) {
            this.b4TxQueuedFrames = Math.min(Number.MAX_SAFE_INTEGER, this.b4TxQueuedFrames + 1);
        } else {
            this.b4TxQueuedRawBuffers = Math.min(Number.MAX_SAFE_INTEGER, this.b4TxQueuedRawBuffers + 1);
        }
    }""")
    writer = once(writer,
        "        this.push(buffer);\n    }\n\n    public writeBuffer",
        "        this.b4NoteQueued(buffer.length, true);\n        this.push(buffer);\n    }\n\n    public writeBuffer")
    writer = once(writer,
        "        this.push(buffer);\n    }\n\n    public override _read",
        "        this.b4NoteQueued(buffer.length, false);\n        this.push(buffer);\n    }\n\n    public override _read")
    writer = once(writer,
        "        logger.debug(`--> frame [${[...buffer]}]`, NS);",
        "        logger.debug(`--> frame ${buffer.length} bytes (payload redacted)`, NS);")
    writer = once(writer,
        "        logger.debug(`--> buffer [${[...buffer]}]`, NS);",
        "        logger.debug(`--> buffer ${buffer.length} bytes (payload redacted)`, NS);")
    parser = original[PARSER]
    parser = once(parser,
        "    private buffer: Buffer;",
        """    private buffer: Buffer;
    private b4RxBytes = 0;
    private b4RxChunks = 0;
    private b4UnpiParsed = 0;
    private b4UnpiParseErrors = 0;

    public b4NoWireIngress() {
        return {rxRawBytes: this.b4RxBytes,
            rxChunks: this.b4RxChunks,
            unpiParsedFrames: this.b4UnpiParsed,
            unpiParseErrors: this.b4UnpiParseErrors,
            unpiBufferedBytes: this.buffer.length};
    }""")
    parser = once(parser,
        "        this.buffer = Buffer.concat([this.buffer, chunk]);",
        """        this.b4RxBytes = Math.min(Number.MAX_SAFE_INTEGER, this.b4RxBytes + chunk.length);
        this.b4RxChunks = Math.min(Number.MAX_SAFE_INTEGER, this.b4RxChunks + 1);
        this.buffer = Buffer.concat([this.buffer, chunk]);""")
    parser = once(parser,
        '                    this.emit("parsed", frame);',
        """                    this.b4UnpiParsed = Math.min(Number.MAX_SAFE_INTEGER, this.b4UnpiParsed + 1);
                    this.emit("parsed", frame);""")
    parser = once(parser,
        '                } catch (error) {',
        """                } catch (error) {
                    this.b4UnpiParseErrors = Math.min(Number.MAX_SAFE_INTEGER, this.b4UnpiParseErrors + 1);""")
    parser = once(parser,
        "        logger.debug(`<-- [${[...chunk]}]`, NS);",
        "        logger.debug(`<-- ${chunk.length} bytes (payload redacted)`, NS);")
    parser = once(parser,
        "        logger.debug(`--- parseNext [${[...this.buffer]}]`, NS);",
        "        logger.debug(`--- parseNext ${this.buffer.length} buffered bytes (payload redacted)`, NS);")
    parser = once(parser,
        "                    logger.debug(`--> parsed ${frame}`, NS);",
        "                    logger.debug(`--> parsed type=${frame.type} subsystem=${frame.subsystem} command=${frame.commandID} bytes=${frame.data.length}`, NS);")

    # The pinned Waitress owns a private Map; expose numeric occupancy
    # read-only, without changing resolution, timeout or cancellation behavior.
    waitress = once(original[WAITRESS],
        """    public b4IsIdle(): boolean {
        return this.waiters.size === 0;
    }""",
        """    public b4IsIdle(): boolean {
        return this.waiters.size === 0;
    }

    public b4PendingCount(): number {
        return this.waiters.size;
    }""")
    return {WAITRESS: (original[WAITRESS], waitress),
            DEFINITION: (original[DEFINITION], definition),
            PARAM: (original[PARAM], params), BUFFALO: (original[BUFFALO], buffalo),
            ADAPTER: (original[ADAPTER], adapter), ZNP: (original[ZNP], znp),
            CONTROLLER: (original[CONTROLLER], controller),
            PARSER: (original[PARSER], parser), WRITER: (original[WRITER], writer)}

def apply(root):
    items = plan(root)
    evidence = {"schema": "r4-b4-v4-herdsman-source-v1",
                "stage": "PINNED_DISPOSABLE_SOURCE_ONLY",
                "original_znp_owner": True, "hardware_verified": False,
                "installed": False, "v3_preserved": True,
                "unpi_raw_debug_payload_logging": False, "files": {}}
    for path, (before, after) in items.items():
        write_source_text(root, path, after)
        evidence["files"][path] = {"sha256_before": hashlib.sha256(before.encode()).hexdigest(),
                                   "sha256_after": hashlib.sha256(after.encode()).hexdigest()}
    return evidence

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--checkout", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    a = p.parse_args()
    result = apply(a.checkout)
    a.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
