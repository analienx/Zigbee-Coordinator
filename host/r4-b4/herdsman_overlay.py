"""Source-anchored *experimental* R4 B4 Zigbee-herdsman 10.9.1 overlay.

Applies to a disposable pinned checkout, not installed Z2M. Uses only the
existing ZStackAdapter.znp -> Znp.requestWithReply -> AsyncMutex/waiter owner;
never creates a new serial or USB client. No timer/polling is installed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SHA = "0968f979d558874b17396c96b66382d4236bbdcd"
DEFINITION = "src/adapter/z-stack/znp/definition.ts"
PARAM = "src/adapter/z-stack/znp/parameterType.ts"
BUFFALO = "src/adapter/z-stack/znp/buffaloZnp.ts"
ADAPTER = "src/adapter/z-stack/adapter/zStackAdapter.ts"
ZNP = "src/adapter/z-stack/znp/znp.ts"
MUTEX = "src/utils/async-mutex.ts"
MARKER = "B4_EXPERIMENTAL_EXISTING_OWNER"

ADAPTER_METHOD = r"""
    /** B4_EXPERIMENTAL_EXISTING_OWNER: manually invoked only. Never auto-polls.
     *  Host caller MUST positively attest idle state and OTA=false. This is
     *  not an external Zigbee2MQTT extension API or a production feature.
     *  No counter deltas or claimed radio epoch.
     */
    public async b4ReadOnlyDiagnostics(input: {
        enabled: boolean;
        hostIdle: boolean;
        otaActive: boolean;
    }): Promise<{abi: 3; validityMask: number; srspEnqueued: number | null; sequence: number; radioEpoch: "UNKNOWN"} | undefined> {
        if (
            input?.enabled !== true ||
            input?.hostIdle !== true ||
            input?.otaActive !== false ||
            this.closing ||
            !this.queue ||
            this.queue.count() !== 0 ||
            !this.znp.b4CanProbe() ||
            this.interpanLock
        ) {
            return undefined;
        }
        const now = performance.now(); // monotonic local process clock
        if (this.b4DiagInFlight || now < this.b4NextAllowedMs) {
            return undefined;
        }
        // Coalesce offers, bound the rate even after timeouts, and NEVER
        // retry within a burst or modify ordinary ZNP SRSP policy.
        this.b4DiagInFlight = true;
        this.b4NextAllowedMs = now + 30_000;
        try {
            const result = await this.znp.requestWithReply(Subsystem.SYS, "r4DiagReadOnly", {}, undefined, 1200);
            const data = result.payload.diagnostic;
            if (
                !Buffer.isBuffer(data) ||
                data.length !== 132 ||
                data.toString("ascii", 0, 4) !== "R4D3" ||
                data[4] !== 3 ||
                data[5] !== 0 ||
                data.readUInt16LE(6) !== 132 ||
                data.readUInt32LE(8) !== 0 ||
                data.readBigUInt64LE(16) !== 0n ||
                data.readUInt32LE(24) !== 0
            ) {
                return undefined;
            }
            const validityMask = data.readUInt32LE(12);
            // Native experimental image only supports SRSP enqueue count.
            // Other counters are UNKNOWN rather than fabricated zeros.
            if ((validityMask & ~0x10) !== 0) {
                return undefined;
            }
            return {
                abi: 3,
                validityMask,
                srspEnqueued: validityMask & 0x10 ? data.readUInt32LE(48) : null,
                sequence: data.readUInt32LE(28),
                radioEpoch: "UNKNOWN",
            };
        } catch {
            // Unsupported stock firmware, NPI hang, malformed frame or SRSP
            // timeout: silently back off. No independent raw port and no log.
            return undefined;
        } finally {
            this.b4DiagInFlight = false;
        }
    }

"""

def _git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args],
                                   stderr=subprocess.DEVNULL)

def replace_once(source, original, replacement):
    if source.count(original) != 1:
        raise ValueError("upstream source anchor drift/collision")
    return source.replace(original, replacement, 1)

def plan(root):
    if not root.is_dir() or not str(root.resolve()).startswith("/tmp/"):
        raise ValueError("herdsman overlay only allowed in disposable /tmp checkout")
    if _git(root, "rev-parse", "HEAD").decode().strip() != SHA:
        raise ValueError("herdsman source HEAD not exact version 10.9.1 pin")
    originals = {}
    for name in (DEFINITION, PARAM, BUFFALO, ADAPTER, ZNP, MUTEX):
        actual = (root / name).read_bytes()
        if actual != _git(root, "show", SHA + ":" + name):
            raise ValueError("dirty or wrong upstream source: " + name)
        originals[name] = actual.decode("utf-8")
    if any(MARKER in original for original in originals.values()):
        raise ValueError("overlay already present")
    if "ID: 240" in originals[DEFINITION] or "BUFFER132" in originals[PARAM]:
        raise ValueError("SYS F0 or parameter opcode collision")
    if "private znp: Znp;" not in originals[ADAPTER]:
        raise ValueError("herdsman owner path changed")
    if "this.znp.requestWithReply(" not in originals[ADAPTER]:
        raise ValueError("existing-owner API not present")
    changes = {}
    changes[DEFINITION] = replace_once(
        originals[DEFINITION],
        "    [Subsystem.SYS]: [",
        """    [Subsystem.SYS]: [
        // B4_EXPERIMENTAL_EXISTING_OWNER: read-only SYS F0; default disabled.
        {
            name: "r4DiagReadOnly",
            ID: 240,
            type: CommandType.SREQ,
            request: [],
            response: [{name: "diagnostic", parameterType: ParameterType.BUFFER132}],
        },""",
    )
    changes[PARAM] = replace_once(
        originals[PARAM],
        "    BUFFER100 = 10,",
        "    BUFFER100 = 10,\n    BUFFER132 = 19, // B4_EXPERIMENTAL_EXISTING_OWNER: fixed 132-byte diagnostic",
    )
    changes[BUFFALO] = replace_once(
        originals[BUFFALO],
        """            case ParameterType.BUFFER100: {
                return this.readBuffer(100);
            }""",
        """            case ParameterType.BUFFER100: {
                return this.readBuffer(100);
            }
            case ParameterType.BUFFER132: {
                // B4_EXPERIMENTAL_EXISTING_OWNER: strict fixed-size
                // payload. Buffalo.readBuffer alone silently truncates.
                if (this.getBuffer().length - this.getPosition() !== 132) {
                    throw new Error("B4 diagnostic length must be exactly 132");
                }
                return this.readBuffer(132);
            }""",
    )
    adapter = replace_once(
        originals[ADAPTER],
        "import assert from \"node:assert\";",
        'import assert from "node:assert";\nimport {performance} from "node:perf_hooks"; // B4 existing-owner monotonic cooldown',
    )
    adapter = replace_once(adapter,
       "    private interpanLock: boolean;",
       """    private interpanLock: boolean;
    private b4DiagInFlight = false;
    private b4NextAllowedMs = 0;""")
    adapter = replace_once(adapter,
       "    public async stop(): Promise<void> {",
       ADAPTER_METHOD + "    public async stop(): Promise<void> {")
    changes[ADAPTER] = adapter
    # The pinned AsyncMutex.count counts *queued* requests, not the
    # in-flight lock. An empty queue is NOT sufficient to prove ZNP idle.
    changes[MUTEX] = replace_once(
        originals[MUTEX],
        """    get count() {
        return this.#queue.length;
    }""",
        """    get count() {
        return this.#queue.length;
    }

    // B4_EXPERIMENTAL_EXISTING_OWNER: observation only; never alters locking.
    isIdle(): boolean {
        return !this.#locked && this.#queue.length === 0;
    }""",
    )
    // B4: bounded in-process timeout metadata, entirely free of device IDs,
    // IEEE addresses, raw frames, payloads, serial paths and disk access.
    changes[ZNP] = replace_once(
        originals[ZNP],
        "    private waitress: Waitress<ZpiObject, WaitressMatcher>;",
        """    private waitress: Waitress<ZpiObject, WaitressMatcher>;
    private b4HostForensicsEnabled = false;
    private b4HostTimeouts: Array<{at_ms: number; kind: "AF_SREQ_TIMEOUT" | "ZDO_SREQ_TIMEOUT" | "SYS_SREQ_TIMEOUT"}> = [];
    private b4HostDropped = 0;""",
    )
    changes[ZNP] = replace_once(
        changes[ZNP],
        "    public isInitialized(): boolean {",
        """    // B4_EXPERIMENTAL_EXISTING_OWNER: OFF by default. No writer or timer.
    public b4EnablePassiveForensics(enabled: boolean): void {
        this.b4HostForensicsEnabled = enabled === true;
        if (!this.b4HostForensicsEnabled) {
            this.b4HostTimeouts.length = 0;
            this.b4HostDropped = 0;
        }
    }

    public b4ReadPassiveForensics(): {
        schema: "r4-b4-inprocess-host-sreq-v1";
        recent_events: Array<{at_ms: number; kind: "AF_SREQ_TIMEOUT" | "ZDO_SREQ_TIMEOUT" | "SYS_SREQ_TIMEOUT"}>;
        dropped: number;
        radio_epoch: "UNKNOWN";
    } {
        const now = Math.floor(performance.now());
        this.b4HostTimeouts = this.b4HostTimeouts.filter((item) => item.at_ms >= now - 86_400_000);
        return {
            schema: "r4-b4-inprocess-host-sreq-v1",
            recent_events: this.b4HostTimeouts.map((event) => ({...event})),
            dropped: this.b4HostDropped,
            radio_epoch: "UNKNOWN",
        };
    }

    private b4RecordHostSreqTimeout(subsystem: Subsystem, command: string, timeout: number, error: unknown): void {
        if (!this.b4HostForensicsEnabled || !(error instanceof Error)) {
            return;
        }
        // Match the exact pinned Waitress-generated SRSP timeout error.
        // A transport write rejection or other exception is NOT a timeout.
        if (error.message !== this.waitressTimeoutFormatter({type: Type.SRSP, subsystem, command}, timeout)) {
            return;
        }
        const kind = subsystem === Subsystem.AF ? "AF_SREQ_TIMEOUT"
            : subsystem === Subsystem.ZDO ? "ZDO_SREQ_TIMEOUT"
            : subsystem === Subsystem.SYS ? "SYS_SREQ_TIMEOUT" : null;
        if (kind === null) {
            return;
        }
        const at_ms = Math.floor(performance.now());
        if (!Number.isSafeInteger(at_ms) || at_ms < 0) {
            this.b4HostDropped++;
            return;
        }
        if (this.b4HostTimeouts.length >= 256) {
            this.b4HostTimeouts.shift();
            this.b4HostDropped++;
        }
        this.b4HostTimeouts.push({at_ms, kind});
    }

    public isInitialized(): boolean {""",
    )
    changes[ZNP] = replace_once(
        changes[ZNP],
        "    public isInitialized(): boolean {",
        """    /** B4_EXPERIMENTAL_EXISTING_OWNER: query in-process mutex state.
     *  Neither a queue-length=0 nor serial present proves radio health.
     */
    public b4CanProbe(): boolean {
        return this.initialized && this.queue.isIdle();
    }

    public isInitialized(): boolean {""",
    )
    # Only the opt-in diagnostic waiter needs explicit cleanup on timeout:
    # pinned Waitress marks timedout=true but keeps it in its map until a
    # subsequent response. Do not change AF/ZDO/stock SYS waiter policy.
    changes[ZNP] = replace_once(
        changes[ZNP],
        """                const waiter = this.waitress.waitFor({type: Type.SRSP, subsystem: object.subsystem, command: object.command.name}, timeout || t);
                this.unpiWriter.writeFrame(object.unpiFrame);
                const result = await waiter.start().promise;""",
        """                const waiter = this.waitress.waitFor({type: Type.SRSP, subsystem: object.subsystem, command: object.command.name}, timeout || t);
                this.unpiWriter.writeFrame(object.unpiFrame);
                // B4_EXPERIMENTAL_EXISTING_OWNER: prevent a timed-out
                // diagnostic waiter lingering when the radio stays silent.
                const result = await waiter.start().promise.catch((error: unknown) => {
                    this.b4RecordHostSreqTimeout(object.subsystem, object.command.name, timeout || t, error);
                    // The pinned Waitress keeps a timed-out waiter until its
                    // next response; only B4 F0 alters stock cleanup policy.
                    if (object.command.name === "r4DiagReadOnly") {
                        this.waitress.remove(waiter.ID);
                    }
                    throw error;
                });""",
    )
    changes[ZNP] = replace_once(
        changes[ZNP],
        """            const waiter = this.waitress.waitFor({type: Type.SRSP, subsystem: Subsystem.ZDO, command: cmd.name}, timeouts.SREQ);

            this.unpiWriter.writeFrame(unpiFrame);

            const result = await waiter.start().promise;""",
        """            const waiter = this.waitress.waitFor({type: Type.SRSP, subsystem: Subsystem.ZDO, command: cmd.name}, timeouts.SREQ);

            this.unpiWriter.writeFrame(unpiFrame);

            const result = await waiter.start().promise.catch((error: unknown) => {
                this.b4RecordHostSreqTimeout(Subsystem.ZDO, cmd.name, timeouts.SREQ, error);
                throw error;
            });""",
    )
    return {k: (originals[k], changes[k]) for k in changes}

def apply(root):
    plans = plan(root)
    receipt = {
        "schema": "b4-herdsman-source-overlay-v1",
        "sha": SHA,
        "stage": "DISPOSABLE_PINNED_SOURCE_ONLY",
        "serial_owner": "EXISTING_ZNP_ONLY",
        "default_off": True,
        "native_or_host_installed": False,
        "files": {},
    }
    for name, (original, new) in plans.items():
        (root / name).write_text(new, encoding="utf-8", newline="")
        receipt["files"][name] = {
            "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(new.encode()).hexdigest(),
        }
    return receipt

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--checkout", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    args = p.parse_args()
    result = apply(args.checkout)
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
