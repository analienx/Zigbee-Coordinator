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

PIN = "0968f979d558874b17396c96b66382d4236bbdcd"
DEFINITION = "src/adapter/z-stack/znp/definition.ts"
PARAM = "src/adapter/z-stack/znp/parameterType.ts"
BUFFALO = "src/adapter/z-stack/znp/buffaloZnp.ts"
ADAPTER = "src/adapter/z-stack/adapter/zStackAdapter.ts"
ZNP = "src/adapter/z-stack/znp/znp.ts"
PARSER = "src/adapter/z-stack/unpi/parser.ts"
WRITER = "src/adapter/z-stack/unpi/writer.ts"
CONTROLLER = "src/controller/controller.ts"
MARKER = "B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE"

V4_ADAPTER_METHOD = r"""
    /** B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE: manually invoked, default OFF.
     * Uses the same existing ZNP owner and an unpredictable nonce to bind
     * each response to its request. A boot token is NOT a hardware attestation.
     */
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
        if (input?.enabled !== true || input?.hostIdle !== true ||
            input?.otaActive !== false || typeof input.stillAllowed !== "function" ||
            !input.stillAllowed() || this.closing || !this.queue ||
            this.queue.count() !== 0 || this.interpanLock ||
            !this.znp.b4CanProbe()) {
            return undefined;
        }
        const now = performance.now();
        if (this.b4DiagInFlight || now < this.b4NextAllowedMs) {
            return undefined;
        }
        // Uses Node cryptographic random bytes, NOT radio/IEEE or a secret.
        // Returned nonce remains in the request/response only; never logged.
        const nonce = randomBytes(8);
        this.b4DiagInFlight = true;
        this.b4NextAllowedMs = now + 30_000;
        this.znp.b4SetProbeGuard(input.stillAllowed);
        try {
            const response = await this.znp.requestWithReply(
                Subsystem.SYS, "r4DiagReadOnlyV4", {nonce}, undefined, 1200);
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
                return undefined;
            }
            const caps = data.readUInt32LE(8);
            const rawBoot = data.readBigUInt64LE(16);
            if ((caps === 0 && rawBoot !== 0n) ||
                (caps === 1 && rawBoot === 0n) ||
                (data[158] === 0 && data[156] !== 0xFF) ||
                (data[158] === 1 && data[156] === 0xFF)) {
                this.znp.b4PoisonDiagSession();
                return undefined;
            }
            const seq = data.readUInt32LE(28);
            // No cross-reboot counter delta: boot ID is probabilistic and
            // hardware qualification remains a separate physical gate.
            if (this.b4V4LastBoot === rawBoot &&
                this.b4V4LastSeq !== undefined && seq <= this.b4V4LastSeq) {
                this.znp.b4PoisonDiagSession();
                return undefined;
            }
            this.b4V4LastBoot = rawBoot;
            this.b4V4LastSeq = seq;
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
            if (error instanceof Error && error.message === "B4 F0 runtime admission vetoed") {
                return undefined;
            }
            // A failed v4 waiter can consume a late frame; disable further
            // experimental probes, ordinary AF/ZDO/SYS remain unchanged.
            this.znp.b4PoisonDiagSession();
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
    if not root.is_dir() or root.is_symlink() or not str(root.resolve()).startswith("/tmp/"):
        raise ValueError("only disposable /tmp herdsman source")
    if git(root, "rev-parse", "HEAD").decode().strip() != PIN:
        raise ValueError("herdsman HEAD drift")
    paths = (DEFINITION, PARAM, BUFFALO, ADAPTER, ZNP, CONTROLLER, PARSER, WRITER)
    original = {p: (root / p).read_text() for p in paths}
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
        "    private b4V4LastSeq: number | undefined;")
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

    public isStopping(): boolean {""")
    znp = original[ZNP]
    # Both transport checks must also apply to F2, but ONLY the optional
    # diagnostic opcodes. All ordinary command handling remains unmodified.
    # The pinned v3 overlay inserts exactly TWO pre-write optional-only
    # checks (disconnected/Waitress and late OTA veto). Extend both.
    old_check = 'object.command.name === "r4DiagReadOnly" &&'
    if znp.count(old_check) != 2:
        raise ValueError("v3 diagnostic owner mutex guard count drift")
    znp = znp.replace(old_check,
        '(object.command.name === "r4DiagReadOnly" || object.command.name === "r4DiagReadOnlyV4") &&')
    # Redact v3/v4 host nonce and radio boot ID from ZNP DEBUG traces.
    znp = once(znp,
        "            logger.debug(() => `<-- ${object.toString(object.subsystem !== Subsystem.ZDO)}`, NS);",
        "            if (object.subsystem === Subsystem.SYS &&\n                (object.command.name === \"r4DiagReadOnly\" || object.command.name === \"r4DiagReadOnlyV4\")) {\n                logger.debug(\"B4 SYS SRSP (diagnostic body redacted)\", NS);\n            } else {\n                logger.debug(() => `<-- ${object.toString(object.subsystem !== Subsystem.ZDO)}`, NS);\n            }")
    znp = once(znp,
        "            logger.debug(() => `--> ${object}`, NS);",
        "            if (object.subsystem === Subsystem.SYS &&\n                (object.command.name === \"r4DiagReadOnly\" || object.command.name === \"r4DiagReadOnlyV4\")) {\n                logger.debug(\"B4 SYS SREQ (diagnostic nonce redacted)\", NS);\n            } else {\n                logger.debug(() => `--> ${object}`, NS);\n            }")
    # ZNP logging redaction alone is insufficient: pinned UNPI transport
    # DEBUG logging prints raw chunks/frame buffers, including boot token.
    writer = original[WRITER]
    writer = once(writer,
        "        logger.debug(`--> frame [${[...buffer]}]`, NS);",
        "        logger.debug(`--> frame ${buffer.length} bytes (payload redacted)`, NS);")
    writer = once(writer,
        "        logger.debug(`--> buffer [${[...buffer]}]`, NS);",
        "        logger.debug(`--> buffer ${buffer.length} bytes (payload redacted)`, NS);")
    parser = original[PARSER]
    parser = once(parser,
        "        logger.debug(`<-- [${[...chunk]}]`, NS);",
        "        logger.debug(`<-- ${chunk.length} bytes (payload redacted)`, NS);")
    parser = once(parser,
        "        logger.debug(`--- parseNext [${[...this.buffer]}]`, NS);",
        "        logger.debug(`--- parseNext ${this.buffer.length} buffered bytes (payload redacted)`, NS);")
    parser = once(parser,
        "                    logger.debug(`--> parsed ${frame}`, NS);",
        "                    logger.debug(`--> parsed type=${frame.type} subsystem=${frame.subsystem} command=${frame.commandID} bytes=${frame.data.length}`, NS);")

    return {DEFINITION: (original[DEFINITION], definition),
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
        (Path(root) / path).write_text(after, encoding="utf-8", newline="")
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
