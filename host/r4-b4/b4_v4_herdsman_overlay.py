"""Additive v4 (SYS F1) to exact already-audited B4 v3 herdsman 10.9.1.

No change to v3 F0 opcode/request/payload or its default-off policy.
Pins pristine upstream by comparing the v3 overlay receipt's before/after
SHA with actual pinned tree. Caller-supplied random nonce is echoed and
verified after SREQ waiter resolution; stale F1 can never be a valid sample.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from herdsman_overlay import SHA, DEFINITION, PARAM, BUFFALO, ADAPTER, ZNP, CONTROLLER

MARKER = "B4_V4_NONCE_AND_BOOT"
PARSER = "src/adapter/z-stack/unpi/parser.ts"
WRITER = "src/adapter/z-stack/unpi/writer.ts"
PATHS = (DEFINITION, PARAM, BUFFALO, ADAPTER, ZNP, CONTROLLER, PARSER, WRITER)

def _git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args],
                                   stderr=subprocess.DEVNULL)

def replace(source, before, after, count=1):
    if source.count(before) != count:
        raise ValueError("v4 pinned herdsman source anchor moved: " + before[:70])
    return source.replace(before, after)

V4_ADAPTER_METHOD = r"""
    /** B4_V4_NONCE_AND_BOOT: standalone, manually called, never auto-polls.
     *  A nonce is a correlation token, NOT cryptographic authentication.
     */
    public async b4ReadOnlyDiagnosticsV4(input: {
        enabled: boolean; hostIdle: boolean; otaActive: boolean;
        stillAllowed: () => boolean;
    }): Promise<{
        abi: 4; validityMask: number; sequence: number;
        radioEpoch: string | "UNKNOWN"; bootEpochAvailable: boolean;
        resetReason: number; sourceFingerprint: string; minor: 0;
        srspDepth: number | null; srspHighWater: number | null;
        asyncDepth: number; asyncHighWater: number;
        srspEnqueued: number | null; uartTxFinishedEvents: number;
    } | undefined> {
        if (input?.enabled !== true || input?.hostIdle !== true ||
            input?.otaActive !== false || typeof input.stillAllowed !== "function" ||
            input.stillAllowed() !== true ||
            this.closing || !this.queue || this.queue.count() !== 0 ||
            !this.znp.b4CanProbe() || this.interpanLock) {
            return undefined;
        }
        const now = performance.now();
        if (this.b4DiagInFlight || now < this.b4NextAllowedMs) return undefined;
        const nonce = randomBytes(8);
        if (nonce.equals(Buffer.alloc(8))) return undefined;
        this.b4DiagInFlight = true;
        this.b4NextAllowedMs = now + 30_000;
        this.znp.b4SetProbeGuard(input.stillAllowed);
        try {
            const obj = await this.znp.requestWithReply(
                Subsystem.SYS, "r4DiagReadOnlyV4", {nonce}, undefined, 1200);
            const data: Buffer = obj.payload.diagnostic;
            if (!Buffer.isBuffer(data) || data.length !== 160 ||
                data.toString("ascii", 0, 4) !== "R4D4" || data[4] !== 4 ||
                data[5] !== 0 || data.readUInt16LE(6) !== 160 ||
                !data.subarray(132, 140).equals(nonce) ||
                data.readUInt32LE(24) !== 0 || data.readUInt32LE(28) === 0 ||
                data.readUInt16LE(152) !== 0 || data.readUInt32LE(156) !== 0 ||
                data.readBigUInt64LE(144) === 0n) {
                this.znp.b4PoisonDiagSession();
                return undefined;
            }
            const caps = data.readUInt32LE(8);
            const valid = data.readUInt32LE(12);
            const epoch = data.readBigUInt64LE(16);
            const status = data.readUInt16LE(154);
            if ((caps !== 2 && caps !== 3) ||
                (valid !== 0x3F && valid !== 0x2C) ||
                status !== ((caps & 1) !== 0 ? 1 : 0) ||
                (status === 0 && epoch !== 0n) ||
                (status === 1 && epoch === 0n) ||
                Array.from({length: 25}, (_, i) => i)
                    .some((i) => (((valid >>> i) & 1) === 0) &&
                        data.readUInt32LE(32 + 4 * i) !== 0) ||
                (valid === 0x3F && data.readUInt32LE(32) > data.readUInt32LE(36)) ||
                data.readUInt32LE(40) > data.readUInt32LE(44)) {
                this.znp.b4PoisonDiagSession();
                return undefined;
            }
            const sequence = data.readUInt32LE(28);
            if (this.b4LastV4Sequence !== undefined &&
                this.b4LastV4BootEpoch === epoch &&
                sequence <= this.b4LastV4Sequence) {
                this.znp.b4PoisonDiagSession();
                return undefined;
            }
            this.b4LastV4Sequence = sequence;
            this.b4LastV4BootEpoch = epoch;
            return {
                abi: 4, validityMask: valid, sequence,
                radioEpoch: status === 1 ? epoch.toString(16).padStart(16, "0") : "UNKNOWN",
                bootEpochAvailable: status === 1,
                resetReason: data.readUInt32LE(140),
                sourceFingerprint: data.readBigUInt64LE(144).toString(16).padStart(16, "0"),
                minor: 0,
                srspDepth: valid & 1 ? data.readUInt32LE(32) : null,
                srspHighWater: valid & 2 ? data.readUInt32LE(36) : null,
                asyncDepth: data.readUInt32LE(40),
                asyncHighWater: data.readUInt32LE(44),
                srspEnqueued: valid & 16 ? data.readUInt32LE(48) : null,
                uartTxFinishedEvents: data.readUInt32LE(52),
            };
        } catch (error: unknown) {
            if (error instanceof Error && error.message === "B4 F0 runtime admission vetoed") {
                return undefined;
            }
            this.znp.b4PoisonDiagSession();
            return undefined;
        } finally {
            this.znp.b4SetProbeGuard(undefined);
            this.b4DiagInFlight = false;
        }
    }

"""

def plan(root, v3_receipt):
    root = Path(root)
    if not root.is_dir() or root.is_symlink() or not str(root.resolve()).startswith("/tmp/"):
        raise ValueError("disposable /tmp herdsman only")
    if _git(root, "rev-parse", "HEAD").decode().strip() != SHA:
        raise ValueError("v4 exact pinned herdsman SHA mismatch")
    prior = json.loads(Path(v3_receipt).read_text())
    if (prior.get("schema") != "b4-herdsman-source-overlay-v1" or
            prior.get("sha") != SHA or prior.get("serial_owner") != "EXISTING_ZNP_ONLY" or
            prior.get("default_off") is not True or
            prior.get("native_or_host_installed") is not False or
            not set(PATHS[:-2]).issubset(prior.get("files", {}))):
        raise ValueError("verified v3 owner source receipt required")
    src = {}
    for name in PATHS:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("missing actual patched herdsman file")
        content = path.read_bytes()
        pristine = _git(root, "show", SHA+":"+name)
        if name in (PARSER, WRITER):
            # v3 doesn't touch these; demand pristine exact pinned transport.
            if content != pristine:
                raise ValueError("v4 transport logger source changed from pinned upstream")
        else:
            receipt = prior["files"][name]
            if (hashlib.sha256(content).hexdigest() != receipt["after_sha256"] or
                    hashlib.sha256(pristine).hexdigest() != receipt["before_sha256"]):
                raise ValueError("v3 source drift against exact pin")
        src[name] = content.decode()
    if any(MARKER in text for text in src.values()):
        raise ValueError("v4 already present")
    definition = replace(src[DEFINITION],
        '            name: "r4DiagReadOnly",',
        '''            name: "r4DiagReadOnly",''')
    # Add adjacent to v3 command without altering its bytes.
    anchor = '''            response: [{name: "diagnostic", parameterType: ParameterType.BUFFER132}],
        },'''
    definition = replace(definition, anchor, anchor + '''
        // B4_V4_NONCE_AND_BOOT: separate opcode; F0 v3 is untouched.
        {
            name: "r4DiagReadOnlyV4", ID: 241,
            type: CommandType.SREQ,
            request: [{name: "nonce", parameterType: ParameterType.BUFFER8}],
            response: [{name: "diagnostic", parameterType: ParameterType.BUFFER160}],
        },''')
    param = replace(src[PARAM], '    BUFFER132 = 19,',
        '    BUFFER132 = 19,\n    BUFFER160 = 20, // B4_V4_NONCE_AND_BOOT')
    buffalo = replace(src[BUFFALO],
        '''            case ParameterType.BUFFER132: {
                // B4_EXPERIMENTAL_EXISTING_OWNER: strict fixed-size
                // payload. Buffalo.readBuffer alone silently truncates.
                if (this.getBuffer().length - this.getPosition() !== 132) {
                    throw new Error("B4 diagnostic length must be exactly 132");
                }
                return this.readBuffer(132);
            }''',
        '''            case ParameterType.BUFFER132: {
                // B4_EXPERIMENTAL_EXISTING_OWNER: strict fixed-size
                // payload. Buffalo.readBuffer alone silently truncates.
                if (this.getBuffer().length - this.getPosition() !== 132) {
                    throw new Error("B4 diagnostic length must be exactly 132");
                }
                return this.readBuffer(132);
            }
            case ParameterType.BUFFER160: {
                // B4_V4_NONCE_AND_BOOT: never accept truncated/extra payload.
                if (this.getBuffer().length - this.getPosition() !== 160) {
                    throw new Error("B4 v4 diagnostic length must be exactly 160");
                }
                return this.readBuffer(160);
            }''')
    adapter = replace(src[ADAPTER], 'import assert from "node:assert";',
        'import assert from "node:assert";\nimport {randomBytes} from "node:crypto"; // B4_V4_NONCE_AND_BOOT nonce')
    adapter = replace(adapter,
        "    /** B4 source-only opt-in; no disk I/O, ZNP request, MQTT, or serial open. */",
        V4_ADAPTER_METHOD + "    /** B4 source-only opt-in; no disk I/O, ZNP request, MQTT, or serial open. */")
    adapter = replace(adapter,
        "    private b4LastDiagSequence: number | undefined;",
        """    private b4LastDiagSequence: number | undefined;
    private b4LastV4Sequence: number | undefined;
    private b4LastV4BootEpoch: bigint | undefined;""")
    znp = src[ZNP]
    znp = replace(znp,
        'command === "r4DiagReadOnly" && this.b4DiagPoisoned',
        '(command === "r4DiagReadOnly" || command === "r4DiagReadOnlyV4") && this.b4DiagPoisoned')
    znp = replace(znp,
        'object.command.name === "r4DiagReadOnly" &&',
        '(object.command.name === "r4DiagReadOnly" || object.command.name === "r4DiagReadOnlyV4") &&', 2)
    znp = replace(znp,
        'object.command.name === "r4DiagReadOnly")',
        '(object.command.name === "r4DiagReadOnly" || object.command.name === "r4DiagReadOnlyV4"))', 2)
    # Redact v3/v4 host nonce and radio boot ID from ZNP DEBUG traces.
    znp = replace(znp,
        "            logger.debug(() => `<-- ${object.toString(object.subsystem !== Subsystem.ZDO)}`, NS);",
        "            if (object.subsystem === Subsystem.SYS &&\n                (object.command.name === \"r4DiagReadOnly\" || object.command.name === \"r4DiagReadOnlyV4\")) {\n                logger.debug(\"B4 SYS SRSP (diagnostic body redacted)\", NS);\n            } else {\n                logger.debug(() => `<-- ${object.toString(object.subsystem !== Subsystem.ZDO)}`, NS);\n            }")
    znp = replace(znp,
        "            logger.debug(() => `--> ${object}`, NS);",
        "            if (object.subsystem === Subsystem.SYS &&\n                (object.command.name === \"r4DiagReadOnly\" || object.command.name === \"r4DiagReadOnlyV4\")) {\n                logger.debug(\"B4 SYS SREQ (diagnostic nonce redacted)\", NS);\n            } else {\n                logger.debug(() => `--> ${object}`, NS);\n            }")
    # ZNP logging redaction alone is insufficient: pinned UNPI transport
    # DEBUG logging prints raw chunks/frame buffers, including boot token.
    writer = src[WRITER]
    writer = replace(writer,
        "        logger.debug(`--> frame [${[...buffer]}]`, NS);",
        "        logger.debug(`--> frame ${buffer.length} bytes (payload redacted)`, NS);")
    writer = replace(writer,
        "        logger.debug(`--> buffer [${[...buffer]}]`, NS);",
        "        logger.debug(`--> buffer ${buffer.length} bytes (payload redacted)`, NS);")
    parser = src[PARSER]
    parser = replace(parser,
        "        logger.debug(`<-- [${[...chunk]}]`, NS);",
        "        logger.debug(`<-- ${chunk.length} bytes (payload redacted)`, NS);")
    parser = replace(parser,
        "        logger.debug(`--- parseNext [${[...this.buffer]}]`, NS);",
        "        logger.debug(`--- parseNext ${this.buffer.length} buffered bytes (payload redacted)`, NS);")
    parser = replace(parser,
        "                    logger.debug(`--> parsed ${frame}`, NS);",
        "                    logger.debug(`--> parsed type=${frame.type} subsystem=${frame.subsystem} command=${frame.commandID} bytes=${frame.data.length}`, NS);")
    controller = replace(src[CONTROLLER],
        "    public isStopping(): boolean {",
        """    /** B4_V4_NONCE_AND_BOOT: guarded internal v4, never new serial. */
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
    return {DEFINITION: (src[DEFINITION], definition),
            PARAM: (src[PARAM], param),
            BUFFALO: (src[BUFFALO], buffalo),
            ADAPTER: (src[ADAPTER], adapter),
            ZNP: (src[ZNP], znp),
            CONTROLLER: (src[CONTROLLER], controller),
            WRITER: (src[WRITER], writer),
            PARSER: (src[PARSER], parser)}

def apply(root, v3_receipt):
    changes = plan(root, v3_receipt)
    result = {"schema": "b4-v4-herdsman-addon-v1",
        "source_sha": SHA,
        "stage": "PINNED_COMPILED_NOT_INSTALLED",
        "same_znp_owner": True,
        "request": {"opcode": 241, "nonce_bytes": 8},
        "response_bytes": 160,
        "auto_enabled": False,
        "files": {}}
    for name, (before, after) in changes.items():
        (Path(root) / name).write_text(after, encoding="utf-8", newline="")
        result["files"][name] = {"before_sha256": hashlib.sha256(before.encode()).hexdigest(),
                                 "after_sha256": hashlib.sha256(after.encode()).hexdigest()}
    return result

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
