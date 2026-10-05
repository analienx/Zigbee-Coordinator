// T832-DIAG-R0 herdsman interoperability probe (hosted CI only).
//
// Reads C-emitted DEBUG.msg MT payloads as hex lines, frames each as a real
// ZNP AREQ DEBUG.msg wire frame (SOF/length/cmd/FCS), parses it with the
// pinned zigbee-herdsman UNPI Frame + ZpiObject parser, and emits fake
// zigbee2mqtt debug log lines using the real ZpiObject.toString()
// serialization. The Python decoders then prove the records survive.
//
// Usage:
//   node herdsman_interop.cjs payloads.hex z2m-roundtrip.log
//   node herdsman_interop.cjs --negatives z2m-negative.log
//
// Exit nonzero on any round-trip mismatch: the parsed `string` Buffer must
// equal the C-emitted DEBUG string bytes exactly.
'use strict';

const fs = require('node:fs');
const {Frame} = require('zigbee-herdsman/dist/adapter/z-stack/unpi/frame');
const {ZpiObject} = require('zigbee-herdsman/dist/adapter/z-stack/znp/zpiObject');

const CMD0_DEBUG_AREQ = 0x48;
const CMD1_DEBUG_MSG = 0x80;

function fcs(bytes) {
    let c = 0;
    for (const b of bytes) {
        c ^= b;
    }
    return c;
}

function framePayload(mtPayloadHex) {
    const payload = Buffer.from(mtPayloadHex.trim(), 'hex');
    if (payload.length < 8 || payload.length > 240) {
        throw new Error(`payload-length:${payload.length}`);
    }
    const head = Buffer.from([payload.length, CMD0_DEBUG_AREQ, CMD1_DEBUG_MSG]);
    const wire = Buffer.concat([Buffer.from([0xfe]), head, payload]);
    return Buffer.concat([wire, Buffer.from([fcs(wire.subarray(1))])]);
}

function roundtrip(mtPayloadHex) {
    const payload = Buffer.from(mtPayloadHex.trim(), 'hex');
    const wire = framePayload(mtPayloadHex);
    const frame = Frame.fromBuffer(payload.length, 4 + payload.length, wire);
    const obj = ZpiObject.fromUnpiFrame(frame);
    if (obj.command.name !== 'msg') {
        throw new Error(`unexpected-command:${obj.command.name}`);
    }
    const parsed = obj.payload.string;
    if (!Buffer.isBuffer(parsed)) {
        throw new Error('string-not-a-buffer');
    }
    // Herdsman consumes the length prefix: parsed equals the C string bytes.
    const expected = payload.subarray(1);
    if (expected.length !== obj.payload.length) {
        throw new Error(`length-prefix:${obj.payload.length}-vs-${expected.length}`);
    }
    if (!parsed.equals(expected)) {
        throw new Error('roundtrip-mismatch');
    }
    return `2026-10-03T09:00:00Z zh:zstack:znp: ${obj.toString()}`;
}

function main() {
    const args = process.argv.slice(2);
    if (args[0] === '--negatives') {
        const lines = [
            // Truncated Buffer array (valid JSON, undecodable payload).
            '2026-10-03T09:00:00Z zh:zstack:znp: AREQ: DEBUG - msg - {"length":9,"string":{"type":"Buffer","data":[84,56,51,50]}}}',
            // Unknown schema tag.
            '2026-10-03T09:00:01Z zh:zstack:znp: AREQ: DEBUG - msg - {"length":12,"string":{"type":"Buffer","data":[84,56,51,50,68,57,58,48,48,49,50,51]}}}',
            // Corrupt hex length (odd nibble count after prefix).
            '2026-10-03T09:00:02Z some T832D2:ABC plaintext fallback fragment',
            // Non-DEBUG Buffer must be ignored by the collector.
            '2026-10-03T09:00:03Z zh:zstack:znp: AREQ: SYS - ping - {"capabilities":{"type":"Buffer","data":[84,56,51,50,68,50]}}}',
        ];
        fs.writeFileSync(args[1], lines.join('\n') + '\n');
        console.log(`wrote ${lines.length} negative lines`);
        return;
    }
    const hexLines = fs.readFileSync(args[0], 'utf8').split('\n').filter((l) => l.trim().length > 0);
    if (hexLines.length === 0) {
        throw new Error('no-payloads');
    }
    const out = hexLines.map((hex, i) => {
        try {
            return roundtrip(hex);
        } catch (err) {
            throw new Error(`line-${i}:${err.message}`);
        }
    });
    fs.writeFileSync(args[1], out.join('\n') + '\n');
    console.log(`roundtrip OK: ${out.length} frames`);
}

main();
