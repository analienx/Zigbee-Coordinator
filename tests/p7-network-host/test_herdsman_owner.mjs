/** Real pinned Herdsman producer/parser/request/waitress; no port is opened.
 * P7_HERDSMAN_ROOT points to an isolated zigbee-herdsman@10.9.1 installation.
 */
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {createP7Diagnostics, HEALTH_COMMAND, loadHerdsmanBindings,
    validateHealthPayload} from '../../deploy/p7u_herdsman_diagnostics.mjs';

const root = process.env.P7_HERDSMAN_ROOT;
assert.ok(root, 'P7_HERDSMAN_ROOT must name the isolated pinned dependency');
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const bindings = loadHerdsmanBindings(root);
const require = createRequire(resolve(root, 'package.json'));
const {Frame} = require('./dist/adapter/z-stack/unpi/frame.js');
const {ZpiObject} = require('./dist/adapter/z-stack/znp/zpiObject.js');
require('./dist/utils/logger.js').setLogger({debug() {}, info() {}, warning() {}, error() {}});
const {Type, Subsystem, Znp} = bindings;

function crc16(buffer) {
    let crc = 0xFFFF;
    for (const value of buffer) {
        crc ^= value << 8;
        for (let bit = 0; bit < 8; bit++)
            crc = ((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0)) & 0xFFFF;
    }
    return crc;
}

function health({status = 0, enable = 1, cache = 1, discovery = 60, radius = 10} = {}) {
    const payload = Buffer.alloc(status ? 18 : 118);
    payload.write('P7G6');
    payload[4] = 2;
    payload[5] = status;
    payload[6] = 1;
    payload.writeUInt32LE(1000, 8);
    if (!status) {
        payload[16] = 16;
        payload[100] = enable;
        payload[101] = cache;
        payload[102] = discovery;
        payload[103] = radius;
        payload.writeUInt32LE(100000, 104);
        payload.writeUInt32LE(70000, 108);
    }
    payload.writeUInt16LE(crc16(payload.subarray(0, -2)), payload.length - 2);
    return payload;
}

function wrapped(payload) {
    return Buffer.concat([Buffer.from([payload.length]), payload]);
}

function owner(handler) {
    // Platform boundary only: use the actual constructor, queue, request,
    // ZpiObject, UNPI parser and waitress, replacing the physical writer.
    const znp = new Znp('TEST_NO_PORT_OPEN', 115200, false);
    znp.initialized = true;
    znp.open = () => { throw new Error('TEST_MUST_NOT_OPEN_PORT'); };
    znp.close = () => { throw new Error('TEST_MUST_NOT_CLOSE_OWNER'); };
    znp.unpiParser.on('parsed', frame => znp.onUnpiParsed(frame));
    const writes = [];
    znp.unpiWriter.writeFrame = frame => {
        const wire = frame.toBuffer();
        writes.push(wire);
        const reply = handler(frame);
        if (reply !== null) queueMicrotask(() => {
            const bytes = Buffer.isBuffer(reply) ?
                new Frame(Type.SRSP, Subsystem.SYS, frame.commandID, reply).toBuffer() : reply.wire;
            znp.unpiParser.write(bytes.subarray(0, 3));
            znp.unpiParser.write(bytes.subarray(3));
        });
    };
    return {znp, writes, client: () => createP7Diagnostics({znp, herdsmanRoot: root, session: 'test-owner-session'})};
}

test('real pinned Znp request/serializer/parser returns complete length-prefixed raw health', async () => {
    const raw = health();
    const fixture = owner(frame => {
        assert.equal(frame.type, Type.SREQ);
        assert.equal(frame.subsystem, Subsystem.SYS);
        assert.equal(frame.commandID, 0xF0);
        assert.deepEqual(frame.data, Buffer.from([2, 1]));
        return wrapped(raw);
    });
    const report = await fixture.client().readHealth();
    assert.deepEqual(fixture.writes, [Buffer.from('fe0221f00201d0', 'hex')]);
    assert.deepEqual(report.rawHealth, raw);
    assert.deepEqual(report.runtimeConcentrator,
        {enable: 1, route_cache: 1, discovery_seconds: 60, radius: 10});
    assert.equal(report.fullBodyDecoded, false);
    assert.equal(report.rebootIdentity, null);
    // An independent full decoder validates the same raw bytes, including
    // the appended heap fields. This is protocol evidence, not a radio test.
    const decoded = JSON.parse(execFileSync(process.env.PYTHON ?? 'python', ['-c',
        'import sys,json;sys.path.insert(0,"firmware/slzb-06p7/ti832/g6");import p7_g6_decode;print(json.dumps(p7_g6_decode.decode(bytes.fromhex(sys.argv[1]))))',
        raw.toString('hex')], {cwd: repo, encoding: 'utf8'}));
    assert.equal(decoded.heap.total_bytes, 100000);
    assert.deepEqual(decoded.runtime_concentrator, report.runtimeConcentrator);
});

test('actual ZpiObject dynamic BUFFER round trip supports both success and bounded error', () => {
    const fixture = owner(() => null);
    fixture.client();
    for (const raw of [health(), health({status: 4})]) {
        const wire = new Frame(Type.SRSP, Subsystem.SYS, 0xF0, wrapped(raw)).toBuffer();
        const parsed = Frame.fromBuffer(wire[1], wire.length - 1, wire);
        const object = ZpiObject.fromUnpiFrame(parsed);
        assert.equal(object.command.name, HEALTH_COMMAND);
        assert.equal(object.payload.length, raw.length);
        assert.deepEqual(object.payload.data, raw);
        assert.equal(validateHealthPayload(object.payload.data).status, raw[5]);
    }
});

test('only four public concentrator NV items are requested through normal owner API', async () => {
    const values = new Map([[0x32, 1], [0x33, 60], [0x34, 10], [0x36, 1]]);
    const fixture = owner(frame => {
        if (frame.commandID === 0xF0) return wrapped(health({enable: 0, cache: 0, discovery: 3}));
        assert.equal(frame.commandID, 8);
        assert.equal(frame.data.length, 3);
        assert.equal(frame.data[2], 0);
        assert.ok(values.has(frame.data.readUInt16LE(0)));
        return Buffer.from([0, 1, values.get(frame.data.readUInt16LE(0))]);
    });
    const report = await fixture.client().readConcentratorEvidence();
    assert.equal(fixture.writes.length, 5);
    assert.equal(fixture.writes[0].toString('hex'), 'fe03210832000018');
    assert.deepEqual(report.persisted, {enable: 1, discovery_seconds: 60, radius: 10, route_cache: 1});
    assert.equal(report.runtime.enable, 0);
    assert.equal(report.settingsVerified, false);
    assert.equal(report.routingBehaviorVerified, false);
});

test('matching persisted and live values qualify settings, never routing delivery', async () => {
    const values = new Map([[0x32, 1], [0x33, 60], [0x34, 10], [0x36, 1]]);
    const fixture = owner(frame => frame.commandID === 0xF0 ? wrapped(health()) :
        Buffer.from([0, 1, values.get(frame.data.readUInt16LE(0))]));
    const report = await fixture.client().readConcentratorEvidence();
    assert.equal(report.settingsVerified, true);
    assert.equal(report.routingBehaviorVerified, false);
});

test('timeouts use actual waitress and poison every client on the same owner with zero retries', async () => {
    const fixture = owner(() => null);
    const first = fixture.client();
    const second = fixture.client();
    await assert.rejects(first.readHealth({timeoutMs: 10}), /after 10ms/);
    await assert.rejects(first.readHealth(), /REPLACEMENT_OWNER_BOUNDARY_REQUIRED/);
    await assert.rejects(second.readPersistedConcentrator(), /REPLACEMENT_OWNER_BOUNDARY_REQUIRED/);
    assert.throws(() => fixture.client(), /REPLACEMENT_OWNER_BOUNDARY_REQUIRED/);
    assert.equal(fixture.writes.length, 1);
});

test('single operation guard spans the complete series across clients', async () => {
    const fixture = owner(() => null);
    const first = fixture.client();
    const second = fixture.client();
    const pending = first.readHealth({timeoutMs: 10});
    await assert.rejects(second.readPersistedConcentrator(), /ALREADY_PENDING/);
    await assert.rejects(pending, /after 10ms/);
    assert.equal(fixture.writes.length, 1);
});

test('bad inner CRC or NV item shape aborts once and poisons the owner', async () => {
    const raw = health();
    raw[20] ^= 1;
    const broken = owner(() => wrapped(raw));
    await assert.rejects(broken.client().readHealth(), /INVALID_P7_HEALTH_CRC/);
    assert.equal(broken.writes.length, 1);
    const nv = owner(() => Buffer.from([0, 0]));
    await assert.rejects(nv.client().readPersistedConcentrator(), /INVALID_CONCENTRATOR_NV_RESPONSE/);
    assert.equal(nv.writes.length, 1);
});

test('valid busy diagnostic response preserves status evidence without a retry', async () => {
    const fixture = owner(() => wrapped(health({status: 4})));
    const client = fixture.client();
    assert.equal((await client.readHealth()).status, 4);
    assert.equal(fixture.writes.length, 1);
});

test('CRC-valid truncated success is rejected rather than accepted as a shorter schema', async () => {
    const raw = health().subarray(0, 106);
    raw.writeUInt16LE(crc16(raw.subarray(0, -2)), raw.length - 2);
    const fixture = owner(() => wrapped(raw));
    await assert.rejects(fixture.client().readHealth(), /INVALID_P7_HEALTH_BODY/);
    assert.equal(fixture.writes.length, 1);
});

test('the actual stream parser drops bad outer FCS and the real waiter times out once', async () => {
    const wire = new Frame(Type.SRSP, Subsystem.SYS, 0xF0, wrapped(health())).toBuffer();
    wire[wire.length - 1] ^= 1;
    const fixture = owner(() => ({wire}));
    const client = fixture.client();
    await assert.rejects(client.readHealth({timeoutMs: 10}), /after 10ms/);
    await assert.rejects(client.readHealth(), /REPLACEMENT_OWNER_BOUNDARY_REQUIRED/);
    assert.equal(fixture.writes.length, 1);
});

test('an owner close invalidates existing clients and cannot silently cross a session', async () => {
    const fixture = owner(() => wrapped(health()));
    const client = fixture.client();
    fixture.znp.emit('close');
    await assert.rejects(client.readHealth(), /REPLACEMENT_OWNER_BOUNDARY_REQUIRED/);
    assert.throws(() => fixture.client(), /REPLACEMENT_OWNER_BOUNDARY_REQUIRED/);
    assert.equal(fixture.writes.length, 0);
    const inFlight = owner(() => {
        queueMicrotask(() => inFlight.znp.emit('close'));
        return wrapped(health());
    });
    await assert.rejects(inFlight.client().readHealth(), /REPLACEMENT_OWNER_BOUNDARY_REQUIRED/);
    assert.equal(inFlight.writes.length, 1);
});

test('wrong owner, uninitialized owner and command collisions are rejected before requests', () => {
    assert.throws(() => createP7Diagnostics({znp: {request() {}}, herdsmanRoot: root, session: 'x'}),
        /EXISTING_INITIALIZED_ZNP_OWNER_REQUIRED/);
    const znp = new Znp('TEST_NO_PORT_OPEN', 115200, false);
    assert.throws(() => createP7Diagnostics({znp, herdsmanRoot: root, session: 'x'}),
        /EXISTING_INITIALIZED_ZNP_OWNER_REQUIRED/);
    for (const collision of [{ID: 0xF0, name: 'foreignVendorCommand'},
        {ID: 0xF1, name: HEALTH_COMMAND}]) {
        bindings.Definition[Subsystem.SYS].push(collision);
        try { assert.throws(() => owner(() => null).client(), /COLLISION/); }
        finally { assert.equal(bindings.Definition[Subsystem.SYS].pop(), collision); }
    }
});
