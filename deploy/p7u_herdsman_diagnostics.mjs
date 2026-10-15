/** Read-only P7 diagnostics using an already initialized Herdsman Znp owner.
 * No port, socket, reset, reconnect, NV write, timer loop or process is opened.
 * This adapter targets the pinned Herdsman 10.9.1 public Znp.request API.
 */
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

export const PINNED_HERDSMAN = Object.freeze({version: '10.9.1',
    sourceCommit: '0968f979d558874b17396c96b66382d4236bbdcd'});
export const HEALTH_COMMAND = 'p7uReadOnlyHealthV2';
const owners = new WeakMap();
const registrations = new WeakMap();
const NV_ITEMS = Object.freeze({enable: 0x32, discovery_seconds: 0x33,
    radius: 0x34, route_cache: 0x36});
const EXPECTED = Object.freeze({enable: 1, discovery_seconds: 60, radius: 10, route_cache: 1});

export function loadHerdsmanBindings(herdsmanRoot) {
    const root = resolve(herdsmanRoot);
    const metadata = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
    if (metadata.name !== 'zigbee-herdsman' || metadata.version !== PINNED_HERDSMAN.version)
        throw new Error('PINNED_HERDSMAN_VERSION_REQUIRED');
    const require = createRequire(resolve(root, 'package.json'));
    const {Znp} = require('./dist/adapter/z-stack/znp/znp.js');
    const Definition = require('./dist/adapter/z-stack/znp/definition.js').default;
    const ParameterType = require('./dist/adapter/z-stack/znp/parameterType.js').default;
    const {Subsystem, Type} = require('./dist/adapter/z-stack/unpi/constants.js');
    if (Subsystem.SYS !== 1 || Type.SREQ !== 1 || Type.SRSP !== 3 ||
        ParameterType.UINT8 !== 0 || ParameterType.BUFFER !== 4)
        throw new Error('UNEXPECTED_HERDSMAN_ABI');
    return {Znp, Definition, ParameterType, Subsystem, Type};
}

function register(bindings) {
    const {Definition, ParameterType: P, Subsystem, Type} = bindings;
    const commands = Definition[Subsystem.SYS];
    if (!Array.isArray(commands)) throw new Error('SYS_DEFINITION_MISSING');
    const matching = commands.filter(command => command.ID === 0xF0 || command.name === HEALTH_COMMAND);
    const previous = registrations.get(Definition);
    if (matching.length) {
        if (matching.length !== 1 || matching[0] !== previous)
            throw new Error('SYS_F0_OR_COMMAND_NAME_COLLISION');
        return previous;
    }
    if (previous) throw new Error('P7_COMMAND_REGISTRATION_REMOVED');
    const fields = array => Object.freeze(array.map(Object.freeze));
    const command = Object.freeze({name: HEALTH_COMMAND, ID: 0xF0, type: Type.SREQ,
        request: fields([{name: 'version', parameterType: P.UINT8},
            {name: 'operation', parameterType: P.UINT8}]),
        response: fields([{name: 'length', parameterType: P.UINT8},
            {name: 'data', parameterType: P.BUFFER}])});
    commands.push(command);
    registrations.set(Definition, command);
    return command;
}

function crc16(data) {
    let crc = 0xFFFF;
    for (const value of data) {
        crc ^= value << 8;
        for (let bit = 0; bit < 8; bit++)
            crc = ((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0)) & 0xFFFF;
    }
    return crc;
}

export function validateHealthPayload(data) {
    // Preserve the complete bounded raw payload for the firmware's full decoder.
    // Version 2 has one exact success schema; a new schema needs a version change.
    if (!Buffer.isBuffer(data) || data.length < 18 || data.length > 144 ||
        data.subarray(0, 4).toString('ascii') !== 'P7G6' || data[4] !== 2)
        throw new Error('INVALID_P7_HEALTH_ENVELOPE');
    if (data.readUInt16LE(data.length - 2) !== crc16(data.subarray(0, -2)))
        throw new Error('INVALID_P7_HEALTH_CRC');
    if (data[5] > 5 || data[6] !== 1 || data[7] !== 0 ||
        data.readUInt32LE(8) === 0 || data.readUInt32LE(12) !== 0)
        throw new Error('INVALID_P7_HEALTH_HEADER');
    const result = {version: 2, status: data[5], rawHealth: Buffer.from(data),
        tickPeriodUs: data.readUInt32LE(8), rebootIdentity: null};
    if (data[5] !== 0) {
        if (data.length !== 18) throw new Error('INVALID_P7_ERROR_LENGTH');
        return result;
    }
    if (data.length !== 118 || data[16] !== 16 || data[17] > 1 ||
        data.readUInt16LE(18) !== 0 || data[100] > 1 || data[101] > 1)
        throw new Error('INVALID_P7_HEALTH_BODY');
    result.runtimeConcentrator = {enable: data[100], route_cache: data[101],
        discovery_seconds: data[102], radius: data[103]};
    result.fullBodyDecoded = false;
    return result;
}

function responseObject(reply, bindings, id, name) {
    if (!reply || reply.type !== bindings.Type.SRSP || reply.subsystem !== bindings.Subsystem.SYS ||
        reply.command?.ID !== id || reply.command?.name !== name || !reply.payload)
        throw new Error('UNEXPECTED_OWNER_SRSP');
    return reply.payload;
}

/** Pass the actual Znp instance and its own installed package root.
 * A poisoned instance cannot be reused by constructing another client. The
 * existing application owner must establish a drained/reconnected boundary
 * with a replacement Znp instance before creating another diagnostic client.
 */
export function createP7Diagnostics({znp, herdsmanRoot, session}) {
    const bindings = loadHerdsmanBindings(herdsmanRoot);
    if (!(znp instanceof bindings.Znp) || !znp.isInitialized())
        throw new Error('EXISTING_INITIALIZED_ZNP_OWNER_REQUIRED');
    if (typeof session !== 'string' || session.length < 1 || session.length > 128)
        throw new Error('OPAQUE_OWNER_SESSION_REQUIRED');
    const command = register(bindings);
    let state = owners.get(znp);
    if (!state) {
        state = {busy: false, poisoned: false};
        owners.set(znp, state);
        znp.once('close', () => { state.poisoned = true; });
    }
    if (state.poisoned) throw new Error('REPLACEMENT_OWNER_BOUNDARY_REQUIRED');

    async function operation(timeoutMs, work) {
        if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000)
            throw new Error('REQUEST_TIMEOUT_OUT_OF_RANGE');
        if (state.poisoned) throw new Error('REPLACEMENT_OWNER_BOUNDARY_REQUIRED');
        if (state.busy) throw new Error('DIAGNOSTIC_OPERATION_ALREADY_PENDING');
        if (!znp.isInitialized()) throw new Error('OWNER_NOT_INITIALIZED');
        state.busy = true;
        try {
            const result = await work();
            if (state.poisoned || !znp.isInitialized())
                throw new Error('REPLACEMENT_OWNER_BOUNDARY_REQUIRED');
            return result;
        }
        catch (error) {
            // No nonce exists in these SRSPs. A late reply after a failed read
            // must not be mistaken for the next read on the same owner.
            state.poisoned = true;
            throw error;
        } finally { state.busy = false; }
    }

    async function healthRead(timeoutMs) {
        const reply = await znp.request(bindings.Subsystem.SYS, HEALTH_COMMAND,
            {version: 2, operation: 1}, undefined, timeoutMs);
        const payload = responseObject(reply, bindings, command.ID, command.name);
        if (!Number.isInteger(payload.length) || !Buffer.isBuffer(payload.data) ||
            payload.length !== payload.data.length || payload.length > 144)
            throw new Error('INVALID_OWNER_HEALTH_LENGTH');
        return {...validateHealthPayload(payload.data), session};
    }

    async function concentratorReads(timeoutMs) {
        const result = {};
        for (const [name, id] of Object.entries(NV_ITEMS)) {
            const reply = await znp.request(bindings.Subsystem.SYS, 'osalNvRead',
                {id, offset: 0}, undefined, timeoutMs);
            const payload = responseObject(reply, bindings, 8, 'osalNvRead');
            if (payload.status !== 0 || payload.len !== 1 || !Buffer.isBuffer(payload.value) ||
                payload.value.length !== 1) throw new Error('INVALID_CONCENTRATOR_NV_RESPONSE');
            result[name] = payload.value[0];
        }
        return result;
    }

    return Object.freeze({
        readHealth: ({timeoutMs = 2000} = {}) => operation(timeoutMs, () => healthRead(timeoutMs)),
        readPersistedConcentrator: ({timeoutMs = 2000} = {}) =>
            operation(timeoutMs, () => concentratorReads(timeoutMs)),
        readConcentratorEvidence: ({timeoutMs = 2000} = {}) => operation(timeoutMs, async () => {
            const persisted = await concentratorReads(timeoutMs);
            const health = await healthRead(timeoutMs);
            const runtime = health.runtimeConcentrator ?? null;
            const settingsVerified = runtime !== null && Object.entries(EXPECTED).every(
                ([key, value]) => persisted[key] === value && runtime[key] === value);
            return {session, expected: {...EXPECTED}, persisted, runtime, settingsVerified,
                routingBehaviorVerified: false, health};
        }),
    });
}
