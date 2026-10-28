"use strict";
/* Actual compiled pinned manager/UNPI, public fake NV and one mocked Znp.
 * Never opens serial, starts HA, forms a network or executes a device reset.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const root = process.env.P7U_HERDSMAN_ROOT;
if (!root || !path.isAbsolute(root) || !root.startsWith("/tmp/")) {
    throw new Error("P7U_HERDSMAN_ROOT must be a disposable /tmp checkout");
}
const mod = (p) => require(path.join(root, "dist", ...p.split("/")));
const {ZnpAdapterManager} = mod("adapter/z-stack/adapter/manager.js");
const {NvItemsIds} = mod("adapter/z-stack/constants/common.js");
const {ZnpVersion} = mod("adapter/z-stack/adapter/tstype.js");
const Structs = mod("adapter/z-stack/structs/index.js");
const {ZpiObject} = mod("adapter/z-stack/znp/zpiObject.js");
const {Znp} = mod("adapter/z-stack/znp/znp.js");
const {Frame} = mod("adapter/z-stack/unpi/frame.js");
const {Type, Subsystem} = mod("adapter/z-stack/unpi/constants.js");

const config = {
    panId: 0x1234, extendedPanId: Buffer.alloc(8, 0x21),
    networkKey: Buffer.alloc(16, 0x5a), channelList: [11], networkKeyDistribute: false,
};
const ieee = Buffer.from("00124b0000000001", "hex"); // public synthetic identity
function status(stage = 1) {
    const bytes = Buffer.alloc(24);
    bytes.write("B1S1"); bytes[4] = 1; bytes[5] = 24;
    bytes[6] = stage; bytes[8] = 0xe3; bytes[9] = stage === 5 ? 15 : 7;
    bytes[11] = 7; bytes.writeUInt32LE(0x12345678, 12);
    return bytes;
}
function validNib() {
    const nib = Structs.nib();
    nib.nwkState = 8; nib.nwkDevAddress = 0; nib.nwkKeyLoaded = 1;
    nib.nwkPanId = config.panId; nib.extendedPANID = config.extendedPanId;
    nib.nwkLogicalChannel = 11; nib.channelList = 1 << 11;
    const raw = nib.serialize("aligned");
    assert.equal(raw.length, 116);
    return raw;
}
function fixture(state = {}) {
    let rawNib = state.missingNib ? null : validNib();
    if (state.badNib && rawNib) {
        const nib = Structs.nib(rawNib);
        nib[state.badNib[0]] = state.badNib[1];
        rawNib = nib.serialize("aligned");
    }
    const records = new Map([
        [NvItemsIds.ZNP_HAS_CONFIGURED_ZSTACK3, state.configured ? Buffer.from([0x55]) : null],
        [NvItemsIds.NIB, rawNib],
        [NvItemsIds.NWK_ACTIVE_KEY_INFO, state.missingKey ? null : {key: Buffer.from(config.networkKey)}],
        [NvItemsIds.STARTUP_OPTION, state.startup ?? Buffer.from([0])],
        [NvItemsIds.BDBNODEISONANETWORK, Buffer.from([state.bdb ?? 1])],
        [NvItemsIds.LOGICAL_TYPE, Buffer.from([state.role ?? 0])],
    ]);
    const mutations = [], requests = [], reads = [], budgets = [];
    const nv = {
        memoryAlignment: state.alignment ?? "aligned",
        async init() {reads.push("init");},
        async readItem(id) {
            reads.push(id);
            if (state.failReadId === id) throw new Error("simulated NV transport failure");
            return records.get(id) ?? null;
        },
        async deleteItem(id) {mutations.push("delete:" + id);},
        async writeItem(id) {mutations.push("write:" + id);},
        async updateItem(id) {mutations.push("update:" + id);},
    };
    const znp = {
        async requestWithReply(system, command, payload, unused, timeout) {
            requests.push(command);
            budgets.push({command,timeout});
            if (command === "p7uRetainedStatus") {
                assert.equal(system, Subsystem.SYS);
                assert.deepEqual(payload.query, Buffer.from([0x42, 0x31, 0x51, 0x31, 1, 8, 0, 0]));
                if (state.statusTimeout) throw new Error("timeout");
                return {payload: {snapshot: state.status ?? status(state.stage ?? 1)}};
            }
            if (command === "getExtAddr") return {payload: {extaddress: "0x" + ieee.toString("hex")}};
            if (command === "getDeviceInfo") return {payload: {devicestate: state.deviceState ?? 9}};
            throw new Error("unexpected request: " + command);
        },
        async request(system, command) {
            requests.push(command);
            if (system === Subsystem.ZDO && command === "startupFromApp") return {};
            mutations.push(command);
            throw new Error("unexpected mutation request");
        },
        waitFor() {return {start() {return {promise: Promise.resolve({})};}};},
    };
    const manager = new ZnpAdapterManager({}, znp, {
        version: state.version ?? ZnpVersion.ZStack3x0, backupPath: "/tmp/synthetic-backup",
        networkOptions: {panID: config.panId, extendedPanID: [...config.extendedPanId],
                         networkKey: [...config.networkKey], channelList: [11]},
        adapterOptions: {},
    });
    manager.nv = nv;
    manager.backup = {getStoredBackup: () => state.backup ? ({
        networkOptions: {...config, panId: state.badBackupPan ? 0x9999 : config.panId},
        coordinatorIeeeAddress: state.badBackupIeee ? Buffer.alloc(8, 9) : ieee,
    }) : undefined};
    manager.nwkOptions = {...config, panId: state.wrongPan ? 0x9999 : config.panId};
    manager.registerEndpoints = async () => {};
    manager.addToGroup = async () => {};
    return {manager, mutations, requests, reads, budgets};
}
async function held(state) {
    const f = fixture(state);
    await assert.rejects(f.manager.determineStrategy(), /HOLD_EXISTING_NV|simulated NV transport failure/);
    assert.deepEqual(f.mutations, []);
    assert(!f.requests.includes("resetReq"));
    return f;
}

test("real F1 UNPI codec accepts exactly24B and encodes the fixed op0 request", () => {
    const object = ZpiObject.fromUnpiFrame(new Frame(Type.SRSP, Subsystem.SYS, 241, status()));
    assert.deepEqual(object.payload.snapshot, status());
    for (const length of [0, 23, 25, 100]) {
        assert.throws(() => ZpiObject.fromUnpiFrame(new Frame(Type.SRSP, Subsystem.SYS, 241, Buffer.alloc(length))));
    }
    const query = Buffer.from([0x42, 0x31, 0x51, 0x31, 1, 8, 0, 0]);
    assert.deepEqual(ZpiObject.createRequest(Subsystem.SYS, "p7uRetainedStatus", {query}).unpiFrame.data, query);
});

test("healthy retained network resumes read-only with configured marker absent or present", async () => {
    for (const configured of [false, true]) for (const stage of [1, 5]) {
        const f = fixture({configured, stage, backup: true, deviceState: stage === 1 ? 0 : 9});
        assert.equal(await f.manager.determineStrategy(), "startup");
        await f.manager.beginStartup();
        assert(f.budgets.filter(b=>b.command==='p7uRetainedStatus' || b.command==='getDeviceInfo')
            .every(b=>b.timeout===20000),'bounded startup reads cover measured retained-radio latency');
        assert.deepEqual(f.mutations, []);
        assert(!f.reads.includes(NvItemsIds.NWK_ALTERN_KEY_INFO));
        assert(!f.reads.includes(NvItemsIds.PRECFGKEY));
        assert(!f.requests.includes("resetReq"));
        if (stage === 1) assert(f.requests.includes("startupFromApp"));
    }
    const f = fixture();
    assert.equal(await f.manager.start(), "resumed");
    assert.deepEqual(f.mutations, []);
});

test("held/malformed/unavailable F1 or legacy version stops before first NV operation", async () => {
    const variants = [
        {statusTimeout: true}, {version: ZnpVersion.ZStack12}, {status: Buffer.alloc(24)},
        {status: status().subarray(0, 23)},
        ...[6, 7, 8, 9, 10, 11, 16].map((position) => {
            const bytes = status(); bytes[position] = position === 6 ? 2 : 0xff;
            return {status: bytes};
        }),
    ];
    for (const state of variants) {
        const f = fixture(state);
        await assert.rejects(f.manager.start(), /HOLD_EXISTING_NV/);
        assert.deepEqual(f.reads, []);
        assert.deepEqual(f.mutations, []);
        assert(!f.requests.includes("resetReq"));
    }
});

test("NIB/BDB/role/startup/key/config/backup ambiguity cannot select restore", async () => {
    for (const state of [
        {missingNib: true, backup: true}, {missingNib: true}, {missingKey: true},
        {bdb: 0}, {bdb: 2}, {role: 1}, {wrongPan: true}, {alignment: "unaligned"},
        {badNib: ["nwkState", 0]}, {badNib: ["nwkKeyLoaded", 0]},
        {badNib: ["nwkDevAddress", 1]}, {badNib: ["nwkLogicalChannel", 27]},
        {startup: Buffer.from([3])}, {startup: Buffer.from([0x80])},
        {startup: Buffer.from([0, 0])}, {failReadId: NvItemsIds.NIB},
        {backup: true, badBackupPan: true}, {backup: true, badBackupIeee: true},
    ]) await held(state);
});

test("all direct destructive methods remain vetoed even after healthy validation", async () => {
    const f = fixture({backup: true});
    assert.equal(await f.manager.determineStrategy(), "startup");
    for (const [name, args] of [
        ["beginRestore", []], ["beginCommissioning", [config]], ["clearAdapter", []],
        ["resetAdapter", []], ["updateCommissioningNvItems", [config]], ["writeConfigurationFlag", []],
    ]) await assert.rejects(f.manager[name](...args), /HOLD_EXISTING_NV/);
    assert.deepEqual(f.mutations, []);
    assert(!f.requests.includes("resetReq"));
});

test("fresh HOLD before startup revokes previous compatibility proof", async () => {
    const state = {};
    const f = fixture(state);
    assert.equal(await f.manager.determineStrategy(), "startup");
    state.status = status(); state.status[6] = 2; state.status[8] |= 4;
    await assert.rejects(f.manager.beginStartup(), /HOLD_EXISTING_NV/);
    assert.deepEqual(f.mutations, []);
    assert(!f.requests.includes("startupFromApp"));
});

test("actual startup owner accepts a7.9s UTIL reply once without resetting or repeating startup", async t => {
    const f=fixture({configured:true,stage:5});await f.manager.determineStrategy();
    t.mock.timers.enable({apis:["setTimeout"]});
    const znp=new Znp('/dev/never-opened',115200,false);znp.initialized=true;
    const sent=[];znp.unpiWriter.writeFrame=frame=>{
        sent.push(frame);
        if(frame.subsystem===Subsystem.SYS && frame.commandID===241)
            queueMicrotask(()=>znp.onUnpiParsed(new Frame(Type.SRSP,Subsystem.SYS,241,status(5))));
    };
    f.manager.znp=znp;const pending=f.manager.beginStartup();
    const flush=async()=>{for(let i=0;i<20;i++)await Promise.resolve();};await flush();
    assert.equal(sent.length,2);assert.equal(sent[1].subsystem,Subsystem.UTIL);
    t.mock.timers.tick(7900);await flush();assert.equal(sent.length,2);
    const body=Buffer.alloc(14);body[12]=9;
    znp.onUnpiParsed(new Frame(Type.SRSP,Subsystem.UTIL,0,body));await pending;
    assert.equal(sent.length,2);assert.equal(znp.queue.isIdle(),true);
    assert.equal(znp.waitress.waiters.size,0);assert.deepEqual(f.mutations,[]);
});
