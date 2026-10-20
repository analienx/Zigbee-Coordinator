"use strict";
/* Real compiled pinned herdsman; mocked NV and ZNP. Never opens radio. */
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

const config = {
    panId: 0x1234, extendedPanId: Buffer.alloc(8, 0x21),
    networkKey: Buffer.alloc(16, 0x5a),
    channelList: [11], networkKeyDistribute: false,
};
const configured = {isConfigured: () => true};
const validNib = {
    nwkPanId: config.panId, extendedPANID: Buffer.from(config.extendedPanId),
    channelList: Buffer.from([0, 0x08, 0, 0]), nwkLogicalChannel: 11,
};
function fixture(state = {}) {
    const records = new Map([
        [NvItemsIds.ZNP_HAS_CONFIGURED_ZSTACK3, state.configured ? configured : null],
        [NvItemsIds.NIB, state.nib ? validNib : null],
        [NvItemsIds.PRECFGKEY, {key: Buffer.from(config.networkKey)}],
        [NvItemsIds.NWK_ACTIVE_KEY_INFO, state.key ? {key: Buffer.from(config.networkKey)} : null],
        [NvItemsIds.NWK_ALTERN_KEY_INFO, state.key ? {key: Buffer.from(config.networkKey)} : null],
        [NvItemsIds.TRUSTCENTER_ADDR, state.tc ? Buffer.alloc(8, 0x24) : null],
        [NvItemsIds.STARTUP_OPTION, state.startup === undefined ? Buffer.from([0]) : state.startup],
    ]);
    const writes = [];
    const nv = {
        async init() {},
        async readItem(id) {
            if (state.failReadId === id) throw new Error("simulated ambiguous NV transport failure");
            return records.get(id) ?? null;
        },
        async deleteItem(id) {
            writes.push("delete:" + id);
            throw new Error("TEST_SAFE_VIRGIN_REACHED_DELETE");
        },
        async writeItem(id, bytes) {writes.push("write:" + id + ":" + bytes.toString("hex"));},
        async updateItem(id, bytes) {writes.push("update:" + id + ":" + bytes.toString("hex"));},
    };
    const manager = new ZnpAdapterManager(
        {}, {async request() {writes.push("znp-request"); throw new Error("FORBIDDEN_ZNP");}},
        {version: ZnpVersion.ZStack3x0, backupPath: "/tmp/no-backup", networkOptions: {}, adapterOptions: {}}
    );
    manager.nv = nv;
    manager.backup = {getStoredBackup: () => state.backup ? ({
        networkOptions: {
            panId: config.panId, extendedPanId: Buffer.from(config.extendedPanId),
            networkKey: Buffer.from(config.networkKey),
            channelList: [11], networkKeyDistribute: false,
        }
    }) : null};
    manager.nwkOptions = {
        ...config,
        panId: state.wrongPan ? 0x9999 : config.panId,
        extendedPanId: Buffer.from(config.extendedPanId),
        networkKey: Buffer.from(config.networkKey),
    };
    return {manager, writes};
}
async function holds(state, message) {
    const {manager, writes} = fixture(state);
    await assert.rejects(manager.determineStrategy(), message);
    await assert.rejects(manager.beginCommissioning(config), /HOLD_EXISTING_NV/);
    await assert.rejects(manager.clearAdapter(), /HOLD_EXISTING_NV/);
    assert.deepEqual(writes, []);
}
test("valid configured NIB and keys allow normal startup without writes", async () => {
    const {manager, writes} = fixture({configured: true, nib: true, key: true});
    assert.equal(await manager.determineStrategy(), "startup");
    assert.deepEqual(writes, []);
});
test("missing NIB with matching coordinator backup never auto-restores", async () => {
    await holds({backup: true, key: true, tc: true}, /HOLD_EXISTING_NV/);
});
test("deleted NIB with retained key or Trust Center without backup holds", async () => {
    await holds({key: true}, /HOLD_EXISTING_NV/);
    await holds({tc: true}, /HOLD_EXISTING_NV/);
});
test("configured flag surviving absent NIB holds", async () => {
    await holds({configured: true}, /HOLD_EXISTING_NV/);
});
test("NIB present with absent configured flag holds", async () => {
    await holds({nib: true, key: true}, /HOLD_EXISTING_NV/);
});
test("existing NIB and mismatched configured PAN holds", async () => {
    await holds({configured: true, nib: true, key: true, wrongPan: true}, /HOLD_EXISTING_NV/);
});
test("backup present on empty coordinator does not automatically replay", async () => {
    await holds({backup: true}, /HOLD_EXISTING_NV/);
});
test("NV read transport failure holds before any write", async () => {
    await holds({failReadId: NvItemsIds.NIB}, /simulated ambiguous NV transport failure/);
});
test("0x03, 0x80 or malformed startup options hold", async () => {
    for (const startup of [Buffer.from([3]), Buffer.from([0x80]), Buffer.from([0, 0])]) {
        await holds({startup}, /HOLD_EXISTING_NV/);
    }
});
test("provably virgin allows only one commissioning attempt", async () => {
    const {manager, writes} = fixture();
    assert.equal(await manager.determineStrategy(), "startCommissioning");
    await assert.rejects(manager.beginCommissioning(config), /TEST_SAFE_VIRGIN_REACHED_DELETE/);
    assert.deepEqual(writes, ["delete:" + NvItemsIds.NIB]);
    await assert.rejects(manager.beginCommissioning(config), /HOLD_EXISTING_NV/);
    await assert.rejects(manager.clearAdapter(), /HOLD_EXISTING_NV/);
    assert.deepEqual(writes, ["delete:" + NvItemsIds.NIB]);
});
test("direct beginRestore cannot commission retained network", async () => {
    const {manager, writes} = fixture({backup: true, key: true});
    await assert.rejects(manager.beginRestore(), /HOLD_EXISTING_NV/);
    assert.deepEqual(writes, []);
});
