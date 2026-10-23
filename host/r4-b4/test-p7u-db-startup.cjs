/* P7U H1: actual compiled herdsman startup guard, no adapter instantiated.
 * GH-hosted tests only. /config is an ephemeral GitHub runner directory.
 */
"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const root = process.env.B4_HERDSMAN_ROOT;
assert.ok(root && root.startsWith("/tmp/"));
const {Controller} = require(path.join(root, "dist/controller/controller.js"));
const {Znp} = require(path.join(root, "dist/adapter/z-stack/znp/znp.js"));
const check = Controller.prototype.p7uRequireApprovedDatabase;
assert.equal(typeof check, "function", "actual production controller must be guarded");
const base = "/config/zigbee2mqtt";
const db = path.join(base, "database.db");
const approval = path.join(base, ".p7u-approved.json");
const oldEnv = process.env.P7U_APPROVED_DB_MANIFEST;
const rows = [
    {id: 1, type: "Coordinator", ieeeAddr: "0x00124b0000000001"},
    {id: 2, type: "Router", ieeeAddr: "0x00124b0000000002"},
    {id: 3, type: "EndDevice", ieeeAddr: "0x00124b0000000003"},
    {id: 4, type: "Group", groupID: 42},
];

function sha(raw) {return crypto.createHash("sha256").update(raw).digest("hex");}
function seal(entries = rows) {
    fs.mkdirSync(base, {recursive: true});
    const raw = entries.map(r => JSON.stringify(r)).join("\n");
    fs.writeFileSync(db, raw);
    const ieee = entries.filter(r => r.ieeeAddr).map(r => r.ieeeAddr.toLowerCase()).sort();
    const inventory = sha(ieee.join("\n") + "\n");
    fs.writeFileSync(approval, JSON.stringify({
        schema: "p7u-db-admission-v1", database_sha256: sha(raw),
        inventory_sha256: inventory, rows: entries.length,
        devices: ieee.length, generation: "operator-approved-0001",
    }));
    process.env.P7U_APPROVED_DB_MANIFEST = approval;
}
function admit() {return check.call({options: {databasePath: db}});}
function hold(fragment) {
    assert.throws(admit, err => {
        assert.match(err.message, /P7U HOLD_EXISTING_DB/);
        assert.match(err.message, fragment);
        return true;
    });
}
function fresh() {
    // /config belongs to root on hosted Linux; only mutate test fixture
    // files within the runner-owned zigbee2mqtt subdirectory.
    fs.mkdirSync(base, {recursive: true});
    for (const file of [db, approval, db + ".tmp", approval + ".pending"]) {
        fs.rmSync(file, {force: true});
    }
    seal();
}
test("actual compiled start controller guard allows exact fresh approval", () => {
    fresh();
    assert.doesNotThrow(admit);
    assert.equal(fs.readFileSync(db, "utf8").split("\n").length, 4);
});
test("absent approval holds before Adapter.create", () => {
    fresh();
    delete process.env.P7U_APPROVED_DB_MANIFEST;
    hold(/missing approval/);
});
test("malformed JSONL never silently drops a device", () => {
    fresh();
    fs.appendFileSync(db, "\n{truncated");
    hold(/corrupt JSONL/);
});
test("validly structured DB edited after approval holds", () => {
    fresh();
    fs.writeFileSync(db, JSON.stringify(rows[0]));
    hold(/approval does not match/);
});
test("same identity twice holds", () => {
    fresh();
    const modified = rows.map(r => ({...r}));
    modified[2].ieeeAddr = modified[1].ieeeAddr;
    seal(modified);
    hold(/duplicate or invalid IEEE/);
});
test("duplicate row IDs hold", () => {
    fresh();
    const modified = rows.map(r => ({...r}));
    modified[2].id = modified[1].id;
    seal(modified);
    hold(/invalid or duplicate entity id/);
});
test("unresolved database.db.tmp holds without promotion", () => {
    fresh();
    fs.writeFileSync(db + ".tmp", "untrusted");
    hold(/unresolved temporary DB/);
    assert.equal(fs.readFileSync(db + ".tmp", "utf8"), "untrusted");
});
test("orphaned private receipt holds before serial, no auto-promote", () => {
    fresh();
    fs.writeFileSync(approval + ".pending", "uncertain prior commit");
    hold(/unresolved temporary DB/);
    assert.equal(fs.readFileSync(approval + ".pending", "utf8"), "uncertain prior commit");
    fs.rmSync(approval + ".pending", {force: true});
});
test("missing coordinator holds even if approval matches", () => {
    fresh();
    const modified = rows.map(r => ({...r}));
    modified[0].type = "Router";
    seal(modified);
    hold(/coordinator count/);
});
test("invalid UTF8 must not normalize into trusted identities", () => {
    fresh();
    fs.writeFileSync(db, Buffer.from([0xff, 0xfe]));
    hold(/database encoding/);
});
test("guard is never a data mutation or a serial opener", () => {
    fresh();
    const before = fs.readFileSync(db);
    admit();
    assert.deepEqual(fs.readFileSync(db), before);
});
test("failed initial ping holds without bootloader magic, RTS/DTR or radio reset", async () => {
    const znp = new Znp("/dev/never-opened", 115200, false);
    let writes = 0;
    let toggles = 0;
    znp.request = async () => { throw new Error("synthetic ping timeout"); };
    znp.unpiWriter.writeBuffer = () => { writes++; };
    znp.serialPort = {asyncSet: async () => { toggles++; }};
    await assert.rejects(znp.skipBootloader(), /P7U HOLD_EXISTING_NV: ping unavailable/);
    assert.equal(writes, 0);
    assert.equal(toggles, 0);
    const fn = Znp.prototype.skipBootloader.toString();
    assert.doesNotMatch(fn, /writeBuffer|asyncSet/);
});
process.on("exit", () => {
    if (oldEnv === undefined) delete process.env.P7U_APPROVED_DB_MANIFEST;
    else process.env.P7U_APPROVED_DB_MANIFEST = oldEnv;
});
