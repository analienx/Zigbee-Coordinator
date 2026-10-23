"use strict";
/** Actual compiled retained DB: gated sealer and file+directory fsync.
 * Offline GH-hosted /config fixture. No coordinator or adapter is opened.
 */
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const root = process.env.B4_HERDSMAN_ROOT;
assert.ok(root && root.startsWith("/tmp/"));
const Database = require(path.join(root, "dist/controller/database.js")).default;
const sha = b => crypto.createHash("sha256").update(b).digest("hex");

test("H3: unapproved in-memory database cannot silently write retained state", () => {
    const db = Database.open("/tmp/p7u-unarmed-db-does-not-exist.db");
    assert.throws(() => db.write(), /unarmed commit receipt/);
    assert.equal(fs.existsSync("/tmp/p7u-unarmed-db-does-not-exist.db"), false);
});

test("H3: approved live models commit DB and receipt with independent directory fsync; fail-closed crash gap", () => {
    const top = "/config/zigbee2mqtt";
    fs.mkdirSync(top, {recursive: true});
    const dir = fs.mkdtempSync(path.join(top, "gha-p7u-db-"));
    const dbPath = path.join(dir, "database.db");
    const approval = path.join(dir, ".approval.json");
    const rows = [
        {id: 1, type: "Coordinator", ieeeAddr: "0x00124b0000000001"},
        {id: 2, type: "Router", ieeeAddr: "0x00124b0000000002"},
    ];
    const raw = rows.map(x => JSON.stringify(x)).join("\n");
    const inventory = sha(rows.map(x => x.ieeeAddr).sort().join("\n") + "\n");
    const manifest = {
        schema: "p7u-db-admission-v1", database_sha256: sha(raw),
        inventory_sha256: inventory, rows: 2, devices: 2,
        generation: "operator-approved-0001"
    };
    const encoded = JSON.stringify(manifest) + "\n";
    fs.writeFileSync(dbPath, raw);
    fs.writeFileSync(approval, encoded);
    const original = fs.fsyncSync;
    const observations = [];
    try {
        Database.p7uArmApproval(dbPath, approval, manifest.generation, sha(encoded));
        const database = Database.open(dbPath);
        fs.fsyncSync = fd => {
            observations.push(fs.fstatSync(fd).isDirectory() ? "directory" : "file");
            return original(fd);
        };
        database.write();
        assert.deepEqual(observations, ["file", "directory", "file", "directory"]);
        const approved = JSON.parse(fs.readFileSync(approval, "utf8"));
        assert.equal(approved.database_sha256, sha(fs.readFileSync(dbPath)));
        assert.equal(approved.rows, 2);
        assert.equal(fs.existsSync(dbPath + ".tmp"), false);
        assert.equal(fs.existsSync(approval + ".pending"), false);

        // Force a change in trusted models, then simulate fsync failure at
        // the DB directory commit: the approval MUST NOT be auto-promoted.
        database.update({...rows[1], modelId: "simulated-queued-change"}, false);
        fs.fsyncSync = fd => {
            if (fs.fstatSync(fd).isDirectory()) {
                throw Error("synthetic directory fsync failure");
            }
            return original(fd);
        };
        assert.throws(() => database.write(), /synthetic directory fsync failure/);
        assert.notEqual(JSON.parse(fs.readFileSync(approval, "utf8")).database_sha256,
                        sha(fs.readFileSync(dbPath)));
    } finally {
        fs.fsyncSync = original;
        fs.rmSync(dir, {recursive: true, force: true});
    }
});
