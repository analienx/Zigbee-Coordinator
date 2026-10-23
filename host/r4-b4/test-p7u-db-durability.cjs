"use strict";
/** Test real compiled Database.write() durability ordering, no serial. */
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const root = process.env.B4_HERDSMAN_ROOT;
assert.ok(root && root.startsWith("/tmp/"));
const Database = require(path.join(root, "dist/controller/database.js")).default;
test("H3: durable DB write fsyncs file then containing directory after rename", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "p7u-db-fsync-"));
    const file = path.join(dir, "database.db");
    const original = fs.fsyncSync;
    const observations = [];
    try {
        fs.fsyncSync = (fd) => {
            observations.push(fs.fstatSync(fd).isDirectory() ? "directory" : "file");
            return original(fd);
        };
        const database = Database.open(file);
        database.write();
        assert.equal(fs.existsSync(file), true);
        assert.deepEqual(observations, ["file", "directory"]);
        assert.equal(fs.existsSync(file + ".tmp"), false);
    } finally {
        fs.fsyncSync = original;
        fs.rmSync(dir, {recursive: true, force: true});
    }
});
test("H3: a directory fsync failure fails the database save and cannot claim success", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "p7u-db-fsync-failure-"));
    const file = path.join(dir, "database.db");
    const original = fs.fsyncSync;
    try {
        fs.fsyncSync = (fd) => {
            if (fs.fstatSync(fd).isDirectory()) throw Error("synthetic directory fsync failure");
            return original(fd);
        };
        const database = Database.open(file);
        assert.throws(() => database.write(), /synthetic directory fsync failure/);
    } finally {
        fs.fsyncSync = original;
        fs.rmSync(dir, {recursive: true, force: true});
    }
});
