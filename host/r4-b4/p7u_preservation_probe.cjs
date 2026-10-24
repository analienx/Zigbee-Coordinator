"use strict";
/** One fixed B1/F1 op0, through a qualified existing Znp transport.
 * No Controller/Adapter startup, private vendor API, reset, NV or network setup.
 * Root and source are fixed in the image; caller-supplied commands do not exist.
 */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const ROOT = "/share/p7u-lifecycle/private/preservation-f1";
const PORT = "/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00";
const OPERATION = "b2660c95-38f5-40b2-9589-6864ed178210";
const QUERY = Buffer.from([0x42,0x31,0x51,0x31,1,8,0,0]);
const FIELDS = ["schema","source_sha","operation_id","command","serial_by_id","image_id",
    "database_sha256","backup_sha256","history_sha256","original_container_id","prior_result_sha256"];
const hash = raw => crypto.createHash("sha256").update(raw).digest("hex");
const requireSafe = (value, reason) => {if (!value) throw Error("P7U_PRESERVATION_" + reason);};
function bytes(file, limit = 65536) {
    const st = fs.lstatSync(file);
    requireSafe(st.isFile() && !st.isSymbolicLink() && st.size <= limit, "PRIVATE_FILE_UNSAFE");
    const raw = fs.readFileSync(file);
    requireSafe(raw.length <= limit, "PRIVATE_FILE_TOO_LARGE");
    return raw;
}
function unique(file, value) {
    const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try {fs.writeFileSync(fd, JSON.stringify(value) + "\n");fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
    const dir = fs.openSync(path.dirname(file), "r");
    try {fs.fsyncSync(dir);} finally {fs.closeSync(dir);}
}
function admission(root, source, checkData = true) {
    const st = fs.lstatSync(root);
    requireSafe(st.isDirectory() && !st.isSymbolicLink() && (st.mode & 0o077) === 0 &&
        (typeof process.getuid !== "function" || st.uid === process.getuid()), "PRIVATE_DIRECTORY");
    const raw = bytes(path.join(root, "plan.json"));
    const pin = bytes(path.join(root, "plan.sha256"), 65).toString().trim();
    requireSafe(/^[a-f0-9]{64}$/.test(pin) && hash(raw) === pin, "PLAN_HASH");
    const plan = JSON.parse(raw);
    requireSafe(Object.keys(plan).sort().join() === [...FIELDS].sort().join() &&
        plan.schema === "p7u-preservation-f1-plan-v1" && plan.operation_id === OPERATION &&
        /^[a-f0-9]{40}$/.test(source) && plan.source_sha === source && plan.serial_by_id === PORT &&
        plan.command === "SYS_F1_B1Q1_OP0_ONCE" && /^sha256:[a-f0-9]{64}$/.test(plan.image_id) &&
        /^[a-f0-9]{64}$/.test(plan.original_container_id) &&
        [plan.database_sha256,plan.backup_sha256].every(v => /^[a-f0-9]{64}$/.test(v)), "PLAN_SCHEMA");
    for (const key of ["history_sha256","prior_result_sha256"]) {
        requireSafe(plan[key] && typeof plan[key] === "object" && !Array.isArray(plan[key]) &&
            Object.values(plan[key]).length > 0 && Object.values(plan[key]).every(v => /^[a-f0-9]{64}$/.test(v)), "HISTORY_HASHES");
    }
    const authority = JSON.parse(bytes(path.join(root, "authority.intent.json")));
    requireSafe(authority.schema === "p7u-preservation-authority-v1" && authority.operation_id === OPERATION &&
        authority.source_sha === source && authority.plan_sha256 === pin &&
        Number.isSafeInteger(authority.utc_ms) && 0 <= Date.now() - authority.utc_ms && Date.now() - authority.utc_ms < 90000,
        "AUTHORITY_NOT_FRESH");
    if (checkData) {
        const data = "/config/zigbee2mqtt";
        for (const name of ["database.db.tmp",".p7u-approved.json.pending"]) {
            try {fs.lstatSync(path.join(data,name));throw Error("P7U_PRESERVATION_DATABASE_PENDING");}
            catch (error) {if (error.code !== "ENOENT") throw error;}
        }
        requireSafe(hash(bytes(path.join(data,"database.db"),64*1024*1024)) === plan.database_sha256 &&
            hash(bytes(path.join(data,"coordinator_backup.json"),4*1024*1024)) === plan.backup_sha256, "HOST_DATA_CHANGED");
        const approval = JSON.parse(bytes(path.join(data,".p7u-approved.json")));
        requireSafe(approval.database_sha256 === plan.database_sha256 && approval.devices === 107 && approval.rows === 128, "DB_APPROVAL");
    }
    return {plan, pin};
}
function decode(raw) {
    requireSafe(Buffer.isBuffer(raw) && raw.length === 24 && raw.toString("ascii",0,4) === "B1S1" &&
        raw[4] === 1 && raw[5] === 24 && raw[6] <= 5 && (raw[9] & ~15) === 0 &&
        raw.subarray(16).every(v => v === 0), "F1_RESPONSE_SCHEMA");
    return {stage:raw[6], first_error:raw[7], flags:raw[8], capabilities:raw[9], current_error:raw[10], nv_probe:raw[11],
        firmware_source_prefix:raw.subarray(12,16).toString("hex"),
        firmware_source_claim_matches:!!(raw[9] & 4) && raw.subarray(12,16).equals(Buffer.from("323949a9","hex")),
        hardware_image_attested:false, network_recovery_verified:false};
}
function makeZnp() {
    const {Znp} = require("/app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/adapter/z-stack/znp/znp.js");
    return new Znp(PORT,115200,false);
}
async function run({root = ROOT, source, factory = makeZnp, checkData = true, hardDeadline = true} = {}) {
    source = source ?? bytes(path.join(__dirname,"P7U_SOURCE_SHA.txt"),41).toString().trim();
    const {plan,pin} = admission(root,source,checkData);
    const common = {schema:"p7u-preservation-f1-result-v1", source_sha:source, operation_id:OPERATION,
        plan_sha256:pin, only_command:"SYS_F1_B1Q1_OP0_ONCE", resets_requested:0, nv_writes_requested:0,
        explicit_modem_line_toggles:0, normal_network_startup:false};
    unique(path.join(root,"probe.attempt.json"),{...common,utc_ms:Date.now()});
    const znp = factory();
    const timer = hardDeadline ? setTimeout(() => {
        try {unique(path.join(root,"probe.result.json"),{...common,status:"DEADLINE_STATE_UNKNOWN",utc_ms:Date.now()});}
        finally {process.exit(3);}
    },12000) : null;
    let result = {...common,status:"PROBE_FAILED_STATE_UNKNOWN",utc_ms:Date.now(),serial_closed:false};
    try {
        const ready = await znp.p7uOpenPreservationOnly();
        requireSafe(ready?.hupclDisabled === true,"HUPCL_NOT_VERIFIED");
        result.hupcl_disabled = true;
        const reply = await znp.requestWithReply(1,"p7uRetainedStatus",{query:QUERY},undefined,2000);
        const observed = decode(reply.payload.snapshot);
        result = {...result,status:observed.firmware_source_claim_matches ? "F1_OBSERVED" : "F1_SOURCE_UNQUALIFIED", observed};
    } catch (error) {
        result.error_class = error instanceof Error && /^SRSP - SYS - p7uRetainedStatus after 2000ms$/.test(error.message)
            ? "F1_TIMEOUT" : "TRANSPORT_OR_RESPONSE_ERROR";
    } finally {
        try {await znp.close();result.serial_closed = !znp.isInitialized();}
        catch {result.serial_closed = false;result.status = "CLOSE_UNCONFIRMED_STATE_UNKNOWN";}
        clearTimeout(timer);
    }
    result.utc_ms = Date.now();
    unique(path.join(root,"probe.result.json"),result);
    return result;
}
if (require.main === module) {
    run().then(result => {console.log(JSON.stringify(result));process.exitCode = result.serial_closed && result.status === "F1_OBSERVED" ? 0 : 2;})
        .catch(error => {console.error(JSON.stringify({status:"HOLD_NO_REPLAY",error_class:error?.name || "Error"}));process.exitCode = 3;});
}
module.exports = {admission,decode,run,unique,PORT,OPERATION};
