"""Pinned 10.9.1 retained-R4 startup guard; disposable host source only.

Refines PR140: healthy formed networks resume without Koenkk's0x60 marker.
Automatic restore/commission/clear stays prohibited. Deliberate backup restore
uses separately operated stock firmware. This tool never installs or opens I/O.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from safe_checkout_files import read_source_bytes, write_source_text, validate_sources

PIN = "0968f979d558874b17396c96b66382d4236bbdcd"
PATH = "src/adapter/z-stack/adapter/manager.ts"
DEFINITION = "src/adapter/z-stack/znp/definition.ts"
PARAM = "src/adapter/z-stack/znp/parameterType.ts"
BUFFALO = "src/adapter/z-stack/znp/buffaloZnp.ts"
CONTROLLER = "src/controller/controller.ts"
DATABASE = "src/controller/database.ts"
ZNP = "src/adapter/z-stack/znp/znp.ts"
MARKER = "P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD"
FILES = (PATH, DEFINITION, PARAM, BUFFALO, CONTROLLER, ZNP, DATABASE)


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("herdsman 10.9.1 source anchor drift")
    return source.replace(old, new, 1)


STATUS_METHOD = r'''
    /** P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD: same Znp owner, bounded F1.
     * Stage1 is legitimate before startupFromApp; READY is not required.
     */
    private async p7uRequireRetainedR4Status(): Promise<void> {
        if (this.options.version !== ZnpVersion.ZStack3x0) {
            throw new Error("P7U HOLD_EXISTING_NV: retained R4 requires verified ZStack3x0 version");
        }
        let data: Buffer;
        try {
            const response = await this.znp.requestWithReply(
                Subsystem.SYS, "p7uRetainedStatus",
                {query: Buffer.from([0x42, 0x31, 0x51, 0x31, 1, 8, 0, 0])},
                undefined, 2000);
            data = response.payload.snapshot;
        } catch {
            throw new Error("P7U HOLD_EXISTING_NV: retained R4 status unavailable; no automatic restore");
        }
        if (!Buffer.isBuffer(data) || data.length !== 24 ||
            data.toString("ascii", 0, 4) !== "B1S1" || data[4] !== 1 || data[5] !== 24 ||
            (data[6] !== 1 && data[6] !== 5) || data[7] !== 0 || data[10] !== 0 ||
            (data[8] & 0x1c) !== 0 || (data[8] & 0x82) !== 0x82 || data[11] !== 7 ||
            (data[9] & 7) !== 7 || (data[9] & ~0x0f) !== 0 ||
            Boolean(data[9] & 8) !== (data[6] === 5) ||
            data.subarray(12, 16).every((byte) => byte === 0) ||
            !data.subarray(16).every((byte) => byte === 0)) {
            throw new Error("P7U HOLD_EXISTING_NV: R4 NV/security status is held or incompatible");
        }
    }

'''


DB_ADMISSION_METHOD = r'''
    /** P7U_DB_ADMISSION_V1: validate committed DB BEFORE Adapter.create()
     * and before any serial transport opens. No files are repaired/promoted.
     * The private approval file is created only by a separately authorized
     * quiescent snapshot/journal transaction, never by application startup.
     */
    private p7uRequireApprovedDatabase(): void {
        const fail = (reason: string): never => {
            throw new Error("P7U HOLD_EXISTING_DB: " + reason);
        };
        const dbPath = this.options.databasePath;
        const approvalPath = process.env.P7U_APPROVED_DB_MANIFEST ?? "";
        if (!approvalPath || !approvalPath.startsWith("/config/zigbee2mqtt/") ||
            !dbPath.startsWith("/config/zigbee2mqtt/") ||
            !dbPath.endsWith("/database.db") ||
            fs.existsSync(dbPath + ".tmp") ||
            fs.existsSync(approvalPath + ".pending")) {
            fail("missing approval, invalid data path or unresolved temporary DB");
        }
        let raw: Buffer = Buffer.alloc(0);
        let approval: unknown;
        try {
            const dbStatBefore = fs.lstatSync(dbPath);
            const approvalStat = fs.lstatSync(approvalPath);
            if (!dbStatBefore.isFile() || dbStatBefore.isSymbolicLink() ||
                dbStatBefore.size < 1 || dbStatBefore.size > 64 * 1024 * 1024 ||
                !approvalStat.isFile() || approvalStat.isSymbolicLink() ||
                approvalStat.size < 1 || approvalStat.size > 16 * 1024) {
                fail("database or approval type/size");
            }
            raw = fs.readFileSync(dbPath);
            approval = JSON.parse(fs.readFileSync(approvalPath, "utf8"));
            const after = fs.lstatSync(dbPath);
            if (after.ino !== dbStatBefore.ino || after.dev !== dbStatBefore.dev ||
                after.size !== dbStatBefore.size || after.mtimeMs !== dbStatBefore.mtimeMs ||
                raw.length !== dbStatBefore.size) {
                fail("database changed during admission");
            }
        } catch {
            fail("database or approval unreadable");
        }
        const text = raw.toString("utf8");
        if (!Buffer.from(text, "utf8").equals(raw) || text.includes("\u0000")) {
            fail("database encoding");
        }
        const lines = text.split(/\r?\n/);
        if (lines.at(-1) === "") { lines.pop(); }
        if (lines.length === 0 || lines.some((line) => !line.trim())) {
            fail("empty or blank-line database");
        }
        const IDs = new Set<number>();
        const devices = new Set<string>();
        let coordinators = 0;
        for (const line of lines) {
            let row: Record<string, unknown> = {};
            try { row = JSON.parse(line); } catch { fail("corrupt JSONL row"); }
            if (!row || typeof row !== "object" || Array.isArray(row) ||
                !Number.isSafeInteger(row.id) || (row.id as number) < 0 ||
                IDs.has(row.id as number)) {
                fail("invalid or duplicate entity id");
            }
            IDs.add(row.id as number);
            if (!["Coordinator", "Router", "EndDevice", "Unknown", "GreenPower", "Group"]
                .includes(row.type as string)) {
                fail("invalid entity type");
            }
            if (row.type === "Group") {
                if (!Number.isSafeInteger(row.groupID) ||
                    (row.groupID as number) < 0 || (row.groupID as number) > 65535) {
                    fail("invalid group id");
                }
            } else {
                if (row.type === "Coordinator") { coordinators++; }
                const ieee = row.ieeeAddr;
                if (row.type !== "GreenPower" && (typeof ieee !== "string" ||
                    !/^0x[0-9a-f]{16}$/i.test(ieee))) {
                    fail("missing device IEEE");
                }
                if (ieee !== undefined) {
                    if (typeof ieee !== "string" || !/^0x[0-9a-f]{16}$/i.test(ieee) ||
                        devices.has((ieee as string).toLowerCase())) {
                        fail("duplicate or invalid IEEE");
                    }
                    devices.add((ieee as string).toLowerCase());
                }
            }
        }
        if (coordinators !== 1) { fail("coordinator count"); }
        if (!approval || typeof approval !== "object" || Array.isArray(approval)) {
            fail("approval schema");
        }
        const seal = approval as Record<string, unknown>;
        const digest = createHash("sha256").update(raw).digest("hex");
        const inventory = createHash("sha256").update(
            [...devices].sort().join("\n") + "\n", "ascii").digest("hex");
        if (seal.schema !== "p7u-db-admission-v1" ||
            seal.database_sha256 !== digest || seal.inventory_sha256 !== inventory ||
            seal.rows !== lines.length || seal.devices !== devices.size ||
            typeof seal.generation !== "string" ||
            !/^[a-zA-Z0-9_-]{12,100}$/.test(seal.generation)) {
            fail("approval does not match latest committed DB");
        }
        Database.p7uArmApproval(dbPath, approvalPath, seal.generation as string,
            createHash("sha256").update(fs.readFileSync(approvalPath)).digest("hex"));
    }

'''

STRATEGY = r'''    private async determineStrategy(): Promise<StartupStrategy> {
        await this.p7uRequireRetainedR4Status();
        this.p7uRetainedNetworkValidated = false;
        /* P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD: missing0x60 alone is not
         * evidence of an uncommissioned network on retained TI stock NV.
         * No read can authorize deletion or recreation of any record.
         */
        const configured = await this.nv.readItem(NvItemsIds.ZNP_HAS_CONFIGURED_ZSTACK3);
        const startup = await this.nv.readItem(NvItemsIds.STARTUP_OPTION);
        const bdb = await this.nv.readItem(NvItemsIds.BDBNODEISONANETWORK);
        const role = await this.nv.readItem(NvItemsIds.LOGICAL_TYPE);
        const rawNib = await this.nv.readItem(NvItemsIds.NIB);
        const active = await this.nv.readItem(NvItemsIds.NWK_ACTIVE_KEY_INFO, 0, Structs.nwkKeyDescriptor);
        const byteEquals = (raw: Buffer | null, value: number): boolean =>
            Buffer.isBuffer(raw) && raw.length === 1 && raw[0] === value;
        if ((configured !== null && !byteEquals(configured, 0x55)) ||
            !byteEquals(startup, 0) || !byteEquals(bdb, 1) || !byteEquals(role, 0) ||
            this.nv.memoryAlignment !== "aligned" ||
            !Buffer.isBuffer(rawNib) || rawNib.length !== 116 ||
            !active || !Buffer.isBuffer(active.key) || active.key.length !== 16) {
            throw new Error("P7U HOLD_EXISTING_NV: retained formed-network records incomplete or incompatible");
        }
        let nib: ReturnType<typeof Structs.nib>;
        try {
            nib = Structs.nib(rawNib);
        } catch {
            throw new Error("P7U HOLD_EXISTING_NV: retained NIB ABI mismatch");
        }
        /* TI8.33 native witness: sizeof(nwkIB_t)=116; NWK_ROUTER=8.
         * F1 requires admitted NV and no security HOLD. A different alternate
         * or transport key does not justify commissioning over this network.
         */
        if (nib.nwkState !== 8 || nib.nwkDevAddress !== 0 || nib.nwkKeyLoaded !== 1 ||
            nib.nwkLogicalChannel < 11 || nib.nwkLogicalChannel > 26 ||
            nib.nwkPanId === 0xffff || nib.nwkPanId !== this.nwkOptions.panId ||
            !nib.extendedPANID.equals(this.nwkOptions.extendedPanId) ||
            nib.extendedPANID.every((byte) => byte === 0) ||
            nib.extendedPANID.every((byte) => byte === 0xff) ||
            !this.nwkOptions.channelList.includes(nib.nwkLogicalChannel) ||
            !active.key.equals(this.nwkOptions.networkKey) ||
            active.key.every((byte) => byte === 0) || active.key.every((byte) => byte === 0xff)) {
            throw new Error("P7U HOLD_EXISTING_NV: retained network does not match configured identity and active key");
        }
        const backup = this.backup.getStoredBackup();
        if (backup) {
            const response = await this.znp.requestWithReply(Subsystem.SYS, "getExtAddr", {});
            const ieee = response.payload.extaddress;
            if (typeof ieee !== "string" || !/^0x[0-9a-f]{16}$/i.test(ieee) ||
                !Buffer.isBuffer(backup.coordinatorIeeeAddress) ||
                !backup.coordinatorIeeeAddress.equals(Buffer.from(ieee.slice(2), "hex")) ||
                backup.networkOptions.panId !== nib.nwkPanId ||
                !backup.networkOptions.extendedPanId.equals(nib.extendedPANID) ||
                !backup.networkOptions.networkKey.equals(active.key)) {
                throw new Error("P7U HOLD_EXISTING_NV: backup identity conflicts with retained network");
            }
        }
        this.p7uRetainedNetworkValidated = true;
        logger.debug("P7U retained formed network verified; resuming without NV writes", NS);
        return "startup";
    }

'''


def plan(checkout, composition_receipt=None):
    validate_sources(checkout, FILES)

    def git(*arguments):
        return subprocess.check_output(
            ["git", "-C", str(checkout), *arguments], stderr=subprocess.DEVNULL)

    if git("rev-parse", "HEAD").decode().strip() != PIN:
        raise ValueError("wrong upstream herdsman commit")
    receipt = None
    if composition_receipt is not None:
        receipt = json.loads(Path(composition_receipt).read_bytes())
        if (receipt.get("schema") != "r4-b4-v4-herdsman-source-v1" or
                receipt.get("stage") != "PINNED_DISPOSABLE_SOURCE_ONLY" or
                receipt.get("original_znp_owner") is not True or
                receipt.get("installed") is not False):
            raise ValueError("unreviewed B4 composition receipt")
    originals = {}
    for name in FILES:
        raw = read_source_bytes(checkout, name)
        if name in (PATH, DATABASE) or receipt is None:
            if raw != git("show", f"{PIN}:{name}"):
                raise ValueError("dirty or substituted upstream source: " + name)
        elif hashlib.sha256(raw).hexdigest() != receipt.get("files", {}).get(name, {}).get("sha256_after"):
            raise ValueError("B4 composition preimage drift: " + name)
        originals[name] = raw.decode("utf-8")
    if any(MARKER in source for source in originals.values()):
        raise ValueError("already patched")
    manager = once(originals[PATH], "    private znp: Znp;\n", """    // P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD: preserved network only.
    private p7uRetainedNetworkOnly = true;
    private p7uRetainedNetworkValidated = false;
    private znp: Znp;
""")
    manager = once(manager, '        logger.debug("beginning znp startup", NS);',
                   '        logger.debug("beginning znp startup", NS);\n'
                   '        this.p7uRetainedNetworkValidated = false;\n'
                   '        await this.p7uRequireRetainedR4Status();')
    start = manager.index("    private async determineStrategy(): Promise<StartupStrategy> {")
    end = manager.index("    /**\n     * Internal method to perform regular adapter startup", start)
    manager = manager[:start] + STATUS_METHOD + STRATEGY + manager[end:]
    manager = once(manager, "    private async beginStartup(): Promise<void> {",
                   "    private async beginStartup(): Promise<void> {\n"
                   "        if (!this.p7uRetainedNetworkValidated) {\n"
                   '            throw new Error("P7U HOLD_EXISTING_NV: retained startup was not validated");\n'
                   "        }\n        await this.p7uRequireRetainedR4Status();")
    for signature in (
        "    private async beginRestore(): Promise<void> {",
        "    private async beginCommissioning(nwkOptions: Models.NetworkOptions, failOnCollision = true, writeConfiguredFlag = true): Promise<void> {",
        "    private async clearAdapter(): Promise<void> {",
        "    private async resetAdapter(): Promise<void> {",
        "    private async updateCommissioningNvItems(options: Models.NetworkOptions): Promise<void> {",
        "    private async writeConfigurationFlag(): Promise<void> {",
    ):
        manager = once(manager, signature, signature + "\n"
                       "        if (this.p7uRetainedNetworkOnly) {\n"
                       '            throw new Error("P7U HOLD_EXISTING_NV: automatic restore/commission/clear/reset disabled for retained R4");\n'
                       "        }")
    definition = originals[DEFINITION]
    if "ID: 241," in definition or 'name: "p7uRetainedStatus"' in definition:
        raise ValueError("SYS F1 command collision")
    definition = once(definition, "    [Subsystem.SYS]: [", """    [Subsystem.SYS]: [
        // P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD: read-only B1 op0, exact24B.
        {
            name: "p7uRetainedStatus",
            ID: 241,
            type: CommandType.SREQ,
            request: [{name: "query", parameterType: ParameterType.BUFFER8}],
            response: [{name: "snapshot", parameterType: ParameterType.BUFFER24}],
        },""")
    params = originals[PARAM]
    if "BUFFER24" in params or "= 21," in params:
        raise ValueError("BUFFER24 parameter collision")
    params = once(params, "    INT8 = 18,", "    INT8 = 18,\n"
                  "    BUFFER24 = 21, // P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD")
    buffalo = once(originals[BUFFALO], """            case ParameterType.BUFFER100: {
                return this.readBuffer(100);
            }""", """            case ParameterType.BUFFER100: {
                return this.readBuffer(100);
            }
            case ParameterType.BUFFER24: {
                if (this.getBuffer().length - this.getPosition() !== 24) {
                    throw new Error("P7U retained status length must be exactly24");
                }
                return this.readBuffer(24);
            }""")
    controller = once(originals[CONTROLLER],
        'import fs from "node:fs";',
        'import fs from "node:fs";\nimport {createHash} from "node:crypto"; // P7U_DB_ADMISSION_V1')
    controller = once(controller,
        "    public async start(abortSignal?: AbortSignal): Promise<AdapterTsType.StartResult> {",
        DB_ADMISSION_METHOD +
        "    public async start(abortSignal?: AbortSignal): Promise<AdapterTsType.StartResult> {\n"
        "        this.p7uRequireApprovedDatabase();")
    # A retained network must never be silently re-formed, switched channel
    # or assigned a replacement coordinator identity by Controller.start().
    controller = once(controller,
        '        this.adapterDisconnected = false;\n\n        abortSignal?.throwIfAborted();',
        '        this.adapterDisconnected = false;\n'
        '        if (String(startResult) !== "resumed") {\n'
        '            throw new Error("P7U HOLD_EXISTING_NV: non-resumed adapter startup denied");\n'
        '        }\n\n        abortSignal?.throwIfAborted();')
    controller = once(controller,
        "            if (configuredChannel !== adapterChannel) {",
        '            if (configuredChannel !== adapterChannel) {\n'
        '                throw new Error("P7U HOLD_EXISTING_NV: channel mismatch; automatic migration disabled");')
    controller = once(controller,
        '            databaseCoordinator.changeIeeeAddress(coordinatorIEEE);',
        '            throw new Error("P7U HOLD_EXISTING_NV: coordinator IEEE mismatch; no host repair");')
    controller = once(controller,
        """        clearInterval(this.databaseSaveTimer);

        if (this.adapterDisconnected) {""",
        """        clearInterval(this.databaseSaveTimer);

        // P7U_DB_ADMISSION_V1: database/models saved before the first
        // potentially stalled radio/permitJoin/adapter await. A failed save
        // aborts graceful stop rather than pretending it was durable.
        if (!this.adapterDisconnected) { this.databaseSave(); }
        if (this.adapterDisconnected) {""")
    # H1: pinned upstream skipBootloader uses a 0xEF magic byte and
    # serialPort.asyncSet DTR/RTS after a failed ping. Neither is allowed on
    # the sole retained-network P7U. Unexpected source drift holds.
    znp = originals[ZNP]
    first = znp.index("    private async skipBootloader(): Promise<void> {")
    end = znp.index("    public async close(): Promise<void> {", first)
    original_method = znp[first:end]
    if "Buffer.from([0xef])" not in original_method or "asyncSet({dtr: false, rts:" not in original_method:
        raise ValueError("pinned source skipBootloader implementation drift")
    safe_method = """    /** P7U_SAFE_PING_NO_BOOTLOADER_SIGNALS: retained owner only.
     * One bounded readiness request tolerates the observed USB/app boot
     * interval. No 0xEF magic, RTS/DTR fallback, or automatic reset.
     */
    private async skipBootloader(): Promise<void> {
        if (this.p7uStartupPingConsumed) {
            throw new Error("P7U HOLD_EXISTING_NV: startup ping already consumed; no retry");
        }
        this.p7uStartupPingConsumed = true; // before an uncertain transmission
        try {
            await this.request(Subsystem.SYS, "ping", {capabilities: 1}, undefined, 10000);
        } catch {
            throw new Error("P7U HOLD_EXISTING_NV: ping unavailable; no bootloader magic or line toggles");
        }
    }

"""
    znp = znp[:first] + safe_method + znp[end:]
    znp = once(znp, "    private initialized: boolean;",
        "    private initialized: boolean;\n    private p7uStartupPingConsumed = false;")
    # A retained-only manager is not the sole caller of Znp.request():
    # Controller.reset()/Adapter.reset() can also submit SYS/SAPI resets.
    # Enforce the no-radio-reset contract at the transport boundary too.
    znp = once(znp,
        "        const object = ZpiObject.createRequest(subsystem, command, payload);",
        """        const object = ZpiObject.createRequest(subsystem, command, payload);
        if (object.isResetCommand()) {
            throw new Error("P7U HOLD_EXISTING_NV: runtime radio reset disabled for retained R4");
        }""")
    # H3: after atomic db rename, fsync its *parent directory* to make
    # replacement of the directory entry durable on supported POSIX FS.
    # A failure raises and the host cannot claim a successfully saved DB.
    database = once(originals[DATABASE],
        'import fs from "node:fs";',
        'import fs from "node:fs";\nimport * as path from "node:path"; // P7U_DB_DIRECTORY_FSYNC')
    database = once(database,
        'import * as path from "node:path"; // P7U_DB_DIRECTORY_FSYNC',
        'import * as path from "node:path"; // P7U_DB_DIRECTORY_FSYNC\n'
        'import {createHash} from "node:crypto";')
    database = once(database,
        '    public static open(path: string): Database {',
        """    /** Live DB changes are sealed only AFTER a trusted startup approval.
     *  The caller must prove the latest committed snapshot first.
     */
    private static p7uSeal: {db: string; manifest: string;
        generation: string; digest: string} | null = null;

    public static p7uArmApproval(db: string, manifest: string,
                                generation: string, digest: string): void {
        if (!db.endsWith("/database.db") ||
            !manifest.startsWith("/config/zigbee2mqtt/") ||
            !/^[A-Za-z0-9_-]{12,100}$/.test(generation) ||
            !/^[a-f0-9]{64}$/.test(digest)) {
            throw new Error("P7U DB approval arm invalid");
        }
        if (Database.p7uSeal !== null && (Database.p7uSeal.db !== db ||
            Database.p7uSeal.manifest !== manifest ||
            Database.p7uSeal.generation !== generation)) {
            throw new Error("P7U DB approval already bound to a different owner");
        }
        Database.p7uSeal = {db, manifest, generation, digest};
    }

    /** Calculate the next private commit receipt from trusted model state.
     *  Never "approve" arbitrary disk bytes or rehydrate a .tmp.
     */
    private p7uNextReceipt(raw: string): {payload: string;
        seal: NonNullable<typeof Database.p7uSeal>} {
        const seal = Database.p7uSeal;
        if (seal === null || seal.db !== this.path) {
            throw new Error("P7U HOLD_EXISTING_DB: unarmed commit receipt");
        }
        const existing = fs.readFileSync(seal.manifest);
        if (createHash("sha256").update(existing).digest("hex") !== seal.digest) {
            throw new Error("P7U HOLD_EXISTING_DB: committed receipt externally changed");
        }
        const devices = new Set<string>();
        let coordinators = 0;
        for (const entry of this.entries.values()) {
            if (entry.type === "Group") { continue; }
            if (entry.type === "Coordinator") { coordinators++; }
            const ieee: unknown = entry.ieeeAddr;
            if (entry.type !== "GreenPower" &&
                (typeof ieee !== "string" || !/^0x[0-9a-f]{16}$/i.test(ieee))) {
                throw new Error("P7U HOLD_EXISTING_DB: missing model IEEE");
            }
            if (ieee !== undefined) {
                if (typeof ieee !== "string" || !/^0x[0-9a-f]{16}$/i.test(ieee) ||
                    devices.has(ieee.toLowerCase())) {
                    throw new Error("P7U HOLD_EXISTING_DB: duplicate model IEEE");
                }
                devices.add(ieee.toLowerCase());
            }
        }
        if (coordinators !== 1) {
            throw new Error("P7U HOLD_EXISTING_DB: coordinator identity changed");
        }
        const receipt = {
            schema: "p7u-db-admission-v1",
            database_sha256: createHash("sha256").update(raw, "utf8").digest("hex"),
            inventory_sha256: createHash("sha256").update(
                [...devices].sort().join("\\n") + "\\n", "ascii").digest("hex"),
            rows: this.entries.size, devices: devices.size,
            generation: seal.generation,
        };
        return {payload: JSON.stringify(receipt) + "\\n", seal};
    }

    public static open(path: string): Database {""")
    database = once(database,
        "        fs.renameSync(tmpPath, this.path);",
        """        fs.renameSync(tmpPath, this.path);
        // P7U_DB_DIRECTORY_FSYNC: file fsync without directory fsync does
        // not alone guarantee the renamed entry survives sudden power loss.
        const parentFd = fs.openSync(path.dirname(this.path), "r");
        try { fs.fsyncSync(parentFd); }
        finally { fs.closeSync(parentFd); }""")

    # Extend the protected DB write: the authorization receipt follows the
    # DB's directory-fsynced rename, with its OWN fsync+rename+dirfsync.
    # A crash between the two commits yields HOLD on the next start.
    database = once(database,
        """        const tmpPath = `${this.path}.tmp`;""",
        """        const approved = this.p7uNextReceipt(lines.slice(0, -1));
        const tmpPath = `${this.path}.tmp`;""")
    database = once(database,
        """        finally { fs.closeSync(parentFd); }""",
        """        finally { fs.closeSync(parentFd); }
        const approvalPending = approved.seal.manifest + ".pending";
        const receiptFd = fs.openSync(approvalPending, "wx", 0o600);
        try {
            fs.writeFileSync(receiptFd, approved.payload, "utf8");
            fs.fsyncSync(receiptFd);
        } finally { fs.closeSync(receiptFd); }
        fs.renameSync(approvalPending, approved.seal.manifest);
        const approvalDirFd = fs.openSync(path.dirname(approved.seal.manifest), "r");
        try { fs.fsyncSync(approvalDirFd); }
        finally { fs.closeSync(approvalDirFd); }
        approved.seal.digest = createHash("sha256").update(approved.payload, "utf8").digest("hex");""")
    return {DATABASE: (originals[DATABASE], database),
            ZNP: (originals[ZNP], znp),
            CONTROLLER: (originals[CONTROLLER], controller),
            PATH: (originals[PATH], manager),
            DEFINITION: (originals[DEFINITION], definition),
            PARAM: (originals[PARAM], params),
            BUFFALO: (originals[BUFFALO], buffalo)}


def apply(checkout, composition_receipt=None):
    planned = plan(checkout, composition_receipt)
    receipt = {
        "schema": "p7u-herdsman10.9.1-startup-hold-v1", "pinned_head": PIN,
        "file": PATH, "retained_only": True,
        "mandatory_readonly_f1": True, "healthy_missing_marker_resume": True,
        "installed": False, "network_recovered": False, "radio_access": False,
        "restore_automatically_allowed": False, "virgin_commissioning_allowed": False,
        "files": {},
    }
    if composition_receipt is not None:
        receipt["b4_composition_receipt_sha256"] = hashlib.sha256(Path(composition_receipt).read_bytes()).hexdigest()
    for name, (before, after) in planned.items():
        write_source_text(checkout, name, after)
        receipt["files"][name] = {
            "sha256_before": hashlib.sha256(before.encode()).hexdigest(),
            "sha256_after": hashlib.sha256(after.encode()).hexdigest(),
        }
    receipt["upstream_sha256"] = receipt["files"][PATH]["sha256_before"]
    receipt["patched_sha256"] = receipt["files"][PATH]["sha256_after"]
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--composition-receipt", type=Path)
    args = parser.parse_args()
    receipt = apply(args.checkout, args.composition_receipt)
    args.receipt.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
