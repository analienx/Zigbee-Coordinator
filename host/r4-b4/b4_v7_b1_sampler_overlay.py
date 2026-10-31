"""V7 production B1 evidence sampler through the EXISTING herdsman ZNP owner.

The 27-Oct F2 sampler skipped 1097 of 1177 slots (ADAPTER_QUEUE_PENDING,
ZNP_WAITRESS_PENDING) and went blind for the final 13 hours, because it
refused to wait for the busy production owner. This sampler never skips for
queue depth: each page is ONE ordinary SREQ through the same Znp mutex as
every production request (never a second outstanding SREQ, never another
UART owner), so a slot waits its turn. The firmware answers B1Q1 op4 in its
priority-6 NPI owner, not in the Stack task it reports on.

Default OFF (P7U_B1_SAMPLER=1). Every P7U_B1_SAMPLER_MS (>= 30 s, default
60 s): B1E2 (Stack/MAC) and B1E6 (NPI->MT->UART, OSAL timers, in-flight);
every 10th slot also B1E3 (onset) and B1E5 (60-minute trend). Raw pages are
journaled (JSON lines, 8 MiB rotation); nothing is acted upon. A slot that
cannot start because the previous one is still waiting is journaled as
OVERLAP, never as a zero measurement.
"""
import argparse
import hashlib
import json
from pathlib import Path

from b4_first_warning_overlay import checked
from b4_v5_herdsman_overlay import once

PIN = "0968f979d558874b17396c96b66382d4236bbdcd"
BUFFALO = "src/adapter/z-stack/znp/buffaloZnp.ts"
ADAPTER = "src/adapter/z-stack/adapter/zStackAdapter.ts"
MARKER = "B4_V7_B1_EVIDENCE_SAMPLER"

PARSE_OLD = """            case ParameterType.BUFFER24: {
                if (this.getBuffer().length - this.getPosition() !== 24) {
                    throw new Error("P7U retained status length must be exactly24");
                }
                return this.readBuffer(24);
            }"""
PARSE_NEW = """            case ParameterType.BUFFER24: {
                // B4_V7_B1_EVIDENCE_SAMPLER: a B1Q1 F1 reply is the exact 24-byte
                // B1S1 or a 248-byte op4 page (B1E2..B1E6). Startup still demands
                // exactly 24 bytes and the B1S1 tag before any network request.
                const remaining = this.getBuffer().length - this.getPosition();
                if (remaining !== 24 && remaining !== 248) {
                    throw new Error("P7U retained status length must be exactly24 or 248");
                }
                return this.readBuffer(remaining);
            }"""

IMPORT_OLD = 'import {logger} from "../../../utils/logger";\n'
IMPORT_NEW = IMPORT_OLD + 'import fs from "node:fs"; // B4_V7_B1_EVIDENCE_SAMPLER journal\n'

FIELD_OLD = "    private b4V4Attempt = 0;\n"
FIELD_NEW = FIELD_OLD + """    private p7uB1Timer: ReturnType<typeof setInterval> | undefined;
    private p7uB1InFlight = false;
    private p7uB1Slot = 0;
"""

START_OLD = "        return await startResult;\n"
START_NEW = """        const p7uStarted = await startResult;
        this.p7uB1Start(); // B4_V7: only after a completed start
        return p7uStarted;
"""

STOP_OLD = "    public async stop(): Promise<void> {\n        this.closing = true;\n"
STOP_NEW = """    /** B4_V7_B1_EVIDENCE_SAMPLER: see host/r4-b4/b4_v7_b1_sampler_overlay.py. */
    private p7uB1Start(): void {
        if (process.env.P7U_B1_SAMPLER !== "1" || this.p7uB1Timer !== undefined) return;
        const requested = Number(process.env.P7U_B1_SAMPLER_MS ?? "60000");
        const period = Number.isFinite(requested) ? Math.max(30000, requested) : 60000;
        this.p7uB1Timer = setInterval(() => {
            void this.p7uB1Sample();
        }, period);
        this.p7uB1Timer.unref?.();
    }

    /** One slot: ordinary SREQs through the existing Znp mutex, in order. */
    public async p7uB1Sample(): Promise<Record<string, unknown>> {
        const slot = ++this.p7uB1Slot;
        const record: Record<string, unknown> = {schema: "p7u-b1-sample-v1", slot, utc: Date.now()};
        if (this.closing) {
            record.outcome = "ADAPTER_CLOSING";
        } else if (this.p7uB1InFlight) {
            record.outcome = "OVERLAP_PREVIOUS_SLOT_STILL_WAITING";
        } else {
            this.p7uB1InFlight = true;
            const tags = ["B1E2", "B1E3", "B1E4", "B1E5", "B1E6"];
            const pages = slot % 10 === 1 ? [0, 4, 1, 3] : [0, 4];
            try {
                for (const page of pages) {
                    const tag = tags[page];
                    const started = performance.now();
                    try {
                        const response = await this.znp.requestWithReply(
                            Subsystem.SYS, "p7uRetainedStatus",
                            {query: Buffer.from([0x42, 0x31, 0x51, 0x31, 1, 8, 4, page])}, undefined, 8000);
                        const data: unknown = response.payload.snapshot;
                        if (!Buffer.isBuffer(data) || data.length !== 248 ||
                            data.toString("ascii", 0, 4) !== tag || data[4] !== 1 || data[5] !== 248) {
                            throw new Error("B1_PAGE_SHAPE");
                        }
                        record[tag] = data.toString("hex");
                    } catch (error) {
                        record[tag + "_error"] = (error instanceof Error ? error.message : String(error)).slice(0, 80);
                    }
                    record[tag + "_ms"] = Math.round(performance.now() - started);
                }
                record.outcome = "SAMPLED";
            } finally {
                this.p7uB1InFlight = false;
            }
        }
        this.p7uB1Journal(record);
        return record;
    }

    private p7uB1Journal(record: Record<string, unknown>): void {
        const path = process.env.P7U_B1_SAMPLER_JOURNAL ?? "/config/zigbee2mqtt/p7u-b1-evidence.jsonl";
        try {
            if (fs.existsSync(path) && fs.statSync(path).size > 8 * 1024 * 1024) {
                fs.renameSync(path, path + ".1");
            }
            fs.appendFileSync(path, JSON.stringify(record) + "\\n", {mode: 0o600});
        } catch {
            logger.debug("P7U B1 sampler journal unavailable", NS);
        }
    }

    public async stop(): Promise<void> {
        this.closing = true;
        if (this.p7uB1Timer !== undefined) {
            clearInterval(this.p7uB1Timer);
            this.p7uB1Timer = undefined;
        }
"""


def herdsman(root):
    root = checked(root, PIN)
    out = {}
    for rel, edits in ((BUFFALO, ((PARSE_OLD, PARSE_NEW, "V7_F1_PAGE_LENGTH"),)),
                       (ADAPTER, ((IMPORT_OLD, IMPORT_NEW, "V7_FS_IMPORT"),
                                  (FIELD_OLD, FIELD_NEW, "V7_FIELDS"),
                                  (START_OLD, START_NEW, "V7_START_AFTER_COMPLETED_START"),
                                  (STOP_OLD, STOP_NEW, "V7_SAMPLER_AND_STOP")))):
        text = (root / rel).read_text()
        if MARKER in text:
            raise ValueError("V7_ALREADY_APPLIED")
        for old, new, label in edits:
            text = once(text, old, new, label)
        (root / rel).write_text(text, encoding="utf-8", newline="")
        out[rel] = hashlib.sha256(text.encode()).hexdigest()
    return {"schema": "p7u-v7-b1-sampler-v1", "default_enabled": False,
            "enable_env": "P7U_B1_SAMPLER=1", "period_floor_ms": 30000,
            "second_outstanding_sreq": False, "new_serial_owner": False,
            "skips_for_queue_depth": False, "modified_sha256": out}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--herdsman", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    args.receipt.write_text(json.dumps(herdsman(args.herdsman), indent=2) + "\n")
