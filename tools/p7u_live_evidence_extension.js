// One-shot, read-only P7U evidence snapshot through the running owner
// (official Zigbee2MQTT app, zigbee-herdsman Z-Stack adapter). Installed and
// removed again by tools/p7u_live_evidence.py through the bridge API.
//
// Sends only the firmware's RAM-only B1Q1 queries (MT SYS 0xF1, answered by
// the NPI owner) that host/flash/p7u_hang_evidence_once.py uses, inside
// herdsman's own ZNP request mutex: one serial owner, never two outstanding
// SREQs. No NV access, reset, BSL, radio or retry; stops at the first missing
// reply, except that an optional page older firmware rejects with an MT RPC
// error is only listed as missing. Herdsman logs one harmless
// "CommandID 241 ... not found" per reply
// (and "CommandID 0 from subsystem 0" for an optional page older firmware
// rejects).
const fs = require('node:fs');
const {Frame} = require('/app/node_modules/zigbee-herdsman/dist/adapter/z-stack/unpi/frame');

const OUT = '/config/zigbee2mqtt/p7u_live_evidence/evidence.json';
const SYS = 1;
const CMD = 0xf1;
const SREQ = 1;
const SRSP = 3;
const TIMEOUT_MS = 3000;
const q = (page, sub) => Buffer.from([0x42, 0x31, 0x51, 0x31, 0x01, 0x08, page, sub]);
const FIRST = [['B1E3', q(4, 1)], ['B1E6', q(4, 4)], ['B1E7', q(4, 5)], ['B1E2', q(4, 0)],
    ['B1E5', q(4, 3)], ['B1E4', q(4, 2)], ['B1E1', q(3, 0)], ['B1S1', q(0, 0)]];
const LATER = [['B1E2_LATER', q(4, 0)], ['B1E6_LATER', q(4, 4)], ['B1E7_LATER', q(4, 5)]];
// V57+: optional. Older firmware rejects page6 with an MT RPC error
// (SRSP RES0 cmd 0, data {3, 0x21, 0xF1}); that ends only this page.
const OPTIONAL = [['B1E8', q(4, 6)]];

class P7uLiveEvidence {
    constructor(zigbee, mqtt, state, publishEntityState, eventBus,
        enableDisableExtension, restartCallback, addExtension, settings, logger) {
        this.zigbee = zigbee;
        this.logger = logger;
    }

    async start() {
        const out = {started: new Date().toISOString(), replies: {}, timing_ms: {}};
        try {
            const znp = this.zigbee.zhController.adapter.znp;
            if (!znp || !znp.queue || !znp.unpiWriter || !znp.unpiParser) throw new Error('ZNP internals not available');
            const ask = (name, payload) => new Promise((resolve, reject) => {
                const t0 = process.hrtime.bigint();
                const onFrame = (frame) => {
                    if (frame.type === SRSP && frame.subsystem === 0 && frame.commandID === 0 &&
                        frame.data && frame.data[1] === 0x21 && frame.data[2] === CMD) {
                        clearTimeout(timer);
                        znp.unpiParser.off('parsed', onFrame);
                        reject(new Error('rejected ' + name));
                        return;
                    }
                    if (frame.type === SRSP && frame.subsystem === SYS && frame.commandID === CMD) {
                        clearTimeout(timer);
                        znp.unpiParser.off('parsed', onFrame);
                        out.replies[name] = Buffer.from(frame.data).toString('hex');
                        out.timing_ms[name] = Number(process.hrtime.bigint() - t0) / 1e6;
                        resolve();
                    }
                };
                const timer = setTimeout(() => {
                    znp.unpiParser.off('parsed', onFrame);
                    reject(new Error('no SRSP for ' + name));
                }, TIMEOUT_MS);
                znp.unpiParser.on('parsed', onFrame);
                znp.unpiWriter.writeFrame(new Frame(SREQ, SYS, CMD, payload));
            });
            await znp.queue.run(async () => {
                for (const [name, payload] of FIRST) await ask(name, payload);
                await new Promise((ok) => setTimeout(ok, 1000));
                for (const [name, payload] of LATER) await ask(name, payload);
                for (const [name, payload] of OPTIONAL) {
                    try {
                        await ask(name, payload);
                    } catch (error) {
                        // Only an RPC rejection (older firmware) is optional;
                        // a timeout on firmware that has the page is a failure.
                        if (!/^rejected /.test(String(error && error.message))) throw error;
                        out.optional_missing = (out.optional_missing || []).concat([name]);
                    }
                }
            });
            out.result = 'OK';
        } catch (error) {
            out.error = String(error && error.message ? error.message : error);
            out.result = 'PARTIAL_OR_ERROR';
        }
        out.finished = new Date().toISOString();
        try {
            fs.writeFileSync(OUT, JSON.stringify(out, null, 2), {mode: 0o600});
        } catch (e) {
            // the log line below still carries the summary
        }
        if (this.logger) {
            this.logger.info(`p7u_live_evidence: ${out.result} ${Object.keys(out.replies).length} replies ${out.error || ''}`);
        }
    }

    async stop() {}
}

module.exports = P7uLiveEvidence;
