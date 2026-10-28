#!/usr/bin/env python3
"""Source-bound V5 read inside *existing* herdsman Znp/adapter owner.

Apply AFTER audited V4+preservation source overlays and BEFORE TS build.
No second serial/port, sidecar, MQTT, recovery, NV or automatic probe timer.
The fixed 9-byte F2 request cannot be encoded by V4's BUFFER8 definition,
so enqueue a 9-byte UnpiFrame using the SAME ZNP queue/waitress/stream owner.
"""
import hashlib
from pathlib import Path

ZNP="src/adapter/z-stack/znp/znp.ts"
ADAPTER="src/adapter/z-stack/adapter/zStackAdapter.ts"
CONTROLLER="src/controller/controller.ts"
MARKER="B4_F2_V5_EXISTING_OWNER"

ZNP_METHOD=r'''
    /** B4_F2_V5_EXISTING_OWNER. Requires explicit existing-owner admission.
     * No alternate transport/serial handle or background retry.
     * This is the only correct wire form: [page:uint8, nonce:8 bytes].
     */
    public async b4ReadV5Page(page: 1 | 2, nonce: Buffer): Promise<Buffer> {
        if (!Buffer.isBuffer(nonce) || nonce.length !== 8 ||
            (page !== 1 && page !== 2) || !this.initialized ||
            this.b4IsDiagPoisoned() || this.b4F2ReadAdmissionReason() !== null ||
            !this.queue.isIdle() || !this.b4F2NoBlockingWaiters()) {
            throw new Error("B4 V5_OWNER_ADMISSION_DENIED");
        }
        const request = Buffer.concat([Buffer.from([page]), nonce]);
        const frame = new UnpiFrame(Type.SREQ, Subsystem.SYS, 0xF2, request);
        return this.queue.run(async () => {
            /* Revalidate immediately before the existing UART writer,
             * not just before entering the ZNP mutex: OTA or shutdown
             * may have begun while this request waited in the queue. */
            if (!this.initialized || this.b4IsDiagPoisoned() ||
                this.b4F2ReadAdmissionReason() !== null ||
                !this.b4F2NoBlockingWaiters() ||
                (this.b4ProbeGuard !== undefined && this.b4ProbeGuard() !== true)) {
                throw new Error("B4 V5_LATE_OWNER_GUARD");
            }
            /* The pinned ZpiObject parser maps SYS/F2 to the original
             * v4 command object, so use its name for waitress matching.
             * The matcher is extended below to distinguish LEN8/LEN9. */
            const waiter = this.waitress.waitFor({
                type: Type.SRSP, subsystem: Subsystem.SYS,
                command: "r4DiagReadOnlyV4", b4F2Nonce: request,
            }, 6000);
            try {
                this.unpiWriter.writeFrame(frame);
                const response = await waiter.start().promise;
                const data = response?.payload?.diagnostic;
                if (!Buffer.isBuffer(data) || data.length !== 160 ||
                    data.toString("ascii", 0, 4) !== "R4D5" ||
                    data[4] !== 5 || data[5] !== page ||
                    data.readUInt16LE(6) !== 160 ||
                    !data.subarray(8, 16).equals(nonce)) {
                    this.b4PoisonDiagSession();
                    throw new Error("B4 V5_INVALID_NATIVE_PAGE");
                }
                this.b4F2AcceptReply();
                return Buffer.from(data);
            } catch (error) {
                this.waitress.b4Cancel(waiter.ID, "B4 v5 no stale waiter");
                /* v4 first-timeout cooldown and progress gate are retained,
                 * never retry or send another diagnostic after uncertainty. */
                if (!(error instanceof Error) ||
                    error.message !== "B4 V5_INVALID_NATIVE_PAGE") {
                    this.b4PoisonDiagSession();
                }
                throw error;
            }
        });
    }

'''
ADAPTER_METHOD=r'''
    /** Opt-in F2 v5 pages; returns only allowlisted scalar diagnosis.
     * The radio and host source ABI are validated before production use.
     * No raw nonce, boot ID, packet payloads, keys or device IDs exported.
     * Existing v4 sample/worker behavior is unchanged.
     */
    public async b4ReadHangFlightV5(input: {
        enabled: boolean; hostIdle: boolean; otaActive: boolean;
        stillAllowed: () => boolean;
    }): Promise<{
        abi: 5; pageSequence: number; eventCount: number;
        counters: Record<string, number>;
        events: {tick: number; stage: number; subsystem: string; result: number}[];
        source: "RADIO_READ_ONLY";
    } | undefined> {
        if (input?.enabled !== true || input.hostIdle !== true ||
            input.otaActive !== false || typeof input.stillAllowed !== "function" ||
            !input.stillAllowed() || this.closing || !this.queue ||
            this.queue.count() !== 0 || this.interpanLock ||
            this.b4DiagInFlight || performance.now() < this.b4NextAllowedMs ||
            !this.znp.b4CanProbeV4()) return undefined;
        const nonce = randomBytes(8);
        this.b4DiagInFlight = true;
        this.b4NextAllowedMs = performance.now() + 30_000;
        this.znp.b4SetProbeGuard(() => input.stillAllowed() &&
            !this.closing && !this.interpanLock);
        try {
            const a = await this.znp.b4ReadV5Page(1, nonce);
            if (!input.stillAllowed() || this.closing || this.interpanLock)
                return undefined;
            const b = await this.znp.b4ReadV5Page(2, nonce);
            if (!a.subarray(8, 32).equals(b.subarray(8, 32)) ||
                a.readUInt32LE(24) === 0 || a[5] !== 1 || b[5] !== 2)
                throw new Error("B4 V5_CROSS_PAGE_MISMATCH");
            const positions: Record<string, number> = {
                npiWakes: 32, npiLastTick: 36, mtEntered: 40,
                mtLastEnteredTick: 44, mtExited: 48, mtLastExitedTick: 52,
                eventTotal: 56, reserveUsed: 60, reserveExhausted: 64,
                reserveReleaseFault: 68, reserveActive: 72,
                allSrspProduced: 76, allSrspAllocationFailed: 80,
                allSrspFramingFailed: 84, allSrspTlRejected: 88,
                uartTxCallbackOk: 92, uartTxCallbackError: 96,
                uartRxBytes: 100, validityFlags: 104,
                eventCount: 108, clockTickPeriodUs: 112,
                npiRequests: 116, uartWriteAccepted: 120,
                uartWriteRejected: 124, uartStateFlags: 128,
                firstUartFaultKind: 132, firstUartFaultTick: 136,
                b1FirstFailure: 140,
            };
            const counters: Record<string, number> = {};
            for (const [name, offset] of Object.entries(positions))
                counters[name] = a.readUInt32LE(offset);
            if (counters.reserveActive > 3 ||
                counters.mtExited > counters.mtEntered ||
                counters.firstUartFaultKind > 5 ||
                counters.b1FirstFailure > 255 ||
                (counters.uartStateFlags & 0xfff0) !== 0 ||
                (counters.firstUartFaultKind === 0 && counters.firstUartFaultTick !== 0) ||
                counters.eventCount > 16 ||
                counters.eventCount !== Math.min(counters.eventTotal, 16) ||
                (counters.validityFlags & ~3) !== 0 ||
                (counters.validityFlags & 2) === 0 ||
                counters.clockTickPeriodUs === 0 ||
                counters.clockTickPeriodUs > 100000 ||
                !a.subarray(144).equals(Buffer.alloc(16))) {
                throw new Error("B4 V5_INVALID_METRICS");
            }
            const events: {tick: number; stage: number; subsystem: string; result: number}[]=[];
            for (let i = 0; i < 16; i++) {
                const offset=32+i*8;
                if (i >= counters.eventCount) {
                    if (!b.subarray(offset,offset+8).equals(Buffer.alloc(8)))
                        throw new Error("B4 V5_DIRTY_RING_TAIL");
                    continue;
                }
                const command=b.readUInt16LE(offset+4);
                const subsystem= (command >> 8) & 0x1F;
                const stage=b[offset+6], result=b[offset+7];
                if (stage < 1 || stage > 9 ||
                    (stage === 8 && result === 0)) {
                    throw new Error("B4 V5_INVALID_RING");
                }
                events.push({tick:b.readUInt32LE(offset),stage,
                    subsystem:subsystem===4?"AF":subsystem===1?"SYS":
                        subsystem===5?"ZDO":"OTHER",result});
            }
            return {abi:5,pageSequence:a.readUInt32LE(24),
                eventCount:counters.eventCount,counters,events,
                source:"RADIO_READ_ONLY"};
        } catch {
            /* No serial recovery or reset. An uncertain F2 page pair must
             * not permit another diagnostic or be shown as healthy. */
            this.znp.b4PoisonDiagSession();
            return undefined;
        } finally {
            this.znp.b4SetProbeGuard(undefined);
            this.b4DiagInFlight = false;
        }
    }

'''
def once(src,a,b,label):
    if src.count(a)!=1:raise ValueError("V5_HOST_SOURCE_DRIFT_"+label+":"+str(src.count(a)))
    return src.replace(a,b,1)

def apply(root):
    root=Path(root)
    paths=(ZNP,ADAPTER,CONTROLLER)
    original={p:(root/p).read_text(encoding="utf-8") for p in paths}
    z,a,c=original[ZNP],original[ADAPTER],original[CONTROLLER]
    if MARKER in z or "b4F2ReadAdmissionReason" not in z or "b4ReadOnlyDiagnosticsV4" not in a:
        raise ValueError("V5_HOST_REQUIRES_PINNED_V4_OWNER")
    z=once(z,"    public b4F2ReadAdmissionReason(): string | null {",
           ZNP_METHOD+"    public b4F2ReadAdmissionReason(): string | null {","method")
    # Reuse the exact same ZpiObject waiter response, but permit V5 LEN9
    # with nonce returned at bytes 8..15 and reject any other form.
    needle="""(Buffer.isBuffer(matcher.b4F2Nonce) && matcher.b4F2Nonce.length === 8 &&
                 Buffer.isBuffer(zpiObject.payload.diagnostic) && [160, 240, 248].includes(zpiObject.payload.diagnostic.length) &&
                 matcher.b4F2Nonce.equals(zpiObject.payload.diagnostic.subarray(132, 140)))"""
    replacement="""(Buffer.isBuffer(matcher.b4F2Nonce) &&
                 Buffer.isBuffer(zpiObject.payload.diagnostic) &&
                 ((matcher.b4F2Nonce.length === 8 &&
                   [160, 240, 248].includes(zpiObject.payload.diagnostic.length) &&
                   matcher.b4F2Nonce.equals(zpiObject.payload.diagnostic.subarray(132, 140))) ||
                  (matcher.b4F2Nonce.length === 9 &&
                   zpiObject.payload.diagnostic.length === 160 &&
                   zpiObject.payload.diagnostic.subarray(0,4).toString("ascii") === "R4D5" &&
                   zpiObject.payload.diagnostic[4] === 5 &&
                   (zpiObject.payload.diagnostic[5] === matcher.b4F2Nonce[0] ||
                    zpiObject.payload.diagnostic[5] === 255) &&
                   matcher.b4F2Nonce.subarray(1).equals(zpiObject.payload.diagnostic.subarray(8,16)))))"""
    z=once(z,needle,replacement,"nonce_waiter_matcher")
    a=once(a,"    public async b4ReadOnlyDiagnosticsV4(input: ",
           ADAPTER_METHOD+"    public async b4ReadOnlyDiagnosticsV4(input: ","adapter_method")
    c=once(c,"    public isStopping(): boolean {", "    /** P7U_F2_V5_EXISTING_OWNER: existing one ZStackAdapter, no UART open. */\n    public async b4ReadHangFlightV5FromExistingOwner(input: {\n        enabled: boolean; hostIdle: boolean; otaActive: boolean;\n        stillAllowed: () => boolean;\n    }) {\n        if (this.stopping || this.adapterDisconnected ||\n            typeof input?.stillAllowed !== \"function\" ||\n            !(this.adapter instanceof ZStackAdapter)) return undefined;\n        return await this.adapter.b4ReadHangFlightV5(input);\n    }\n\n" + "    public isStopping(): boolean {","CONTROLLER_PROXY")
    for p,data in ((ZNP,z),(ADAPTER,a),(CONTROLLER,c)):
        (root/p).write_text(data,encoding="utf-8",newline="")
    return {"schema":"p7u-f2-v5-herdsman-existing-owner-v1",
      "serial_owner":"EXISTING_ZNP_ONLY","default_enabled":False,
      "new_serial_port":False,"native_radio_hardware_verified":False,
      "before_sha256":{p:hashlib.sha256(t.encode()).hexdigest() for p,t in original.items()},
      "modified_sha256":{ZNP:hashlib.sha256(z.encode()).hexdigest(),
                         ADAPTER:hashlib.sha256(a.encode()).hexdigest(),
                         CONTROLLER:hashlib.sha256(c.encode()).hexdigest()}}

if __name__=="__main__":
    import argparse,json
    p=argparse.ArgumentParser()
    p.add_argument("--checkout",required=True,type=Path)
    p.add_argument("--receipt",required=True,type=Path)
    args=p.parse_args()
    result=apply(args.checkout)
    args.receipt.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))
