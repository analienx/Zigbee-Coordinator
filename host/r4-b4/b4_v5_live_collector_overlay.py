#!/usr/bin/env python3
"""Add low-rate V5 flights to the existing no-serial evidence worker.

Apply AFTER: pinned V4 Z2M collector and V5 existing-owner herdsman overlay.
Never installs, sends Zigbee traffic, starts a worker or opens serial itself.
V5 is explicitly opt-in; every 5th original F2 sample is *substituted* by
a pair, not additional requests after the normal V4 read.
"""
import argparse,hashlib,json,subprocess
from pathlib import Path

Z2M_SHA="62b02e2aa1997c574223b80c196677b63a25f4a7"
HERDSMAN_SHA="0968f979d558874b17396c96b66382d4236bbdcd"
CONTROLLER="lib/controller.ts"
ZSTACK_CONTROLLER="src/controller/controller.ts"
MARKER="P7U_F2_V5_OPTIN_DURABLE_FLIGHT"

PROXY=r'''
    /** P7U_F2_V5_OPTIN_DURABLE_FLIGHT: use current ZStackAdapter/Znp owner.
     * Never construct new serial port, retry or bypass OTA/shutdown. */
    public async b4ReadHangFlightV5FromExistingOwner(input: {
        enabled: boolean; hostIdle: boolean; otaActive: boolean;
        stillAllowed: () => boolean;
    }) {
        if (this.stopping || this.adapterDisconnected ||
            typeof input?.stillAllowed !== "function" ||
            !(this.adapter instanceof ZStackAdapter)) return undefined;
        return await this.adapter.b4ReadHangFlightV5(input);
    }

'''

Z2M_METHOD=r'''
    /** P7U_F2_V5_OPTIN_DURABLE_FLIGHT: same v4 OTA gate and one ZNP owner.
     * No extra diagnostics if OTA, shutdown or queue is busy. */
    public async b4ProbeReadOnlyHangFlightV5(enabled = false) {
        const herdsman=this.zigbee.zhController;
        if (enabled !== true || !this.#b4Operational ||
            !herdsman || herdsman.isStopping() ||
            herdsman.isAdapterDisconnected()) return undefined;
        const ota=[...this.extensions].find(
            (extension): extension is ExtensionOTAUpdate =>
                extension instanceof ExtensionOTAUpdate);
        if (!ota) return undefined;
        const stillAllowed=(): boolean =>
            this.#b4Operational && ota.b4CanAcceptReadOnlyDiagnostics() &&
            !herdsman.isStopping() && !herdsman.isAdapterDisconnected();
        if (!stillAllowed()) return undefined;
        return await herdsman.b4ReadHangFlightV5FromExistingOwner({
            enabled:true,hostIdle:true,otaActive:false,stillAllowed,
        });
    }

'''

SAMPLE=r'''
            /* Replaces one of every five V4 samples when explicit opt-in is
             * enabled; never stacks three F2 reads atop a normal V4 sample.
             * The paired V5 data is committed as distinct FLIGHT record,
             * not manufactured VALID minor4 and not part of V4 freshness.
             * No request on an active OTA/busy/poisoned owner. */
            if (process.env.P7U_B4_FLIGHT_V5 === "1" &&
                (++this.#b4V5EveryFifth % 5) === 0) {
                const flight=await this.b4ProbeReadOnlyHangFlightV5(true);
                if (!this.#b4Operational) return;
                const utc=Date.now();
                if (flight) {
                    this.#b4Persist({
                        schema:"p7u-b4-native-sample-v1",kind:"FLIGHT",utc,
                        monotonicReceiveNs:process.hrtime.bigint().toString(),
                        probeLatencyMs:Math.max(0,Math.round(performance.now()-probeStarted)),
                        flightV5:flight,
                    });
                } else {
                    this.#b4Persist({
                        schema:"p7u-b4-native-sample-v1",kind:"SKIPPED",utc,
                        monotonicReceiveNs:process.hrtime.bigint().toString(),
                        reason:"HOST_OR_OTA_ADMISSION_SKIPPED",
                        submissionState:"NONE",sourceAbi:5,
                    });
                }
                return;
            }
'''

def once(src,old,new,label):
    count=src.count(old)
    if count!=1:raise ValueError("V5_DURABLE_DRIFT_"+label+":"+str(count))
    return src.replace(old,new,1)

def read_checked(root,relative):
    path=root/relative
    if path.is_symlink() or not path.is_file() or root.is_symlink():
        raise ValueError("V5_DURABLE_UNTRUSTED_SOURCE_"+relative)
    return path.read_text(encoding="utf-8")

def apply(z2m,herdsman):
    z2m,herdsman=Path(z2m).resolve(),Path(herdsman).resolve()
    for root,expected in ((z2m,Z2M_SHA),(herdsman,HERDSMAN_SHA)):
        if not str(root).startswith("/tmp/") or subprocess.check_output(
            ["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()!=expected:
            raise ValueError("V5_DURABLE_PIN_DRIFT")
    src=read_checked(z2m,CONTROLLER)
    ctl=read_checked(herdsman,ZSTACK_CONTROLLER)
    if (MARKER in src or MARKER in ctl or
        "P7U_B4_SAMPLED_SINGLE_OWNER_R4_V1" not in src or
        "b4ReadHangFlightV5(input:" not in read_checked(
             herdsman,"src/adapter/z-stack/adapter/zStackAdapter.ts") or
        "b4ReadOnlyDiagnosticsV4FromExistingOwner" not in ctl):
        raise ValueError("V5_DURABLE_REQUIRES_V4_V5_OWNERS")
    ctl=once(ctl,"    public isStopping(): boolean {",
        PROXY+"    public isStopping(): boolean {","HERDSMAN_PROXY")
    src=once(src,"    #b4Schedule(delay = 60_000): void {",
        Z2M_METHOD+"    #b4Schedule(delay = 60_000): void {","Z2M_METHOD")
    src=once(src,
        "    async #b4Sample(): Promise<void> {",
        "    #b4V5EveryFifth = 0;\n    async #b4Sample(): Promise<void> {",
        "V5_SAMPLING_COUNTER")
    src=once(src,
        "            const outcomeBefore = this.zigbee.zhController?.b4V4ReadOutcomeFromExistingOwner();",
        SAMPLE+"            const outcomeBefore = this.zigbee.zhController?.b4V4ReadOutcomeFromExistingOwner();",
        "V5_SUBSTITUTE_F2_SAMPLE")
    files={CONTROLLER:src,ZSTACK_CONTROLLER:ctl}
    (z2m/CONTROLLER).write_text(src,encoding="utf-8",newline="")
    (herdsman/ZSTACK_CONTROLLER).write_text(ctl,encoding="utf-8",newline="")
    return {
      "schema":"p7u-f2-v5-optin-durable-sampler-v1",
      "v4_legacy_samples_unchanged":True,
      "v5_replaces_every_fifth_sample_only":True,
      "v5_optin_env":"P7U_B4_FLIGHT_V5",
      "default_enabled":False,"one_serial_owner":True,
      "worker_chain":"EXISTING_P7U_F2_WORKER_V2",
      "live_installed":False,"radio_hardware_proven":False,
      "files_sha256":{p:hashlib.sha256(v.encode()).hexdigest() for p,v in files.items()}
    }

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--z2m",type=Path,required=True)
    ap.add_argument("--herdsman",type=Path,required=True)
    ap.add_argument("--receipt",type=Path,required=True)
    a=ap.parse_args()
    obj=apply(a.z2m,a.herdsman)
    a.receipt.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
    print(json.dumps(obj,sort_keys=True))
