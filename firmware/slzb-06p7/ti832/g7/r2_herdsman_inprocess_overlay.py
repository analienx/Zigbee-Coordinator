#!/usr/bin/env python3
"""Optional pinned-herdsman owner-side SYS/F0 adapter, source-only staging.

No Z2M extension is enabled, no current installed herdsman is edited, and no
radio serial port is opened. Pinned source must be deliberately rebuilt for
an isolated P7U after independently verifying application and backup.
"""
from __future__ import annotations
import argparse,hashlib,json,subprocess
from pathlib import Path

PINNED_HERDSMAN_SHA="0968f979d558874b17396c96b66382d4236bbdcd"
DEFINITION="src/adapter/z-stack/znp/definition.ts"
OBJECT="src/adapter/z-stack/znp/zpiObject.ts"
ADAPTER="src/adapter/z-stack/adapter/zStackAdapter.ts"
PATCHES=(DEFINITION,OBJECT,ADAPTER)
CMD='''        {
            name: "p7UDiagnosticSnapshot",
            ID: 240,
            type: CommandType.SREQ,
            request: [
                {name: "version", parameterType: ParameterType.UINT8},
                {name: "operation", parameterType: ParameterType.UINT8},
            ],
            response: [],
        },
'''
PARSE='''        } else if (frame.type === Type.SRSP && frame.subsystem === Subsystem.SYS && frame.commandID === 0xf0) {
            // P7 R2: vendor read-only G6 variable-length response. Do not
            // assume an upstream length-prefixed ZNP parameter or parse as NV.
            payload.data = Buffer.from(frame.data);
'''
METHOD='''    /**
     * P7U R2 read-only RAM recorder; uses the existing ZNP SREQ queue.
     * Host is responsible for checking coordinator IEEE and G6 CRC.
     */
    public async getP7UDiagnosticSnapshot(): Promise<Buffer> {
        const response = await this.znp.requestWithReply(
            Subsystem.SYS, "p7UDiagnosticSnapshot", {version: 1, operation: 0},
            undefined, 4000,
        );
        const raw = response.payload.data;
        if (!Buffer.isBuffer(raw)) throw new Error("P7U diagnostic response is not binary");
        return raw;
    }

'''

def replace_once(source: str, anchor: str, patch: str, tag: str)->str:
    count=source.count(anchor)
    if count!=1:raise ValueError(f"PINNED_UPSTREAM_ANCHOR_{tag}:count={count}")
    return source.replace(anchor,patch,1)

def modify(inp:dict[str,str])->dict[str,str]:
    out=dict(inp)
    d=inp[DEFINITION];o=inp[OBJECT];a=inp[ADAPTER]
    if 'name: "p7UDiagnosticSnapshot"' in d or "frame.commandID === 0xf0" in o:
        raise ValueError("ALREADY_PATCHED_OR_CONFLICT")
    # Guard actual upstream SYS entries (not unrelated namespaces' 240 values).
    sys_def=d.split("[Subsystem.SYS]: [",1)[-1].split("[Subsystem.MAC]:",1)[0]
    import re
    if re.search(r"\bID:\s*(?:0xf0|240)\b",sys_def,re.I):
        raise ValueError("UPSTREAM_SYS_F0_COLLISION")
    out[DEFINITION]=replace_once(d,"    [Subsystem.SYS]: [\n",
                                    "    [Subsystem.SYS]: [\n"+CMD,"SYS_DEFINITION")
    out[OBJECT]=replace_once(o,"        } else if (isMtCmdSreqZdo(cmd)) {\n",
        PARSE+"        } else if (isMtCmdSreqZdo(cmd)) {\n","READ_VARIABLE_SRSP")
    out[ADAPTER]=replace_once(a,"    public async getCoordinatorVersion(): Promise<CoordinatorVersion> {\n",
        METHOD+"    public async getCoordinatorVersion(): Promise<CoordinatorVersion> {\n","ADAPTER_OWNER_METHOD")
    return out

def stage(source:Path,out:Path)->dict:
    if source.resolve()==out.resolve() or source.resolve() in out.resolve().parents:
        raise ValueError("REFUSE_WRITE_IN_SOURCE")
    try:
        actual=subprocess.check_output(["git","-C",str(source),"rev-parse","HEAD"],
                                       text=True,stderr=subprocess.DEVNULL).strip()
    except (OSError,subprocess.CalledProcessError):
        raise ValueError("PINNED_HERDSMAN_CHECKOUT_REQUIRED") from None
    if actual!=PINNED_HERDSMAN_SHA:
        raise ValueError("HERDSMAN_SHA_MISMATCH:"+actual)
    before={p:(source/p).read_text(encoding="utf-8") for p in PATCHES}
    after=modify(before)
    report={"pinned_herdsman_commit":PINNED_HERDSMAN_SHA,
      "qualification":"ISOLATED_OWNER_BUILD_ONLY", "enabled":False,
      "installed_z2m_changed":False,"flash_authorized":False,
      "source_files":{}}
    for name in PATCHES:
        target=out/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(after[name],encoding="utf-8")
        report["source_files"][name]={
            "before_sha256":hashlib.sha256(before[name].encode()).hexdigest(),
            "staged_sha256":hashlib.sha256(after[name].encode()).hexdigest()}
    (out/"P7U-G6-OWNER-OVERLAY-MANIFEST.json").write_text(json.dumps(report,indent=2)+"\n")
    return report

def selftest():
    d="    [Subsystem.SYS]: [\n    ],\n    [Subsystem.MAC]: [\n"
    o="        } else if (isMtCmdSreqZdo(cmd)) {\n"
    a="    public async getCoordinatorVersion(): Promise<CoordinatorVersion> {\n"
    args={DEFINITION:d,OBJECT:o,ADAPTER:a}
    patched=modify(args)
    assert "p7UDiagnosticSnapshot" in patched[DEFINITION]
    assert "Buffer.from(frame.data)" in patched[OBJECT]
    assert "this.znp.requestWithReply(" in patched[ADAPTER]
    try:modify(patched)
    except ValueError:pass
    else:raise AssertionError("PATCH_NOT_IDEMPOTENCY_FAIL_CLOSED")
    try:modify({**args,DEFINITION:d.replace("    ],","        { ID: 240 },\n    ],",1)})
    except ValueError:pass
    else:raise AssertionError("COMMAND_COLLISION_MISSED")
    print("PINNED_HERDSMAN_INPROCESS_OWNER_PATCH_SELFTEST_PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    if a.selftest:selftest()
    if a.source or a.out:
        if not(a.source and a.out):raise ValueError("SOURCE_OUT_PAIR_REQUIRED")
        print(json.dumps(stage(a.source,a.out),sort_keys=True))

if __name__=="__main__":main()
