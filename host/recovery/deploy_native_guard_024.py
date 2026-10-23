#!/usr/bin/env python3
"""Exact-source, guard-only SMLIGHT native binding compatibility deployment.

No Z2M lifecycle, radio/ESP commands, serial owner, registry writes or config
migration. A fresh hash plan is required. Only one local HA add-on is touched.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess

REPO = "analienx/Zigbee-Coordinator"
VERSION = "0.2.4"
GUARD = "local_p7u_recovery"
ORIGINAL = "45df7312_zigbee2mqtt"
ARTIFACTS = Path("C:/Workspace/artifacts")
MODULES = ("policy.py","executor.py","persistence.py","ha_adapter.py",
           "observer.py","mqtt_settings.py","alerts.py","forensics.py","run.py")
EXTRA = ("config.yaml","Dockerfile","README.md")
EXPECTED_CORE = "button.slzb_06p7u_core_restart"
EXPECTED_RADIO = "button.slzb_06p7u_zigbee_restart"


def run(argv, timeout=30, stdin=None):
    proc = subprocess.run(argv, input=stdin, capture_output=True,
                          text=True, timeout=timeout)
    if proc.returncode:
        raise RuntimeError("COMMAND_FAILED " + repr(argv[:3]) +
                           " exit=" + str(proc.returncode) +
                           " stderr=" + proc.stderr[-260:])
    return proc.stdout


def gh(path, sha):
    raw = run(["gh","api","--method","GET",
               "repos/"+REPO+"/contents/"+path,
               "-f","ref="+sha],timeout=20)
    obj = json.loads(raw)
    data = base64.b64decode(obj["content"])
    gitsha = hashlib.sha1(b"blob "+str(len(data)).encode()+b"\x00"+data).hexdigest()
    if gitsha != obj["sha"]:
        raise RuntimeError("SOURCE_GIT_BLOB_MISMATCH")
    return data


def git_checks_ok(sha):
    response=json.loads(run(["gh","api","repos/"+REPO+"/commits/"+sha+"/check-runs"],timeout=20))
    checks=response.get("check_runs",[])
    for name in ("Policy and one-shot journal regressions","unittest"):
        rows=[c for c in checks if c.get("name")==name]
        if not rows or any(c.get("status")!="completed" or c.get("conclusion")!="success" for c in rows):
            raise RuntimeError("EXACT_SHA_GITHUB_CHECKS_NOT_GREEN: "+name)


def ssh_python(body):
    return run(["ssh","-o","BatchMode=yes","-o","ConnectTimeout=8",
                "ha","python3","-"],stdin=body,timeout=65)


REMOTE_PREFLIGHT = r'''
import json,subprocess
data={}
for slug in ("local_p7u_recovery","45df7312_zigbee2mqtt"):
 p=subprocess.run(["ha","apps","info",slug,"--raw-json"],
    capture_output=True,text=True,timeout=15,check=True)
 data[slug]=json.loads(p.stdout)["data"]
g=data["local_p7u_recovery"]
z=data["45df7312_zigbee2mqtt"]
o=g["options"]
assert g["version"] in ("0.2.3","0.2.4") and g["state"]=="started"
assert g["boot"]=="manual" and g["watchdog"] is False
assert o["enabled"] is False and o["dry_run"] is True
assert o["serial_owner_approved"] is False and o["allow_private_http_fallback"] is False
assert o["esp_restart_entity"]=="button.slzb_06p7u_core_restart"
assert o["zigbee_restart_entity"]=="button.slzb_06p7u_zigbee_restart"
assert z["watchdog"] is False
assert z["state"] in ("started","error","stopped")
assert z["options"]["serial"]["adapter"]=="zstack"
assert str(z["options"]["serial"]["port"]).endswith("SLZB-06p7U115236-if00")
assert z["options"]["socat"]["enabled"] is False
print(json.dumps({"version":g["version"],"guard_state":g["state"],
 "guard_options":o,"z2m_state":z["state"],"z2m_version":z["version"]},
 sort_keys=True))
'''


def preflight():
    obj=json.loads(ssh_python(REMOTE_PREFLIGHT))
    if obj["guard_options"].get("notify_on_confirmed_hang") is not True:
        raise RuntimeError("WARNING_ONLY_MONITOR_NOT_CONFIGURED")
    return obj


def plan(sha):
    if len(sha)!=40 or any(c not in "0123456789abcdef" for c in sha):
        raise RuntimeError("INVALID_COMMIT_SHA")
    git_checks_ok(sha)
    now=preflight()
    paths={"host/recovery/"+m:m for m in MODULES}
    paths.update({"host/recovery/addon/"+m:m for m in EXTRA})
    hashes={target:hashlib.sha256(gh(src,sha)).hexdigest()
            for src,target in paths.items()}
    if b'version: "0.2.4"' not in gh("host/recovery/addon/config.yaml",sha):
        raise RuntimeError("WRONG_ADDON_VERSION")
    if b'BUILD_VERSION=0.2.4' not in gh("host/recovery/addon/Dockerfile",sha):
        raise RuntimeError("WRONG_BUILD_VERSION")
    p={"operation":"deploy_native_guard_024_only","source_sha":sha,
       "guard_old_version":now["version"],"guard_old_options_hash":
         hashlib.sha256(json.dumps(now["guard_options"],sort_keys=True).encode()).hexdigest(),
       "z2m_state":now["z2m_state"],"z2m_version":now["z2m_version"],
       "source_hashes":hashes}
    digest=hashlib.sha256(json.dumps(p,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return p,digest


def deploy(p):
    sha=p["source_sha"]
    target=ARTIFACTS/("p7u-native-guard-024-"+sha[:12])
    if target.exists():
        raise RuntimeError("DEPLOY_ATTEMPT_EXISTS_NO_REPEAT")
    # Receipt is created before the first external operation.
    pkg=target/"p7u_recovery"
    pkg.mkdir(parents=True,exist_ok=False)
    (target/"plan.json").write_text(json.dumps(p,indent=2))
    paths={"host/recovery/"+m:m for m in MODULES}
    paths.update({"host/recovery/addon/"+m:m for m in EXTRA})
    for src,name in paths.items():
        data=gh(src,sha)
        if hashlib.sha256(data).hexdigest()!=p["source_hashes"][name]:
            raise RuntimeError("SOURCE_CHANGED_AFTER_PLAN")
        (pkg/name).write_bytes(data)
    run(["scp","-o","BatchMode=yes","-o","ConnectTimeout=8",
         "-r","ha:/addons/local/p7u_recovery",
         str(target/"previous_p7u_recovery")],timeout=90)
    run(["scp","-o","BatchMode=yes","-o","ConnectTimeout=8",
         "-r",str(pkg),"ha:/addons/local/"],timeout=90)
    expected={x:p["source_hashes"][x] for x in MODULES+EXTRA}
    ssh_python("import pathlib,hashlib\nexpected="+repr(expected)+
     "\nfor name,h in expected.items():\n assert hashlib.sha256((pathlib.Path('/addons/local/p7u_recovery')/name).read_bytes()).hexdigest()==h,name\nprint('GUARD_SOURCE_MATCHES_EXACT_SHA')\n")
    # Only the guard is stopped/rebuilt/started. Original Z2M is untouched.
    process=r'''
import subprocess,json
def app(*args):
 p=subprocess.run(["ha","apps",*args,"--raw-json"],capture_output=True,text=True,timeout=360,check=True)
 print("GUARD_ONLY_CLI",args[0],p.returncode,flush=True)
 return json.loads(p.stdout)
app("stop","local_p7u_recovery")
app("update","local_p7u_recovery")
app("start","local_p7u_recovery")
g=app("info","local_p7u_recovery")["data"]
assert g["version"]=="0.2.4" and g["state"]=="started"
assert g["options"]["enabled"] is False and g["options"]["dry_run"] is True
assert g["options"]["esp_restart_entity"]=="button.slzb_06p7u_core_restart"
assert g["options"]["zigbee_restart_entity"]=="button.slzb_06p7u_zigbee_restart"
print("GUARD_024_STARTED_WARNING_ONLY")
'''
    ssh_python("import subprocess\np=subprocess.run(['ha','store','reload','--raw-json'],capture_output=True,text=True,timeout=90)\nassert p.returncode==0\nprint('LOCAL_STORE_RELOADED')\n")
    # The rebuild may take longer than one SSH command's default timeout.
    run(["ssh","-o","BatchMode=yes","-o","ConnectTimeout=8",
         "ha","python3","-"],stdin=process,timeout=900)
    final=preflight()
    if final["version"]!=VERSION or final["guard_options"]!=p["old_options"]:
        raise RuntimeError("GUARD_OPTION_DRIFT_AFTER_DEPLOYMENT")
    if final["z2m_state"]!=p["z2m_state"]:
        raise RuntimeError("UNEXPECTED_Z2M_STATE_CHANGE")
    (target/"receipt.json").write_text(json.dumps({
      "status":"GUARD_024_DEPLOYED_WARNING_ONLY","source_sha":sha,
      "native_buttons_bound":True,"automatic_resets":False,
      "z2m_unchanged":True},indent=2))
    print("GUARD_ONLY_024_DEPLOY_SUCCESS")


def main():
    a=argparse.ArgumentParser()
    a.add_argument("mode",choices=("plan","apply"))
    a.add_argument("--source-sha",required=True)
    a.add_argument("--expected-plan-hash",default="")
    args=a.parse_args()
    p,digest=plan(args.source_sha)
    print(json.dumps({"event":"GUARD_024_PLAN","plan_hash":digest,
                      "source_sha":p["source_sha"],"z2m_state":p["z2m_state"],
                      "guard_old_version":p["guard_old_version"]}),flush=True)
    if args.mode=="plan":return
    if digest!=args.expected_plan_hash:
        raise RuntimeError("PLAN_HASH_NOT_EXACT")
    # Preserve the entire current options object across guard-only rebuild.
    p["old_options"]=preflight()["guard_options"]
    if hashlib.sha256(json.dumps(p["old_options"],sort_keys=True).encode()).hexdigest()!=p["guard_old_options_hash"]:
        raise RuntimeError("OPTIONS_CHANGED_AFTER_PLAN")
    deploy(p)


if __name__=="__main__":
    main()
