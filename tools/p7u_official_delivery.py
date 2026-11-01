#!/usr/bin/env python3
"""End-to-end P7U firmware delivery with the official Zigbee2MQTT app as owner.

Wraps tools/p7u_ha_flash_driver.py (which wraps the sealed HA operator) so a
delivery is a handful of commands. It adds no new radio, NV or flash path:

  preflight   READ-ONLY. GitHub runs, HA owner/serial/automation/button state,
              predecessor operation, backup size. Exit 0 only with no BLOCK.
  automation  off|on the boot-time Z2M automation the operator requires OFF
              for the flash window (a reversible HA setting, recorded).
  prepare     driver fetch + stage + plan. Read-only admission: Z2M keeps
              running; prints the operation id the flash must be authorized for.
  flash       --authorize <operation id>: deploy -> boot -> (finish) -> serving.
              Stops Z2M (household Zigbee outage for the window), ONE protected
              APP+AC000 write, ONE native boot, Z2M start, MQTT serving check.
              Every step is once-only; nothing is retried or rolled back here.
  status      read-only operation status.

Defaults pin the V54 delivery over the installed V53 operation.
"""
import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host" / "flash"))
import p7u_paired_binding as binding  # noqa: E402

REPO = "analienx/Zigbee-Coordinator"
DRIVER = ROOT / "tools" / "p7u_ha_flash_driver.py"
DEFAULTS = {"firmware": "20a2474a67c1d420b6614b3fcb2f7ed543b1420e",
            "installed": "8ec1439786e3e98151d2796e6797675bb9ef5965",
            "previous_operation": "b66de81f093ee1556fc870831e10490c",
            "native_run": "41284426604"}
BOOT_AUTOMATION = "automation.boot_deterministic_emqx_then_zigbee2mqtt"
SERIAL = "/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00"

# Runs on HA (SSH app, Supervisor token in env). Reads only; the serial scan is
# a --rm, --network none container of the already-pinned owner image.
REMOTE_PREFLIGHT = r'''
import json,os,subprocess,urllib.request
from pathlib import Path
O=json.loads(%(cfg)r);out=[]
def add(name,ok,detail,level="BLOCK"):out.append({"check":name,"result":"PASS" if ok else level,"detail":detail})
def api(path):
 q=urllib.request.Request("http://supervisor/"+path,headers={"Authorization":"Bearer "+os.environ["SUPERVISOR_TOKEN"]})
 return json.load(urllib.request.urlopen(q,timeout=15))
def info(slug):
 try:return api("addons/"+slug+"/info")["data"]
 except Exception:return None
a=info(O["owner"]) or {}
add("owner app pinned",a.get("version")==O["version"] and a.get("boot")=="manual" and a.get("watchdog") is False and a.get("auto_update") is False,
    {k:a.get(k) for k in ("state","version","boot","watchdog","auto_update")})
for s in ("local_p7u_r4_native_host","local_p7u_r4_fallback","local_p7u_r4_owner_inspector"):
 b=info(s)
 add("retired app "+s+" cannot start",b is None or b.get("installed") is False or (b.get("state") in ("stopped","error") and b.get("boot")=="manual"),
     None if b is None else {k:b.get(k) for k in ("installed","state","boot")})
try:c=json.loads(subprocess.check_output(["docker","inspect","app_"+O["owner"]]))[0]
except Exception:c=None
add("owner container image",c is not None and c["Image"]==O["image"],None if c is None else {"running":c["State"]["Running"],"image":c["Image"][:19]})
tty=os.path.realpath(O["serial"])
scan=subprocess.run(["docker","run","--rm","--pid=host","--privileged","--network","none","--entrypoint","sh",O["image"],"-c",O["scan"]],capture_output=True,text=True,timeout=90)
holders=[l.split() for l in scan.stdout.splitlines() if len(l.split())==4 and l.split()[2]==tty]
add("serial held only by owner",scan.returncode==0 and c is not None and holders and all(h[3]==c["Id"] for h in holders),
    {"tty":tty,"holders":[(h[0],h[1],h[3][:12]) for h in holders]})
for e,want,level in ((O["boot_automation"],"off","BLOCK"),("automation.zigbee2mqtt_mesh_communication_outage_alert","off","BLOCK"),
                     ("button.slzb_06p7u_zigbee_restart","available","BLOCK")):
 try:st=api("core/api/states/"+e)["state"]
 except Exception as x:st="ERROR "+type(x).__name__
 add(e+" "+want,st!="unavailable" and not st.startswith("ERROR") if want=="available" else st==want,st,level)
op=Path("/share/p7u-r4-firmware-operations")/O["previous_operation"]
try:
 p=json.loads((op/"plan.json").read_text());w=json.loads((op/"verified-write.json").read_text())
 ok=p.get("source")==O["installed"] and w["result"]["status"]=="APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL"
except Exception as x:ok=False;w={"error":type(x).__name__}
add("predecessor operation verified write",ok,O["previous_operation"])
for d in ("/share/p7u-paired-input-"+O["installed"][:12],"/share/p7u-paired-stage-"+O["installed"][:12],"/share/p7u-lifecycle/private/exclusive-manager.lock"):
 add("exists "+d,os.path.exists(d),None)
try:
 b=json.load(open("/homeassistant/zigbee2mqtt/coordinator_backup.json"));n=len(b.get("devices",[]))
except Exception:n=-1
add("backup peers within %%d..%%d"%%(O["min"],O["max"]),O["min"]<=n<=O["max"],n)
try:
 h=urllib.request.build_opener(urllib.request.ProxyHandler({})).open("http://192.168.50.59/ha_info",timeout=8)
 i=json.load(h)["Info"];add("SLZB management reachable",i.get("model")=="SLZB-06p7U" and i.get("zb_hw")=="CC2652P7",{"model":i.get("model"),"zb_hw":i.get("zb_hw")})
except Exception as x:add("SLZB management reachable",False,type(x).__name__)
print(json.dumps(out))
'''

REMOTE_AUTOMATION = r'''
import json,os,urllib.request
e=%(entity)r;svc=%(svc)r
def call(path,payload=None):
 q=urllib.request.Request("http://supervisor/core/api/"+path,data=None if payload is None else json.dumps(payload).encode(),
   headers={"Authorization":"Bearer "+os.environ["SUPERVISOR_TOKEN"],"Content-Type":"application/json"},method="GET" if payload is None else "POST")
 return json.load(urllib.request.urlopen(q,timeout=20))
before=call("states/"+e)["state"]
if svc:call("services/automation/"+svc,{"entity_id":e})
print(json.dumps({"entity":e,"before":before,"after":call("states/"+e)["state"]}))
'''


def ssh_python(code, timeout=180):
    # Script on stdin: Windows argv quoting would otherwise rewrite \" sequences.
    run = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "ha", "python3 -B -"],
                         input=code, capture_output=True, text=True, timeout=timeout)
    if run.returncode:
        sys.exit("HA_PYTHON_FAILED rc=%d\n%s\n%s" % (run.returncode, run.stdout[-1500:], run.stderr[-1500:]))
    return json.loads(run.stdout.strip().splitlines()[-1])


def gh_run(run_id):
    out = subprocess.run(["gh", "api", "repos/%s/actions/runs/%s" % (REPO, run_id)],
                         capture_output=True, text=True, timeout=60)
    return json.loads(out.stdout) if out.returncode == 0 else {}


def driver(workdir, *args):
    cmd = [sys.executable, "-B", str(DRIVER)] + list(args[:1]) + ["--workdir", str(workdir)] + list(args[1:])
    print("\n$ " + " ".join(shlex.quote(str(c)) for c in cmd), flush=True)
    return subprocess.run(cmd).returncode


def state(workdir):
    p = Path(workdir) / "state.json"
    return json.loads(p.read_text()) if p.exists() else {}


def run_preflight(a):
    checks = []
    native = gh_run(a.native_run)
    checks.append({"check": "native run exact success", "result": "PASS" if (
        native.get("head_sha") == a.firmware and native.get("conclusion") == "success" and
        native.get("path") == ".github/workflows/test-r4-stock20260311-native.yml") else "BLOCK",
        "detail": {"run": a.native_run, "sha": native.get("head_sha", "")[:12], "conclusion": native.get("conclusion")}})
    if a.package_run:
        pkg = gh_run(a.package_run)
        checks.append({"check": "operator package run", "result": "PASS" if (
            pkg.get("conclusion") == "success" and pkg.get("event") == "workflow_dispatch" and
            pkg.get("path") == ".github/workflows/package-p7u-paired-operator.yml") else "BLOCK",
            "detail": {"run": a.package_run, "sha": pkg.get("head_sha", "")[:12], "conclusion": pkg.get("conclusion")}})
    else:
        checks.append({"check": "operator package run", "result": "BLOCK", "detail": "pass --package-run"})
    checks.append({"check": "firmware qualified for official owner",
                   "result": "PASS" if a.firmware in binding.OFFICIAL_SOURCES and
                   binding.QUALIFIED_SUCCESSORS.get(a.firmware) == a.installed else "BLOCK",
                   "detail": {"firmware": a.firmware[:12], "installed": a.installed[:12]}})
    sys.path.insert(0, str(ROOT / "host" / "flash"))
    scan = _operator_constant("SERIAL_SCAN")
    lo, hi = _operator_constant("PEERS_MIN"), _operator_constant("PEERS_MAX")
    cfg = {"owner": binding.OFFICIAL_OWNER, "version": binding.OFFICIAL_OWNER_VERSION,
           "image": binding.OFFICIAL_OWNER_IMAGE, "serial": SERIAL, "scan": scan,
           "boot_automation": BOOT_AUTOMATION, "previous_operation": a.previous_operation,
           "installed": a.installed, "min": lo, "max": hi}
    checks += ssh_python(REMOTE_PREFLIGHT % {"cfg": json.dumps(cfg)})
    width = max(len(c["check"]) for c in checks)
    for c in checks:
        print("%-5s  %-*s  %s" % (c["result"], width, c["check"], json.dumps(c["detail"])))
    blocks = [c["check"] for c in checks if c["result"] == "BLOCK"]
    print("\nPREFLIGHT " + ("READY" if not blocks else "BLOCKED: " + "; ".join(blocks)))
    return 1 if blocks else 0


def _operator_constant(name):
    """Read a literal constant from the sealed operator without importing it (it needs fcntl)."""
    import ast
    tree = ast.parse((ROOT / "host/flash/p7u_pr154_ha.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return ast.literal_eval(node.value)
                if isinstance(t, ast.Tuple) and name in [e.id for e in t.elts]:
                    return ast.literal_eval(node.value)[[e.id for e in t.elts].index(name)]
    raise KeyError(name)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("phase", choices=("preflight", "automation", "prepare", "flash", "status"))
    p.add_argument("value", nargs="?", help="automation: off|on")
    p.add_argument("--workdir", default=str(Path.home() / ".p7u-deliveries" / "v54-official"))
    p.add_argument("--package-run")
    p.add_argument("--authorize", help="flash: the operation id printed by prepare")
    for k, v in DEFAULTS.items():
        p.add_argument("--" + k.replace("_", "-"), default=v)
    a = p.parse_args()
    work = Path(a.workdir)
    if a.phase == "preflight":
        return run_preflight(a)
    if a.phase == "automation":
        if a.value not in ("off", "on"):
            sys.exit("automation off|on")
        r = ssh_python(REMOTE_AUTOMATION % {"entity": BOOT_AUTOMATION, "svc": "turn_" + a.value})
        work.mkdir(parents=True, exist_ok=True)
        with (work / "automation-log.jsonl").open("a") as f:
            f.write(json.dumps(r) + "\n")
        print(json.dumps(r))
        return 0 if r["after"] == a.value else 1
    if a.phase == "status":
        return driver(work, "status")
    if a.phase == "prepare":
        if not a.package_run:
            sys.exit("prepare needs --package-run (official-z2m operator package)")
        if run_preflight(a):
            sys.exit("PREPARE_REFUSED: preflight has BLOCK items")
        st = state(work)
        if "firmware" not in st:
            rc = driver(work, "fetch", "--firmware", a.firmware, "--installed", a.installed,
                        "--previous-operation", a.previous_operation, "--native-run", a.native_run,
                        "--package-run", a.package_run)
            if rc:
                return rc
        if "binding_pin" not in state(work):
            rc = driver(work, "stage")
            if rc:
                return rc
        if "operation_id" not in state(work):
            rc = driver(work, "plan")
            if rc:
                return rc
        st = state(work)
        print("\nPREPARED operation %s (plan expires %s). Flash with:\n  python tools/p7u_official_delivery.py "
              "flash --authorize %s --package-run %s" % (st["operation_id"], st.get("plan_expires_at"),
                                                         st["operation_id"], a.package_run))
        return 0
    if a.phase == "flash":
        st = state(work)
        if not a.authorize or a.authorize != st.get("operation_id"):
            sys.exit("FLASH_REFUSED: --authorize must equal the prepared operation id %s" % st.get("operation_id"))
        for phase in ("deploy", "boot"):
            if phase + "_intent" not in state(work):
                rc = driver(work, phase)
                if rc:
                    print("\nSTOPPED after %s rc=%d. Inspect with: python tools/p7u_official_delivery.py status" % (phase, rc))
                    return rc
        boot = state(work).get("boot_result", {}).get("status", "")
        if boot == "READY_OBSERVED_VERIFICATION_INCOMPLETE" and "finish_intent" not in state(work):
            rc = driver(work, "finish")
            if rc:
                return rc
        rc = driver(work, "serving")
        print("\nSERVING " + ("ACCEPTED" if rc == 0 else "NOT YET PROVEN (re-run `serving` via the driver; never re-flash)"))
        print("After acceptance re-enable the boot automation: python tools/p7u_official_delivery.py automation on")
        return rc


if __name__ == "__main__":
    sys.exit(main() or 0)
