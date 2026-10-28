"""Guard-only versioned HA deployment; never touches Z2M or CC2652.

Requires green exact-SHA GitHub runners and the current guard to be disabled.
Run on authorized Windows host with gh, git, scp, ssh and Python 3.12.
Explicitly does not enable real alerts or physical recovery.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path("C:/Workspace/worktrees/zigbee-p7u-recovery-finalize-20261022")
ARTIFACTS = Path("C:/Workspace/artifacts")
VERSION = "0.2.3"
MODULES = ("policy.py", "executor.py", "persistence.py", "ha_adapter.py",
           "observer.py", "mqtt_settings.py", "alerts.py", "forensics.py", "run.py")
SLUG = "local_p7u_recovery"
Z2M = "45df7312_zigbee2mqtt"


def cmd(argv: list[str], *, timeout: int = 70, input_text: str | None = None) -> str:
    p = subprocess.run(argv, capture_output=True, text=True,
                       input=input_text, timeout=timeout)
    if p.returncode:
        raise RuntimeError("COMMAND_FAILED " + " ".join(argv[:3]) + " rc=" + str(p.returncode)
                           + " " + p.stderr[-450:])
    return p.stdout


def ssh(script: str, *, timeout: int = 60) -> str:
    return cmd(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                "ha", "python3", "-"], input_text=script, timeout=timeout)


def preflight():
    return ssh("""
import subprocess,json
for slug in ('45df7312_zigbee2mqtt','local_p7u_recovery'):
  data=json.loads(subprocess.check_output(['ha','apps','info',slug,'--raw-json']))['data']
  assert data['state']=='started', 'ADDON_NOT_STARTED_'+slug
  if slug=='local_p7u_recovery':
    opts=data['options']
    assert opts['enabled'] is False and opts['dry_run'] is True
    assert opts['serial_owner_approved'] is False
    assert opts['notify_on_confirmed_hang'] is False
    assert opts['allow_private_http_fallback'] is False
    assert data['watchdog'] is False and data['boot']=='manual'
  else:
    assert data['version']=='2.14.0-1', 'Z2M_VERSION_CHANGED'
print('PREFLIGHT_NETWORK_UNTOUCHED_AND_GUARD_UNARMED')
""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source_sha")
    args = ap.parse_args()
    sha = args.source_sha.strip().lower()
    assert len(sha) == 40 and all(c in "0123456789abcdef" for c in sha)
    assert cmd(["git","-C",str(ROOT),"rev-parse","HEAD"]).strip() == sha
    checks = json.loads(cmd(["gh","api",
        "repos/analienx/Zigbee-Coordinator/commits/"+sha+"/check-runs"]))["check_runs"]
    for check in ("Policy and one-shot journal regressions","unittest"):
        matches = [r for r in checks if r.get("name")==check]
        assert matches and all(r.get("conclusion")=="success" for r in matches), check
    preflight()
    output = ARTIFACTS / ("p7u-guard-023-" + sha[:12])
    package = output / "p7u_recovery"
    package.mkdir(parents=True,exist_ok=False)
    paths = {("host/recovery/"+name):name for name in MODULES}
    paths.update({("host/recovery/addon/"+name):name
                  for name in ("config.yaml","Dockerfile","README.md")})
    hashes = {}
    for gitpath,name in paths.items():
        data=subprocess.check_output(["git","-C",str(ROOT),"show",sha+":"+gitpath])
        (package/name).write_bytes(data)
        hashes[name]=hashlib.sha256(data).hexdigest()
    assert 'version: "'+VERSION+'"' in (package/"config.yaml").read_text()
    assert ("COPY " in (package/"Dockerfile").read_text()
            and "forensics.py" in (package/"Dockerfile").read_text())
    cmd(["scp","-o","BatchMode=yes","-o","ConnectTimeout=8","-r",
         "ha:/addons/local/p7u_recovery",str(output/"old-p7u_recovery")],timeout=100)
    (output/"reviewed-receipt.json").write_text(json.dumps({
        "source_sha":sha,"version":VERSION,"modules":hashes,
        "old_addon_copy":"old-p7u_recovery",
        "physical_recovery":False,"alerts":False},indent=2))
    cmd(["scp","-o","BatchMode=yes","-o","ConnectTimeout=8","-r",
         str(package),"ha:/addons/local/"],timeout=90)
    ssh("import hashlib\nfrom pathlib import Path\n"
        "expected="+repr(hashes)+"\n"
        "for name,digest in expected.items():\n"
        " assert hashlib.sha256((Path('/addons/local/p7u_recovery')/name).read_bytes()).hexdigest()==digest\n"
        "print('REMOTE_EXACT_SOURCE_STAGED')\n")
    ssh("import subprocess\n"
        "subprocess.run(['ha','store','reload','--raw-json'],check=True,timeout=80,"
        "capture_output=True)\nprint('STORE_RELOADED')\n",timeout=100)
    preflight()
    # This is a guard-only HA lifecycle operation. No command targets Z2M.
    ssh("""
import subprocess,json
def cli(verb):
 r=subprocess.run(['ha','apps',verb,'local_p7u_recovery','--raw-json'],
   capture_output=True,text=True,timeout=300)
 if r.returncode:raise RuntimeError('GUARD_'+verb+'_FAILED '+r.stderr[-350:])
 print('GUARD_ONLY_'+verb+'_ACCEPTED')
cli('stop')
installed=json.loads(subprocess.check_output(
 ['ha','apps','info','local_p7u_recovery','--raw-json']))['data']['version']
cli('update' if installed!='0.2.3' else 'rebuild')
info=json.loads(subprocess.check_output(
 ['ha','apps','info','local_p7u_recovery','--raw-json']))['data']
assert info['version']=='0.2.3' and info['options']['enabled'] is False
assert info['options']['notify_on_confirmed_hang'] is False
cli('start')
print('GUARD_023_STARTED_NOT_ARMED')
""",timeout=760)
    ssh("import subprocess,hashlib,json\nfrom pathlib import Path\n"
        "expected="+repr({k:hashes[k] for k in MODULES})+"\n"
        "p=subprocess.run(['docker','exec','app_local_p7u_recovery','python3','-c',"
        "'import hashlib;from pathlib import Path; print(\"MODULE_READY\")'],capture_output=True)\n"
        "assert p.returncode==0\n"
        "for n,h in expected.items():\n"
        " output=subprocess.check_output(['docker','exec','app_local_p7u_recovery','sha256sum','/app/'+n]).decode()\n"
        " assert output.split()[0]==h,n\n"
        "assert json.loads(subprocess.check_output(['ha','apps','info','45df7312_zigbee2mqtt','--raw-json']))['data']['state']=='started'\n"
        "print('GUARD_MODULES_VERIFIED_Z2M_STILL_RUNNING')\n",timeout=80)
    (output/"deployed.json").write_text(json.dumps({
        "source_sha":sha,"version":VERSION,"state":"GUARD_ONLY_DEPLOYED_UNARMED",
        "hosted_checks":"green","actual_radio_recovery":"NOT_TESTED"},indent=2))
    print("DEPLOYED_GUARD_ONLY",output/"deployed.json")


if __name__ == "__main__":
    main()
