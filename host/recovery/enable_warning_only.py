"""Versioned HA warning-only enablement: never arms physical recovery.

Use from Windows where 'ssh ha' reaches the authorized Home Assistant host:
    python host/recovery/enable_warning_only.py
Does not touch Zigbee2MQTT, serial, flash, coordinator, or watchdog resets.
The only changed option is notify_on_confirmed_hang. Idempotent.
"""
from __future__ import annotations
import subprocess

CODE = r'''
import json,os,urllib.request
headers={"Authorization":"Bearer "+os.environ["SUPERVISOR_TOKEN"],
         "Content-Type":"application/json"}
def read(path, options=None):
    request=urllib.request.Request(
        "http://supervisor"+path, headers=headers,
        data=None if options is None else json.dumps(options).encode("utf-8"),
        method="GET" if options is None else "POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)
guard=read("/addons/local_p7u_recovery/info")["data"]
z2m=read("/addons/45df7312_zigbee2mqtt/info")["data"]
assert guard["state"]=="started" and guard["version"]=="0.2.3"
assert z2m["state"]=="started" and z2m["version"]=="2.14.0-1"
assert guard["watchdog"] is False and z2m["watchdog"] is False
opt=guard["options"]
assert opt["enabled"] is False and opt["dry_run"] is True
assert opt["serial_owner_approved"] is False
assert opt["allow_private_http_fallback"] is False
assert opt["firmware_flash_active"] is False
if opt["notify_on_confirmed_hang"] is True:
    print("ALREADY_WARNING_ONLY_NO_RESET")
else:
    assert opt["notify_on_confirmed_hang"] is False
    update=dict(opt)
    update["notify_on_confirmed_hang"]=True
    assert read("/addons/local_p7u_recovery/options",{"options":update})["result"]=="ok"
after=read("/addons/local_p7u_recovery/info")["data"]
assert after["state"]=="started"
assert after["options"]=={**opt,"notify_on_confirmed_hang":True}
assert read("/addons/45df7312_zigbee2mqtt/info")["data"]["state"]=="started"
print("CONFIRMED_WARNINGS_ENABLED_ACTIVE_RESETS_DISABLED")
'''


def main():
    # The token stays inside the running guard container and is not
    # included in subprocess arguments, stdout, repository or artifacts.
    remote = (
        "import subprocess\n"
        "p=subprocess.run(['docker','exec','-i','app_local_p7u_recovery',"
        "'python3','-c',"+repr(CODE)+"],capture_output=True,text=True,timeout=75)\n"
        "if p.returncode: raise RuntimeError('WARNING_CONFIG_REFUSED '+p.stderr[-200:])\n"
        "print(p.stdout)\n"
    )
    p=subprocess.run(["ssh","-o","BatchMode=yes","-o","ConnectTimeout=8",
        "ha","python3","-"],input=remote,capture_output=True,text=True,timeout=90)
    if p.returncode:
        raise SystemExit("GUARD_WARNING_ACTIVATION_FAILED; no restart or reset attempted: "+
                         p.stderr[-300:])
    print(p.stdout.strip())


if __name__=="__main__":
    main()
