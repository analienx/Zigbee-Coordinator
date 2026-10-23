#!/usr/bin/env python3
"""Bind *only* the native SMLIGHT restart buttons in an unarmed P7U HA guard.

On Zephyrus: python host/recovery/bind_native_controls.py plan
Then: python host/recovery/bind_native_controls.py apply --expected-plan-hash <hash>

No restart, Zigbee2MQTT mutation, firmware action or private SMLIGHT reset.
The guard remains warning-only: enabled=false / dry_run=true / owner_approval=false.
"""
from __future__ import annotations
import argparse
import json
import subprocess

CORE = "button.slzb_06p7u_core_restart"
RADIO = "button.slzb_06p7u_zigbee_restart"
SLUG = "local_p7u_recovery"
Z2M = "45df7312_zigbee2mqtt"
LAN = "http://192.168.50.59"

# This program is executed inside the HA SSH add-on: SUPERVISOR_TOKEN never
# crosses SSH stdout or argv, and no credential is accepted from the caller.
REMOTE = r'''
import hashlib,json,os,pathlib,sys,urllib.request
mode=sys.argv[1]
expected=sys.argv[2]
slug="local_p7u_recovery"
core="button.slzb_06p7u_core_restart"
radio="button.slzb_06p7u_zigbee_restart"
headers={"Authorization":"Bearer "+os.environ["SUPERVISOR_TOKEN"],"Content-Type":"application/json"}
def api(path,data=None):
    assert path.startswith("/") and ".." not in path
    req=urllib.request.Request("http://supervisor"+path,
        headers=headers,method="POST" if data is not None else "GET",
        data=None if data is None else json.dumps(data,sort_keys=True).encode())
    with urllib.request.urlopen(req,timeout=18) as r:
        if r.status != 200:raise RuntimeError("SUPERVISOR_HTTP_NOT_200")
        return json.load(r)
def registry(name,key):
    path=pathlib.Path("/homeassistant/.storage")/name
    if path.is_symlink() or path.stat().st_size>8000000:
        raise RuntimeError("UNSAFE_REGISTRY")
    value=json.loads(path.read_text())["data"][key]
    if not isinstance(value,list):raise RuntimeError("REGISTRY_SHAPE")
    return value
guard=api("/addons/"+slug+"/info")["data"]
z2m=api("/addons/45df7312_zigbee2mqtt/info")["data"]
old=dict(guard["options"])
if guard.get("version")!="0.2.3" or guard.get("state")!="started":
    raise RuntimeError("GUARD_VERSION_OR_STATE_CHANGED")
if guard.get("watchdog") is not False or guard.get("boot")!="manual":
    raise RuntimeError("GUARD_WATCHDOG_OR_BOOT_CHANGED")
if (old.get("enabled") is not False or old.get("dry_run") is not True or
    old.get("serial_owner_approved") is not False or
    old.get("allow_private_http_fallback") is not False):
    raise RuntimeError("GUARD_NOT_SAFE_WARNING_ONLY")
if z2m.get("slug")!="45df7312_zigbee2mqtt":
    raise RuntimeError("UNEXPECTED_ZIGBEE_OWNER")
if z2m.get("watchdog") is not False:
    raise RuntimeError("ZIGBEE_WATCHDOG_ACTIVE")
opts=z2m.get("options") or {}
serial=opts.get("serial") or {}
if (serial.get("adapter")!="zstack" or
    not str(serial.get("port","")).endswith("SLZB-06p7U115236-if00") or
    (opts.get("socat") or {}).get("enabled") is not False):
    raise RuntimeError("ZIGBEE_OWNER_USB_SERIAL_MISMATCH")
with urllib.request.urlopen("http://192.168.50.59/ha_info",timeout=8) as r:
    info=json.load(r)["Info"]
if (info.get("model")!="SLZB-06p7U" or info.get("zb_hw")!="CC2652P7"
    or info.get("coord_mode")!=2 or info.get("sw_version")!=old.get("expected_sw_version")):
    raise RuntimeError("SLZB_WRONG_MODEL_MODE_OR_FIRMWARE")
mac=str(info.get("MAC","")).lower()
if not mac or mac!=str(old.get("expected_mac","")).lower():
    raise RuntimeError("SLZB_WRONG_MAC")
entries=registry("core.config_entries","entries")
matched=[e for e in entries if e.get("domain")=="smlight"
    and e.get("unique_id")==mac and (e.get("data") or {}).get("host")=="192.168.50.59"
    and e.get("source")=="user"]
if len(matched)!=1:raise RuntimeError("NATIVE_SMLIGHT_CONFIG_ENTRY_NOT_UNIQUE")
entry=matched[0]["entry_id"]
entities=registry("core.entity_registry","entities")
devices=registry("core.device_registry","devices")
for entity_id,suffix in ((core,"core_restart"),(radio,"zigbee_restart")):
    e=[x for x in entities if x.get("entity_id")==entity_id]
    if (len(e)!=1 or e[0].get("platform")!="smlight" or
        e[0].get("unique_id")!=mac+"-"+suffix or
        e[0].get("config_entry_id")!=entry or e[0].get("disabled_by") is not None):
        raise RuntimeError("NATIVE_BUTTON_IDENTITY_MISMATCH")
    d=[x for x in devices if x.get("id")==e[0].get("device_id")]
    if len(d)!=1 or ["mac",mac] not in d[0].get("connections",[]):
        raise RuntimeError("NATIVE_DEVICE_MAC_MISMATCH")
    if d[0].get("config_entry_id")!=entry and entry not in d[0].get("config_entries",[]):
        raise RuntimeError("NATIVE_DEVICE_ENTRY_MISMATCH")
    state=api("/core/api/states/"+entity_id)
    if state.get("entity_id")!=entity_id or state.get("state")=="unavailable":
        raise RuntimeError("NATIVE_BUTTON_UNAVAILABLE")
if old.get("esp_restart_entity") not in ("",core) or old.get("zigbee_restart_entity") not in ("",radio):
    raise RuntimeError("UNEXPECTED_PREEXISTING_BINDING")
new=dict(old)
new["esp_restart_entity"]=core
new["zigbee_restart_entity"]=radio
plan={"operation":"bind_native_smlight_buttons_warning_only",
      "guard_version":"0.2.3","guard_enabled":False,
      "guard_dry_run":True,"private_fallback":False,
      "entry_id":entry,"slzb_model":"SLZB-06p7U",
      "old_core":old["esp_restart_entity"],"old_zigbee":old["zigbee_restart_entity"],
      "new_core":core,"new_zigbee":radio}
hashval=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(",",":")).encode()).hexdigest()
print(json.dumps({"event":"NATIVE_BIND_PLAN","plan_hash":hashval,**plan},sort_keys=True),flush=True)
if mode=="plan":sys.exit(0)
if mode!="apply" or expected!=hashval:raise RuntimeError("PLAN_HASH_MISMATCH")
if old != new:
    response=api("/addons/"+slug+"/options",{"options":new})
    if response.get("result")!="ok":raise RuntimeError("HA_OPTIONS_UPDATE_FAILED")
after=api("/addons/"+slug+"/info")["data"]
if after.get("options")!=new:
    raise RuntimeError("NATIVE_BIND_READBACK_MISMATCH")
if (after.get("options",{}).get("enabled") is not False or
    after.get("options",{}).get("dry_run") is not True):
    raise RuntimeError("RECOVERY_UNEXPECTEDLY_ARMED")
print(json.dumps({"event":"NATIVE_BUTTONS_BOUND","applied":old!=new,
                   "guard_unarmed":True,"core":core,"zigbee":radio}),flush=True)
'''


def run(mode: str, expected: str) -> None:
    p = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
         "ha", "python3", "-", mode, expected],
        input=REMOTE, capture_output=True, text=True, timeout=110,
    )
    if p.returncode:
        raise SystemExit("NATIVE_BIND_BLOCKED: " + p.stderr[-300:])
    print(p.stdout, end="")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "apply"))
    parser.add_argument("--expected-plan-hash", default="")
    a = parser.parse_args()
    if a.mode == "apply" and (len(a.expected_plan_hash) != 64 or
                              any(x not in "0123456789abcdef" for x in a.expected_plan_hash)):
        parser.error("apply requires exact fresh 64-character SHA-256 plan hash")
    run(a.mode, a.expected_plan_hash)


if __name__ == "__main__":
    main()
