#!/usr/bin/env python3
"""One-shot incident escalation: ESP restart AFTER documented radio reset.

DOES NOT reset radio, erase NV, open serial, restore, flash, start Zigbee2MQTT
or change any device configuration. The existing incident and HOLD history are
immutable. Runs in the existing HA host via SSH; local machine holds no tokens.
"""
from __future__ import annotations
import argparse
import subprocess
import hashlib
import json

REMOTE = r'''
import hashlib,json,os,pathlib,subprocess,sys,urllib.request,datetime
mode=sys.argv[1]; approved=sys.argv[2] if len(sys.argv)>2 else ""
INCIDENT="b2660c9538f540b295896864ed178210"
ROOT=pathlib.Path("/share/p7u-lifecycle/private/source-3921b7923025")
RECEIPT=ROOT/"native-post-radio-esp-only.intent.json"
TARGET="button.slzb_06p7u_core_restart"
RADIO="button.slzb_06p7u_zigbee_restart"
PORT="/dev/serial/by-id/usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00"
EXPECTED_MAC="70:af:09:a5:dc:30"
BASE="http://supervisor"
def inspect(path):
    req=urllib.request.Request(BASE+path,headers={"Authorization":"Bearer "+os.environ["SUPERVISOR_TOKEN"]})
    with urllib.request.urlopen(req,timeout=12) as r:
        if r.status!=200:raise RuntimeError("HA_HTTP_BAD_STATUS")
        return json.load(r)
def single(array,field,value):
    match=[x for x in array if x.get(field)==value]
    if len(match)!=1:raise RuntimeError("UNIQUE_REGISTRY_ENTRY_REQUIRED")
    return match[0]
def get_reg(name,key):
    path=pathlib.Path("/homeassistant/.storage")/name
    if path.is_symlink() or path.stat().st_size>8000000:raise RuntimeError("REGISTRY_UNSAFE")
    return json.loads(path.read_text())["data"][key]
if not ROOT.is_dir() or ROOT.is_symlink():raise RuntimeError("OLD_INCIDENT_NOT_PRESENT")
for name in ("native-radio-fallback.intent.json","native-original-final-start.intent.json",
             "manual-esp-restart.intent.json","native-final-warning.intent.json"):
    data=json.loads((ROOT/name).read_text())
    if data.get("incident_id")!=INCIDENT:raise RuntimeError("HISTORY_INCIDENT_MISMATCH")
if RECEIPT.exists() or RECEIPT.is_symlink():
    raise RuntimeError("POST_RADIO_ESP_INTENT_ALREADY_EXISTS_NO_REPLAY")
owner=inspect("/addons/45df7312_zigbee2mqtt/info")["data"]
guard=inspect("/addons/local_p7u_recovery/info")["data"]
opts=guard.get("options",{})
if (owner.get("state")!="error" or owner.get("watchdog") is not False
    or owner.get("boot")!="manual"):raise RuntimeError("ZIGBEE_OWNER_NOT_QUIESCED")
if (opts.get("enabled") is not False or opts.get("dry_run") is not True
    or opts.get("serial_owner_approved") is not False or
    opts.get("allow_private_http_fallback") is not False
    or opts.get("maintenance") is True or opts.get("firmware_flash_active") is True):
    raise RuntimeError("RECOVERY_GUARD_NOT_PASSIVE")
if (opts.get("esp_restart_entity")!=TARGET or
    opts.get("zigbee_restart_entity")!=RADIO):raise RuntimeError("NATIVE_BINDING_CHANGED")
serial=(owner.get("options") or {}).get("serial") or {}
if (serial.get("port")!=PORT or serial.get("adapter")!="zstack" or
    serial.get("baudrate")!=115200 or serial.get("rtscts") is not False or
    ((owner.get("options") or {}).get("socat") or {}).get("enabled") is not False):
    raise RuntimeError("SERIAL_CONFIG_CHANGED")
port=pathlib.Path(PORT)
if not port.exists() or port.resolve()!=pathlib.Path("/dev/ttyACM0"):
    raise RuntimeError("SERIAL_IDENTITY_DISAPPEARED")
holder=subprocess.run(["fuser","/dev/ttyACM0"],capture_output=True,text=True,timeout=8)
if holder.returncode not in (1,) or holder.stdout.strip():
    raise RuntimeError("SERIAL_IN_USE_OR_INSPECTION_UNKNOWN")
with urllib.request.urlopen("http://192.168.50.59/ha_info",timeout=6) as r:
    info=json.load(r)["Info"]
if (str(info.get("MAC","")).lower()!=EXPECTED_MAC or
    info.get("model")!="SLZB-06p7U" or info.get("zb_hw")!="CC2652P7" or
    info.get("sw_version")!="v3.4.3.dev1" or info.get("coord_mode")!=2):
    raise RuntimeError("WRONG_COORDINATOR")
entry=single(get_reg("core.config_entries","entries"),"entry_id","01M5N792N9YAY9BFQT972WPQ3J")
if (entry.get("domain")!="smlight" or
    (entry.get("data") or {}).get("host")!="192.168.50.59"):
    raise RuntimeError("SMLIGHT_INTEGRATION_CHANGED")
entity=single(get_reg("core.entity_registry","entities"),"entity_id",TARGET)
dev=single(get_reg("core.device_registry","devices"),"id",entity.get("device_id"))
if (entity.get("platform")!="smlight" or
    entity.get("unique_id")!=EXPECTED_MAC+"-core_restart" or
    entity.get("config_entry_id")!=entry["entry_id"] or
    entity.get("disabled_by") is not None or
    ["mac",EXPECTED_MAC] not in dev.get("connections",[]) or
    (dev.get("config_entry_id")!=entry["entry_id"] and
     entry["entry_id"] not in dev.get("config_entries",[]))):
    raise RuntimeError("NATIVE_BUTTON_IDENTITY_MISMATCH")
state=inspect("/core/api/states/"+TARGET)
if state.get("entity_id")!=TARGET or state.get("state")=="unavailable":
    raise RuntimeError("NATIVE_ESP_BUTTON_UNAVAILABLE")
report={"operation":"once_esp_after_native_radio_and_failed_zdo",
        "incident_id":INCIDENT,"guard_version":guard.get("version"),
        "last_recovery":"stateChangeInd_60000ms","core_button":TARGET,
        "target_mac":EXPECTED_MAC,"mode":"USB","owner_state":"error",
        "earlier_radio_intent":"native-radio-fallback.intent.json",
        "prior_original_failed_start":"native-original-final-start.intent.json"}
digest=hashlib.sha256(json.dumps(report,sort_keys=True,separators=(",",":")).encode()).hexdigest()
print(json.dumps({"event":"ESP_FOLLOWUP_PLAN","sha256":digest,**report},sort_keys=True),flush=True)
if mode=="plan":sys.exit(0)
if mode!="apply" or approved!=digest:raise RuntimeError("PLAN_HASH_NOT_MATCHED")
body={"incident_id":INCIDENT,"operation":report["operation"],
      "plan_sha256":digest,"target":TARGET,
      "utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
      "status":"INTENT_BEFORE_SINGLE_HA_BUTTON_PRESS"}
with RECEIPT.open("x",encoding="utf-8") as f:
    json.dump(body,f,sort_keys=True)
    f.flush();os.fsync(f.fileno())
print(json.dumps({"event":"ONE_SHOT_INTENT_DURABLE","incident_id":INCIDENT}),flush=True)
req=urllib.request.Request(BASE+"/core/api/services/button/press",method="POST",
    headers={"Authorization":"Bearer "+os.environ["SUPERVISOR_TOKEN"],
             "Content-Type":"application/json"},
    data=json.dumps({"entity_id":TARGET}).encode())
try:
    with urllib.request.urlopen(req,timeout=14) as r:
        ack={"status":r.status,"json_array":isinstance(json.load(r),list)}
    print(json.dumps({"event":"ESP_NATIVE_PRESS_ACK","ack":ack}),flush=True)
except Exception as e:
    print(json.dumps({"event":"ESP_NATIVE_PRESS_AMBIGUOUS_NO_RETRY",
                      "error_class":type(e).__name__}),flush=True)
    sys.exit(2)
'''
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("plan","apply"))
    p.add_argument("--expected-plan-hash",default="")
    a=p.parse_args()
    if a.mode=="apply" and (len(a.expected_plan_hash)!=64 or
                             any(c not in "0123456789abcdef" for c in a.expected_plan_hash)):
        p.error("apply requires the exact SHA-256 plan")
    cmd=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=8","ha","python3","-",a.mode,a.expected_plan_hash]
    proc=subprocess.run(cmd,input=REMOTE,text=True,capture_output=True,timeout=110)
    if proc.returncode:
        raise SystemExit("ESCALATION_BLOCKED: "+proc.stderr[-450:]+proc.stdout[-600:])
    print(proc.stdout,end="")
if __name__=="__main__":main()
