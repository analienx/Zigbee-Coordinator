#!/usr/bin/env python3
"""Read-only diff of the P7U coordinator address-manager table.

Compares a fresh NV capture (a held operation's fresh-sparse-snapshot.bin)
with the installed baseline (installed-before.bin) using the SEALED operator
package's own reader and parser, reproduces the retained-security verdict and
classifies every changed row the way the runtime-upgrade rule sees it.

Prints IEEE addresses and Zigbee2MQTT friendly names (not secret); never
keys, seeds, counters or raw NV. No radio, service or file change.

  python tools/p7u_addrmgr_diff.py [--operation ID] [--json]
"""
import argparse
import json
import subprocess
import sys

ROOT_OPS = "/share/p7u-r4-firmware-operations"

REMOTE = r'''
import json,os,sys,tarfile,io,re
from pathlib import Path
A=json.loads(%(args)r)
ops=Path(A["ops"])
if A["operation"]:
    op=ops/A["operation"]
else:
    held=[p for p in ops.iterdir() if (p/"fresh-sparse-snapshot.bin").is_file() and (p/"plan.json").is_file()
          and json.loads((p/"plan.json").read_text()).get("source")==A["source"]]
    op=max(held,key=lambda p:(p/"fresh-sparse-snapshot.bin").stat().st_mtime)
pkg=Path(A["package"]);root=pkg/"source/firmware/slzb-06p7u/r4"
sys.dont_write_bytecode=True
sys.path[:0]=[str(pkg/"vendor"),str(root/"release"),str(root/"release/rom_writer"),str(root/"qualification"),str(root/"b0/tools")]
import stock20260311_security_preflight as sec
sys.path.insert(0,str(pkg/"source/host/flash"))
import p7u_paired_binding as pb
meta=json.loads((pkg/"PACKAGE.json").read_text())
acks=A["acks"] if A["acks"] is not None else meta.get("acknowledged_changes",[])
ack_native,ack_new=pb.acknowledged({"acknowledged_changes":acks})
from p7u_usb_security_model import parse_backup
abi=json.loads(Path(A["stage"],"security-native-abi.json").read_text())
reader=pkg/"security-reader-aarch64"
cap=(op/"fresh-sparse-snapshot.bin").read_bytes();base=Path(A["input"],"installed-before.bin").read_bytes()
rec_now,cnt_now=sec.read_private(reader,cap);rec_old,cnt_old=sec.read_private(reader,base)
now=sec.inspect_state(rec_now,abi);old=sec.inspect_state(rec_old,abi)
# Runtime inventory exactly as the operator builds it (quiesced DB from the op's cold archive).
db=None
if (op/"cold-before-flash.tar").is_file():
    with tarfile.open(op/"cold-before-flash.tar") as t: db=t.extractfile("zigbee2mqtt/database.db").read()
else:
    db=Path("/homeassistant/zigbee2mqtt/database.db").read_bytes()
rows=[json.loads(l) for l in db.splitlines() if l.strip()]
dbdev={bytes.fromhex(r["ieeeAddr"][2:]):r for r in rows if r.get("type") in ("Router","EndDevice") and re.fullmatch("0x[0-9a-fA-F]{16}",str(r.get("ieeeAddr","")))}
hist=parse_backup(json.loads(Path(A["input"],"historical-backup.json").read_text()))
inventory=frozenset(p[::-1] for p in hist.peers if p in dbdev)
names={}
try:
    import yaml
    cfg=yaml.safe_load(open("/homeassistant/zigbee2mqtt/configuration.yaml"))
    devs=cfg.get("devices") or {}
    if isinstance(devs,str): devs=yaml.safe_load(open("/homeassistant/zigbee2mqtt/"+devs)) or {}
    names={k.lower():(v or {}).get("friendly_name") for k,v in devs.items()}
except Exception: pass
F=lambda raw,m: sec.field(raw,abi,"AddrMgrEntry_t",m)
def who(ext):
    if not sec.real(ext): return {"ieee":None}
    ieee="0x"+ext[::-1].hex(); big=ext[::-1]
    return {"ieee":ieee,"name":names.get(ieee),"in_z2m_db":big in dbdev,"in_backup":big in set(hist.peers),
            "in_runtime_inventory":ext in inventory,"type":(dbdev.get(big) or {}).get("type")}
uo,_=abi["structs"]["AddrMgrEntry_t"]["fields"]["user"]
out=[]
for i,b in sorted(old["addresses"].items()):
    a=now["addresses"].get(i)
    if a==b: continue
    r={"slot":i,"in_aps_before":i in old["aps"],"in_aps_now":i in now["aps"]}
    if a is None:
        r.update(change="ROW_MISSING",allowed=False,before=who(F(b,"extAddr")));out.append(r);continue
    eb,ea=F(b,"extAddr"),F(a,"extAddr");ub,ua=b[uo],a[uo]
    r.update(user_before=ub,user_now=ua,before=who(eb),now=who(ea))
    if eb==ea:
        short=F(a,"nwkAddr")!=F(b,"nwkAddr")
        if ua==ub: r.update(change="SHORT_ADDRESS" if short else "OTHER_BYTES",allowed=short)
        elif ub&2 and ub&1 and not ua&1 and (ua|1)==ub: r.update(change="ASSOC_RELEASE"+("+SHORT" if short else ""),allowed=True)
        else: r.update(change="FLAGS_CHANGED"+("+SHORT" if short else ""),allowed=False)
    elif i in old["empty_addresses"]:
        why=[k for k,ok in (("user_0_to_2",ub==0 and ua==2),("in_runtime_inventory",ea in inventory),
             ("not_in_aps",i not in old["aps"] and i not in now["aps"]),
             ("unique",sum(F(x,"extAddr")==ea for x in now["addresses"].values())==1 and
                       all(F(x,"extAddr")!=ea for x in old["addresses"].values()))) if not ok]
        r.update(change="VACANT_FILL",allowed=not why,refused_because=why)
    elif not sec.real(ea): r.update(change="VACATED",allowed=False)
    else: r.update(change="REPLACED",allowed=False)
    out.append(r)
tail=[i for i in now["addresses"] if i not in old["addresses"] and i not in now["empty_addresses"]]
# Trust-centre link-key table: which retained entries changed and how (names
# and key attributes only; never key bytes, seed shifts or counter values).
ATTR={0:"PROVISIONAL(install code)",1:"UNVERIFIED",2:"VERIFIED",0xfd:"DISTRIBUTED_DEFAULT",0xff:"DEFAULT"}
tc=[]
for ext in sorted(set(old["peers"])|set(now["peers"])):
    b,a=old["peers"].get(ext),now["peers"].get(ext)
    if b and a and all(b[k]==a[k] for k in ("index","key_metadata","key")):continue
    e={"ieee":who(ext)["ieee"],"name":who(ext).get("name"),"in_z2m_db":who(ext).get("in_z2m_db")}
    if b is None:e["change"]="TC_ENTRY_ADDED"
    elif a is None:e["change"]="TC_ENTRY_REMOVED"
    else:
        mb,ma=b["key_metadata"],a["key_metadata"];n=("extAddr","keyAttributes","keyType","SeedShift","IcIndex")
        e["change"]="TC_ENTRY_CHANGED";e["fields"]=[n[i] for i in range(5) if mb[i]!=ma[i]]+(["slot"] if b["index"]!=a["index"] else [])+(["install_code_key"] if b["key"]!=a["key"] else [])
        e["keyAttributes"]="%%s -> %%s"%%(ATTR.get(mb[1][0],mb[1][0]),ATTR.get(ma[1][0],ma[1][0]))
        e["keyType"]="%%d -> %%d"%%(mb[2][0],ma[2][0])
    tc.append(e)
verdict=sec.evaluate_records(rec_now,rec_old,abi,runtime_upgrade=True,runtime_inventory_peers=inventory,acknowledged_changes=ack_native)
# Second gate: current-owner reconciliation (counter floor is proven separately by the operator).
from p7u_usb_current_owner_gate import reconcile_current
fresh_path=op/"owner-backup-before-stop.json"
fresh=json.load(open("/homeassistant/zigbee2mqtt/coordinator_backup.json")) if A["live"] or not fresh_path.is_file() else json.loads(fresh_path.read_text())
rc=reconcile_current(historical=json.loads(Path(A["input"],"historical-backup.json").read_text()),fresh=fresh,records=rec_now,abi=abi,
   native_preflight_pass=True,candidate_semantics_pass=True,baseline_counter_floor=None,runtime_inventory_peers=inventory,acknowledged_new_peers=ack_new)
fb=parse_backup(fresh);hp=set(hist.peers)
def peer(ieee_big):
    k=fb.peers.get(ieee_big) or hist.peers.get(ieee_big) or (None,None,None,False)
    ieee="0x"+ieee_big.hex()
    return {"ieee":ieee,"name":names.get(ieee),"in_z2m_db":ieee_big in dbdev,"keyed":k[0] is not None,"child":bool(k[3]),
            "type":(dbdev.get(ieee_big) or {}).get("type")}
owner_gate={"reason_codes":sorted(set(rc.get("reason_codes",[]))-{"CURRENT_SILICON_NWK_COUNTER_FLOOR_NOT_PROVEN"}),
  "counts":{k:rc.get(k) for k in ("historical_devices","current_devices","silicon_devices","historical_only","historically_new")},
  "new_since_reference":[peer(p) for p in sorted(set(fb.peers)-hp)],
  "missing_since_reference":[peer(p) for p in sorted(hp-set(fb.peers))]}
print(json.dumps({"operation":op.name,"capture_mtime":int((op/"fresh-sparse-snapshot.bin").stat().st_mtime),
  "verdict":{k:verdict.get(k) for k in ("semantic_checks_passed","reason_codes","comparison_scope")},
  "identity_and_keys_unchanged":now["identity"]==old["identity"] and now["active"]==old["active"] and now["seed"]==old["seed"] and now["alternate"]==old["alternate"],
  "aps_opaque_tail_unchanged":now["aps_opaque_tail"]==old["aps_opaque_tail"],
  "nwk_floors_not_regressed":now["selected_floor"]>=old["selected_floor"] and now["legacy_floor"]>=old["legacy_floor"],
  "slots":{"baseline":len(old["addresses"]),"now":len(now["addresses"]),"baseline_empty":len(old["empty_addresses"]),"now_empty":len(now["empty_addresses"])},
  "nv_active_records":{"baseline":cnt_old.get("active_records"),"now":cnt_now.get("active_records")},
  "runtime_inventory":len(inventory),"z2m_devices":len(dbdev),"backup_peers":len(hist.peers),
  "new_tail_not_empty":tail,"changed_rows":out,"owner_gate":owner_gate,"tc_changes":tc,"acknowledged":acks,"fresh_backup":"live" if A["live"] else "operation"}))
'''


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--operation", help="held operation id (default: newest capture for --source)")
    p.add_argument("--source", default="20a2474a67c1d420b6614b3fcb2f7ed543b1420e")
    p.add_argument("--package", default="/share/p7u-paired-operator-161e412fe63d-d713cec81d878d38")
    p.add_argument("--json", action="store_true")
    p.add_argument("--ack", help='override package acknowledgements, JSON [{"ieee":"0x..","change":"NEW_PEER|ASSOC_GAIN"}]')
    p.add_argument("--live", action="store_true", help="owner gate against the live Zigbee2MQTT coordinator backup")
    a = p.parse_args()
    args = {"ops": ROOT_OPS, "operation": a.operation, "source": a.source, "package": a.package,
            "acks": json.loads(a.ack) if a.ack else None, "live": a.live,
            "stage": "/share/p7u-paired-stage-" + a.source[:12], "input": "/share/p7u-paired-input-" + a.source[:12]}
    run = subprocess.run(["ssh", "-o", "BatchMode=yes", "ha", "python3 -B -"], input=REMOTE % {"args": json.dumps(args)},
                         capture_output=True, text=True, timeout=300)
    if run.returncode:
        sys.exit("REMOTE_FAILED\n" + run.stderr[-3000:])
    r = json.loads(run.stdout.strip().splitlines()[-1])
    if a.json:
        print(json.dumps(r, indent=1)); return 0
    print("operation %(operation)s  verdict %(verdict)s" % r)
    print("  %-28s %s (owner gate vs %s backup)" % ("acknowledged", r["acknowledged"], r["fresh_backup"]))
    for k in ("identity_and_keys_unchanged", "aps_opaque_tail_unchanged", "nwk_floors_not_regressed",
              "slots", "nv_active_records", "runtime_inventory", "z2m_devices", "backup_peers", "new_tail_not_empty"):
        print("  %-28s %s" % (k, r[k]))
    rows = r["changed_rows"]
    counts = {}
    for x in rows:
        counts[(x["change"], x["allowed"])] = counts.get((x["change"], x["allowed"]), 0) + 1
    print("\nchanged rows: %d  %s" % (len(rows), {("%s/%s" % (c, "ok" if ok else "REFUSED")): n for (c, ok), n in sorted(counts.items())}))
    for x in rows:
        if x["allowed"]:
            continue
        b, n = x.get("before") or {}, x.get("now") or {}
        print("  slot %3d %-14s before=%s %s  now=%s %s  flags %s->%s aps %s/%s %s" % (
            x["slot"], x["change"], b.get("ieee"), b.get("name") or "", n.get("ieee"), n.get("name") or "",
            x.get("user_before"), x.get("user_now"), x["in_aps_before"], x["in_aps_now"],
            ("refused: " + ",".join(x["refused_because"])) if x.get("refused_because") else
            ("now: z2m=%s backup=%s inventory=%s" % (n.get("in_z2m_db"), n.get("in_backup"), n.get("in_runtime_inventory"))
             if n.get("ieee") else "")))
    print(chr(10) + "trust-centre link-key entries changed: %d (TC set before/now %s)" % (len(r["tc_changes"]), r["slots"]))
    for e in r["tc_changes"]:
        print("  %-17s %s %-34s %s %s %s" % (e["change"], e["ieee"], e["name"] or "-", ",".join(e.get("fields", [])),
                                            e.get("keyAttributes", ""), ("keyType " + e["keyType"]) if e.get("keyType") else ""))
    g = r["owner_gate"]
    print("\nowner reconciliation: %s  %s" % (g["reason_codes"] or "PASS (counter floor checked at deploy)", g["counts"]))
    for label in ("new_since_reference", "missing_since_reference"):
        for d in g[label]:
            print("  %-24s %s %-34s z2m=%s keyed=%s child=%s %s" % (label, d["ieee"], d["name"] or "-", d["in_z2m_db"],
                                                                  d["keyed"], d["child"], d["type"] or ""))
    return 0 if r["verdict"]["semantic_checks_passed"] and not g["reason_codes"] else 1


if __name__ == "__main__":
    sys.exit(main())
