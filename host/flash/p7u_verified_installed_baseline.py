#!/usr/bin/env python3
"""Build one immutable installed-image input from the *verified prior flash*.

Private HA-only preparation. Source/ROM/counter identity must be checked AGAIN
by the next operator before any firmware write. No serial or network action.
"""
import hashlib,json,os
from pathlib import Path

OLD_INPUT=Path("/share/p7u-r4-input-afbb7a8")
OLD_CANDIDATE=Path("/share/p7u-r4-stage-afbb7a8")
OP=Path("/share/p7u-r4-firmware-operations/e579bb986d49be68daf2108ebc22dc0f")
TARGET=Path("/share/p7u-r4-input-efb264b")
INSTALLED="afbb7a8445f0454d53038ed34b4110fa29a5d671"
OLD_INPUT_PIN="692a7ae7d85151548824a39ec46e088058f8f2fac8fbb4af1e7557d1fd9519b0"
OLD_CANDIDATE_PIN="ff77c12ef20a2e54ab3d4bb93e19a2cea08d45240226c5145e701f0f94b95983"
OP_PLAN_PIN="190516b0e4e1cb322929a714b41857879ee42c732c6170917f83141ed2ade48d"
FROZEN_PLAN_PIN="9b789410d8753ddb621828baf956ac2a1b11c731a978d3c04a10384e7c87c059"
SNAPSHOT_PIN="b49fbfd133f5bea2bd204a3d5dafa730513f6feaddfe10852e7334314229c22d"
JOURNAL_PIN="22329fd262861f27136f374f7544d0d31cf84ec4331a0f89ebb67e7032f2b091"
INPUT_NAMES={
 "installed-candidate.json","installed-app.hex","installed-handoff.bin",
 "installed-plan.json","installed-result.json","installed-before.bin",
 "management.json","historical-backup.json"
}

def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
def need(ok,reason):
 if not ok:raise ValueError("PREVIOUS_WRITE_BASELINE_HOLD_"+reason)
def private(p):
 need(p.is_dir() and not p.is_symlink() and p.stat().st_mode&0o077==0,"PRIVATE_ROOT")
def checked_file(p):
 need(p.is_file() and not p.is_symlink(),"MISSING_OR_SYMLINK_"+p.name)
 return p.read_bytes()
def verify_manifest(root,name,pin,private_required=True):
 if private_required: private(root)
 else: need(root.is_dir() and not root.is_symlink(),"PUBLIC_CANDIDATE_ROOT")
 raw=checked_file(root/name)
 need(sha(raw)==pin,"SEALED_MANIFEST")
 m=json.loads(raw)
 for path,h in m["files"].items():
  f=root/path
  need(f.resolve().is_relative_to(root) and sha(checked_file(f))==h,"SEALED_FILE_"+path)
 need({x.relative_to(root).as_posix() for x in root.rglob("*") if x.is_file()}==
      set(m["files"])|{name},"SEALED_EXTRA_FILE")
 return m

def derive(preflight_only=False):
 need(not TARGET.exists() and not TARGET.is_symlink(),"TARGET_EXISTS")
 private(OP)
 verify_manifest(OLD_INPUT,"INPUT.json",OLD_INPUT_PIN)
 c=verify_manifest(OLD_CANDIDATE,"candidate.json",
                   sha(checked_file(OLD_CANDIDATE/"candidate.json")),private_required=False)
 need(c["source_sha"]==INSTALLED and sha(canonical(c))==OLD_CANDIDATE_PIN,
      "CURRENT_INSTALLED_FIRMWARE_PIN")
 raw_plan=checked_file(OP/"plan.json")
 op_plan=json.loads(raw_plan)
 need(op_plan["source"]==INSTALLED and op_plan["operation_id"]==OP.name
      and sha(canonical(op_plan))==OP_PLAN_PIN,"OPERATION_BINDING")
 raw_frozen=checked_file(OP/"frozen-plan.json")
 frozen=json.loads(raw_frozen)
 embedded=frozen.pop("plan_sha256")
 need(embedded==FROZEN_PLAN_PIN and sha(canonical(frozen))==FROZEN_PLAN_PIN
      and frozen["source_sha"]==INSTALLED,"FROZEN_PLAN")
 frozen["plan_sha256"]=embedded
 snap=checked_file(OP/"fresh-sparse-snapshot.bin")
 need(len(snap)==720896 and sha(snap)==SNAPSHOT_PIN and
      frozen["capture_sha256"]==SNAPSHOT_PIN,"PRIOR_FRESH_ROM")
 j=checked_file(OP/"mutation-journal.jsonl")
 need(sha(j)==JOURNAL_PIN,"IMMUTABLE_WRITE_JOURNAL")
 envelope=json.loads(checked_file(OP/"verified-write.json"))
 result=envelope["result"]
 need(envelope["operation_plan_sha256"]==OP_PLAN_PIN and
      envelope["frozen_plan_sha256"]==FROZEN_PLAN_PIN and
      envelope["journal_sha256"]==JOURNAL_PIN and
      result["status"]=="APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL" and
      result["verification_scope"]=="WRITTEN_SHA_PLUS_ALL88_ROM_CRC" and
      all(result[k] is False for k in ("nv_touched","ccfg_touched",
                                      "reset_issued","automatic_rollback")),"VERIFIED_WRITE_ENVELOPE")
 events=[json.loads(line) for line in j.splitlines()]
 verified=[(x["address"],x["sha256"]) for x in events if x.get("event")=="SECTOR_VERIFIED"]
 expected=[(a,frozen["sector_sha256"][str(a)]) for a in result["written_sectors"]]
 need(verified==expected and
      result["written_sectors"]==frozen["program_order"],"EVERY_WRITTEN_SECTOR_VERIFIED")
 assert set(INPUT_NAMES)==set(json.loads(checked_file(OLD_INPUT/"INPUT.json"))["files"])
 files={
  "installed-candidate.json":checked_file(OLD_CANDIDATE/"candidate.json"),
  "installed-app.hex":checked_file(OLD_CANDIDATE/"P7U-STOCK20260311-APP-ONLY.hex"),
  "installed-handoff.bin":checked_file(OLD_CANDIDATE/"P7U-STOCK20260311-AC000-HANDOFF.bin"),
  "installed-plan.json":raw_frozen,
  "installed-result.json":canonical(result),
  "installed-before.bin":snap,
  "management.json":checked_file(OLD_INPUT/"management.json"),
  "historical-backup.json":checked_file(OLD_INPUT/"historical-backup.json"),
 }
 need(sha(files["installed-app.hex"])==c["app_hex_sha256"] and
      sha(files["installed-handoff.bin"])==c["handoff_sha256"],"EXACT_OLD_APP_AC000")
 # No reuse of prior INPUT.json: every file above is identified and newly sealed.
 m={"files":{name:sha(content) for name,content in sorted(files.items())}}
 pin=sha(canonical(m))
 if preflight_only:
  return {"status":"PREVIOUS_INSTALLED_PAIR_PREVALIDATED_NO_WRITE",
          "sealed_input_pin":pin,"source":INSTALLED,"files":len(files)}
 TARGET.mkdir(mode=0o700)
 for name,content in files.items():
  with (TARGET/name).open("xb") as f:
   os.fchmod(f.fileno(),0o600)
   f.write(content);f.flush();os.fsync(f.fileno())
 with (TARGET/"INPUT.json").open("xb") as f:
  os.fchmod(f.fileno(),0o600);f.write(canonical(m));f.flush();os.fsync(f.fileno())
 return {"status":"PREVIOUS_VERIFIED_ROM_APP_PAIR_DERIVED_NO_SERIAL",
         "installed_source":INSTALLED,"frozen_plan_pin":FROZEN_PLAN_PIN,
         "prior_operation_pin":OP_PLAN_PIN,"retained_previous_snapshot_pin":SNAPSHOT_PIN,
         "sealed_input_pin":pin,"input_files":len(files),
         "nv_changes":0,"radio_actions":0}
if __name__=="__main__":
 import argparse
 p=argparse.ArgumentParser()
 p.add_argument("action",choices=("preflight","stage"))
 a=p.parse_args()
 print(json.dumps(derive(preflight_only=a.action=="preflight")))
