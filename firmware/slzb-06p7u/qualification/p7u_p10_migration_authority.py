#!/usr/bin/env python3
"""P10 -> P7U migration evidence + counter-floor planning, OFFLINE ONLY.

No radio, network, HA, NV, SMLIGHT management, MQTT, or Zigbee2MQTT API access.
Never prints or publishes IEEE identities, Zigbee keys or TCLK material.
"""
from __future__ import annotations
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

import verify_z2m_backup as gate

MARGIN=2500
MAX=(1<<32)-1

class MigrationError(ValueError):
    pass

def need(ok:bool,why:str):
    if not ok:raise MigrationError(why)

def sha(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def extract_bytes(archive:Path, member:str)->bytes:
    try:
        with zipfile.ZipFile(archive) as z:
            members=z.namelist()
            # Full HA cold archives retain earlier nested snapshots. Use the
            # canonical live data path; NEVER silently choose an old copy.
            direct=[x for x in ("data/"+member,member) if x in members]
            need(len(direct)>=1,"CANONICAL_LIVE_BACKUP_MEMBER_MISSING")
            chosen=direct[0]
            need(members.count(chosen)==1,"CANONICAL_LIVE_BACKUP_MEMBER_DUPLICATED")
            need(z.testzip() is None,"BACKUP_ARCHIVE_CRC_FAILURE")
            data=z.read(chosen)
            need(len(data)<5_000_000,"BACKUP_ARCHIVE_MEMBER_OVERSIZED")
            return data
    except (OSError,zipfile.BadZipFile,RuntimeError) as exc:
        raise MigrationError("BACKUP_ARCHIVE_CORRUPT_OR_UNREADABLE") from exc

def load(source:Path,archive:bool=False)->tuple[dict,bytes]:
    try:
        raw=extract_bytes(source,"coordinator_backup.json") if archive else source.read_bytes()
        data=json.loads(raw)
        need(isinstance(data,dict),"BACKUP_NOT_OBJECT")
        return data,raw
    except (OSError,json.JSONDecodeError,UnicodeDecodeError) as exc:
        raise MigrationError("BACKUP_INVALID_OR_MISSING") from exc

def validated(data:dict)->dict:
    # Same strict Zigbee2MQTT unified schema as the existing backup gate.
    # Date is validated but may be historical; this is NOT freshness approval.
    try:
        info=gate.check_backup(data,data.get("coordinator_ieee"),
                               datetime.now(timezone.utc),365*24*20)
    except (gate.BackupGateError,KeyError,TypeError) as exc:
        raise MigrationError("BACKUP_SCHEMA_OR_SECURITY_INVALID") from exc
    return info

def db_roster(raw:bytes)->dict[str,str]:
    out={}
    try:
        for s in raw.decode("utf-8-sig").splitlines():
            if not s.strip():continue
            row=json.loads(s)
            if row.get("type") not in ("Router","EndDevice"):continue
            ieee=gate.normalized_ieee(row.get("ieeeAddr"))
            need(ieee not in out,"DATABASE_DUPLICATE_IEEE")
            out[ieee]=row["type"]
    except (ValueError,KeyError,UnicodeDecodeError,gate.BackupGateError) as exc:
        raise MigrationError("DATABASE_INVALID") from exc
    need(len(out)>0,"DATABASE_NO_ZIGBEE_DEVICES")
    return out

def missing_device_triage(source_archive:Path,prior_paths:list[Path])->list[dict]:
    """Private-only action list for DB devices absent from latest coordinator backup.

    Historical key presence is NOT proof that an old key is still valid.
    Never graft old key bytes into a restore candidate.
    """
    current,_=load(source_archive,True)
    info=validated(current)
    db=db_roster(extract_bytes(source_archive,"database.db"))
    missing=sorted(set(db)-set(info["devices"]))
    historical={ieee:0 for ieee in missing}
    for path in prior_paths:
        old,_=load(path,path.suffix.lower()==".zip")
        previous=validated(old)
        need(same_identity(current,old),"PRIOR_BACKUP_NETWORK_IDENTITY_MISMATCH")
        need(gate.parse_time(old["metadata"]["internal"]["date"])<=
             gate.parse_time(current["metadata"]["internal"]["date"]),
             "PRIOR_BACKUP_NEWER_THAN_SOURCE")
        for ieee in missing:
            if previous["devices"].get(ieee,{}).get("link_key"):
                historical[ieee]+=1
    return [{
        "ieee_address":ieee,
        "device_type":db[ieee],
        "older_backup_key_candidates":historical[ieee],
        "historical_key_is_currently_verified":False,
        "recommended_action":("VERIFY_CURRENT_KEY_OR_PLAN_REPAIR"
                              if historical[ieee] else "PLAN_CONTROLLED_REPAIR_OR_REJOIN"),
        "automatically_restore":False,
    } for ieee in missing]


def same_identity(a:dict,b:dict)->bool:
    fields=("coordinator_ieee","pan_id","extended_pan_id","channel","security_level","nwk_update_id")
    if any(str(a.get(k)).lower()!=str(b.get(k)).lower() for k in fields):return False
    for k in ("key","sequence_number"):
        if str(a["network_key"].get(k)).lower()!=str(b["network_key"].get(k)).lower():return False
    return str(a["stack_specific"]["zstack"].get("tclk_seed")).lower()==str(
        b["stack_specific"]["zstack"].get("tclk_seed")).lower()

def analyze(source_archive:Path,prior_paths:list[Path],expected_backup_sha:str,
            expected_database_sha:str,margin:int=MARGIN):
    need(type(margin) is int and 2500<=margin<=100000,"COUNTER_MARGIN_POLICY_INVALID")
    now,raw=load(source_archive,True)
    need(sha(raw)==expected_backup_sha.lower(),"AUTHORITATIVE_BACKUP_SHA_MISMATCH")
    info=validated(now)
    dbraw=extract_bytes(source_archive,"database.db")
    need(sha(dbraw)==expected_database_sha.lower(),"AUTHORITATIVE_DATABASE_SHA_MISMATCH")
    db=db_roster(dbraw)
    by=info["devices"]
    absent_db=sorted(set(db)-set(by))
    ghost=sorted(set(by)-set(db))
    unkeyed=[i for i,v in by.items() if not v.get("link_key")]
    network_high=now["network_key"]["frame_counter"]
    high_tx={i:v["link_key"]["tx_counter"] for i,v in by.items() if v.get("link_key")}
    rx_regression=set()
    key_conflicts=0
    old_keyed_coverage=set()
    older_reports=[]
    for path in prior_paths:
        old,oldraw=load(path,path.suffix.lower()==".zip")
        oi=validated(old)
        need(same_identity(now,old),"PRIOR_BACKUP_NETWORK_IDENTITY_MISMATCH")
        need(gate.parse_time(old["metadata"]["internal"]["date"])<=
             gate.parse_time(now["metadata"]["internal"]["date"]),
             "PRIOR_BACKUP_NEWER_THAN_SOURCE")
        network_high=max(network_high,old["network_key"]["frame_counter"])
        samekey=0
        for ieee,d in oi["devices"].items():
            link=d.get("link_key")
            if link:old_keyed_coverage.add(ieee)
            if ieee not in by or not link or not by[ieee].get("link_key"):continue
            current=by[ieee]["link_key"]
            if current["key"].lower()!=link["key"].lower():
                key_conflicts+=1
                continue
            samekey+=1
            high_tx[ieee]=max(high_tx[ieee],link["tx_counter"])
            if link["rx_counter"]>current["rx_counter"]:
                rx_regression.add(ieee)
        older_reports.append({"backup_sha256":sha(oldraw),
                              "devices":len(oi["devices"]),"same_active_link_keys":samekey,
                              "historical_nwk_counter":old["network_key"]["frame_counter"]})
    need(network_high+margin<=MAX,"NETWORK_COUNTER_OVERFLOW")
    need(all(v+margin<=MAX for v in high_tx.values()),"LINK_COUNTER_OVERFLOW")
    proposed=copy.deepcopy(now)
    proposed["network_key"]["frame_counter"]=network_high
    bumps=0
    for dev in proposed["devices"]:
        ieee=gate.normalized_ieee(dev["ieee_address"])
        if dev.get("link_key"):
            target=high_tx[ieee]
            current=dev["link_key"]
            if target>current["tx_counter"]:
                current["tx_counter"]=target
                bumps+=1
    report={
      "qualification":"SOURCE_VERIFIED_COUNTER_PLAN_ONLY_NOT_RESTORE_READY",
      "source_backup_sha256":sha(raw),
      "source_archive_sha256":sha(source_archive.read_bytes()),
      "source_database_sha256":sha(dbraw),
      "source_backup_devices":len(by),
      "source_link_keys":len(high_tx),
      "db_devices":len(db),"missing_db_router_security":sum(db[k]=="Router" for k in absent_db),
      "missing_db_end_device_security":sum(db[k]=="EndDevice" for k in absent_db),
      "backup_only_old_security_records":len(ghost),
      "source_entries_without_link_key":len(unkeyed),
      "historical_keys_for_db_missing":len(set(absent_db)&old_keyed_coverage),
      "historical_link_key_conflicts":key_conflicts,
      "historical_rx_counter_above_latest":len(rx_regression),
      "source_nwk_counter":now["network_key"]["frame_counter"],
      "highest_historical_nwk_counter":network_high,
      "planned_restore_nwk_counter_floor":network_high+margin,
      "source_link_tx_counter_bumps":bumps,
      "planned_restore_tx_margin":margin,
      "prior_sources":older_reports,
      "restoration_authorized":False,
      "flash_authorized":False,
      "nv5_erase_authorized":False,
      "physical_rom_bsl_qualified":False,
      "requires_hardware_security_counter_readback":True,
      "requires_absent_db_devices_resolution":bool(absent_db),
      "requires_historical_rx_reconciliation":bool(rx_regression),
    }
    return report,proposed

def stage_private(folder:Path,report:dict,proposal:dict,missing_triage:list[dict]|None=None)->dict:
    # Only stage under user's existing private workspace, no public Git paths.
    resolved=folder.resolve()
    private=Path(r"C:\Workspace\.analienx\sonoff-private").resolve()
    need(private in resolved.parents,"PRIVATE_ROOT_REQUIRED")
    need(not resolved.exists(),"PRIVATE_STAGE_MUST_NOT_EXIST")
    folder.mkdir(parents=True)
    name="NOT_RESTORE_READY_p10_to_p7u_counter_floor.json"
    payload=(json.dumps(proposal,indent=2,sort_keys=True)+"\n").encode()
    with (folder/name).open("xb") as out:out.write(payload)
    receipt=copy.deepcopy(report)
    receipt["private_candidate_sha256"]=sha(payload)
    receipt["private_candidate_filename"]=name
    (folder/"PLAN_NOT_FLASHABLE.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    if missing_triage is not None:
        need(len(missing_triage)==report["missing_db_router_security"]+
             report["missing_db_end_device_security"],"MISSING_TRIAGE_COUNT_CHANGED")
        # Private IEEE identities are intentionally never written to CLI stdout.
        with (folder/"MISSING_DEVICE_TRIAGE_NOT_RESTORE_READY.json").open("x",encoding="utf8") as out:
            json.dump({"schema":"p7u-missing-device-triage-v1",
                       "source_backup_sha256":report["source_backup_sha256"],
                       "devices":missing_triage,
                       "restore_approved":False,
                       "device_repair_required":bool(missing_triage)},out,indent=2,sort_keys=True)
            out.write("\n")
    return {"private_stage_created":True,"private_candidate_sha256":sha(payload),
            "restoration_authorized":False,"flash_authorized":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-archive",type=Path,required=True)
    p.add_argument("--prior",action="append",type=Path,default=[])
    p.add_argument("--expected-backup-sha256",required=True)
    p.add_argument("--expected-database-sha256",required=True)
    p.add_argument("--stage-private",type=Path)
    args=p.parse_args()
    try:
        report,proposal=analyze(args.source_archive,args.prior,
            args.expected_backup_sha256,args.expected_database_sha256)
        if args.stage_private:
            triage=missing_device_triage(args.source_archive,args.prior)
            report["staged_candidate"]=stage_private(args.stage_private,report,proposal,triage)
        print(json.dumps(report,indent=2,sort_keys=True))
    except (MigrationError,OSError) as e:
        print(json.dumps({"qualification":"FAIL_CLOSED","reason":str(e),
                           "restoration_authorized":False,"flash_authorized":False}))
        raise SystemExit(2) from None

if __name__=="__main__":main()
