#!/usr/bin/env python3
"""Read-only, fail-closed Z2M/Open Coordinator Backup inventory qualification.

Does NOT authorize flashing or establish NV flash, key/counter or migration
durability. NEVER logs key/TCLK seeds or full network identifiers.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

UINT32_MAX=(1 << 32)-1


class BackupGateError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise BackupGateError(reason)


def normalized_ieee(s: object) -> str:
    require(isinstance(s,str), "IEEE_FORMAT_INVALID")
    text=s[2:] if s.lower().startswith("0x") else s
    require(re.fullmatch(r"[0-9A-Fa-f]{16}",text) is not None, "IEEE_FORMAT_INVALID")
    return text.lower()


def hex_key(s: object, label: str) -> None:
    require(isinstance(s,str) and re.fullmatch(r"[0-9A-Fa-f]{32}",s) is not None,
            label+"_MISSING_OR_INVALID")
    require(any(x!="0" for x in s),label+"_ALL_ZERO")


def counter(x: object, name: str) -> int:
    require(type(x) is int and 0<=x<=UINT32_MAX,name+"_INVALID_COUNTER")
    return x


def parse_time(s: object) -> datetime:
    require(isinstance(s,str),"BACKUP_DATE_MISSING")
    try:
        v=datetime.fromisoformat(s.replace("Z","+00:00"))
    except ValueError as e:
        raise BackupGateError("BACKUP_DATE_INVALID") from e
    require(v.tzinfo is not None,"BACKUP_DATE_NO_TIMEZONE")
    return v.astimezone(timezone.utc)


def load_backup(path: Path) -> dict:
    try:
        raw=json.loads(path.read_text(encoding="utf8"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError) as e:
        raise BackupGateError("COORDINATOR_BACKUP_MISSING_OR_INVALID") from e
    require(type(raw) is dict,"BACKUP_ROOT_NOT_OBJECT")
    return raw


def check_backup(data: dict, expected_ieee: str, now: datetime,
                 max_age_h: float) -> dict:
    metadata=data.get("metadata")
    require(type(metadata) is dict,"BACKUP_METADATA_MISSING")
    require(metadata.get("format")=="zigpy/open-coordinator-backup"
            and metadata.get("version")==1,"BACKUP_FORMAT_VERSION_UNSUPPORTED")
    require(isinstance(metadata.get("source"),str) and metadata["source"].strip(),
            "BACKUP_SOURCE_MISSING")
    require(type(metadata.get("internal")) is dict,"BACKUP_INTERNAL_METADATA_MISSING")
    stamp=parse_time(metadata["internal"].get("date"))
    age=(now-stamp).total_seconds()/3600
    require(0<=age<=max_age_h,"BACKUP_TOO_OLD_OR_FUTURE")
    coord=normalized_ieee(data.get("coordinator_ieee"))
    require(coord==normalized_ieee(expected_ieee),"BACKUP_COORDINATOR_IEEE_MISMATCH")
    for key,ln in (("pan_id",4),("extended_pan_id",16)):
        v=data.get(key)
        length_spec="1,"+str(ln) if key=="pan_id" else str(ln)
        require(isinstance(v,str) and re.fullmatch("[0-9A-Fa-f]{"+length_spec+"}",v) is not None,
                key.upper()+"_MISSING")
    require(type(data.get("channel")) is int and 11<=data["channel"]<=26,"CHANNEL_INVALID")
    mask=data.get("channel_mask")
    require(type(mask) is list and len(mask)>0
            and all(type(ch) is int and 11<=ch<=26 for ch in mask)
            and data["channel"] in mask,"CHANNEL_MASK_INVALID")
    require(type(data.get("security_level")) is int and data["security_level"]==5,
            "SECURITY_LEVEL_UNEXPECTED")
    require(type(data.get("nwk_update_id")) is int and 0<=data["nwk_update_id"]<=255,
            "NETWORK_UPDATE_ID_INVALID")
    network_key=data.get("network_key")
    require(type(network_key) is dict,"NETWORK_KEY_BLOCK_MISSING")
    hex_key(network_key.get("key"),"NETWORK_KEY")
    require(type(network_key.get("sequence_number")) is int
            and 0<=network_key["sequence_number"]<=255,"NETWORK_KEY_SEQUENCE_INVALID")
    nwk_counter=counter(network_key.get("frame_counter"),"NWK")
    # On a Z-Stack backup the TC seed is required to rebuild transient
    # Trust-Center link-key material. A generic format permits omission, but
    # this stricter same-family preflash gate intentionally does not.
    stack=data.get("stack_specific")
    require(type(stack) is dict and type(stack.get("zstack")) is dict,
            "ZSTACK_SECURITY_STATE_MISSING")
    hex_key(stack["zstack"].get("tclk_seed"),"ZSTACK_TCLK_SEED")
    devices=data.get("devices")
    require(type(devices) is list and len(devices)>0,"BACKUP_DEVICE_INVENTORY_EMPTY")
    by_ieee={}
    for dev in devices:
        require(type(dev) is dict,"BACKUP_DEVICE_ROW_INVALID")
        ieee=normalized_ieee(dev.get("ieee_address"))
        require(ieee!=coord,"COORDINATOR_INCLUDED_AS_CHILD")
        require(ieee not in by_ieee,"BACKUP_DUPLICATE_DEVICE")
        require(type(dev.get("is_child")) is bool,"BACKUP_CHILD_FLAG_INVALID")
        addr=dev.get("nwk_address")
        require(addr is None or
                (isinstance(addr,str) and re.fullmatch(r"[0-9a-fA-F]{1,4}",addr) is not None),
                "BACKUP_DEVICE_NWK_ADDRESS_INVALID")
        link=dev.get("link_key")
        if link is not None:
            require(type(link) is dict,"BACKUP_LINK_KEY_INVALID")
            hex_key(link.get("key"),"BACKUP_LINK_KEY")
            counter(link.get("rx_counter"),"LINK_RX")
            counter(link.get("tx_counter"),"LINK_TX")
        by_ieee[ieee]=dev
    return {"metadata_date":stamp.isoformat(),
            "nwk_counter":nwk_counter,"devices":by_ieee,
            "coordinator_ieee":coord,
            "extended_pan_id":data["extended_pan_id"].lower(),
            "network_key_sequence":network_key["sequence_number"]}


def read_database(path: Path) -> set[str]:
    try:
        lines=path.read_text(encoding="utf8").splitlines()
    except (OSError,UnicodeDecodeError) as e:
        raise BackupGateError("Z2M_DATABASE_MISSING_OR_INVALID") from e
    ieee_set=set()
    for line in lines:
        if not line.strip():
            continue
        try:
            item=json.loads(line)
        except json.JSONDecodeError as e:
            raise BackupGateError("Z2M_DATABASE_CORRUPT") from e
        require(type(item) is dict,"Z2M_DATABASE_ROW_INVALID")
        kind=item.get("type")
        if kind not in ("Router","EndDevice","Coordinator"):
            continue
        if kind=="Coordinator":
            continue
        ieee=normalized_ieee(item.get("ieeeAddr"))
        require(ieee not in ieee_set,"Z2M_DATABASE_DUPLICATE_DEVICE")
        ieee_set.add(ieee)
    require(bool(ieee_set),"Z2M_DATABASE_NO_DEVICES")
    return ieee_set


def qualify(backup: Path,database: Path,expected_ieee: str,
            previous: Path|None=None, max_age_hours:float=24,
            now:datetime|None=None) -> dict:
    now=now or datetime.now(timezone.utc)
    require(max_age_hours>0 and max_age_hours<=168,"MAX_AGE_POLICY_INVALID")
    fresh=check_backup(load_backup(backup),expected_ieee,now,max_age_hours)
    known=read_database(database)
    require(known==set(fresh["devices"]),"BACKUP_AND_Z2M_DEVICE_INVENTORY_DIFFER")
    if previous:
        old=check_backup(load_backup(previous),expected_ieee,now,
                         365*24*100)  # Previous baseline may legitimately be old.
        require(fresh["extended_pan_id"]==old["extended_pan_id"],
                "EXTENDED_PAN_ID_CHANGED")
        require(fresh["network_key_sequence"]>=old["network_key_sequence"],
                "NETWORK_KEY_SEQUENCE_REGRESSION")
        if fresh["network_key_sequence"]==old["network_key_sequence"]:
            require(fresh["nwk_counter"]>=old["nwk_counter"],
                    "NETWORK_COUNTER_REGRESSION")
            require(load_backup(backup)["network_key"]["key"].lower() ==
                    load_backup(previous)["network_key"]["key"].lower(),
                    "NETWORK_KEY_CHANGED_WITHOUT_SEQUENCE_UPDATE")
        require(load_backup(backup)["stack_specific"]["zstack"]["tclk_seed"].lower() ==
                load_backup(previous)["stack_specific"]["zstack"]["tclk_seed"].lower(),
                "TRUST_CENTER_SEED_CHANGED")
        for ieee,dev in fresh["devices"].items():
            prior=old["devices"].get(ieee)
            if not prior:
                continue
            newer_key=dev.get("link_key")
            older_key=prior.get("link_key")
            if older_key and newer_key:
                require(newer_key["key"].lower()==older_key["key"].lower(),
                        "DEVICE_LINK_KEY_CHANGED")
                for kind in ("rx_counter","tx_counter"):
                    require(newer_key[kind]>=older_key[kind],"DEVICE_LINK_COUNTER_REGRESSION")
            elif older_key and not newer_key:
                raise BackupGateError("DEVICE_LINK_KEY_RECORD_LOST")
    return {
        "qualification":"Z2M_BACKUP_INVENTORY_AND_COUNTER_FLOOR_ONLY",
        "backup_sha256":hashlib.sha256(backup.read_bytes()).hexdigest(),
        "database_sha256":hashlib.sha256(database.read_bytes()).hexdigest(),
        "backup_device_count":len(fresh["devices"]),
        "z2m_database_device_count":len(known),
        "checked_against_prior":previous is not None,
        "network_nv_restore_qualified":False,
        "hardware_qualified":False,
        "security_counter_power_loss_qualified":False,
        "flash_authorized":False,
    }


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--backup",type=Path,required=True)
    p.add_argument("--database",type=Path,required=True)
    p.add_argument("--expected-ieee",required=True)
    p.add_argument("--previous-backup",type=Path)
    p.add_argument("--max-age-hours",type=float,default=24)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    try:
        result=qualify(a.backup,a.database,a.expected_ieee,
                       a.previous_backup,a.max_age_hours)
        message=json.dumps(result,indent=2)+"\n"
        if a.out:
            a.out.write_text(message,encoding="utf8")
        print(message)
        return 0
    except BackupGateError as e:
        print("BACKUP_PREFLIGHT_REJECTED:"+str(e),file=sys.stderr)
        return 2


if __name__=="__main__":
    sys.exit(main())
