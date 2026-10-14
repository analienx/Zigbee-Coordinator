#!/usr/bin/env python3
"""Synthetic-only adversarial preflash coordinator backup checks (no real keys)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT=Path(__file__).resolve().parents[2]
P=ROOT/"firmware/slzb-06p7u/qualification/verify_z2m_backup.py"
spec=importlib.util.spec_from_file_location("backup",P)
v=importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

IEEE="00124b0011223344"
A="00158d0000000001"
B="00158d0000000002"
FAKE_NWK_KEY="11"*16
FAKE_SEED="22"*16
FAKE_LINK="33"*16


def setup(now,older=False):
    t=now-timedelta(days=2 if older else 0,hours=0 if older else 1)
    return {
        "metadata":{"format":"zigpy/open-coordinator-backup","version":1,
                    "source":"zstack",
                    "internal":{"date":t.isoformat()}},
        "stack_specific":{"zstack":{"tclk_seed":FAKE_SEED}},
        "coordinator_ieee":IEEE,
        "pan_id":"7f",  # exact pinned herdsman formats unpadded hex
        "extended_pan_id":"0102030405060708",
        "security_level":5, "nwk_update_id":4,
        "channel":11,"channel_mask":[11,15,20],
        "network_key":{"key":FAKE_NWK_KEY,"sequence_number":2,
                       "frame_counter":90 if older else 100},
        "devices":[
            {"nwk_address":"0","ieee_address":A,"is_child":False,
             "link_key":{"key":FAKE_LINK,
                         "rx_counter":40 if older else 50,
                         "tx_counter":60 if older else 70}},
            {"nwk_address":None,"ieee_address":B,"is_child":True,
             "link_key":None},
        ],
    }


def rejected(callback,code):
    try:callback()
    except v.BackupGateError as e:
        if code not in str(e):
            raise AssertionError("INCORRECT_DENY_REASON:"+str(e))
    else:
        raise AssertionError("SECURITY_GATE_ACCEPTED_INVALID_BACKUP:"+code)


def main():
    now=datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory() as d:
        base=Path(d)
        backup=base/"coordinator_backup.json"
        previous=base/"prior.json"
        database=base/"database.db"
        database.write_text(
            "\n".join(json.dumps(x) for x in (
                {"type":"Coordinator","ieeeAddr":IEEE},
                {"type":"Router","ieeeAddr":A},
                {"type":"EndDevice","ieeeAddr":B},
            ))+"\n")
        baseline=setup(now)
        old=setup(now,older=True)
        previous.write_text(json.dumps(old))
        def run(data,prior=None):
            backup.write_text(json.dumps(data))
            return v.qualify(backup,database,IEEE,previous if prior else None,24,now)
        good=run(baseline,True)
        assert good["flash_authorized"] is False
        assert good["backup_device_count"]==2
        assert FAKE_NWK_KEY not in json.dumps(good)
        assert FAKE_SEED not in json.dumps(good)
        assert IEEE not in json.dumps(good)
        damaged=json.loads(json.dumps(baseline))
        damaged["network_key"]["key"]="00"*16
        rejected(lambda:run(damaged),"NETWORK_KEY_ALL_ZERO")
        damaged=json.loads(json.dumps(baseline))
        damaged["stack_specific"]["zstack"].pop("tclk_seed")
        rejected(lambda:run(damaged),"ZSTACK_TCLK_SEED")
        damaged=json.loads(json.dumps(baseline))
        damaged["coordinator_ieee"]="00124bfffffffffe"
        rejected(lambda:run(damaged),"BACKUP_COORDINATOR_IEEE_MISMATCH")
        damaged=json.loads(json.dumps(baseline))
        damaged["devices"].pop()
        rejected(lambda:run(damaged),"BACKUP_AND_Z2M_DEVICE_INVENTORY_DIFFER")
        damaged=json.loads(json.dumps(baseline))
        damaged["devices"].append(damaged["devices"][0])
        rejected(lambda:run(damaged),"BACKUP_DUPLICATE_DEVICE")
        damaged=json.loads(json.dumps(baseline))
        damaged["network_key"]["frame_counter"]=80
        rejected(lambda:run(damaged,True),"NETWORK_COUNTER_REGRESSION")
        damaged=json.loads(json.dumps(baseline))
        damaged["devices"][0]["link_key"]["rx_counter"]=30
        rejected(lambda:run(damaged,True),"DEVICE_LINK_COUNTER_REGRESSION")
        damaged=json.loads(json.dumps(baseline))
        damaged["stack_specific"]["zstack"]["tclk_seed"]="55"*16
        rejected(lambda:run(damaged,True),"TRUST_CENTER_SEED_CHANGED")
        damaged=json.loads(json.dumps(baseline))
        damaged["extended_pan_id"]="1111111111111111"
        rejected(lambda:run(damaged,True),"EXTENDED_PAN_ID_CHANGED")
        damaged=json.loads(json.dumps(baseline))
        damaged["network_key"]["key"]="44"*16
        rejected(lambda:run(damaged,True),"NETWORK_KEY_CHANGED_WITHOUT_SEQUENCE_UPDATE")
        damaged=json.loads(json.dumps(baseline))
        damaged["metadata"]["internal"]["date"]=(now-timedelta(days=3)).isoformat()
        rejected(lambda:run(damaged),"BACKUP_TOO_OLD_OR_FUTURE")
        database.write_text('{"type":"Router","ieeeAddr":"BAD"}\n')
        rejected(lambda:run(baseline),"IEEE_FORMAT_INVALID")
        print("P7U_BACKUP_PREFLIGHT_12_ADVERSARIAL_CASES_PASS_NO_SECRETS_NO_FLASH")


if __name__=="__main__":
    main()
