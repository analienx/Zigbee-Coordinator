#!/usr/bin/env python3
"""Host-only synthetic migration and security-counter adversarial regressions."""
import copy
from datetime import datetime,timezone,timedelta
import hashlib,json
from pathlib import Path
import sys,tempfile,zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"firmware/slzb-06p7u/qualification"))
import p7u_p10_migration_authority as m

def fixture(counter=12000,ids=("1122334455667788","1122334455667799")):
    return {
      "metadata":{"format":"zigpy/open-coordinator-backup","version":1,
         "source":"zigbee-herdsman@10.9.1",
         "internal":{"date":datetime(2026,10,15,tzinfo=timezone.utc).isoformat()}},
      "coordinator_ieee":"00124b0011223344",
      "pan_id":"45a1","extended_pan_id":"d6167914c10a3a3a",
      "channel":11,"channel_mask":[11],"security_level":5,"nwk_update_id":0,
      "network_key":{"key":"a1"*16,"sequence_number":0,"frame_counter":counter},
      "stack_specific":{"zstack":{"tclk_seed":"b2"*16}},
      "devices":[{"ieee_address":i,"nwk_address":"abcd","is_child":False,
                  "link_key":{"key":("c3" if x==0 else "d4")*16,
                     "rx_counter":100,"tx_counter":2000+x}}
                  for x,i in enumerate(ids)]
    }

def zipped(path,backup,db_ids,with_nested=False):
    raw=(json.dumps(backup,sort_keys=True)+"\n").encode()
    db=("\n".join(json.dumps({"ieeeAddr":"0x"+i,"type":"Router"}) for i in db_ids)+"\n").encode()
    with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("data/coordinator_backup.json",raw)
        z.writestr("data/database.db",db)
        if with_nested:
            z.writestr("data/recovery/old/coordinator_backup.json",b'{"old":true}')
            z.writestr("data/recovery/old/database.db",b"{}")
    return m.sha(raw),m.sha(db)

def mustfail(code,fun):
    try:fun()
    except m.MigrationError as e:
        assert str(e)==code,(code,str(e))
    else:raise AssertionError("NOT_REJECTED:"+code)

with tempfile.TemporaryDirectory(prefix="p7u-p10-migrate-") as td:
    root=Path(td)
    latest=fixture()
    prior=copy.deepcopy(latest)
    prior["metadata"]["internal"]["date"]=(datetime(2026,10,14,tzinfo=timezone.utc)).isoformat()
    prior["network_key"]["frame_counter"]=45000
    prior["devices"][0]["link_key"]["tx_counter"]=9500
    prior["devices"][1]["link_key"]["key"]="e5"*16
    pa=root/"latest.zip";old=root/"prior.json"
    bs,ds=zipped(pa,latest,("1122334455667788","0102030405060708"),with_nested=True)
    old.write_text(json.dumps(prior),encoding="utf8")
    report,proposal=m.analyze(pa,[old],bs,ds)
    assert report["source_link_keys"]==2
    assert report["missing_db_router_security"]==1
    assert report["historical_link_key_conflicts"]==1
    assert report["source_link_tx_counter_bumps"]==1
    assert report["highest_historical_nwk_counter"]==45000
    assert report["planned_restore_nwk_counter_floor"]==47500
    assert proposal["network_key"]["frame_counter"]==45000
    assert proposal["devices"][0]["link_key"]["tx_counter"]==9500
    assert proposal["devices"][1]["link_key"]["tx_counter"]==2001
    assert proposal["devices"][1]["link_key"]["key"]=="d4"*16
    assert latest["network_key"]["frame_counter"]==12000  # source is immutable
    assert report["restoration_authorized"] is False
    # Missing database members get explicit repair triage, not synthesized keys.
    triage=m.missing_device_triage(pa,[old])
    assert len(triage)==1
    assert triage[0]["ieee_address"]=="0102030405060708"
    assert triage[0]["older_backup_key_candidates"]==0
    assert triage[0]["automatically_restore"] is False
    assert triage[0]["recommended_action"]=="PLAN_CONTROLLED_REPAIR_OR_REJOIN"
    earlier_extra=copy.deepcopy(prior)
    earlier_extra["devices"].append({
        "ieee_address":"0102030405060708","nwk_address":"abcd","is_child":False,
        "link_key":{"key":"f7"*16,"rx_counter":50,"tx_counter":100}
    })
    earlier_extra_file=root/"prior-extra.json"
    earlier_extra_file.write_text(json.dumps(earlier_extra),encoding="utf8")
    historical=m.missing_device_triage(pa,[old,earlier_extra_file])
    assert len(historical)==1
    assert historical[0]["older_backup_key_candidates"]==1
    assert historical[0]["historical_key_is_currently_verified"] is False
    assert historical[0]["recommended_action"]=="VERIFY_CURRENT_KEY_OR_PLAN_REPAIR"
    assert "key" not in historical[0]  # no historical key material in triage
    mustfail("AUTHORITATIVE_BACKUP_SHA_MISMATCH",lambda:m.analyze(pa,[old],"0"*64,ds))
    mustfail("AUTHORITATIVE_DATABASE_SHA_MISMATCH",lambda:m.analyze(pa,[old],bs,"0"*64))
    mustfail("COUNTER_MARGIN_POLICY_INVALID",lambda:m.analyze(pa,[old],bs,ds,1))
    different=copy.deepcopy(prior);different["network_key"]["key"]="f6"*16
    old.write_text(json.dumps(different),encoding="utf8")
    mustfail("PRIOR_BACKUP_NETWORK_IDENTITY_MISMATCH",lambda:m.analyze(pa,[old],bs,ds))
    # Regenerated old frame counter below source does not cause backward movement.
    different["network_key"]["key"]=latest["network_key"]["key"]
    different["network_key"]["frame_counter"]=11000
    old.write_text(json.dumps(different),encoding="utf8")
    rep,pro=m.analyze(pa,[old],bs,ds)
    assert pro["network_key"]["frame_counter"]==12000
    # Data/ canonical path always wins over nested historical copies.
    assert m.extract_bytes(pa,"coordinator_backup.json").startswith(b"{")
    # Missing canonical member never permits silent historical rollback.
    bad=root/"nestedonly.zip"
    with zipfile.ZipFile(bad,"w") as z:z.writestr("archive/2025/coordinator_backup.json",b"{}")
    mustfail("CANONICAL_LIVE_BACKUP_MEMBER_MISSING",lambda:m.extract_bytes(bad,"coordinator_backup.json"))
    # Overflow before even providing a restore candidate.
    over=copy.deepcopy(latest)
    over["network_key"]["frame_counter"]=(1<<32)-200
    bs2,ds2=zipped(pa,over,("1122334455667788","0102030405060708"))
    mustfail("NETWORK_COUNTER_OVERFLOW",lambda:m.analyze(pa,[],bs2,ds2))
    # A staged private secret must never be placed under source/worktree.
    mustfail("PRIVATE_ROOT_REQUIRED",lambda:m.stage_private(root/"do-not-stage",report,proposal))
print("P7U_P10_MIGRATION_SECURITY_HOST_TEST_PASS")
