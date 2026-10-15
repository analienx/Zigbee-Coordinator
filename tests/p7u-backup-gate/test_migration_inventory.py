#!/usr/bin/env python3
"""Retained/cross-stack material coverage, no device/database modifications."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile

from test_backup_gate import v, setup, IEEE, A, B, FAKE_NWK_KEY, FAKE_LINK, FAKE_SEED, rejected


def main():
    now = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        backup, db = root/"backup.json", root/"database.db"
        db.write_text("\n".join(json.dumps({"type": kind, "ieeeAddr": ieee})
                                 for kind, ieee in (("Router", A), ("EndDevice", B)))+"\n")
        def run(data):
            backup.write_text(json.dumps(data))
            before = (backup.read_bytes(), db.read_bytes())
            report = v.migration_inventory(backup, db, now, IEEE)
            assert before == (backup.read_bytes(), db.read_bytes())
            encoded = json.dumps(report)
            for secret in (IEEE, A, B, FAKE_NWK_KEY, FAKE_LINK, FAKE_SEED):
                assert secret not in encoded
            assert report["same_network_restore_qualified"] is False
            assert report["individual_security_relationships_verified"] is False
            return report
        original = setup(now)
        report = run(original)
        assert report["source_stack"] == "zstack" and report["zstack_tc_seed_present"]
        assert report["devices_with_explicit_link_key_and_counters"] == 1
        assert report["devices_without_explicit_link_key_record"] == 1
        # Old Ember source is assessable, without passing the strict same-family gate.
        original["stack_specific"] = {"ezsp": {"hashed_tclk": "44"*16}}
        original["metadata"]["internal"]["date"] = (now-timedelta(days=60)).isoformat()
        report = run(original)
        assert report["source_stack"] == "ember" and not report["zstack_tc_seed_present"]
        assert report["backup_age_hours"] == 60*24
        rejected(lambda: v.qualify(backup, db, IEEE, now=now), "BACKUP_TOO_OLD_OR_FUTURE")
        original["devices"].pop()
        assert run(original)["database_devices_missing_from_backup"] == 1
        original["network_key"]["frame_counter"] = v.UINT32_MAX
        assert not run(original)["nwk_counter_has_headroom"]
        rejected(lambda: v.migration_inventory(backup, db, now, "00124bfffffffffe"),
                 "BACKUP_COORDINATOR_IEEE_MISMATCH")
        original["devices"][0]["link_key"]["tx_counter"] = -1
        backup.write_text(json.dumps(original))
        rejected(lambda: v.migration_inventory(backup, db, now, IEEE), "LINK_TX_INVALID_COUNTER")
    print("P7U_CROSS_STACK_MIGRATION_MATERIAL_COVERAGE_PASS_NO_RESTORE")


if __name__ == "__main__":
    main()
