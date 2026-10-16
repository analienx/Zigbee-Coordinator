"""R4-B3 offline-only authority adversarial tests (synthetic values, no live backups)."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
import zipfile

PATH = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/b3/tools/b3_migration_sim.py"
spec = importlib.util.spec_from_file_location("b3_migration_sim", PATH)
sim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sim)


def network():
    return {"coordinator": "SIM-COORD-A", "pan": "SIM-PAN-A",
            "extpan": "SIM-EXTPAN-A", "channel": 11,
            "nwk_key_ref": "SIM-NWK-A", "key_sequence": 1}


def snapshot(n=3, counter=102, layout="NV2", time="2026-10-16T14:00:00Z"):
    return {"network": network(), "captured_utc": time, "source_radio": "SIM-RADIO-A",
            "online": False, "layout": layout,
            "security": [{"device": f"SIM-D{i:03}", "key_ref": f"SIM-LINK-{i:03}",
                          "tx_counter": counter + i} for i in range(n)]}


def good(n=3):
    return {"coordinator_backup.json": {"snapshots": [snapshot(n)]},
            "z2m_database.json": {"network": network(),
                                   "devices": [f"SIM-D{i:03}" for i in range(n)]},
            "z2m_config.json": {"network": network(), "active_radio": "SIM-RADIO-A"}}


def archive(parts=None, mutate=None, add=None):
    parts = good() if parts is None else copy.deepcopy(parts)
    raw_members = {name: json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
                   for name, obj in parts.items()}
    manifest = {"schema": "r4-b3-synthetic-v1", "synthetic": True,
                "target_layout": "NV2",
                "member_sha256": {k: hashlib.sha256(v).hexdigest()
                                  for k, v in raw_members.items()}}
    if mutate:
        mutate(manifest, raw_members)
    raw_members["manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
    with io.BytesIO() as fd:
        with zipfile.ZipFile(fd, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for name in sorted(raw_members):
                z.writestr(name, raw_members[name])
            if add:
                name, payload = add
                z.writestr(name, payload)
        raw = fd.getvalue()
    return raw, hashlib.sha256(raw).hexdigest()


def check(parts=None, mutate=None, add=None, wrong_pin=False):
    raw, digest = archive(parts, mutate, add)
    return sim.judge(raw, "0" * 64 if wrong_pin else digest)


class OfflineAuthorityTests(unittest.TestCase):
    def assertDenied(self, result, code=None):
        self.assertFalse(result["restore_authorized"])
        self.assertFalse(result["flash_authorized"])
        self.assertFalse(result["network_mutation_authorized"])
        self.assertEqual(result["source_authentication"], "NOT_ESTABLISHED")
        if code:
            self.assertEqual(result["status"], "NOT_RESTORE_READY")
            self.assertIn(code, result["reason_codes"])

    def test_m36_consistent_is_still_not_authorized(self):
        result = check()
        self.assertEqual(result["status"], "OFFLINE_CONSISTENT_FOR_REVIEW")
        self.assertEqual(result["reason_codes"], [])
        self.assertDenied(result)

    def test_m17_106_128_160_192_synthetic_rows(self):
        for n in (106, 128, 160, 192):
            with self.subTest(n=n):
                result = check(good(n))
                self.assertEqual(result["counts"]["latest_security_rows"], n)
                self.assertEqual(result["status"], "OFFLINE_CONSISTENT_FOR_REVIEW")
                self.assertDenied(result)

    def test_m28_three_missing_three_stale(self):
        parts = good(106)
        rows = parts["coordinator_backup.json"]["snapshots"][-1]["security"]
        del rows[:3]
        for i in range(106, 109):
            rows.append({"device": f"SIM-D{i:03}", "key_ref": f"SIM-LINK-{i:03}",
                         "tx_counter": 100})
        result = check(parts)
        self.assertDenied(result, "MISSING_SECURITY_RECORDS")
        self.assertIn("STALE_SECURITY_RECORDS", result["reason_codes"])
        self.assertEqual(result["counts"]["db_missing_security"], 3)
        self.assertEqual(result["counts"]["security_not_in_db"], 3)

    def test_m29_higher_tx_in_older_snapshot(self):
        parts = good()
        old = snapshot(counter=500, time="2026-10-14T14:00:00Z")
        parts["coordinator_backup.json"]["snapshots"].insert(0, old)
        self.assertDenied(check(parts), "COUNTER_FLOOR_CONFLICT")

    def test_m30_key_conflict_in_other_epoch(self):
        parts = good()
        old = snapshot(time="2026-10-14T14:00:00Z")
        old["security"][0]["key_ref"] = "SIM-DIFFERENT-KEY"
        parts["coordinator_backup.json"]["snapshots"].insert(0, old)
        self.assertDenied(check(parts), "CHANGED_LINK_KEY")

    def test_m31_same_ieee_two_online_radios(self):
        parts = good()
        old = snapshot(time="2026-10-14T14:00:00Z")
        old["online"] = True
        parts["coordinator_backup.json"]["snapshots"][-1]["online"] = True
        parts["coordinator_backup.json"]["snapshots"].insert(0, old)
        parts["coordinator_backup.json"]["snapshots"][-1]["source_radio"] = "SIM-RADIO-B"
        parts["z2m_config.json"]["active_radio"] = "SIM-RADIO-B"
        self.assertDenied(check(parts), "SAME_IEEE_DOUBLE_ONLINE")

    def test_m32_cross_network_config(self):
        parts = good()
        parts["z2m_database.json"]["network"]["extpan"] = "SIM-OTHER"
        self.assertDenied(check(parts), "CROSS_NETWORK_CONFLICT")

    def test_m33_layout_mismatch(self):
        parts = good()
        parts["coordinator_backup.json"]["snapshots"][0]["layout"] = "NV5"
        self.assertDenied(check(parts), "NV_LAYOUT_MISMATCH")

    def test_m19_counter_overflow(self):
        parts = good()
        parts["coordinator_backup.json"]["snapshots"][0]["security"][0]["tx_counter"] = 0xFFFFFFFF
        self.assertDenied(check(parts), "COUNTER_OVERFLOW")

    def test_m20_tx_floor_conflict(self):
        parts = good()
        older = snapshot(counter=1000, time="2026-10-14T14:00:00Z")
        parts["coordinator_backup.json"]["snapshots"].insert(0, older)
        self.assertDenied(check(parts), "COUNTER_FLOOR_CONFLICT")

    def test_m23_missing_required_key(self):
        parts = good()
        parts["coordinator_backup.json"]["snapshots"][0]["security"].pop()
        self.assertDenied(check(parts), "MISSING_SECURITY_RECORDS")

    def test_m26_nested_old_backup(self):
        self.assertDenied(check(add=("stale/coordinator_backup.json", b"{}")),
                          "ZIP_MEMBER_SELECTION")

    def test_m27_zip_duplicate_member(self):
        self.assertDenied(check(add=("manifest.json", b"{}")), "ZIP_DUPLICATE_MEMBER")

    def test_m27_zip_path_traversal(self):
        self.assertDenied(check(add=("../coordinator_backup.json", b"{}")),
                          "ZIP_MEMBER_SELECTION")

    def test_m27_member_hash_forgery(self):
        self.assertDenied(check(mutate=lambda man, _: man["member_sha256"].__setitem__(
            "coordinator_backup.json", "0" * 64)), "MEMBER_HASH_MISMATCH")

    def test_m34_external_hash_mismatch(self):
        self.assertDenied(check(wrong_pin=True), "EXTERNAL_SHA_MISMATCH")

    def test_m34_untrusted_claim_not_authenticated(self):
        result = check(mutate=lambda man, _: man.__setitem__("source_authenticated", True))
        self.assertEqual(result["source_authentication"], "NOT_ESTABLISHED")
        self.assertDenied(result)

    def test_duplicate_security_device(self):
        parts = good()
        rows = parts["coordinator_backup.json"]["snapshots"][0]["security"]
        rows.append(copy.deepcopy(rows[0]))
        self.assertDenied(check(parts), "DUPLICATE_SECURITY_DEVICE")

    def test_stale_snapshot_out_of_order(self):
        parts = good()
        parts["coordinator_backup.json"]["snapshots"].append(snapshot(
            time="2026-10-13T14:00:00Z"))
        self.assertDenied(check(parts), "SNAPSHOT_TIME_ORDER")

    def test_unsanitized_identifiers_rejected(self):
        parts = good()
        parts["z2m_config.json"]["network"]["pan"] = "0x1a62"
        self.assertDenied(check(parts), "NON_SYNTHETIC_ID")

    def test_negative_counter_rejected(self):
        parts = good()
        parts["coordinator_backup.json"]["snapshots"][0]["security"][0]["tx_counter"] = -1
        self.assertDenied(check(parts), "INVALID_TX_COUNTER")

    def test_boolean_counter_rejected(self):
        parts = good()
        parts["coordinator_backup.json"]["snapshots"][0]["security"][0]["tx_counter"] = True
        self.assertDenied(check(parts), "INVALID_TX_COUNTER")

    def test_non_synthetic_marker_rejected(self):
        self.assertDenied(check(mutate=lambda man, _: man.__setitem__("synthetic", False)),
                          "NON_SYNTHETIC_BUNDLE")

    def test_m27_zip_symlink(self):
        parts = good()
        raw, _ = archive(parts)
        # A ZIP symlink is metadata-driven, not a filename ending in /.
        with zipfile.ZipFile(io.BytesIO(raw), "r") as z:
            members = {n: z.read(n) for n in z.namelist()}
        with io.BytesIO() as out:
            with zipfile.ZipFile(out, "w") as z:
                for n, data in members.items():
                    info = zipfile.ZipInfo(n)
                    if n == "manifest.json":
                        info.create_system = 3
                        info.external_attr = (0o120777 << 16)
                    z.writestr(info, data)
            hostile = out.getvalue()
        self.assertDenied(sim.judge(hostile, hashlib.sha256(hostile).hexdigest()),
                          "ZIP_SYMLINK")

    def test_bad_layout_is_typechecked_not_traceback(self):
        self.assertDenied(check(mutate=lambda man, _: man.__setitem__(
            "target_layout", {"nested": "NV2"})), "UNKNOWN_TARGET_LAYOUT")

    def test_bad_snapshot_layout_is_typechecked_not_traceback(self):
        parts = good()
        parts["coordinator_backup.json"]["snapshots"][0]["layout"] = ["NV2"]
        self.assertDenied(check(parts), "UNKNOWN_NV_LAYOUT")

    def test_invalid_calendar_date_rejected(self):
        parts = good()
        parts["coordinator_backup.json"]["snapshots"][0][
            "captured_utc"] = "2026-99-99T14:00:00Z"
        self.assertDenied(check(parts), "INVALID_SNAPSHOT_TIME")

    def test_missing_snapshot_network_key_rejected(self):
        parts = good()
        del parts["coordinator_backup.json"]["snapshots"][0]["network"]["nwk_key_ref"]
        self.assertDenied(check(parts), "INVALID_NETWORK_IDENTITY")

    def test_external_pin_required(self):
        raw, _ = archive()
        self.assertDenied(sim.judge(raw, ""), "EXTERNAL_SHA_REQUIRED")

    def test_oversize_archive_fails_before_zip_parse(self):
        huge = b"x" * (sim.MAX_ARCHIVE + 1)
        self.assertDenied(sim.judge(huge, hashlib.sha256(huge).hexdigest()),
                          "ARCHIVE_SIZE")

    def test_manifest_false_auth_claim_never_grants_authority(self):
        result = check(mutate=lambda man, _: man.__setitem__(
            "origin_signature_verified", True))
        self.assertDenied(result)
        self.assertEqual(result["status"], "OFFLINE_CONSISTENT_FOR_REVIEW")

    def test_hostile_duplicate_json_field_rejected(self):
        def mutate(man, contents):
            data = contents["z2m_config.json"]
            contents["z2m_config.json"] = b'{"network":{},"network":{},"active_radio":"SIM-RADIO-A"}'
            man["member_sha256"]["z2m_config.json"] = hashlib.sha256(
                contents["z2m_config.json"]).hexdigest()
        self.assertDenied(check(mutate=mutate), "DUPLICATE_JSON_KEY")


if __name__ == "__main__":
    unittest.main()
