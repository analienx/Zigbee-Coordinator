"""Hosted temporary-file and mock-only entry-point tests; no live host I/O."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "ha-addon"))
sys.path.insert(0, str(HERE.parent))
spec = importlib.util.spec_from_file_location("p7u_lifecycle_main", HERE / "p7u_lifecycle_main.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

SOURCE_SHA = "e" * 40


def plan():
    return {
        "schema": "p7u-one-shot-plan-v1", "source_sha": SOURCE_SHA,
        "operation_id": "f72c0f59-d13e-4f07-9b95-51d912241a82",
        "serial_by_id": "/dev/serial/by-id/verified-device",
        "original_slot": "official", "target_slot": "diagnostic",
        "original_owner": {"container_id": "a" * 64, "pid": 123,
            "started_at": "2026-10-23T08:00:00.000Z", "image_digest": "sha256:" + "b" * 64},
        "diagnostic_image_sha256": "c" * 64, "fallback_image_sha256": "d" * 64,
        "preserved_backup_path": "/backup/retained-host.tar",
        "preserved_backup_sha256": "f" * 64,
        "mqtt": {"host": "core-mosquitto", "port": 1883, "username": "private", "password": "secret"},
        "expected_topics": ["DeviceOne", "DeviceTwo", "DeviceThree"],
        "ha_entity_id": "sensor.device_one",
        "image_references": {slot: "localhost:50144/p7u-r4-" + slot + ":0.2.1-" + SOURCE_SHA[:12]
                             for slot in ("diagnostic", "fallback")},
    }


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.operation = self.private / "operation"
        self.operation.mkdir(mode=0o700)
        self.source = self.root / "SOURCE_SHA"
        self.source.write_text(SOURCE_SHA + "\n")
        for name, value in (("PRIVATE_ROOT", self.private), ("SOURCE", self.source)):
            p = patch.object(m, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.path = self.operation / "plan.json"

    def write_plan(self, value=None):
        raw = (json.dumps(value or plan(), sort_keys=True) + "\n").encode()
        self.path.write_bytes(raw)
        self.path.chmod(0o600)
        return hashlib.sha256(raw).hexdigest()

    def test_plan_binds_exact_source_image_references_and_bytes(self):
        digest = self.write_plan()
        self.assertEqual(m.load_plan(self.path, digest), plan())
        self.path.write_bytes(self.path.read_bytes() + b" ")
        with self.assertRaisesRegex(m.LifecycleHold, "PLAN_SHA_MISMATCH"):
            m.load_plan(self.path, digest)

    def test_different_source_or_mutable_image_tag_is_hold(self):
        p = plan()
        p["image_references"]["diagnostic"] = "localhost:50144/p7u-r4-diagnostic:latest"
        digest = self.write_plan(p)
        with self.assertRaisesRegex(m.LifecycleHold, "PLAN_SOURCE_IMAGE_REFERENCE"):
            m.load_plan(self.path, digest)
        p = plan(); p["source_sha"] = "a" * 40
        digest = self.write_plan(p)
        with self.assertRaisesRegex(m.LifecycleHold, "MANAGER_SOURCE_SHA"):
            m.load_plan(self.path, digest)

    def test_explicit_database_renewal_is_hash_bound_and_only_from_official_owner(self):
        p = plan(); p["previous_approval_sha256"] = "1" * 64
        digest = self.write_plan(p)
        self.assertEqual(m.load_plan(self.path, digest)["previous_approval_sha256"], "1" * 64)
        p["original_slot"] = "fallback"
        digest = self.write_plan(p)
        with self.assertRaisesRegex(m.LifecycleHold, "PLAN_DB_RENEWAL_SCOPE"):
            m.load_plan(self.path, digest)
        p["original_slot"] = "official"; p["previous_approval_sha256"] = "invalid"
        digest = self.write_plan(p)
        with self.assertRaisesRegex(m.LifecycleHold, "PLAN_DB_RENEWAL_SCOPE"):
            m.load_plan(self.path, digest)

    def test_plan_outside_private_directory_or_symlink_is_hold(self):
        digest = self.write_plan()
        outside = self.root / "outside.json"
        outside.write_bytes(self.path.read_bytes())
        with self.assertRaisesRegex(m.LifecycleHold, "PRIVATE_PLAN_PATH"):
            m.load_plan(outside, digest)
        link = self.operation / "linked.json"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(m.LifecycleHold, "PRIVATE_PLAN_PATH"):
            m.load_plan(link, digest)

    def test_public_readable_plan_is_hold(self):
        digest = self.write_plan()
        self.path.chmod(0o644)
        with self.assertRaisesRegex(m.LifecycleHold, "PRIVATE_PLAN_PERMISSIONS"):
            m.load_plan(self.path, digest)

    def test_preflight_never_enters_manager_or_creates_journal(self):
        digest = self.write_plan()
        with patch.object(m, "PreservingPort") as port, \
             patch.object(m, "validate_live_plan") as validate, \
             patch.object(m, "Manager") as manager:
            result = m.run({"plan_path": str(self.path), "plan_sha256": digest, "execute": False})
        self.assertEqual(result["status"], "PREFLIGHT_PASS")
        self.assertFalse(result["service_mutated"])
        validate.assert_called_once()
        manager.assert_not_called()
        self.assertFalse((self.operation / "journal").exists())

    def test_existing_intent_never_repeats_stop_or_start(self):
        digest = self.write_plan()
        journal = self.operation / "journal"
        journal.mkdir(mode=0o700)
        with m.Journal(journal) as j:
            j.append("PREFLIGHT", {})
            j.append("STOP_INTENT", {"pinned_container_id": "a" * 64})
        with patch.object(m, "PreservingPort"), \
             patch.object(m, "validate_live_plan"), \
             patch.object(m, "Manager") as manager:
            with self.assertRaisesRegex(m.LifecycleHold, "PRIOR_OPERATION_REQUIRES_RECONCILIATION"):
                m.run({"plan_path": str(self.path), "plan_sha256": digest, "execute": True})
        manager.assert_not_called()

    def test_another_operation_directory_cannot_hide_prior_intent(self):
        digest = self.write_plan()
        with m.global_operation_lock():
            m.claim_operation(plan(), digest)
        with patch.object(m, "PreservingPort"), \
             patch.object(m, "validate_live_plan"), \
             patch.object(m, "Manager") as manager:
            with self.assertRaisesRegex(m.LifecycleHold, "PRIOR_GLOBAL_OPERATION_REQUIRES_RECONCILIATION"):
                m.run({"plan_path": str(self.path), "plan_sha256": digest, "execute": True})
        manager.assert_not_called()

    def test_global_lock_excludes_second_open_description(self):
        with m.global_operation_lock():
            with self.assertRaisesRegex(m.LifecycleHold, "ANOTHER_MANAGER_RUNNING"):
                with m.global_operation_lock():
                    self.fail("second manager acquired the singleton lock")

    def test_cold_backup_contains_current_database_and_is_exclusive(self):
        data = self.root / "zigbee2mqtt"
        data.mkdir()
        database = data / "database.db"
        database.write_bytes(b'{"id":1,"type":"Coordinator","ieeeAddr":"0x00124b0000000001"}\n')
        (data / "coordinator_backup.json").write_bytes(b'{"private":"retained"}')
        with patch.object(m, "DATABASE", database):
            receipt = m.cold_backup(self.operation)
            archive = self.operation / receipt["archive"]
            self.assertEqual(receipt["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            with tarfile.open(archive) as backup:
                self.assertEqual(backup.extractfile("zigbee2mqtt/database.db").read(), database.read_bytes())
                self.assertIn("zigbee2mqtt/coordinator_backup.json", backup.getnames())
            with self.assertRaisesRegex(m.LifecycleHold, "COLD_BACKUP_ALREADY_EXISTS"):
                m.cold_backup(self.operation)

    def test_symlink_data_tree_is_rejected_before_stop(self):
        data = self.root / "zigbee2mqtt"
        data.mkdir()
        database = data / "database.db"
        database.write_bytes(b"retained")
        (data / "external").symlink_to(self.source)
        with patch.object(m, "DATABASE", database):
            with self.assertRaisesRegex(m.LifecycleHold, "HOST_DATA_UNAPPROVED_SYMLINK"):
                m.data_files()

    def test_allowlisted_node_modules_symlink_is_archived_without_following(self):
        data = self.root / "zigbee2mqtt"
        data.mkdir()
        database = data / "database.db"
        database.write_bytes(b"retained")
        extension = data / "external_extensions"
        extension.mkdir()
        (extension / "node_modules").symlink_to("/app/node_modules")
        with patch.object(m, "DATABASE", database):
            receipt = m.cold_backup(self.operation)
        with tarfile.open(self.operation / receipt["archive"]) as archive:
            entry = archive.getmember("zigbee2mqtt/external_extensions/node_modules")
            self.assertTrue(entry.issym())
            self.assertEqual(entry.linkname, "/app/node_modules")
            self.assertFalse(any(p.startswith(entry.name + "/") for p in archive.getnames()))

    def test_cold_backup_never_runs_with_owner_still_running(self):
        with patch.object(m.HaSupervisorPort, "__init__", return_value=None):
            port = m.PreservingPort("serial", artifact_directory=self.operation)
        port.inspect = MagicMock(return_value=MagicMock(running=True))
        with patch.object(m, "cold_backup") as backup:
            with self.assertRaisesRegex(m.LifecycleHold, "COLD_BACKUP_OWNER_STILL_RUNNING"):
                port.approve_quiesced_database({})
        backup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
