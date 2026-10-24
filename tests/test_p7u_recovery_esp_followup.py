"""Hostile tests for the actual one-shot follow-up helper; synthetic data only."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("esp_followup", Path(__file__).parents[1] / "host/recovery/incident_native_esp_followup.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
SOURCE = "a" * 40


class Fake:
    def __init__(self):
        self.calls = []
        self.button = "unknown"
        self.fail = False
        self.running = False
        self.receipts = {"RADIO_RESET_PENDING": {"recorded_utc": "2026-10-23T23:31:09+00:00"}}

    def owners(self):
        m.require(not self.running, "OWNER_RUNNING")
        return {m.ORIGINAL: m.FAILED_CONTAINER}

    def guard_admission(self):
        return self.receipts

    def host_proof(self):
        return [{"utc": time.time(), "proof": {"serial_opened": False}}] * 3

    def api(self, path, payload=None):
        self.calls.append((path, payload))
        if payload is None:
            return {"state": self.button}
        if self.fail:
            raise TimeoutError("ambiguous synthetic reply")
        self.button = "2026-10-24T01:00:00+00:00"
        return [] if "button/press" in path else {"result": "ok"}


class Followup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "source-3921b7923025"
        self.root.mkdir()
        self.data = Path(self.tmp.name) / "data"
        self.data.mkdir()
        self.backend = Fake()
        for folder in m.JOURNALS:
            path = self.root.parent / folder / "journal"
            path.mkdir(parents=True, exist_ok=True)
            (path / "events.jsonl").write_text(json.dumps({"phase": "DB_APPROVED", "evidence": {"cold_backup": {
                "archive": "cold.bin", "sha256": m.hashlib.sha256(b"synthetic").hexdigest()}}}) + "\n" + json.dumps({"phase": "HOLD"}) + "\n")
        (self.root / "cold.bin").write_bytes(b"synthetic")
        journals = {f: m.hashlib.sha256((self.root.parent / f / "journal/events.jsonl").read_bytes()).hexdigest() for f in m.JOURNALS}
        for name in ("native-radio-fallback.intent.json", "native-original-final-start.intent.json", "manual-esp-restart.intent.json"):
            (self.root / name).write_text(json.dumps({"incident_id": m.INCIDENT}))
        (self.root / "native-final-warning.intent.json").write_text(json.dumps({"operation": "report_recovery_exhausted", "physical_action": False}))
        (self.root / "native-final-start.private.log").write_text("synthetic failure")
        (self.data / "database.db").write_bytes(b"synthetic database")
        (self.data / "coordinator_backup.json").write_bytes(b"synthetic backup")
        (self.data / ".p7u-approved.json").write_text(json.dumps({"devices": 107, "rows": 128, "database_sha256": m.hashlib.sha256(b"synthetic database").hexdigest()}))
        self.patches = [patch.object(m, "DATA", self.data), patch.object(m, "JOURNALS", journals),
                        patch.object(m, "LOG_SHA", m.hashlib.sha256(b"synthetic failure").hexdigest()),
                        patch.object(m, "BACKUP_SHA", m.hashlib.sha256(b"synthetic backup").hexdigest())]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def plan(self, stage="esp"):
        return m.snapshot(self.root, self.backend, stage, SOURCE)

    def apply(self, stage="esp"):
        plan = self.plan(stage)
        return m.perform(self.root, self.backend, stage, plan, m.digest(plan))

    def test_plan_does_not_actuate(self):
        self.plan()
        self.assertFalse(any(payload is not None for _, payload in self.backend.calls))
        self.assertFalse(list(self.root.glob("native-post-radio*")))

    def test_exact_native_button_only_then_replay_refused(self):
        self.assertEqual(self.apply(), 0)
        self.assertEqual([x for x in self.backend.calls if x[1] is not None], [("/core/api/services/button/press", {"entity_id": m.TARGET})])
        with self.assertRaisesRegex(RuntimeError, "NO_REPLAY"):
            self.apply()

    def test_ambiguous_reply_is_durable_and_never_repeated(self):
        self.backend.fail = True
        self.assertEqual(self.apply(), 2)
        result = json.loads((self.root / "native-post-radio-esp-only.result.json").read_text())
        self.assertEqual(result["status"], "AMBIGUOUS_NO_RETRY")
        with self.assertRaisesRegex(RuntimeError, "NO_REPLAY"):
            self.apply()

    def test_mismatched_hash_never_acts(self):
        plan = self.plan()
        with self.assertRaisesRegex(RuntimeError, "PLAN_HASH"):
            m.perform(self.root, self.backend, "esp", plan, "0" * 64)
        self.assertFalse(any(payload is not None for _, payload in self.backend.calls))

    def test_changed_database_blocks(self):
        plan = self.plan()
        (self.data / "database.db").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "DATABASE_NOT_ADMITTED"):
            m.perform(self.root, self.backend, "esp", plan, m.digest(plan))

    def test_old_journal_changes_cannot_be_reconciled_silently(self):
        (self.root / "journal/events.jsonl").write_text("changed")
        with self.assertRaisesRegex(RuntimeError, "OLD_HOLD_HISTORY_CHANGED"):
            self.plan()

    def test_pending_database_blocks(self):
        (self.data / ".p7u-approved.json.pending").write_text("pending")
        with self.assertRaisesRegex(RuntimeError, "DATABASE_NOT_ADMITTED"):
            self.plan()

    def test_unknown_owner_blocks(self):
        self.backend.running = True
        with self.assertRaisesRegex(RuntimeError, "OWNER_RUNNING"):
            self.plan()

    def test_prior_manual_esp_after_radio_blocks_repeat(self):
        self.backend.button = "2026-10-24T01:00:00+00:00"
        with self.assertRaisesRegex(RuntimeError, "ESP_ALREADY_PRESSED_AFTER_RADIO"):
            self.plan()

    def test_intent_symlink_blocks_before_side_effect(self):
        (self.root / "native-post-radio-esp-only.intent.json").symlink_to(self.root / "missing")
        with self.assertRaisesRegex(RuntimeError, "NO_REPLAY"):
            self.plan()

    def test_start_requires_actual_ack_and_grace(self):
        with self.assertRaisesRegex(RuntimeError, "PRIVATE_EVIDENCE_UNSAFE"):
            self.plan("start")
        self.apply()
        with self.assertRaisesRegex(RuntimeError, "ESP_GRACE"):
            self.plan("start")
        p = self.root / "native-post-radio-esp-only.result.json"
        d = json.loads(p.read_text());d["utc"] -= 30;p.write_text(json.dumps(d))
        self.assertEqual(self.apply("start"), 0)
        self.assertEqual(self.backend.calls[-1], ("/addons/" + m.ORIGINAL + "/start", {}))
        with self.assertRaisesRegex(RuntimeError, "NO_REPLAY"):
            self.apply("start")

    def test_start_never_accepts_ambiguous_esp_result(self):
        self.backend.fail = True
        self.apply()
        with self.assertRaisesRegex(RuntimeError, "ESP_RECEIPT_NOT_ACKNOWLEDGED"):
            self.plan("start")

    def test_host_proof_staleness_blocks(self):
        self.backend.host_proof = lambda: [{"utc": time.time() - 40}]
        with self.assertRaisesRegex(RuntimeError, "HOST_PROOF_STALE"):
            self.apply()

    def test_only_three_fixed_posts_are_permitted(self):
        b = m.Backend()
        for path, payload in [("/addons/foreign/start", {}), ("/core/api/services/button/press", {"entity_id": "button.flash"}),
                              ("/core/api/services/button/press", {"entity_id": m.TARGET, "extra": True})]:
            with self.assertRaisesRegex(RuntimeError, "SIDE_EFFECT_NOT_ALLOWED"):
                b.api(path, payload)

    def test_global_lock_refuses_second_executor(self):
        import fcntl
        lock = self.root.parent / "exclusive-manager.lock"
        lock.touch()
        with lock.open("r+") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(m, "ROOT", self.root):
                with self.assertRaises(BlockingIOError):
                    m.remote_main("plan", "esp", "", SOURCE)


class HostNamespaceProof(unittest.TestCase):
    def test_stale_container_epoch_never_counts(self):
        b = m.Backend()
        b.info = lambda slug: {"state": "stopped", "protected": False, "host_pid": True}
        b.docker = lambda slug: {"Id": "same", "Image": m.INSPECTOR_IMAGE, "State": {"Running": False, "ExitCode": 0}, "HostConfig": {"PidMode": "host"}}
        b.api = lambda path, payload=None: {"result": "ok"}
        with patch.object(m.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "HOST_INSPECTOR_EPOCH_INVALID"):
                b.host_proof()

    def test_wrong_image_or_private_namespace_never_counts(self):
        for image, namespace in [("wrong", "host"), (m.INSPECTOR_IMAGE, "private")]:
            b = m.Backend()
            b.info = lambda slug: {"state": "stopped", "protected": False, "host_pid": True}
            ids = iter(["old", "new"])
            b.docker = lambda slug: {"Id": next(ids), "Image": image, "State": {"Running": False, "ExitCode": 0}, "HostConfig": {"PidMode": namespace}}
            b.api = lambda path, payload=None: {"result": "ok"}
            with patch.object(m.time, "sleep"):
                with self.assertRaisesRegex(RuntimeError, "HOST_INSPECTOR_EPOCH_INVALID"):
                    b.host_proof()

    def test_any_host_holder_prevents_actuation(self):
        b = m.Backend()
        b.info = lambda slug: {"state": "stopped", "protected": False, "host_pid": True}
        ids = iter(["old", "new"])
        b.docker = lambda slug: {"Id": next(ids), "Image": m.INSPECTOR_IMAGE, "State": {"Running": False, "ExitCode": 0}, "HostConfig": {"PidMode": "host"}}
        proof = {"schema": "p7u-host-tty-cgroup-evidence-v2", "exclusive_owner_verified": True, "serial_opened": False,
                 "tty_holders_pids": [123], "slots": {x: {"running": False} for x in ["official", "diagnostic", "fallback"]}}
        b.api = lambda path, payload=None: {"result": "ok"} if payload is not None else json.dumps(proof)
        with patch.object(m.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "HOST_OWNERSHIP_NOT_PROVEN"):
                b.host_proof()


class CommittedSource(unittest.TestCase):
    def test_windows_checkout_sends_exact_committed_bytes(self):
        committed = b"print('synthetic')\n"
        self.assertEqual(m.qualified_source(committed.replace(b"\n", b"\r\n"), committed), committed)

    def test_any_code_change_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "HELPER_NOT_EXACT_SOURCE"):
            m.qualified_source(b"changed()\r\n", b"original()\n")
