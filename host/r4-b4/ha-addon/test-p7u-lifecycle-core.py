"""GH-hosted source-only negative controls for the P7U lifecycle core."""
import importlib.util
import json
from pathlib import Path
import os
import tempfile
import unittest
import sys

MODULE = Path(__file__).with_name("p7u_lifecycle_core.py")
spec = importlib.util.spec_from_file_location("p7u_lifecycle_core", MODULE)
assert spec is not None and spec.loader is not None
lib = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lib
spec.loader.exec_module(lib)


def docker(cid="a", pid=1001, started="2026-10-23T08:00:00.000000Z"):
    return {
        "Id": cid * 64,
        "Image": "sha256:" + "c" * 64,
        "State": {"Running": True, "Pid": pid, "StartedAt": started},
    }


class OwnerTests(unittest.TestCase):
    def test_pinned_generation_matches(self):
        identity = lib.Owner.from_inspect(docker())
        identity.require_same_generation(lib.Owner.from_inspect(docker()))

    def test_reused_container_name_cannot_be_killed(self):
        identity = lib.Owner.from_inspect(docker())
        with self.assertRaisesRegex(lib.LifecycleHold, "OWNER_IDENTITY_CHANGED"):
            lib.require_no_replacement(identity, docker(cid="b"))

    def test_pid_or_creation_time_change_is_not_same_generation(self):
        identity = lib.Owner.from_inspect(docker())
        with self.assertRaisesRegex(lib.LifecycleHold, "OWNER_IDENTITY_CHANGED"):
            identity.require_same_generation(lib.Owner.from_inspect(docker(pid=2002)))
        with self.assertRaisesRegex(lib.LifecycleHold, "OWNER_IDENTITY_CHANGED"):
            identity.require_same_generation(lib.Owner.from_inspect(
                docker(started="2026-10-23T08:00:59.000000Z")))

    def test_stopped_or_ambiguous_inspect_is_not_safe(self):
        value = docker()
        value["State"]["Running"] = False
        with self.assertRaisesRegex(lib.LifecycleHold, "NOT_RUNNING"):
            lib.Owner.from_inspect(value)
        with self.assertRaisesRegex(lib.LifecycleHold, "IDENTITY_ID"):
            lib.Owner.from_inspect({**docker(), "Id": "not-sha"})

    def test_fallback_requires_distinct_qualified_image(self):
        image = "b" * 64
        c = {
            "diagnostic_profile_sha": image, "fallback_profile_sha": image,
            "identity_inspection": True, "tty_fd_inspection": True,
            "source_database_gate": True, "save_before_adapter_close": True,
        }
        with self.assertRaisesRegex(lib.LifecycleHold, "FALLBACK_NOT_INDEPENDENT"):
            lib.require_host_capabilities(c)
        c["fallback_profile_sha"] = "f" * 64
        lib.require_host_capabilities(c)
        c["tty_fd_inspection"] = False
        with self.assertRaisesRegex(lib.LifecycleHold, "CAPABILITY_UNQUALIFIED"):
            lib.require_host_capabilities(c)


class JournalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "private"
        self.root.mkdir(mode=0o700)

    def test_roundtrip_fsynced_chain(self):
        with lib.Journal(self.root) as j:
            one = j.append("PREFLIGHT", {"owner": docker()["Id"]})
            two = j.append("STOP_INTENT", {"pinned": one})
            self.assertNotEqual(one, two)
        with lib.Journal(self.root) as replay:
            self.assertEqual(replay.seq, 2)
            self.assertEqual(replay.phase, "STOP_INTENT")
            self.assertEqual(replay.head, two)

    def test_second_manager_cannot_acquire_lock(self):
        with lib.Journal(self.root):
            with self.assertRaisesRegex(lib.LifecycleHold, "MANAGER_ALREADY_RUNNING"):
                with lib.Journal(self.root):
                    pass

    def test_lost_stop_ack_does_not_allow_repeat_stop(self):
        with lib.Journal(self.root) as j:
            j.append("PREFLIGHT", {})
            j.append("STOP_INTENT", {})
        with lib.Journal(self.root) as j:
            with self.assertRaisesRegex(lib.LifecycleHold, "AMBIGUOUS_PREVIOUS_INTENT"):
                j.append("STOP_INTENT", {})
            j.append("HOLD", {"why": "ack lost"})
        with lib.Journal(self.root) as j:
            self.assertEqual(j.phase, "HOLD")
            with self.assertRaisesRegex(lib.LifecycleHold, "AMBIGUOUS_PREVIOUS_INTENT"):
                j.append("START_INTENT", {})

    def test_after_exact_owner_absent_evidence_reconciliation_is_explicit(self):
        with lib.Journal(self.root) as j:
            j.append("PREFLIGHT", {})
            j.append("STOP_INTENT", {})
            j.append("OWNER_ABSENT", {"verified_by": "three tty holder checks"})
            j.append("START_INTENT", {"owner_image": "sha256:" + "d" * 64})
            j.append("OWNER_SERVING", {"mqtt": True})
            j.append("COMMITTED", {"evidence": "valid"})
        with lib.Journal(self.root) as j:
            self.assertEqual((j.seq, j.phase), (6, "COMMITTED"))

    def test_torn_tail_forces_hold_no_automatic_truncate(self):
        with lib.Journal(self.root) as j:
            j.append("PREFLIGHT", {})
        journal = self.root / "events.jsonl"
        with journal.open("ab") as fp:
            fp.write(b'{"seq":2')
        before = journal.read_bytes()
        with self.assertRaisesRegex(lib.LifecycleHold, "TORN_JOURNAL_TAIL"):
            with lib.Journal(self.root):
                pass
        self.assertEqual(journal.read_bytes(), before)

    def test_tampered_journal_hash_forces_hold(self):
        with lib.Journal(self.root) as j:
            j.append("PREFLIGHT", {"approved": True})
        journal = self.root / "events.jsonl"
        line = json.loads(journal.read_text())
        line["evidence"]["approved"] = False
        journal.write_text(json.dumps(line) + "\n")
        with self.assertRaisesRegex(lib.LifecycleHold, "JOURNAL_CHAIN"):
            with lib.Journal(self.root):
                pass

    def test_private_permissions_are_mandatory(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(lib.LifecycleHold, "JOURNAL_PERMISSIONS"):
            with lib.Journal(self.root):
                pass
        self.root.chmod(0o700)

    def test_no_repair_or_truncation_after_corrupt_record(self):
        with lib.Journal(self.root) as j:
            j.append("PREFLIGHT", {})
        journal = self.root / "events.jsonl"
        journal.write_bytes(b"{bad}\n")
        with self.assertRaisesRegex(lib.LifecycleHold, "JOURNAL_CORRUPT"):
            with lib.Journal(self.root):
                pass
        self.assertEqual(journal.read_bytes(), b"{bad}\n")


if __name__ == "__main__":
    unittest.main()
