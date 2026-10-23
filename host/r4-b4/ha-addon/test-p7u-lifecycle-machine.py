"""Adversarial, offline injected-port lifecycle machine tests. No HA calls."""
import tempfile
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import p7u_lifecycle_core as core
import p7u_lifecycle_machine as machine

CAP = {
    "diagnostic_profile_sha": "d"*64, "fallback_profile_sha": "f"*64,
    "identity_inspection": True, "tty_fd_inspection": True,
    "source_database_gate": True, "save_before_adapter_close": True,
}
OLD = core.Owner("a"*64, 1001, "2026-10-23T08:00:00.000Z", "sha256:" + "a"*64)
NEW = core.Owner("b"*64, 2002, "2026-10-23T08:05:00.000Z", "sha256:" + "d"*64)

class Port:
    def __init__(self):
        self.owner = {"official": OLD, "diagnostic": None, "fallback": None}
        self.events = []
        self.stuck = False
        self.lost_ack = False
        self.changed = False
        self.bad_image = False
        self.extra_holder = False
        self.serving = True
    def inspect(self, slot):
        owner = self.owner[slot]
        if self.changed and slot == "official":
            owner = core.Owner("c"*64, 1099, OLD.started_at, OLD.image_digest)
        return machine.Presence(owner is not None, owner)
    def tty_holders(self):
        pids = frozenset(x.pid for x in self.owner.values() if x is not None)
        return pids | (frozenset({5151}) if self.extra_holder else frozenset())
    def prove_owner_holders(self, owner, holders):
        # Synthetic source fixture: in real HA a Node child is proven by
        # docker top + cgroup + stable Linux /proc start time, not main PID.
        from p7u_lifecycle_core import guard
        guard(holders == frozenset({owner.pid}), "FOREIGN_UART_OWNER")
    def stop(self, slot, *, timeout_seconds):
        self.events.append(("stop", slot, timeout_seconds))
        if not self.stuck:
            self.owner[slot] = None
        return not self.lost_ack
    def start(self, slot, *, expected_image_sha):
        self.events.append(("start", slot, expected_image_sha))
        self.owner[slot] = (core.Owner(NEW.container_id, NEW.pid, NEW.started_at, "sha256:"+"e"*64)
                            if self.bad_image else NEW)
        return True
    def serving_evidence(self, slot, *, max_seconds):
        self.events.append(("serve", slot, max_seconds))
        return {"fresh_devices": 3 if self.serving else 0,
                "mqtt_messages_fresh": self.serving,
                "non_actuating_read": self.serving}

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/"private"
        self.root.mkdir(mode=0o700)
        self.port = Port()
        self.sleep_patch = patch.object(machine.time, "sleep", return_value=None)
        self.sleep_patch.start()
        self.addCleanup(self.sleep_patch.stop)

    def switch(self, cap=CAP, **kwargs):
        with core.Journal(self.root) as j:
            return machine.Manager(j, self.port, cap).switch_once(
                original_slot="official", target_slot="diagnostic",
                database_approved=True, guard_passive=True, **kwargs)

    def test_one_owner_success_and_serving_gate(self):
        self.assertEqual(self.switch(), "COMMITTED")
        self.assertEqual(self.port.owner["official"], None)
        self.assertEqual(self.port.owner["diagnostic"], NEW)
        self.assertEqual([e[0] for e in self.port.events].count("start"), 1)
        self.assertEqual([e[0] for e in self.port.events].count("stop"), 1)
        with core.Journal(self.root) as j:
            self.assertEqual(j.phase, "COMMITTED")

    def test_lost_supervisor_stop_ack_reconciles_without_retry(self):
        self.port.lost_ack = True
        self.assertEqual(self.switch(), "COMMITTED")
        self.assertEqual([e[0] for e in self.port.events].count("stop"), 1)
        history = (self.root / "events.jsonl").read_text()
        self.assertIn("STOP_ACK_UNKNOWN", history)

    def test_hanging_stop_no_force_and_no_start(self):
        self.port.stuck = True
        with self.assertRaisesRegex(core.LifecycleHold, "STOP_NOT_VERIFIED"):
            self.switch()
        self.assertEqual([e[0] for e in self.port.events], ["stop"])
        with core.Journal(self.root) as j:
            self.assertEqual(j.phase, "HOLD")

    def test_stale_reused_container_identity_fails_closed(self):
        self.port.stuck = True
        self.port.changed = True
        with self.assertRaisesRegex(core.LifecycleHold, "FOREIGN_UART_OWNER|ORIGINAL_REPLACED"):
            self.switch()
        self.assertFalse(any(a[0] == "start" for a in self.port.events))

    def test_unexpected_tty_holder_blocks_all_effects(self):
        self.port.extra_holder = True
        with self.assertRaisesRegex(core.LifecycleHold, "FOREIGN_UART_OWNER"):
            self.switch()
        self.assertEqual(self.port.events, [])

    def test_mismatched_expected_new_image_holds_without_restarting_original(self):
        self.port.bad_image = True
        with self.assertRaisesRegex(core.LifecycleHold, "TARGET_UNEXPECTED_IMAGE"):
            self.switch()
        self.assertIsNone(self.port.owner["official"])
        self.assertIsNotNone(self.port.owner["diagnostic"])
        self.assertEqual([e[0] for e in self.port.events].count("stop"), 1)
        with core.Journal(self.root) as j:
            self.assertEqual(j.phase, "HOLD")

    def test_insufficient_live_traffic_is_hold_not_host_restart(self):
        self.port.serving = False
        with self.assertRaisesRegex(core.LifecycleHold, "SERVING_UNVERIFIED"):
            self.switch()
        self.assertEqual(len([e for e in self.port.events if e[0] == "stop"]), 1)
        self.assertEqual(len([e for e in self.port.events if e[0] == "start"]), 1)
        self.assertIsNotNone(self.port.owner["diagnostic"])
        self.assertIsNone(self.port.owner["official"])

    def test_actual_node_child_uart_holder_can_be_proven_without_container_init_fd(self):
        orig=self.port.prove_owner_holders
        def descendants(owner, holders):
            self.assertEqual(holders, frozenset({owner.pid+32}))
        self.port.tty_holders=lambda: frozenset(
            {x.pid+32 for x in self.port.owner.values() if x is not None})
        self.port.prove_owner_holders=descendants
        self.assertEqual(self.switch(), "COMMITTED")

    def test_missing_db_approval_never_stops_or_starts(self):
        with core.Journal(self.root) as j:
            with self.assertRaisesRegex(core.LifecycleHold, "DATABASE_OR_GUARD"):
                machine.Manager(j, self.port, CAP).switch_once(
                    original_slot="official", target_slot="diagnostic",
                    database_approved=False, guard_passive=True)
        self.assertEqual(self.port.events, [])

    def test_missing_independent_fallback_is_veto(self):
        cap={**CAP, "fallback_profile_sha": CAP["diagnostic_profile_sha"]}
        with self.assertRaisesRegex(core.LifecycleHold, "FALLBACK_NOT_INDEPENDENT"):
            self.switch(cap)

    def test_crashed_journal_after_stop_intent_never_repeats(self):
        with core.Journal(self.root) as j:
            j.append("PREFLIGHT", {})
            j.append("STOP_INTENT", {})
        with self.assertRaisesRegex(core.LifecycleHold, "UNRECONCILED_JOURNAL"):
            self.switch()
        self.assertEqual(self.port.events, [])

if __name__ == "__main__":
    unittest.main()
