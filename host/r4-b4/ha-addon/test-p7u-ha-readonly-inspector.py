"""Hosted mock-only read-only HA process/tty holder inspection tests."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import p7u_ha_readonly_inspector as m
from p7u_lifecycle_core import LifecycleHold


def owner(pid=1001, cid="a"):
    return {"Id": cid*64, "Image": "sha256:"+"b"*64,
            "State": {"Running": True, "Pid": pid, "StartedAt": "2026-10-23T08:00:00.000Z"}}


class Tests(unittest.TestCase):
    def test_readonly_tty_proof_matches_exact_known_owner(self):
        with patch.object(m,"check_host_namespace"), \
             patch.object(m,"inspect_docker",side_effect=[owner(),None]), \
             patch.object(m,"tty_holders",return_value=frozenset({1001})), \
             patch.object(m,"inspect_addon",return_value={"state":"started"}):
            r=m.inspect("/dev/serial/by-id/serial-P7U")
        self.assertTrue(r["only_known_owners_hold_serial"])
        self.assertFalse(r["mutation_authorized"])
        self.assertFalse(r["serial_opened"])
        self.assertEqual(r["slots"]["official"]["pid"],1001)

    def test_unknown_third_process_must_not_be_reported_as_safe(self):
        with patch.object(m,"check_host_namespace"), \
             patch.object(m,"inspect_docker",side_effect=[owner(),None]), \
             patch.object(m,"tty_holders",return_value=frozenset({1001,5151})), \
             patch.object(m,"inspect_addon",return_value={"state":"started"}):
            self.assertFalse(m.inspect("/dev/serial/by-id/serial-P7U")["only_known_owners_hold_serial"])

    def test_two_running_addons_never_pass_one_owner(self):
        with patch.object(m,"check_host_namespace"), \
             patch.object(m,"inspect_docker",side_effect=[owner(),owner(pid=2002,cid="c")]), \
             patch.object(m,"tty_holders",return_value=frozenset({1001,2002})), \
             patch.object(m,"inspect_addon",return_value={"state":"started"}):
            data=m.inspect("/dev/serial/by-id/serial-P7U")
        self.assertEqual(sum(v["running"] for v in data["slots"].values()),2)
        # The full lifecycle admission must additionally reject 2 active
        # owners, even when both are individually known.
        self.assertTrue(data["only_known_owners_hold_serial"])

    def test_disallow_shell_or_arbitrary_addon_slot(self):
        with self.assertRaisesRegex(LifecycleHold,"UNRECOGNIZED_SLOT"):
            m.inspect_docker("evil && reboot")

    def test_invalid_path_denied_before_any_proc_fd_scan(self):
        with self.assertRaisesRegex(LifecycleHold, "SERIAL_BY_ID_REQUIRED"):
            m.tty_holders("/dev/ttyUSB0; reboot")

    def test_supervisor_options_are_never_returned(self):
        from types import SimpleNamespace
        payload={"result":"ok","data":{"state":"started","version":"1",
            "options":{"mqtt":{"password":"do-not-print"}}}}
        with patch.object(m.subprocess,"run",return_value=SimpleNamespace(
            returncode=0,stdout=json.dumps(payload),stderr=""
        )):
            s=m.inspect_addon("guard")
        self.assertEqual(s["state"],"started")
        self.assertNotIn("options",s)
        self.assertNotIn("do-not-print",json.dumps(s))


if __name__=="__main__":
    unittest.main()
