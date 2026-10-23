"""Hosted mock-only tests for immutable host cgroup + Docker top holder proof."""
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import p7u_ha_readonly_inspector as m
from p7u_lifecycle_core import LifecycleHold, Owner

CID = "a" * 64
CGROUP = "/system.slice/docker-" + CID + ".scope"


def raw(pid=1001, cid=CID):
    return {
        "Id": cid, "Image": "sha256:" + "b" * 64,
        "State": {"Running": True, "Pid": pid,
                  "StartedAt": "2026-10-23T08:00:00.000Z"}
    }


def proof():
    owner = Owner.from_inspect(raw())
    return m.ContainerProof(owner, frozenset({1001, 1042}),
                            ((1001, 100000), (1042, 100005)), CGROUP)


class Tests(unittest.TestCase):
    def mock_proof(self, holders=frozenset({1042}), official=raw(), diagnostic=None,
                   fallback=None):
        return (
            patch.object(m, "check_host_namespace"),
            patch.object(m, "inspect_docker", side_effect=[official, diagnostic, fallback]),
            patch.object(m, "prove_container", return_value=proof()),
            patch.object(m, "tty_holders", return_value=holders),
            patch.object(m, "proc_identity",
                         side_effect=lambda pid: (100005 if pid == 1042 else 100000, CGROUP)),
            patch.object(m, "inspect_addon", return_value={"state": "started"})
        )

    def test_real_node_child_fd_qualifies(self):
        contexts = self.mock_proof()
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4], contexts[5]:
            r = m.inspect("/dev/serial/by-id/usb-P7U")
        self.assertTrue(r["exclusive_owner_verified"])
        self.assertEqual(r["tty_holders_pids"], [1042])
        self.assertEqual(r["slots"]["official"]["init_pid"], 1001)
        self.assertFalse(r["mutation_authorized"])
        self.assertFalse(r["serial_opened"])

    def test_foreign_uart_holder_holds(self):
        contexts = self.mock_proof(holders=frozenset({1042, 5151}))
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4], contexts[5]:
            self.assertFalse(m.inspect("/dev/serial/by-id/usb-P7U")["exclusive_owner_verified"])

    def test_no_uart_fd_is_not_an_active_serving_owner(self):
        contexts = self.mock_proof(holders=frozenset())
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4], contexts[5]:
            self.assertFalse(m.inspect("/dev/serial/by-id/usb-P7U")["exclusive_owner_verified"])

    def test_multiple_container_owners_hold_even_if_one_fd(self):
        contexts = self.mock_proof(diagnostic=raw(pid=2002, cid="c" * 64))
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4], contexts[5]:
            self.assertFalse(m.inspect("/dev/serial/by-id/usb-P7U")["exclusive_owner_verified"])

    def test_prove_container_requires_docker_membership_and_same_host_cgroup(self):
        with patch.object(m,"docker_top_pids",return_value=frozenset({1001,1042})), \
             patch.object(m,"proc_identity",
                          side_effect=lambda pid: (100000 if pid == 1001 else 100005, CGROUP)):
            value=m.prove_container(raw())
        self.assertEqual(value.eligible_pids, frozenset({1001,1042}))
        with patch.object(m,"docker_top_pids",return_value=frozenset({1001,1042})), \
             patch.object(m,"proc_identity",
                          side_effect=lambda pid: (100000, CGROUP if pid == 1001 else "/foreign")):
            with self.assertRaisesRegex(LifecycleHold,"FOREIGN_CGROUP_PROCESS"):
                m.prove_container(raw())

    def test_pid_reuse_after_docker_top_causes_hold(self):
        with patch.object(m,"docker_top_pids",return_value=frozenset({1001,1042})), \
             patch.object(m,"proc_identity",
                          side_effect=[(100000,CGROUP), (100000,CGROUP),
                                       (100005,CGROUP),(100001,CGROUP)]):
            with self.assertRaisesRegex(LifecycleHold, "PROCESS_PID_REUSED"):
                m.prove_container(raw())

    def test_bind_tty_holder_requires_exact_stable_ticks(self):
        p=proof()
        with patch.object(m,"proc_identity",return_value=(100005,CGROUP)):
            self.assertEqual(m.bind_tty_to_owner(frozenset({1042}),p),
                             frozenset({1042}))
        with self.assertRaisesRegex(LifecycleHold,"FOREIGN_UART_OWNER"):
            m.bind_tty_to_owner(frozenset({1042,5151}),p)
        with patch.object(m,"proc_identity",return_value=(999999,CGROUP)):
            with self.assertRaisesRegex(LifecycleHold,"UART_OWNER_PID_REUSED"):
                m.bind_tty_to_owner(frozenset({1042}),p)

    def test_no_arbitrary_addon_name_or_shell_commands(self):
        with self.assertRaisesRegex(LifecycleHold, "UNRECOGNIZED_SLOT"):
            m.inspect_docker("foo && reboot")
        with self.assertRaisesRegex(LifecycleHold, "SERIAL_BY_ID_REQUIRED"):
            m.tty_holders("/dev/ttyUSB0; reboot")
        with self.assertRaisesRegex(LifecycleHold, "DOCKER_TOP_INVALID_ID"):
            m.docker_top_pids("foo && reboot")

    def test_absent_container_accepts_actual_lowercase_and_uppercase_docker_errors(self):
        for error in (
            "error: no such object: app_local_p7u_r4_native_host\n",
            "Error response from daemon: No such object: app_local_p7u_r4_native_host\n",
            "error: no such container: app_local_p7u_r4_native_host\n",
            "Error response from daemon: No such container: app_local_p7u_r4_native_host\n",
        ):
            with self.subTest(error=error), patch.object(m,"run_argv",
                    return_value=SimpleNamespace(returncode=1,stdout="",stderr=error)):
                self.assertIsNone(m.inspect_docker("diagnostic"))

    def test_other_docker_inspection_failure_is_never_owner_absence(self):
        for error in ("permission denied", "Cannot connect to the Docker daemon", "context deadline exceeded"):
            with self.subTest(error=error), patch.object(m,"run_argv",
                    return_value=SimpleNamespace(returncode=1,stdout="",stderr=error)):
                with self.assertRaisesRegex(LifecycleHold,"DOCKER_INSPECT_UNAVAILABLE"):
                    m.inspect_docker("diagnostic")

    def test_supervisor_options_never_exposed(self):
        from types import SimpleNamespace
        payload={"result":"ok","data":{"state":"started","version":"1",
            "options":{"mqtt":{"password":"secret"}}}}
        with patch.object(m, "run_argv",
                          return_value=SimpleNamespace(returncode=0,
                                                       stdout=json.dumps(payload),stderr="")):
            self.assertEqual(m.inspect_addon("guard"), {
                "state": "started", "boot": None,
                "watchdog": None, "version": "1", "passive": False
            })

    def test_guard_passive_requires_all_four_exact_policy_values(self):
        from types import SimpleNamespace
        policy={"enabled":False,"dry_run":True,"serial_owner_approved":False,
                "allow_private_http_fallback":False,"private_token":"secret"}
        def inspect(options):
            payload={"result":"ok","data":{"state":"started","options":options}}
            with patch.dict(m.os.environ,{},clear=True), patch.object(m,"run_argv",
                    return_value=SimpleNamespace(returncode=0,stdout=json.dumps(payload),stderr="")):
                return m.inspect_addon("guard")
        result=inspect(policy)
        self.assertTrue(result["passive"])
        self.assertNotIn("secret",json.dumps(result))
        for key in policy:
            if key != "private_token":
                self.assertFalse(inspect({**policy,key:not policy[key]})["passive"])

if __name__ == "__main__":
    unittest.main()
