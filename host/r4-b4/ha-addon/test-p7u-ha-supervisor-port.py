"""Adversarial mock Supervisor-port tests; zero HA/serial/Docker mutations."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import p7u_ha_supervisor_port as m
from p7u_lifecycle_core import LifecycleHold, Owner
from p7u_lifecycle_machine import Presence
from p7u_ha_readonly_inspector import ContainerProof

CID = "a"*64
OLD = Owner(CID, 1001, "2026-10-23T08:00:00.000Z", "sha256:"+"b"*64)
NEW_SHA = "d"*64
CG = "/system.slice/docker-"+CID+".scope"

def raw(own, running=True):
    return {"Id":own.container_id, "Image":own.image_digest,
            "State":{"Running":running,"Pid":own.pid,"StartedAt":own.started_at}}

class FakeSupervisor:
    def __init__(self):
        self.requests=[]
        self.unknown_ack=False
    def transport(self, method, slug, action, timeout):
        self.requests.append((method,slug,action,timeout))
        if action=="info":
            return {"result":"ok","data":{
                "state":"started" if "zigbee2mqtt" in slug else "stopped",
                "boot":"manual", "watchdog":False}}
        if self.unknown_ack:
            raise TimeoutError("synthetic lost ACK")
        return {"result":"ok","data":{}}

class Tests(unittest.TestCase):
    def setUp(self):
        self.s=FakeSupervisor()
        self.client=m.Supervisor(transport=self.s.transport)
        self.host=patch.object(m,"check_host_namespace")
        self.host.start()
        self.addCleanup(self.host.stop)
        self.port=m.HaSupervisorPort("/dev/serial/by-id/P7U",
                                     client=self.client,
                                     serving_probe=lambda slot,sec:{
                                         "fresh_devices":3,"mqtt_messages_fresh":True,
                                         "non_actuating_read":True})

    def test_ha_supervisor_api_has_exact_verb_slug_and_narrow_endpoint(self):
        r=self.client.call(method="GET",slot="official",action="info")
        self.assertEqual(r["result"],"ok")
        self.assertEqual(self.s.requests, [
            ("GET","45df7312_zigbee2mqtt","info",20)])
        for slot,method,action in [
            ("official","POST","restart"),("evil","POST","stop"),
            ("diagnostic","GET","stop"),("official","POST","info"),
            ("guard","POST","stop"),("official","POST","install"),
        ]:
            with self.assertRaisesRegex(LifecycleHold,"UNAPPROVED"):
                self.client.call(method=method,slot=slot,action=action)

    def test_no_docker_name_kill_and_pin_child_holder_before_stop(self):
        with patch.object(self.port,"inspect",return_value=Presence(True,OLD)), \
             patch.object(self.port,"tty_holders",return_value=frozenset({1042})), \
             patch.object(self.port,"prove_owner_holders") as proof, \
             patch.object(m,"inspect_addon",return_value={"state":"started"}):
            self.port.pinned["official"]=OLD
            self.assertTrue(self.port.stop("official",timeout_seconds=60))
        proof.assert_called_once_with(OLD,frozenset({1042}))
        self.assertEqual([x[2] for x in self.s.requests],["info","stop"])

    def test_container_reused_before_stop_has_no_mutation(self):
        changed=Owner("e"*64,1001,OLD.started_at,OLD.image_digest)
        with patch.object(self.port,"inspect",return_value=Presence(True,changed)):
            self.port.pinned["official"]=OLD
            with self.assertRaisesRegex(LifecycleHold,"STOP_IDENTITY_CHANGED"):
                self.port.stop("official",timeout_seconds=60)
        self.assertEqual(self.s.requests,[])

    def test_missing_pinned_owner_never_stops(self):
        with self.assertRaisesRegex(LifecycleHold,"STOP_WITHOUT_PINNED_OWNER"):
            self.port.stop("official",timeout_seconds=60)
        self.assertEqual(self.s.requests,[])

    def test_stop_timeout_does_not_retry_or_docker_kill(self):
        self.s.unknown_ack=True
        with patch.object(self.port,"inspect",return_value=Presence(True,OLD)), \
             patch.object(self.port,"tty_holders",return_value=frozenset({1042})), \
             patch.object(self.port,"prove_owner_holders"), \
             patch.object(m,"inspect_addon",return_value={"state":"started"}):
            self.port.pinned["official"]=OLD
            with self.assertRaisesRegex(TimeoutError,"lost ACK"):
                self.port.stop("official",timeout_seconds=60)
        self.assertEqual([x[2] for x in self.s.requests],["info","stop"])

    def test_start_requires_image_staged_and_fully_free_serial(self):
        candidate=Owner("d"*64,2002,"2026-10-23T08:15:00.000Z","sha256:"+NEW_SHA)
        with patch.object(self.port,"tty_holders",return_value=frozenset()), \
             patch.object(self.port,"inspect",return_value=Presence(False,None)), \
             patch.object(m,"inspect_docker",return_value=raw(candidate,False)):
            self.assertTrue(self.port.start("diagnostic",expected_image_sha=NEW_SHA))
        self.assertEqual([x[2] for x in self.s.requests],["info","start"])

    def test_start_fails_on_competing_owner_without_supervisor_calls(self):
        with patch.object(self.port,"tty_holders",return_value=frozenset({1042})):
            with self.assertRaisesRegex(LifecycleHold,"START_SERIAL_HOLDER_PRESENT"):
                self.port.start("diagnostic",expected_image_sha=NEW_SHA)
        self.assertEqual(self.s.requests,[])

    def test_start_fails_on_unstaged_image_before_supervisor_calls(self):
        candidate=Owner("d"*64,2002,"2026-10-23T08:15:00.000Z","sha256:"+"c"*64)
        with patch.object(self.port,"tty_holders",return_value=frozenset()), \
             patch.object(self.port,"inspect",return_value=Presence(False,None)), \
             patch.object(m,"inspect_docker",return_value=raw(candidate,False)):
            with self.assertRaisesRegex(LifecycleHold,"TARGET_STAGED_IMAGE_UNVERIFIED"):
                self.port.start("diagnostic",expected_image_sha=NEW_SHA)
        self.assertEqual(self.s.requests,[])

    def test_prove_owner_holders_accepts_child_node_not_docker_init(self):
        owner=OLD
        pr=ContainerProof(owner,frozenset({1001,1042}),
                          ((1001,100000),(1042,100005)),CG)
        def lookup(slot):
            return raw(OLD) if slot=="official" else None
        with patch.object(m,"inspect_docker",side_effect=lookup), \
             patch.object(m,"prove_container",return_value=pr), \
             patch.object(m,"bind_tty_to_owner") as bind:
            self.port.prove_owner_holders(OLD,frozenset({1042}))
        bind.assert_called_once_with(frozenset({1042}),pr)
        self.assertEqual(self.port.pinned["official"],OLD)

    def test_serving_requires_independent_monitor(self):
        self.assertEqual(self.port.serving_evidence("diagnostic",max_seconds=180)["fresh_devices"],3)
        self.port.serving_probe=None
        with self.assertRaisesRegex(LifecycleHold,"NO_INDEPENDENT_SERVING_MONITOR"):
            self.port.serving_evidence("diagnostic",max_seconds=180)

if __name__=="__main__":
    unittest.main()
