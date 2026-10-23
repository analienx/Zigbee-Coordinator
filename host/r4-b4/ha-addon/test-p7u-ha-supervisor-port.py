"""Adversarial mock Supervisor-port tests; zero HA/serial/Docker mutations."""
import json
import hashlib
from pathlib import Path
import sys
import unittest
import tempfile
from contextlib import nullcontext
from types import SimpleNamespace
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
                "boot":"manual", "watchdog":False,"repository":"local",
                "build":False,"version":"0.1.0"}}
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
                                     database=Path("/config/zigbee2mqtt/database.db"),
                                     image_references={
                                         "diagnostic":"localhost:50144/p7u-r4-diagnostic:0.1.0",
                                         "fallback":"localhost:50144/p7u-r4-fallback:0.1.0"},
                                     automation_probe=lambda:{entity:"off" for entity in m.LEGACY_OWNER_AUTOMATIONS},
                                     client=self.client,
                                     serving_probe=lambda slot,sec:{
                                         "fresh_devices":3,"mqtt_messages_fresh":True,
                                         "non_actuating_read":True})
        self.port.database_receipt={"database_sha256":"e"*64,"generation":"owner-quiesced-test"}
        self.guard_patch=patch.object(m,"inspect_addon",return_value={"state":"started","passive":True})
        self.guard_patch.start()
        self.addCleanup(self.guard_patch.stop)
        self.db_patch=patch.object(m,"verify_committed",return_value=SimpleNamespace(
            database_sha256="e"*64,approval_generation="owner-quiesced-test"))
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.image_patch=patch.object(m,"run_argv",return_value=SimpleNamespace(
            returncode=0,stdout=json.dumps([{"Id":"sha256:"+NEW_SHA}]),stderr=""))
        self.image_command=self.image_patch.start()
        self.addCleanup(self.image_patch.stop)

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
             patch.object(m,"inspect_addon",return_value={"state":"started","passive":True}):
            self.port.pinned["official"]=OLD
            self.assertTrue(self.port.stop("official",timeout_seconds=60))
        proof.assert_called_once_with(OLD,frozenset({1042}))
        self.assertEqual([x[2] for x in self.s.requests if x[0]=="POST"],["stop"])

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
             patch.object(m,"inspect_addon",return_value={"state":"started","passive":True}):
            self.port.pinned["official"]=OLD
            with self.assertRaisesRegex(TimeoutError,"lost ACK"):
                self.port.stop("official",timeout_seconds=60)
        self.assertEqual([x[2] for x in self.s.requests if x[0]=="POST"],["stop"])

    def test_start_requires_image_staged_and_fully_free_serial(self):
        candidate=Owner("d"*64,2002,"2026-10-23T08:15:00.000Z","sha256:"+NEW_SHA)
        with patch.object(self.port,"tty_holders",return_value=frozenset()), \
             patch.object(self.port,"inspect",return_value=Presence(False,None)), \
             patch.object(m,"inspect_docker",return_value=raw(candidate,False)):
            self.assertTrue(self.port.start("diagnostic",expected_image_sha=NEW_SHA))
        self.assertEqual([x[2] for x in self.s.requests if x[0]=="POST"],["start"])
        self.image_command.assert_called_once_with([
            "docker","image","inspect","localhost:50144/p7u-r4-diagnostic:0.1.0"])

    def test_first_start_qualifies_installed_image_without_container(self):
        with patch.object(self.port,"tty_holders",return_value=frozenset()), \
             patch.object(self.port,"inspect",return_value=Presence(False,None)), \
             patch.object(m,"inspect_docker",return_value=None):
            self.assertTrue(self.port.start("diagnostic",expected_image_sha=NEW_SHA))
        self.assertEqual([x[2] for x in self.s.requests if x[0]=="POST"],["start"])

    def test_start_fails_on_competing_owner_without_supervisor_calls(self):
        with patch.object(self.port,"tty_holders",return_value=frozenset({1042})):
            with self.assertRaisesRegex(LifecycleHold,"START_SERIAL_HOLDER_PRESENT"):
                self.port.start("diagnostic",expected_image_sha=NEW_SHA)
        self.assertFalse(any(x[0]=="POST" for x in self.s.requests))

    def test_start_fails_on_unstaged_image_before_supervisor_calls(self):
        candidate=Owner("d"*64,2002,"2026-10-23T08:15:00.000Z","sha256:"+"c"*64)
        with patch.object(self.port,"tty_holders",return_value=frozenset()), \
             patch.object(self.port,"inspect",return_value=Presence(False,None)), \
             patch.object(m,"run_argv",return_value=SimpleNamespace(returncode=0,
                          stdout=json.dumps([{"Id":"sha256:"+"c"*64}]),stderr="")), \
             patch.object(m,"inspect_docker",return_value=raw(candidate,False)):
            with self.assertRaisesRegex(LifecycleHold,"TARGET_STAGED_IMAGE_UNVERIFIED"):
                self.port.start("diagnostic",expected_image_sha=NEW_SHA)
        self.assertFalse(any(x[0]=="POST" for x in self.s.requests))

    def test_start_without_quiesced_receipt_never_mutates(self):
        self.port.database_receipt=None
        with self.assertRaisesRegex(LifecycleHold,"START_WITHOUT_QUIESCED_DATABASE"):
            self.port.start("diagnostic",expected_image_sha=NEW_SHA)
        self.assertFalse(any(x[0]=="POST" for x in self.s.requests))

    def test_armed_guard_or_automatic_original_blocks_stop(self):
        with patch.object(m,"inspect_addon",return_value={"state":"started","passive":False}):
            with self.assertRaisesRegex(LifecycleHold,"GUARD_NOT_PASSIVE"):
                self.port.validate_profiles(original_slot="official",target_slot="diagnostic")
        original=self.s.transport
        def automatic(method,slug,action,timeout):
            result=original(method,slug,action,timeout)
            if action=="info" and slug==m.SLUGS["official"]:
                result["data"]["boot"]="auto"
            return result
        self.client.transport=automatic
        with self.assertRaisesRegex(LifecycleHold,"AUTOMATIC_OWNER_RESTART_ENABLED"):
            self.port.validate_profiles(original_slot="official",target_slot="diagnostic")
        self.assertFalse(any(x[0]=="POST" for x in self.s.requests))

    def test_legacy_owner_automation_requires_both_exact_entities_off(self):
        for entity in m.LEGACY_OWNER_AUTOMATIONS:
            for state in ("on","unknown","unavailable","OFF",""):
                with self.subTest(entity=entity,state=state):
                    policy={name:"off" for name in m.LEGACY_OWNER_AUTOMATIONS}
                    policy[entity]=state
                    self.port.automation_probe=lambda:policy
                    with self.assertRaisesRegex(LifecycleHold,"LEGACY_OWNER_AUTOMATION_NOT_DISABLED"):
                        self.port.validate_profiles(original_slot="official",target_slot="diagnostic")
        self.port.automation_probe=lambda:{next(iter(m.LEGACY_OWNER_AUTOMATIONS)):"off"}
        with self.assertRaisesRegex(LifecycleHold,"LEGACY_OWNER_AUTOMATION_NOT_DISABLED"):
            self.port.validate_profiles(original_slot="official",target_slot="diagnostic")
        self.assertFalse(any(x[0]=="POST" for x in self.s.requests))

    def test_automation_policy_is_rechecked_immediately_before_start_and_stop(self):
        policy={entity:"off" for entity in m.LEGACY_OWNER_AUTOMATIONS}
        self.port.automation_probe=lambda:policy
        with patch.object(self.port,"inspect",return_value=Presence(False,None)):
            self.port.validate_profiles(original_slot="official",target_slot="diagnostic")
        policy["automation.boot_deterministic_emqx_then_zigbee2mqtt"]="on"
        with self.assertRaisesRegex(LifecycleHold,"LEGACY_OWNER_AUTOMATION_NOT_DISABLED"):
            self.port.start("diagnostic",expected_image_sha=NEW_SHA)
        self.port.pinned["official"]=OLD
        with patch.object(self.port,"inspect",return_value=Presence(True,OLD)), \
             patch.object(self.port,"tty_holders",return_value=frozenset({1042})), \
             patch.object(self.port,"prove_owner_holders"):
            with self.assertRaisesRegex(LifecycleHold,"LEGACY_OWNER_AUTOMATION_NOT_DISABLED"):
                self.port.stop("official",timeout_seconds=60)
        self.assertFalse(any(x[0]=="POST" for x in self.s.requests))

    def test_real_automation_reader_only_gets_two_pinned_entity_states(self):
        requests=[]
        def response(request, *, timeout):
            entity=request.full_url.rsplit("/",1)[1]
            self.assertIn(entity,m.LEGACY_OWNER_AUTOMATIONS)
            requests.append((request.get_method(),request.full_url,timeout))
            raw=json.dumps({"entity_id":entity,"state":"off",
                            "attributes":{"private_value":"never returned"}}).encode()
            return nullcontext(SimpleNamespace(read=lambda limit:raw))
        with patch.dict(m.os.environ,{"SUPERVISOR_TOKEN":"synthetic-policy-token-123456789"}), \
             patch.object(m,"urlopen",side_effect=response):
            result=m.read_automation_policy()
        self.assertEqual(result,{entity:"off" for entity in m.LEGACY_OWNER_AUTOMATIONS})
        self.assertEqual(requests,[("GET","http://supervisor/core/api/states/"+entity,7)
                                  for entity in sorted(m.LEGACY_OWNER_AUTOMATIONS)])

    def test_quiesced_gate_checks_release_before_sealing(self):
        baseline={"inventory_sha256":"a"*64}
        with patch.object(self.port,"inspect",return_value=Presence(True,OLD)), \
             patch.object(m,"seal_quiesced") as seal:
            with self.assertRaisesRegex(LifecycleHold,"DB_APPROVAL_COMPETING_CONTAINER"):
                self.port.approve_quiesced_database(baseline)
            seal.assert_not_called()

    def test_quiesced_gate_rechecks_no_owner_after_sealing(self):
        baseline={"inventory_sha256":"a"*64}
        receipt={"schema":"p7u-quiesced-approval-v1","database_sha256":"e"*64,
                 "generation":"owner-quiesced-test"}
        self.port.database_receipt=None
        with patch.object(self.port,"inspect",side_effect=[Presence(False,None)]*3+
                          [Presence(True,OLD)]), \
             patch.object(self.port,"tty_holders",return_value=frozenset()), \
             patch.object(m,"zero_tty_three_times") as tty, \
             patch.object(m,"seal_quiesced",return_value=receipt) as seal:
            with self.assertRaisesRegex(LifecycleHold,"DB_APPROVAL_OWNER_RETURNED"):
                self.port.approve_quiesced_database(baseline)
            tty.assert_called_once_with(self.port)
            seal.assert_called_once()
        self.assertIsNone(self.port.database_receipt)

    def test_current_existing_receipt_is_reused_without_overwriting(self):
        from p7u_host_integrity import verify_committed as real_verify
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory=Path(temporary.name)/"zigbee2mqtt"
        directory.mkdir()
        database=directory/"database.db"
        database.write_text(json.dumps({"id":1,"type":"Coordinator",
                                       "ieeeAddr":"0x00124b0000000001"}))
        first=m.inventory_baseline(database)
        m.seal_quiesced(database=database,baseline=first,
                       all_slots_stopped=True,no_tty_holders=True)
        manifest=directory/".p7u-approved.json"
        saved=manifest.read_bytes()
        self.port.database=database
        with patch.object(m,"verify_committed",side_effect=real_verify), \
             patch.object(self.port,"inspect",return_value=Presence(False,None)), \
             patch.object(self.port,"tty_holders",return_value=frozenset()), \
             patch.object(m,"zero_tty_three_times"), \
             patch.object(m,"seal_quiesced") as seal:
            baseline=self.port.preflight_database()
            self.assertIn("existing_approval",baseline)
            receipt=self.port.approve_quiesced_database(baseline)
            self.assertTrue(receipt["reused"])
            seal.assert_not_called()
        self.assertEqual(manifest.read_bytes(),saved)

    def test_existing_receipt_generation_change_is_hold_without_reseal(self):
        baseline={"existing_approval":{"generation":"owner-quiesced-old",
                                        "database_sha256":"e"*64}}
        with patch.object(self.port,"inspect",return_value=Presence(False,None)), \
             patch.object(m,"zero_tty_three_times"), \
             patch.object(m,"seal_quiesced") as seal:
            with self.assertRaisesRegex(LifecycleHold,"DATABASE_APPROVAL_GENERATION_CHANGED"):
                self.port.approve_quiesced_database(baseline)
            seal.assert_not_called()

    def test_protected_autosave_current_receipt_can_advance_hash_same_generation(self):
        from p7u_host_integrity import verify_committed as real_verify, AdmissionHold
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory=Path(temporary.name)/"zigbee2mqtt"
        directory.mkdir()
        database=directory/"database.db"
        row={"id":1,"type":"Coordinator","ieeeAddr":"0x00124b0000000001"}
        database.write_text(json.dumps(row))
        m.seal_quiesced(database=database,baseline=m.inventory_baseline(database),
                       all_slots_stopped=True,no_tty_holders=True)
        manifest=directory/".p7u-approved.json"
        self.port.database=database
        self.port.database_receipt=None
        with patch.object(m,"verify_committed",side_effect=real_verify), \
             patch.object(self.port,"inspect",return_value=Presence(False,None)), \
             patch.object(self.port,"tty_holders",return_value=frozenset()), \
             patch.object(m,"zero_tty_three_times"), \
             patch.object(m,"seal_quiesced") as seal:
            baseline=self.port.preflight_database()
            row["lastSeen"]=1792700000
            database.write_text(json.dumps(row))
            # A DB/receipt gap is never auto-repaired by the cutover manager.
            with self.assertRaisesRegex(AdmissionHold,"COMMITTED_DATABASE_CHANGED"):
                self.port.approve_quiesced_database(baseline)
            self.assertIsNone(self.port.database_receipt)
            receipt=json.loads(manifest.read_bytes())
            receipt["database_sha256"]=hashlib.sha256(database.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(receipt))
            saved=manifest.read_bytes()
            approved=self.port.approve_quiesced_database(baseline)
            self.assertTrue(approved["reused"])
            self.assertNotEqual(approved["database_sha256"],baseline["database_sha256"])
            self.assertEqual(manifest.read_bytes(),saved)
            seal.assert_not_called()

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
