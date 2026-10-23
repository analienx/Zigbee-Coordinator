"""Passive MQTT serving evidence tests: no network, no actuation."""
import json
from pathlib import Path
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

sys.path.insert(0,str(Path(__file__).parent))
import p7u_serving_mqtt as m
from p7u_lifecycle_core import LifecycleHold

def cfg():
    return m.Config("emqx.internal",1883,"","",("KitchenSocket","BedroomSocket","HallwaySocket"),
                    "sensor.zigbee2mqtt_bridge_state")

class Tests(unittest.TestCase):
    def setUp(self):
        self.e=m.FreshMqttEvidence(cfg())
        self.t=self.e.started_monotonic+1

    def event(self,name,*,retained=False,payload=None):
        if payload is None:
            payload=json.dumps({"power":3,"last_seen":int((self.e.started_utc_seconds+0.5)*1000)}).encode()
        self.e.observe(topic="zigbee2mqtt/"+name,payload=payload,retained=retained,now=self.t)

    def test_only_three_fresh_distinct_device_payloads_pass(self):
        self.event("KitchenSocket")
        self.event("KitchenSocket")
        self.event("BedroomSocket")
        self.assertFalse(self.e.result()["mqtt_messages_fresh"])
        self.event("HallwaySocket")
        self.assertEqual(self.e.result()["fresh_devices"],3)
        self.assertTrue(self.e.result()["mqtt_messages_fresh"])

    def test_retained_bridge_availability_and_stale_payload_never_count(self):
        self.event("KitchenSocket",retained=True)
        self.event("BedroomSocket",payload=b'{"availability":"online"}')
        self.event("bridge/state")
        self.e.observe(topic="zigbee2mqtt/HallwaySocket",payload=b'{"power":6}',
                       retained=False,now=self.e.started_monotonic-1)
        self.assertEqual(self.e.result()["fresh_devices"],0)

    def test_tampered_and_unapproved_topics_no_pass(self):
        self.event("HallwaySocket/set")
        self.event("zigbee2mqtt/#")
        self.event("KitchenSocket",payload=b"\xff")
        self.event("KitchenSocket",payload=b"not-json")
        self.assertEqual(self.e.result()["fresh_devices"],0)

    def test_config_disallows_command_topics_and_actuating_ha_domains(self):
        bad=m.Config("emqx.internal",1883,"","",
                     ("KitchenSocket/set","BedroomSocket","HallwaySocket"),
                     "switch.kitchen_socket")
        with self.assertRaisesRegex(LifecycleHold,"PINNED_DEVICE_TOPICS"):
            bad.validate()
        b=m.Config("emqx.internal",1883,"","",
                   ("KitchenSocket","BedroomSocket","HallwaySocket"),
                   "switch.kitchen_socket")
        with self.assertRaisesRegex(LifecycleHold,"HA_NON_ACTUATING_READ_ENTITY"):
            b.validate()

    def test_no_nonactuating_state_if_only_two_devices(self):
        self.event("KitchenSocket")
        self.event("BedroomSocket")
        self.assertFalse(self.e.result()["non_actuating_read"])

    def test_fresh_payload_is_not_physical_active_zigbee_read(self):
        self.event("KitchenSocket")
        self.event("BedroomSocket")
        self.event("HallwaySocket")
        result=self.e.result()
        self.assertTrue(result["mqtt_messages_fresh"])
        self.assertFalse(result["non_actuating_read"])

    def test_nonretained_startup_cache_and_missing_last_seen_never_count(self):
        self.event("KitchenSocket",payload=json.dumps({"power":3,
                   "last_seen":int((self.e.started_utc_seconds-3600)*1000)}).encode())
        self.event("BedroomSocket",payload=b'{"power":3}')
        self.event("HallwaySocket",payload=json.dumps({"power":3,
                   "last_seen":"2020-01-01T00:00:00Z"}).encode())
        self.assertEqual(self.e.result()["fresh_devices"],0)

    def test_last_seen_accepts_epoch_seconds_ms_and_timezone_iso_only_when_fresh(self):
        fresh=self.e.started_utc_seconds+0.5
        # Use a whole-second boundary strictly after start for seconds.
        self.event("KitchenSocket",payload=json.dumps({"power":3,"last_seen":int(fresh)+1}).encode())
        self.event("BedroomSocket",payload=json.dumps({"power":3,"last_seen":int(fresh*1000)}).encode())
        self.event("HallwaySocket",payload=json.dumps({"power":3,
                   "last_seen":m.datetime.fromtimestamp(fresh,m.timezone.utc).isoformat()}).encode())
        self.assertEqual(self.e.result()["fresh_devices"],3)
        for value in (True,1.5,"NaN","2026-10-23T00:00:00",None,10**1000):
            self.assertIsNone(self.e._last_seen_seconds(value))

    def test_real_paho_v2_reasoncode_subscribes_and_collects_without_publish(self):
        # Keep the production callback ABI real: an integer fake hid the
        # TypeError from int(ReasonCode) in the original hosted tests.
        import paho.mqtt.client as mqtt
        from paho.mqtt.reasoncodes import ReasonCode
        from paho.mqtt.packettypes import PacketTypes
        client=MagicMock()
        def connected():
            client.on_connect(client,None,SimpleNamespace(session_present=False),
                              ReasonCode(PacketTypes.CONNACK,"Success"),None)
            for name in cfg().expected_topics:
                client.on_message(client,None,SimpleNamespace(topic="zigbee2mqtt/"+name,
                    payload=json.dumps({"power":3,"last_seen":int((self.e.started_utc_seconds+0.1)*1000)}).encode(),
                    retain=False))
        client.loop_start.side_effect=connected
        with patch.object(mqtt,"Client",return_value=client):
            result=self.e.collect(180,ha_reader=lambda entity:{"read_only":True,"valid":True})
        self.assertEqual(result,{"fresh_devices":3,"mqtt_messages_fresh":True,
                                 "non_actuating_read":True})
        self.assertEqual(client.subscribe.call_count,3)
        client.publish.assert_not_called()
        client.disconnect.assert_called_once()
        client.loop_stop.assert_called_once()

if __name__=="__main__":
    unittest.main()
