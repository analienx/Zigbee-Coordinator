"""Passive MQTT serving evidence tests: no network, no actuation."""
import json
from pathlib import Path
import sys
import time
import unittest
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

    def event(self,name,*,retained=False,payload=b'{"power":3}'):
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

if __name__=="__main__":
    unittest.main()
