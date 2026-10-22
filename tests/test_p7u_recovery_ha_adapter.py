"""Offline HA adapter and passive data tests. No network or HA accessed."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from dataclasses import replace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "recovery"))
from ha_adapter import Configuration, HAActuator, SmlightControl, ControlError
from observer import PassiveObserver, start_failure_kind

class FakeHA:
    def __init__(self):
        self.calls = []
        self.state = "error"
    def addon_state(self,slug):
        self.calls.append(("state",slug))
        return self.state
    def service(self,slug,op):
        self.calls.append(("service",op))
        return True
    def button(self,entity):
        self.calls.append(("button",entity))
        return True
    def hardware_has_port(self,byid):
        self.calls.append(("physical_usb",byid))
        return True

class FakeRadio:
    def __init__(self):
        self.calls = []
    def private_restart(self,kind):
        self.calls.append(kind)
        if kind not in ("RESTART_ESP","RESET_RADIO"):
            raise AssertionError("wrong")
        return True

class AdapterTests(unittest.TestCase):
    def test_first_line_esp_route(self):
        cfg=Configuration(allow_private_http_fallback=True)
        h=FakeHA();r=FakeRadio()
        a=HAActuator(cfg,h,r,lambda:True)
        self.assertTrue(a.perform_once("RESTART_ESP"))
        self.assertEqual(r.calls,["RESTART_ESP"])
        self.assertEqual(h.calls,[])

    def test_native_core_button_preferred(self):
        cfg=Configuration(allow_private_http_fallback=True,
            esp_restart_entity="button.slzb_core_restart")
        h=FakeHA();r=FakeRadio();a=HAActuator(cfg,h,r,lambda:True)
        self.assertTrue(a.perform_once("RESTART_ESP"))
        self.assertEqual(h.calls,[("button","button.slzb_core_restart")])
        self.assertFalse(r.calls)

    def test_private_fallback_must_be_opted_in(self):
        cfg=Configuration()
        a=HAActuator(cfg,FakeHA(),FakeRadio(),lambda:True)
        with self.assertRaises(ControlError):
            a.perform_once("RESTART_ESP")

    def test_unknown_reset_command_forbidden(self):
        cfg=Configuration(allow_private_http_fallback=True)
        with self.assertRaises(ControlError):
            HAActuator(cfg,FakeHA(),FakeRadio(),lambda:True).perform_once("HARD_RESET")

    def test_z2m_start_requires_physical_usb(self):
        h=FakeHA()
        h.hardware_has_port=lambda port:False
        a=HAActuator(Configuration(),h,FakeRadio(),lambda:True)
        with self.assertRaises(ControlError):
            a.perform_once("START_Z2M")
        self.assertFalse(any(x[0]=="service" for x in h.calls))

    def test_safe_web_actuator_exact_commands(self):
        c=SmlightControl(Configuration(allow_private_http_fallback=True))
        calls=[]
        def mock_fetch(path,query=None,*,timeout=8):
            calls.append((path,query))
            if path=="/ha_info":
                return '{"Info":{"model":"SLZB-06p7U","zb_hw":"CC2652P7","coord_mode":2}}'
            if path=="/js/httpApi.js":
                return 'apiLink="/api2?action=" API_CMD:4 CMD_ZB_RST:1 CMD_ESP_RES:3 CMD_HARD_RESET:9'
            if path=="/api2" and query=={"action":4,"cmd":3}:
                return "ok"
            raise AssertionError("Unexpected network call")
        with patch.object(c,"fetch",side_effect=mock_fetch):
            self.assertTrue(c.private_restart("RESTART_ESP"))
        self.assertEqual(calls[-1],("/api2",{"action":4,"cmd":3}))

    def test_wrong_slzb_identity_never_mutates(self):
        c=SmlightControl(Configuration())
        calls=[]
        def fake_fetch(path,query=None,*,timeout=8):
            calls.append(path)
            return '{"Info":{"model":"SLZB-06p10U","zb_hw":"CC2674","coord_mode":2}}'
        with patch.object(c,"fetch",side_effect=fake_fetch):
            with self.assertRaises(ControlError):
                c.private_restart("RESTART_ESP")
        self.assertEqual(calls,["/ha_info"])

    def test_no_external_host_or_https_bypass(self):
        for url in ("http://example.com","https://192.168.50.59",
                    "http://192.168.50.59:9999",
                    "http://192.168.50.59@evil.com"):
            with self.assertRaises(ControlError):
                SmlightControl(Configuration(slzb_url=url))


class ObserverTests(unittest.TestCase):
    def test_no_retained_device_topics(self):
        obs=PassiveObserver()
        # Feed callbacks through a disposable fake paho client.
        class M:
            pass
        fake=M()
        cb={}
        fake.on_connect=None;fake.on_disconnect=None;fake.on_message=None
        fake.subscribe=lambda *a,**k:None
        fake.connect=lambda *a,**k:None
        fake.loop_start=lambda:None
        class Mod:
            class CallbackAPIVersion:
                VERSION2=2
            @staticmethod
            def Client(*args,**kwargs):
                return fake
        import observer as mod
        with patch.object(mod,"mqtt",Mod):
            obs.start("broker",1883,"","")
        fake.on_connect(fake,None,None,0,None)
        def send(name,retained):
            msg=M()
            msg.topic="zigbee2mqtt/"+name
            msg.retain=retained
            msg.payload=b'{"state":"online"}'
            fake.on_message(fake,None,msg)
        send("KitchenSocketRight",True)
        send("BedroomSocketRight",False)
        send("bridge/state",True)
        self.assertEqual(obs.sample()["fresh_device_topics_120s"],1)
        self.assertFalse(obs.sample()["bridge_online_fresh"])
        send("bridge/state",False)
        self.assertTrue(obs.sample()["bridge_online_fresh"])

    def test_deduplicate_live_log_and_exclude_older_epoch(self):
        obs=PassiveObserver()
        text=(
          '[2026-10-22 19:29:10] error: Failed to ping \'a\' (SRSP - AF - dataRequest after 6000ms)\n'
          '[2026-10-22 19:29:10] error: Failed to ping \'b\' (SRSP - AF - dataRequest after 6000ms)\n'
          '[2026-10-22 19:29:10] info: MQTT publish: topic \'zigbee2mqtt/bridge/response/permit_join\', payload \'SRSP - AF - dataRequest after 6000ms\'\n'
        )
        from datetime import datetime
        from zoneinfo import ZoneInfo
        now=datetime(2026,10,22,19,29,20,tzinfo=ZoneInfo("Europe/Prague")).timestamp()
        obs.read_log(text,now)
        obs.read_log(text,now+2)
        result=obs.sample(now+2)
        self.assertEqual(result["srsp_120s"],2)
        self.assertEqual(result["affected_devices_120s"],2)
        self.assertEqual(start_failure_kind(text,now),"")

    def test_sys_ping_only_from_recent_log(self):
        from datetime import datetime
        from zoneinfo import ZoneInfo
        at=datetime(2026,10,22,19,30,10,tzinfo=ZoneInfo("Europe/Prague")).timestamp()
        old='[2026-10-16 09:01:02] error: SRSP - SYS - ping after 6000ms'
        now='[2026-10-22 19:30:02] error: SRSP - SYS - ping after 6000ms'
        self.assertEqual(start_failure_kind(old,at),"")
        self.assertEqual(start_failure_kind(now,at),"SRSP_SYS_PING")

if __name__=="__main__":unittest.main()
