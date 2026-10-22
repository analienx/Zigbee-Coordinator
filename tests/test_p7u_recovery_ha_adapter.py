"""Offline HA adapter and passive data tests. No network or HA accessed."""
from pathlib import Path
import sys
import unittest
import hashlib
import gzip
import io
import json
from tempfile import TemporaryDirectory
from unittest.mock import patch, Mock
from dataclasses import replace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "recovery"))
from ha_adapter import (Configuration, HAActuator, SmlightControl, ControlError,
                        SupervisorClient, verify_native_binding, _NoRedirect)
from observer import PassiveObserver, start_failure_kind

MAC = "aa:bb:cc:dd:ee:ff"
JS = 'apiLink="/api2?action="; const commands={API_CMD:4,CMD_ZB_RST:1,CMD_ESP_RES:3,CMD_HARD_RESET:9};'
CFG = Configuration(expected_mac=MAC,
                    expected_js_sha256=hashlib.sha256(JS.encode()).hexdigest())


def write_registries(directory, unique_id=None, platform="smlight", mac=MAC):
    entity = {"entity_id": "button.slzb_core_restart", "platform": platform,
              "unique_id": unique_id or MAC + "-core_restart", "device_id": "board",
              "config_entry_id": "entry", "disabled_by": None}
    device = {"id": "board", "connections": [["mac", mac]], "config_entries": ["entry"]}
    for name, key, value in (("core.entity_registry", "entities", entity),
                             ("core.device_registry", "devices", device)):
        (Path(directory) / name).write_text(json.dumps({"data": {key: [value]}}))

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
    def identity(self):
        return {"MAC": MAC}
    def private_restart(self,kind):
        self.calls.append(kind)
        if kind not in ("RESTART_ESP","RESET_RADIO"):
            raise AssertionError("wrong")
        return True

class AdapterTests(unittest.TestCase):
    def test_installed_gzip_script_is_bounded_and_hashed_as_decoded_source(self):
        class Response(io.BytesIO):
            status=200
            headers={"Content-Encoding":"gzip"}
        c=SmlightControl(CFG)
        with patch.object(c.opener,"open",return_value=Response(gzip.compress(JS.encode()))):
            self.assertEqual(c.fetch("/js/httpApi.js"),JS)
        with patch.object(c.opener,"open",return_value=Response(gzip.compress(b"x"*300001))):
            with self.assertRaises(ControlError):
                c.fetch("/js/httpApi.js")

    def test_first_line_esp_route(self):
        cfg=replace(CFG,allow_private_http_fallback=True)
        h=FakeHA();r=FakeRadio()
        a=HAActuator(cfg,h,r,lambda:True)
        self.assertTrue(a.perform_once("RESTART_ESP"))
        self.assertEqual(r.calls,["RESTART_ESP"])
        self.assertEqual(h.calls,[("physical_usb",cfg.expected_by_id), ("state",cfg.addon_slug)])

    def test_native_core_button_preferred(self):
        with TemporaryDirectory() as temp:
            write_registries(temp)
            cfg=replace(CFG,allow_private_http_fallback=True,
                esp_restart_entity="button.slzb_core_restart", registry_directory=temp)
            h=FakeHA();r=FakeRadio();a=HAActuator(cfg,h,r,lambda:True)
            self.assertTrue(a.perform_once("RESTART_ESP"))
            self.assertEqual(h.calls[-1],("button","button.slzb_core_restart"))
            self.assertFalse(r.calls)

    def test_private_fallback_must_be_opted_in(self):
        cfg=CFG
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
        a=HAActuator(CFG,h,FakeRadio(),lambda:True)
        with self.assertRaises(ControlError):
            a.perform_once("START_Z2M")
        self.assertFalse(any(x[0]=="service" for x in h.calls))

    def test_running_owner_blocks_radio_reset_and_duplicate_start(self):
        for action in ("RESTART_ESP", "RESET_RADIO", "START_Z2M"):
            with self.subTest(action=action):
                ha, radio = FakeHA(), FakeRadio()
                ha.state = "started"
                with self.assertRaises(ControlError):
                    HAActuator(replace(CFG, allow_private_http_fallback=True),
                               ha, radio, lambda: True).perform_once(action)
                self.assertEqual(radio.calls, [])
                self.assertFalse(any(c[0] == "service" for c in ha.calls))

    def test_safe_web_actuator_exact_commands(self):
        c=SmlightControl(replace(CFG,allow_private_http_fallback=True))
        calls=[]
        def mock_fetch(path,query=None,*,timeout=8):
            calls.append((path,query))
            if path=="/ha_info":
                return json.dumps({"Info":{"model":"SLZB-06p7U","zb_hw":"CC2652P7",
                                  "coord_mode":2,"sw_version":"v3.4.3.dev1","MAC":MAC}})
            if path=="/js/httpApi.js":
                return JS
            if path=="/api2" and query=={"action":4,"cmd":3}:
                return "ok"
            raise AssertionError("Unexpected network call")
        with patch.object(c,"fetch",side_effect=mock_fetch):
            self.assertTrue(c.private_restart("RESTART_ESP"))
        self.assertEqual(calls[-1],("/api2",{"action":4,"cmd":3}))

    def test_wrong_slzb_identity_never_mutates(self):
        c=SmlightControl(CFG)
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
                    "http://192.168.50.59@evil.com",
                    "http://192.168.50.59?cmd=9", "http://192.168.50.59/#api"):
            with self.assertRaises(ControlError):
                SmlightControl(Configuration(slzb_url=url))

    def test_exact_usb_inventory_membership_only(self):
        c=SupervisorClient("fake")
        path="/dev/serial/by-id/"+CFG.expected_by_id
        good={"by_id":path,"subsystem":"tty","dev_path":"/dev/ttyACM0"}
        for device,expected in ((good,True), ({**good,"by_id":path+"-other"},False),
                                ({**good,"subsystem":"usb"},False),
                                ({**good,"by_id":None,"attributes":{"hint":path}},False)):
            with patch.object(c,"call",return_value={"result":"ok","data":{"devices":[device]}}):
                self.assertEqual(c.hardware_has_port(CFG.expected_by_id),expected)

    def test_options_from_other_addon_info_not_self_only_endpoint(self):
        c=SupervisorClient("fake")
        with patch.object(c,"call",return_value={"result":"ok","data":{"options":{"serial":{}}}}) as call:
            self.assertEqual(c.addon_options(CFG.addon_slug),{"serial":{}})
        call.assert_called_once_with("/addons/"+CFG.addon_slug+"/info")

    def test_unknown_button_is_never_pressed_for_admission(self):
        c=SupervisorClient("fake")
        with patch.object(c,"call",return_value={"entity_id":"button.slzb_core_restart","state":"unknown"}) as call:
            self.assertTrue(c.button_available("button.slzb_core_restart"))
            self.assertEqual(call.call_count,1)
            self.assertEqual(call.call_args.kwargs,{})
        with patch.object(c,"call",return_value={"entity_id":"button.slzb_core_restart","state":"unavailable"}):
            with self.assertRaises(ControlError):
                c.button_available("button.slzb_core_restart")

    def test_native_flash_other_device_and_platform_rejected(self):
        with TemporaryDirectory() as temp:
            cfg=replace(CFG,registry_directory=temp)
            for args in ({"unique_id":MAC+"-zigbee_flash_mode"},
                         {"platform":"other"}, {"mac":"11:22:33:44:55:66"}):
                write_registries(temp,**args)
                with self.assertRaises(ControlError):
                    verify_native_binding(cfg,"RESTART_ESP","button.slzb_core_restart")

    def test_native_ambiguous_button_does_not_fall_back(self):
        with TemporaryDirectory() as temp:
            write_registries(temp)
            cfg=replace(CFG,registry_directory=temp,esp_restart_entity="button.slzb_core_restart",
                        allow_private_http_fallback=True)
            ha=FakeHA(); radio=FakeRadio()
            ha.button=Mock(side_effect=TimeoutError("ambiguous"))
            with self.assertRaises(TimeoutError):
                HAActuator(cfg,ha,radio,lambda:True).perform_once("RESTART_ESP")
            self.assertFalse(radio.calls)

    def test_wrong_integer_hash_duplicate_and_mac_never_send_command(self):
        invalid_js=(JS.replace("API_CMD:4","API_CMD:40"),
                    JS.replace("CMD_ZB_RST:1","CMD_ZB_RST:10"),
                    JS.replace("CMD_ESP_RES:3","CMD_ESP_RES:30"),
                    JS+" CMD_ESP_RES:3")
        for script in invalid_js:
            cfg=replace(CFG,expected_js_sha256=hashlib.sha256(script.encode()).hexdigest())
            c=SmlightControl(cfg)
            with patch.object(c,"identity",return_value={"MAC":MAC,"sw_version":cfg.expected_sw_version}), \
                    patch.object(c,"fetch",return_value=script) as fetch:
                with self.assertRaises(ControlError):
                    c.private_restart("RESTART_ESP")
                fetch.assert_called_once_with("/js/httpApi.js")
        c=SmlightControl(CFG)
        with patch.object(c,"identity",return_value={"MAC":MAC,"sw_version":CFG.expected_sw_version}), \
                patch.object(c,"fetch",return_value=JS+" "):
            with self.assertRaises(ControlError):
                c.private_restart("RESTART_ESP")
        wrong={"Info":{"model":"SLZB-06p7U","zb_hw":"CC2652P7","coord_mode":2,
                       "sw_version":CFG.expected_sw_version,"MAC":"11:22:33:44:55:66"}}
        with patch.object(c,"fetch",return_value=json.dumps(wrong)):
            with self.assertRaises(ControlError):
                c.identity()

    def test_no_redirects_and_no_unpinned_actuation(self):
        with self.assertRaises(ControlError):
            _NoRedirect().redirect_request(None,None,302,"",{},"http://other/api2")
        with self.assertRaises(ControlError):
            HAActuator(Configuration(),FakeHA(),FakeRadio(),lambda:True).perform_once("STOP_Z2M")

    def test_log_prefix_tail_epoch_consistency(self):
        c=SupervisorClient("fake")
        prefix="2026-10-22 18:00:00.123+02:00 Starting Zigbee2MQTT\nsecond line"
        with patch.object(c,"log_prefix",side_effect=[prefix,prefix+"\nnew"]), \
                patch.object(c,"log_text",return_value="tail"):
            self.assertEqual(c.log_window(CFG.addon_slug),(prefix,"tail"))
        with patch.object(c,"log_prefix",side_effect=[prefix,prefix.replace("18:00","19:00")]), \
                patch.object(c,"log_text",return_value="tail"):
            with self.assertRaises(ControlError):
                c.log_window(CFG.addon_slug)


class ObserverTests(unittest.TestCase):
    def test_no_retained_device_topics(self):
        import time
        now=time.time()
        obs=PassiveObserver(last_seen_epoch=True,admission_floor=now-1)
        # Feed callbacks through a disposable fake paho client.
        class M:
            pass
        fake=M()
        cb={}
        fake.on_connect=None;fake.on_disconnect=None;fake.on_message=None
        fake.subscribe=lambda *a,**k:(0,7)
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
        class ReasonCode:
            value = 0
        fake.on_connect(fake,None,None,ReasonCode(),None)
        fake.on_subscribe(fake,None,7,[ReasonCode()],None)
        obs.ingest_mqtt("zigbee2mqtt/bridge/devices",json.dumps([
            {"friendly_name":"KitchenSocketRight","ieee_address":"0x0000000000000001","type":"Router"},
            {"friendly_name":"BedroomSocketRight","ieee_address":"0x0000000000000002","type":"Router"}]),retained=True)
        def send(name,retained):
            msg=M()
            msg.topic="zigbee2mqtt/"+name
            msg.retain=retained
            msg.payload=json.dumps({"state":"online","last_seen":int(time.time()*1000)}).encode()
            fake.on_message(fake,None,msg)
        send("KitchenSocketRight",True)
        send("BedroomSocketRight",False)
        send("bridge/state",True)
        self.assertEqual(obs.sample()["fresh_device_topics_120s"],1)
        self.assertFalse(obs.sample()["bridge_online_fresh"])
        send("bridge/state",False)
        self.assertTrue(obs.sample()["bridge_online_fresh"])

    def test_deduplicate_live_log_and_exclude_older_epoch(self):
        text=(
          '[2026-10-22 19:29:10] error: Failed to ping \'a\' (SRSP - AF - dataRequest after 6000ms)\n'
          '[2026-10-22 19:29:10] error: Failed to ping \'b\' (SRSP - AF - dataRequest after 6000ms)\n'
          '[2026-10-22 19:29:10] info: MQTT publish: topic \'zigbee2mqtt/bridge/response/permit_join\', payload \'SRSP - AF - dataRequest after 6000ms\'\n'
        )
        from datetime import datetime
        from zoneinfo import ZoneInfo
        now=datetime(2026,10,22,19,29,20,tzinfo=ZoneInfo("Europe/Prague")).timestamp()
        obs=PassiveObserver(admission_floor=now-60)
        obs.ingest_mqtt("zigbee2mqtt/bridge/devices",json.dumps([
            {"friendly_name":"a","ieee_address":"0x0000000000000001","type":"Router"},
            {"friendly_name":"b","ieee_address":"0x0000000000000002","type":"Router"}]),retained=True)
        obs.seed_process_epoch('[2026-10-22 19:29:00] info: z2m: Starting Zigbee2MQTT version 2.14.0',now)
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
