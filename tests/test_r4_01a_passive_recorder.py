"""R4 passive recorder safety and incident replay -- offline GitHub-hosted tests.

All events synthetic; these tests never import HA, Z2M, serial, USB, MQTT or
contact devices. Explicitly test that 64 timeouts over 44 minutes do NOT
justify an 8-in-120-second claim.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                       "firmware" / "slzb-06p7u" / "r4" / "tools"))
from r4_passive_recorder import PassiveR4Recorder, normalize


def event(kind, at_ms, waiter_id=None):
    o = {"kind": kind, "at_ms": at_ms}
    if waiter_id is not None:
        o["waiter_id"] = waiter_id
    return o


class PassiveRecorderTests(unittest.TestCase):
    def test_af_burst_exact_8_distinct_in_120s(self):
        r=PassiveR4Recorder(process_generation=1)
        for i in range(8):
            self.assertTrue(r.offer(event("AF_SREQ_TIMEOUT", 1000+i*1000, i)))
        self.assertEqual(r.drain(), 8)
        self.assertEqual(r.snapshot()["af_sreq_timeouts"], 8)
        self.assertIn("AF_SREQ_TIMEOUT_BURST_OBSERVED", r.snapshot()["signals"])
        self.assertEqual(r.snapshot()["root_cause"], "UNDETERMINED")

    def test_real_incident_64_over_44_minutes_not_automatically_a_burst(self):
        r=PassiveR4Recorder(process_generation=1)
        # Exactly 64 AF timeouts spread uniformly across 43m 3s:
        # 64 lines are a session aggregate, not 8 in any two minutes.
        for i in range(64):
            r.offer(event("AF_SREQ_TIMEOUT", i*41_000, i))
            r.drain()
        self.assertNotIn("AF_SREQ_TIMEOUT_BURST_OBSERVED", r.snapshot()["signals"])
        self.assertLess(r.snapshot()["af_sreq_timeouts"], 8)

    def test_af_waiter_duplicate_not_double_counted(self):
        r=PassiveR4Recorder(process_generation=1)
        for _ in range(15):
            r.offer(event("AF_SREQ_TIMEOUT", 100, 7))
        self.assertEqual(r.drain(),15)
        self.assertEqual(r.snapshot()["af_sreq_timeouts"],1)
        self.assertEqual(r.snapshot()["dropped"],14)

    def test_dedupe_scoped_to_subsystem(self):
        r=PassiveR4Recorder(process_generation=2)
        r.offer(event("AF_SREQ_TIMEOUT", 1, 7))
        r.offer(event("ZDO_SREQ_TIMEOUT", 2, 7))
        r.drain()
        self.assertEqual(r.snapshot()["af_sreq_timeouts"],1)
        self.assertEqual(r.snapshot()["zdo_sreq_timeouts"],1)

    def test_queue_pressure_drops_diagnostics_not_adapter_commands(self):
        r=PassiveR4Recorder(process_generation=1,max_pending=2)
        self.assertTrue(r.offer(event("ZCL_TIMEOUT",1)))
        self.assertTrue(r.offer(event("ZCL_TIMEOUT",2)))
        self.assertFalse(r.offer(event("ZCL_TIMEOUT",3)))
        self.assertEqual(len(r.pending),2)
        self.assertEqual(r.dropped,1)
        self.assertEqual(r.drain(limit=1),1)
        self.assertTrue(r.offer(event("ZCL_TIMEOUT",4)))
        self.assertEqual(r.drain(),2)

    def test_no_io_or_adapter_call_in_ingress(self):
        r=PassiveR4Recorder(process_generation=1)
        with patch("builtins.open",side_effect=AssertionError("no I/O permitted")):
            self.assertTrue(r.offer(event("ZCL_TIMEOUT",10)))
        self.assertEqual(len(r.pending),1)

    def test_reject_untrusted_device_payload_and_identifier(self):
        variants=[
            {"kind":"AF_SREQ_TIMEOUT","at_ms":10,"waiter_id":1,
             "nwk_key":"do-not-persist"},
            {"kind":"AF_SREQ_TIMEOUT","at_ms":10,"waiter_id":"0x1234"},
            {"kind":"HOST_SIGTERM","at_ms":10,"secret":"private"},
            {"kind":"HOST_SIGTERM","at_ms":10,"waiter_id":9},
            {"kind":"AF_SREQ_TIMEOUT","at_ms":10},
            {"kind":"ZCL_TIMEOUT","at_ms":False},
            {"kind":"ZCL_TIMEOUT","at_ms":-1},
            {"kind":[],"at_ms":1},
        ]
        for sample in variants:
            with self.subTest(sample=repr(sample)),self.assertRaises(ValueError):
                normalize(sample)

    def test_no_unordered_time_creates_false_burst(self):
        r=PassiveR4Recorder(process_generation=1)
        r.offer(event("AF_SREQ_TIMEOUT",1000,1))
        r.offer(event("AF_SREQ_TIMEOUT",999,2))
        r.drain()
        self.assertEqual(r.snapshot()["af_sreq_timeouts"],1)
        self.assertEqual(r.snapshot()["dropped"],1)

    def test_window_expiration(self):
        r=PassiveR4Recorder(process_generation=1)
        for i in range(8):
            r.offer(event("AF_SREQ_TIMEOUT",1000+i,i))
        r.drain()
        self.assertIn("AF_SREQ_TIMEOUT_BURST_OBSERVED",r.snapshot()["signals"])
        r.offer(event("ZCL_TIMEOUT",200_000))
        r.drain()
        self.assertNotIn("AF_SREQ_TIMEOUT_BURST_OBSERVED",r.snapshot()["signals"])

    def test_ota_and_sigterm_are_observations_not_causes(self):
        r=PassiveR4Recorder(process_generation=1)
        r.offer(event("OTA_START",0))
        for i in range(8):
            r.offer(event("AF_SREQ_TIMEOUT",100+i,i))
        r.offer(event("ZDO_SREQ_TIMEOUT",300,900))
        r.offer(event("HOST_SIGTERM",400))
        r.drain()
        z=r.snapshot()
        self.assertIn("HOST_SIGTERM_OBSERVED",z["signals"])
        self.assertIn("AF_SREQ_TIMEOUT_BURST_OBSERVED",z["signals"])
        self.assertIn("ZDO_SREQ_TIMEOUT_OBSERVED",z["signals"])
        self.assertTrue(z["ota_temporal_overlap"])
        self.assertFalse(z["ota_causal"])
        self.assertEqual(z["root_cause"],"UNDETERMINED")

    def test_usb_drop_separate_from_znp_timeout(self):
        r=PassiveR4Recorder(process_generation=1)
        r.offer(event("USB_DISCONNECTED",200))
        r.drain()
        self.assertEqual(r.snapshot()["signals"],["USB_DISCONNECTED_OBSERVED"])
        self.assertEqual(r.snapshot()["radio_boot_identity"],"UNKNOWN")

    def test_history_is_bounded(self):
        r=PassiveR4Recorder(process_generation=1,max_history=3)
        for i in range(20):
            r.offer(event("ZCL_TIMEOUT",i))
            r.drain()
        self.assertEqual(len(r.history),3)
        self.assertEqual(r.history[0]["at_ms"],17)
        self.assertLessEqual(len(r.window_events),3)

    def test_atomic_last_good_and_privacy(self):
        with TemporaryDirectory() as d:
            dst=Path(d)/"last.json"
            r=PassiveR4Recorder(process_generation=10)
            r.offer(event("AF_SREQ_TIMEOUT",100,73))
            r.drain()
            self.assertGreater(r.persist(dst),20)
            data=dst.read_text()
            self.assertIn("AF_SREQ_TIMEOUT",data)
            self.assertNotIn("waiter_id",data)
            self.assertNotIn("73", json.dumps(json.loads(data)["recent_events"]))
            last=PassiveR4Recorder.read_last_good(dst)
            self.assertEqual(last["process_generation"],10)
            self.assertEqual(last["recent_events"][0]["kind"],"AF_SREQ_TIMEOUT")

    def test_crash_before_replace_preserves_prior_good_snapshot(self):
        with TemporaryDirectory() as d:
            dst=Path(d)/"last.json"
            r=PassiveR4Recorder(process_generation=2)
            r.offer(event("ZCL_TIMEOUT",100))
            r.drain()
            r.persist(dst)
            original=dst.read_bytes()
            r.offer(event("USB_DISCONNECTED",101))
            r.drain()
            with patch("r4_passive_recorder.os.replace",side_effect=OSError("simulated crash")):
                with self.assertRaises(OSError):
                    r.persist(dst)
            self.assertEqual(dst.read_bytes(),original)
            self.assertFalse(dst.with_name("last.json.pending").exists())

    def test_history_fits_capped_json(self):
        with TemporaryDirectory() as d:
            r=PassiveR4Recorder(process_generation=2,max_history=4096)
            for i in range(1200):
                r.offer(event("ZCL_TIMEOUT",i))
                r.drain()
            dst=Path(d)/"last.json"
            r.persist(dst,max_bytes=2048)
            self.assertLessEqual(dst.stat().st_size,2048)
            obj=PassiveR4Recorder.read_last_good(dst)
            self.assertGreater(len(obj["recent_events"]),0)
            self.assertEqual(obj["recent_events"][-1]["at_ms"],1199)

    def test_bad_snapshot_schema_rejected(self):
        with TemporaryDirectory() as d:
            dst=Path(d)/"last.json"
            r=PassiveR4Recorder(process_generation=1)
            r.persist(dst)
            parsed=json.loads(dst.read_text())
            parsed["network_key"]="bad"
            dst.write_text(json.dumps(parsed))
            with self.assertRaises(ValueError):
                PassiveR4Recorder.read_last_good(dst)

    def test_no_second_owner_modules_or_wire_calls(self):
        source=(Path(__file__).resolve().parents[1]/
                "firmware/slzb-06p7u/r4/tools/r4_passive_recorder.py").read_text()
        import ast
        tree=ast.parse(source)
        import_roots=set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                import_roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                import_roots.add(node.module.split(".")[0])
        self.assertTrue(import_roots.isdisjoint({
            "serial","paho","mqtt","zigbee","zigbee2mqtt","usb","requests","socket",
        }))
        self.assertNotIn("unpiWriter",source)
        self.assertNotIn("serialPort",source)


class FourSyntheticIncidentReplays(unittest.TestCase):
    # Time values are illustrative and deliberately NOT copies of private logs.
    def test_p7u_oct16_af_zdo_ota_and_later_sigterm(self):
        # 64 AF across 43 minutes is not automatically an 8/120s burst.
        r=PassiveR4Recorder(process_generation=1)
        entries=[event("OTA_START",0),event("OTA_STOP",35*60_000)]
        for i in range(64):
            entries.append(event("AF_SREQ_TIMEOUT",35*60_000+i*41_000,i))
        for i in range(6):
            entries.append(event("ZDO_SREQ_TIMEOUT",52*60_000+i*7000,1000+i))
        for i in range(69):
            entries.append(event("ZCL_TIMEOUT",36*60_000+i*36_000))
        entries.append(event("HOST_SIGTERM",79*60_000))
        for item in sorted(entries,key=lambda o:o["at_ms"]):
            r.offer(item)
            r.drain()
        final=r.snapshot()
        self.assertIn("HOST_SIGTERM_OBSERVED",final["signals"])
        self.assertFalse(final["ota_causal"])
        self.assertEqual(final["root_cause"],"UNDETERMINED")
        self.assertNotIn("AF_SREQ_TIMEOUT_BURST_OBSERVED",final["signals"])
        # ZDO events were earlier; no last-window evidence at teardown.
        self.assertEqual(final["zdo_sreq_timeouts"],0)

    def test_p10_oct2_af_then_zdo_then_sys(self):
        r=PassiveR4Recorder(process_generation=2)
        for i in range(8):
            r.offer(event("AF_SREQ_TIMEOUT",i*3000,i))
        r.offer(event("ZDO_SREQ_TIMEOUT",25_000,100))
        r.offer(event("SYS_SREQ_TIMEOUT",30_000,200))
        r.drain()
        signals=r.snapshot()["signals"]
        self.assertIn("AF_SREQ_TIMEOUT_BURST_OBSERVED",signals)
        self.assertIn("ZDO_SREQ_TIMEOUT_OBSERVED",signals)
        self.assertIn("SYS_SREQ_TIMEOUT_OBSERVED",signals)
        self.assertEqual(r.snapshot()["root_cause"],"UNDETERMINED")

    def test_p10_oct12_usb_drop_is_not_an_af_timeout(self):
        r=PassiveR4Recorder(process_generation=3)
        r.offer(event("USB_DISCONNECTED",100))
        r.drain()
        self.assertEqual(r.snapshot()["signals"],["USB_DISCONNECTED_OBSERVED"])
        self.assertEqual(r.snapshot()["af_sreq_timeouts"],0)

    def test_p10_oct13_zdo_timeout_then_f0_responsive(self):
        r=PassiveR4Recorder(process_generation=4)
        r.offer(event("ZDO_SREQ_TIMEOUT",100,10))
        r.offer(event("DIAG_F0_RESPONSIVE",30_000))
        r.drain()
        self.assertIn("ZDO_SREQ_TIMEOUT_OBSERVED",r.snapshot()["signals"])
        self.assertIn("F0_RESPONSIVE_OBSERVED",r.snapshot()["signals"])
        self.assertEqual(r.snapshot()["radio_boot_identity"],"UNKNOWN")
        self.assertEqual(r.snapshot()["root_cause"],"UNDETERMINED")

    def test_sys_no_waiter_is_rejected(self):
        r=PassiveR4Recorder(process_generation=5)
        with self.assertRaises(ValueError):
            r.offer(event("SYS_SREQ_TIMEOUT",100))


if __name__=="__main__":
    unittest.main()
