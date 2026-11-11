"""V50 B1E2 / V51 B1E3 decode and observer sampling; acceptance gates unchanged."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/release"))
from p7u_r4_startup_observer import (EvidenceError, Q0, Q2, Q3, Q4, Q5, Q8, V50_SOURCES,
                                     V51_SOURCES, V52_SOURCES, decode_e2, decode_e3,
                                     decode_e6, decode_e7, onset_summary, stack_profile, Q9,
                                     V53_SOURCES, nv_cache_evidence_supported,
                                     expected_ready_npi_priority)
from p7u_r4_startup_transport import observe_after_srsp
from tests.test_p7u_r4_startup_observer import evidence as legacy_e1

# Exact V52 source: the newer V53 is in the same sets but adds B1E7.
V50 = "a70ae24ff45e708e13969cd341c9ecb494d1570f"
V53 = "8ec1439786e3e98151d2796e6797675bb9ef5965"
V54 = "20a2474a67c1d420b6614b3fcb2f7ed543b1420e"
V55 = "bb9720a7d502f80e28bdec683e625c754bb5cd1c"
V56 = "08804f2946746104215d3db7d36092706a0dfcad"
V57 = "eb59b6773dd0fe328c1194647c00e8a070d18a22"
V48 = "250441cd17c55e25c78d97e041f056574355ade7"


def e2(source=V50, *, now=1000, busy=0, nwk=0, armed=True, npi=6, count=10):
    raw = bytearray(248)
    raw[:6] = b"B1E2\x01\xf8"
    raw[6] = count
    raw[7] = 1 | (0x80 if armed else 0)
    raw[8:12] = bytes.fromhex(source[:8])
    put = lambda offset, value: raw.__setitem__(slice(offset, offset + 4), value.to_bytes(4, "little"))
    put(12, now); put(16, 10); put(20, nwk + 2); put(36, busy)
    raw[46] = npi; raw[47] = 5
    put(80 + 4 * 2, nwk); put(128 + 4 * 2, busy); put(176 + 4 * 2, 0x2070)
    raw[224 + 4:226 + 4] = (13).to_bytes(2, "little")
    return bytes(raw)


def e7(source=V53, *, hits=900, misses=100, hot=((1, 0x3A, 0, 1, 100, 1000, 12),)):
    """V53 B1E7: counters and hot NV items; never NV bytes."""
    raw = bytearray(248)
    raw[:6] = b"B1E7\x01\xf8"
    raw[6] = 3; raw[7] = 8
    raw[8:12] = bytes.fromhex(source[:8])
    put = lambda offset, value: raw.__setitem__(slice(offset, offset + 4), value.to_bytes(4, "little"))
    put(12, 777); put(16, hits); put(20, misses); put(24, 90); put(28, 4)
    for i, (system, item, sub, kind, count, ticks, worst) in enumerate(hot):
        e = 32 + 24 * i
        raw[e] = system; raw[e + 2:e + 4] = item.to_bytes(2, "little")
        raw[e + 4:e + 6] = sub.to_bytes(2, "little"); raw[e + 6] = kind; raw[e + 7] = 1
        put(e + 8, count); put(e + 12, ticks); put(e + 16, worst)
    return bytes(raw)


def e3(source=V50, *, ready=False, onset=False, long=False, now=5000000):
    """V51 B1E3: NV hooks always installed at Stack task entry."""
    raw = bytearray(248)
    raw[:6] = b"B1E3\x01\xf8"
    raw[7] = 10
    raw[8:12] = bytes.fromhex(source[:8])
    put = lambda offset, value: raw.__setitem__(slice(offset, offset + 4), value.to_bytes(4, "little"))
    put16 = lambda offset, value: raw.__setitem__(slice(offset, offset + 2), value.to_bytes(2, "little"))
    flags = 0x10
    put(12, now); put(52, 400); put(56, 30); put(68, 250000); put(72, 50000)
    put16(76, 900); raw[78] = 4; raw[79] = 3
    put(80, 90000); put(84, 41000); put(88, 12000)
    put(180, 1700000); put16(184, 15000); raw[186] = 6; raw[187] = 120
    put(188, 0x10000); put(196, 180000)
    put16(240, 1800); put16(242, 3072); put16(244, 700); put16(246, 1024)
    if ready:
        flags |= 0x01 | 0x02 | 0x40
        put(16, 400); put(20, 3); put(24, 5); put16(28, 0); put16(30, 2)
        put(32, 1000000); put(36, 1010000); put(40, 4000000)
        put(44, 1800000); put(48, 1900000); put(92, 39000); put(96, 3990000)
        put(160, 4100000); put16(164, 800); raw[166] = 3; raw[167] = 2
        put(168, 0x2070); put(176, 30000)
        put(200 + 4 * 2, 200000)
    if onset:
        flags |= 0x04 | 0x20
        put(100, 4000000); put(104, 1000000); put(108, 1010000); put(112, 820)
        raw[116] = 3; put16(118, 41); put(120, 960000); put(124, 0x2070)
        put(128, 300000); put16(132, 610); put16(134, 77); put(136, 39500)
    if long:
        flags |= 0x08
        put(140, 4500000); put16(144, 1200); raw[146] = 3; raw[147] = 9
        put(148, 0x2070); put(156, 110000)
    raw[6] = flags
    return bytes(raw)


def e6(source=V50, *, deferred=0, stuck_ms=0, fault=0):
    """V52 B1E6: B4_V43 progress, OSAL timers (NWK probe task 2), in-flight."""
    raw = bytearray(248)
    raw[:6] = b"B1E6\x01\xf8"
    raw[8:12] = bytes.fromhex(source[:8])
    put = lambda offset, value: raw.__setitem__(slice(offset, offset + 4), value.to_bytes(4, "little"))
    put16 = lambda offset, value: raw.__setitem__(slice(offset, offset + 2), value.to_bytes(2, "little"))
    put(12, 9000000)
    for i, value in enumerate((40, 30, 30, 70, 0, 70, 0, 0, 0x02F10000, 900)):
        put(16 + 4 * i, value)
    put(16 + 4 * 10, fault); put(16 + 4 * 19, 10)
    put(96, 5000); put(96 + 8, 9000); put(96 + 12, 4990); put(96 + 20, 4000); put(96 + 24, 4980)
    put16(96 + 28, deferred); put16(96 + 30, max(deferred, 12)); put16(96 + 34, 9)
    raw[96 + 38] = 2; raw[96 + 39] = 0xFF
    for i in range(16):
        put16(96 + 72 + 2 * i, 0xFFFF)
    for bit, starts, minimum in ((4, 300, 1000), (6, 4000, 2)):
        put16(96 + 40 + 2 * bit, starts); put16(96 + 72 + 2 * bit, minimum)
    flags = 1
    if stuck_ms:
        flags |= 2
        raw[200] = 3; raw[201] = 4; put(204, 0x2070); put(208, stuck_ms * 100); put(212, 50000)
    put(216, 900000); put(220, 950000); put(224, 70)
    for i, value in enumerate((60, 900, 4000, 800)):
        put(228 + 4 * i, value)
    raw[6] = flags
    return bytes(raw)


def e1(source, state, npi):
    raw = bytearray(legacy_e1())
    raw[8:12] = bytes.fromhex(source[:8])
    raw[6] = state
    raw[47] = npi
    if state != 4:
        raw[7] = 1
        raw[12:16] = (0xf).to_bytes(4, "little")
        raw[64:112] = bytes(24) + b"\xff" * 24
        for i, order in enumerate((1, 2, 3, 4)):
            raw[64 + i] = order; raw[88 + i] = 0
    return bytes(raw)


class FakeZnp:
    """Scripted one-outstanding-request ZNP; records every operation."""
    def __init__(self, source, *, running=6, fail_post_ready_e2=False,
                 fail_post_ready_e3=False, never_ready_e3=False):
        self.source = None
        self.now = 0.0
        self.history = []
        self.sent = []
        self.e1_left = running
        self.e2_count = 0
        self.ready_sent = False
        self.fail_post_ready_e2 = fail_post_ready_e2
        self.fail_post_ready_e3 = fail_post_ready_e3
        self.never_ready_e3 = never_ready_e3
        self.e3_count = 0
        self.src = source

    def clock(self):
        return self.now

    def request(self, sub, cmd, payload=b"", *, deadline):
        self.now += 0.05
        self.sent.append((sub, cmd, payload))
        self.history.append({"operation": payload.hex() if payload else f"{sub:02x}:{cmd:02x}",
                             "result": "COMPLETE"})
        if payload == Q3:
            if self.e1_left:
                self.e1_left -= 1
                return e1(self.src, 3, 6)
            self.ready_sent = True
            return e1(self.src, 4, 6)
        if payload == Q4:
            self.e2_count += 1
            if self.ready_sent and self.fail_post_ready_e2:
                raise TimeoutError("ZNP_OUTSTANDING_RESPONSE_DEADLINE")
            return e2(self.src, now=1000 + 100000 * self.e2_count,
                      busy=95000 * self.e2_count, nwk=75 * self.e2_count)
        if payload == Q5:
            self.e3_count += 1
            if self.ready_sent and self.fail_post_ready_e3:
                raise TimeoutError("ZNP_OUTSTANDING_RESPONSE_DEADLINE")
            return e3(self.src, ready=self.ready_sent and not self.never_ready_e3)
        if payload == Q8:
            return e6(self.src)
        if payload == Q2:
            p = bytearray(32); p[:6] = b"B1P1\x01\x20"; p[6] = 4
            p[12:16] = bytes.fromhex(self.src[:8]); return bytes(p)
        if payload == Q0:
            s = bytearray(24); s[:6] = b"B1S1\x01\x18"; s[6] = 5; s[9] = 8
            s[12:16] = bytes.fromhex(self.src[:8]); return bytes(s)
        if (sub, cmd) == (7, 0):
            return bytes(12) + bytes([9, 0])
        if (sub, cmd) == (1, 8):
            return b"\x00\x01\x55"
        raise AssertionError((sub, cmd, payload))


class StackEvidence(unittest.TestCase):
    def test_decode_and_profile_report_saturation(self):
        first = decode_e2(e2(now=1000, busy=0, nwk=0), V50)
        last = decode_e2(e2(now=101000, busy=98000, nwk=75), V50)
        self.assertTrue(last["npi_armed"])
        self.assertEqual(last["services"][2]["inputs"], 0x2070)
        self.assertEqual(last["services"][2]["longest_ms"], 13)
        profile = stack_profile(first, last)
        self.assertEqual(profile["elapsed_ms"], 1000)
        self.assertEqual(profile["stack_busy_percent"], 98.0)
        self.assertEqual(profile["services"][2]["dispatches"], 75)

    def test_decode_rejects_wrong_source_schema_and_unused_slots(self):
        with self.assertRaisesRegex(EvidenceError, "STACK_EVIDENCE_UNSUPPORTED_SOURCE"):
            decode_e2(e2(V48), V48)
        bad = bytearray(e2()); bad[8] ^= 1
        with self.assertRaisesRegex(EvidenceError, "SOURCE_DIGEST_MISMATCH_B1E2"):
            decode_e2(bytes(bad), V50)
        bad = bytearray(e2()); bad[80 + 4 * 11] = 1
        with self.assertRaisesRegex(EvidenceError, "STACK_EVIDENCE_UNUSED_SLOTS_INVALID"):
            decode_e2(bytes(bad), V50)
        bad = bytearray(e2()); bad[78] = 1
        with self.assertRaisesRegex(EvidenceError, "STACK_EVIDENCE_SCHEMA_INVALID"):
            decode_e2(bytes(bad), V50)

    def test_v50_samples_running_and_post_ready_without_weakening_gates(self):
        znp = FakeZnp(V50, running=6)
        result = observe_after_srsp(znp, V50, 0.0, sleep=lambda s: None)
        self.assertEqual(result["status"], "COORDINATOR_STATE9_MARKER_PASS")
        # Polls 1 and 5 while RUNNING, then exactly two after terminal proof;
        # V51 B1E3 rides along while RUNNING and once after the B1E2 pair.
        self.assertEqual(result["frame_counts"]["B1E2"], 4)
        self.assertEqual(result["frame_counts"]["B1E3"], 3)
        self.assertEqual(result["frame_counts"]["B1E6"], 3)
        self.assertEqual(result["pipeline_record"]["timers"]["probe_task"], 2)
        order = [p for _, _, p in znp.sent if p in (Q0, Q2, Q4, Q5)]
        order = [p for _, _, p in znp.sent if p in (Q0, Q2, Q4, Q5, Q8)]
        self.assertEqual(order[:3], [Q4, Q5, Q8])
        self.assertEqual(order[-6:], [Q2, Q0, Q4, Q4, Q5, Q8])
        self.assertTrue(result["onset_record"]["decoded"]["ready"])
        self.assertEqual(result["onset_record"]["summary"]["stack_high_water_percent"], 58.6)
        self.assertIn("stack_profile", result)
        self.assertGreater(result["stack_profile"]["last_interval"]["stack_busy_percent"], 90)

    def test_post_ready_stack_evidence_failure_is_readonly_incomplete(self):
        znp = FakeZnp(V50, running=2, fail_post_ready_e2=True)
        result = observe_after_srsp(znp, V50, 0.0, sleep=lambda s: None)
        self.assertEqual(result["status"], "FAILED_STOP_NO_RETRY")
        self.assertEqual(result["failure_category"], "READY_OBSERVED_VERIFICATION_INCOMPLETE")
        self.assertEqual(result["incomplete_detail"], "POST_READY_STACK_EVIDENCE")
        self.assertEqual(result["frame_counts"]["UTIL"], 1)

    def test_post_ready_onset_failure_is_readonly_incomplete(self):
        for kwargs in ({"fail_post_ready_e3": True}, {"never_ready_e3": True}):
            znp = FakeZnp(V50, running=2, **kwargs)
            result = observe_after_srsp(znp, V50, 0.0, sleep=lambda s: None)
            self.assertEqual(result["status"], "FAILED_STOP_NO_RETRY")
            self.assertEqual(result["failure_category"], "READY_OBSERVED_VERIFICATION_INCOMPLETE")
            self.assertEqual(result["incomplete_detail"], "POST_READY_ONSET_EVIDENCE")
            self.assertEqual(result["frame_counts"]["MARKER"], 1)

    def test_decode_e3_onset_record_and_summary(self):
        self.assertEqual(V51_SOURCES, V50_SOURCES)
        boot = decode_e3(e3(), V50)
        self.assertTrue(boot["nv_hooked"])
        self.assertFalse(boot["ready"])
        self.assertIsNone(boot["onset"])
        self.assertIsNone(boot["run_worst"])
        self.assertEqual(boot["boot_worst"]["service"], 5)
        self.assertEqual(boot["boot_worst"]["ms"], 15000)
        self.assertEqual(boot["boot_worst"]["nv_ticks"], 180000)
        self.assertEqual(boot["nv"]["longest_kind"], "compact")
        self.assertEqual(boot["nv"]["longest_service"], 2)
        rec = decode_e3(e3(ready=True, onset=True, long=True), V50)
        self.assertEqual(rec["onset"]["top_service"], 2)
        self.assertEqual(rec["onset"]["top_service_inputs"], 0x2070)
        self.assertTrue(rec["onset"]["after_calm"])
        self.assertEqual(rec["first_long"]["ms"], 1200)
        self.assertEqual(rec["heap"]["low_water"], 39000)
        summary = onset_summary(rec, 10)
        self.assertEqual(summary["onset_busy_percent"], 99.0)
        self.assertEqual(summary["onset_age_s"], 10)
        self.assertEqual(summary["onset_nv_ms"], 3000)
        self.assertEqual(summary["nv_service_ms"][2], 2000)
        self.assertEqual(summary["npi_high_water_percent"], 68.4)

    def test_decode_e6_pipeline_timers_and_inflight(self):
        self.assertEqual(V52_SOURCES, V50_SOURCES)
        idle = decode_e6(e6(), V50)
        self.assertIsNone(idle["inflight"]["service"])
        self.assertEqual(idle["timers"]["nwk_bit_starts"], {4: 300, 6: 4000})
        self.assertEqual(idle["timers"]["nwk_bit_min_timeout_ms"], {4: 1000, 6: 2})
        self.assertEqual(idle["npi_mt_uart"]["last_command"], 0x02F1)
        self.assertEqual(idle["nwk_dispatch_bits"]["NWK_BCAST_TIMER_EVT"], 4000)
        stuck = decode_e6(e6(stuck_ms=7000), V50)
        self.assertEqual((stuck["inflight"]["service"], stuck["inflight"]["input"]), (2, 0x2070))
        self.assertEqual(stuck["inflight"]["age_ticks"], 700000)
        bad = bytearray(e6()); bad[6] = 3  # in-flight flag without a service
        with self.assertRaisesRegex(EvidenceError, "PIPELINE_EVIDENCE_SCHEMA_INVALID"):
            decode_e6(bytes(bad), V50)
        bad = bytearray(e6()); bad[208] = 1  # age without an in-flight service
        with self.assertRaisesRegex(EvidenceError, "PIPELINE_EVIDENCE_SCHEMA_INVALID"):
            decode_e6(bytes(bad), V50)
        with self.assertRaisesRegex(EvidenceError, "PIPELINE_EVIDENCE_UNSUPPORTED_SOURCE"):
            decode_e6(e6(V48), V48)

    def test_decode_e3_rejects_inconsistent_latches(self):
        bad = bytearray(e3()); bad[104] = 1  # onset bytes without an onset latch
        with self.assertRaisesRegex(EvidenceError, "ONSET_EVIDENCE_SCHEMA_INVALID"):
            decode_e3(bytes(bad), V50)
        bad = bytearray(e3()); bad[6] |= 0x02  # settled before READY
        with self.assertRaisesRegex(EvidenceError, "ONSET_EVIDENCE_SCHEMA_INVALID"):
            decode_e3(bytes(bad), V50)
        bad = bytearray(e3()); bad[16] = 1  # a rated window before READY
        with self.assertRaisesRegex(EvidenceError, "ONSET_EVIDENCE_SCHEMA_INVALID"):
            decode_e3(bytes(bad), V50)
        bad = bytearray(e3()); bad[9] ^= 1
        with self.assertRaisesRegex(EvidenceError, "SOURCE_DIGEST_MISMATCH_B1E3"):
            decode_e3(bytes(bad), V50)
        with self.assertRaisesRegex(EvidenceError, "ONSET_EVIDENCE_UNSUPPORTED_SOURCE"):
            decode_e3(e3(V48), V48)

    def test_legacy_source_never_sends_op4(self):
        znp = FakeZnp(V48, running=3)
        frames = []
        orig = znp.request
        def request(sub, cmd, payload=b"", *, deadline):
            if payload == Q3:
                raw = bytearray(orig(sub, cmd, payload, deadline=deadline))
                raw[47] = 4
                return bytes(raw)
            return orig(sub, cmd, payload, deadline=deadline)
        znp.request = request
        result = observe_after_srsp(znp, V48, 0.0, sleep=lambda s: None)
        self.assertEqual(result["status"], "COORDINATOR_STATE9_MARKER_PASS")
        self.assertNotIn(Q4, [p for _, _, p in znp.sent])
        self.assertNotIn(Q5, [p for _, _, p in znp.sent])
        self.assertNotIn(Q8, [p for _, _, p in znp.sent])
        self.assertEqual(result["frame_counts"]["B1E2"], 0)
        self.assertEqual(result["frame_counts"]["B1E3"], 0)


class NvCacheEvidence(unittest.TestCase):
    def test_v53_and_v54_answer_every_older_page(self):
        self.assertEqual(V53_SOURCES, frozenset({V53, V54, V55, V56, V57}))
        self.assertTrue({V50, V53, V54, V55, V56, V57} <= V52_SOURCES == V51_SOURCES == V50_SOURCES)
        self.assertTrue(nv_cache_evidence_supported(V53))
        # V54 only guards the V53 cache: READY at priority 6 with every evidence page.
        self.assertTrue(nv_cache_evidence_supported(V54))
        self.assertEqual(expected_ready_npi_priority(V54), 6)
        # V55 changes no evidence page: same READY priority and pages.
        self.assertTrue(nv_cache_evidence_supported(V55))
        self.assertEqual(expected_ready_npi_priority(V55), 6)
        # V56 changes no evidence page either.
        self.assertTrue(nv_cache_evidence_supported(V56))
        self.assertEqual(expected_ready_npi_priority(V56), 6)
        # V57 keeps every page and is the only source that answers B1E8.
        import p7u_r4_startup_observer as observer
        self.assertTrue(nv_cache_evidence_supported(V57))
        self.assertEqual(expected_ready_npi_priority(V57), 6)
        self.assertEqual(observer.V57_SOURCES, frozenset({V57}))
        self.assertFalse(nv_cache_evidence_supported(V50))
        self.assertEqual(Q9, b"B1Q1\x01\x08\x04\x05")

    def test_decode_e7_counters_and_costliest_items_first(self):
        raw = e7(hot=((1, 0x3A, 0, 1, 100, 1000, 12), (1, 0x21, 0, 2, 3, 5000, 2000)))
        value = decode_e7(raw, V53)
        self.assertEqual((value["hits"], value["misses"], value["hit_ratio"]), (900, 100, 0.9))
        self.assertEqual([h["item"] for h in value["hot_items"]], [0x21, 0x3A])
        self.assertEqual(value["hot_items"][1]["kind"], "read")
        self.assertEqual(value["lines_used"], 3)

    def test_decode_e7_rejects_wrong_source_schema_and_data_bytes(self):
        with self.assertRaisesRegex(EvidenceError, "NV_CACHE_EVIDENCE_UNSUPPORTED_SOURCE"):
            decode_e7(e7(V50), V50)
        with self.assertRaisesRegex(EvidenceError, "SOURCE_DIGEST_MISMATCH_B1E7"):
            decode_e7(e7(V50), V53)
        bad = bytearray(e7()); bad[240] = 1
        with self.assertRaisesRegex(EvidenceError, "NV_CACHE_EVIDENCE_SCHEMA_INVALID"):
            decode_e7(bytes(bad), V53)
        bad = bytearray(e7()); bad[32 + 24 + 9] = 1  # unused hot slot carries bytes
        with self.assertRaisesRegex(EvidenceError, "NV_CACHE_EVIDENCE_SCHEMA_INVALID"):
            decode_e7(bytes(bad), V53)
        bad = bytearray(e7()); bad[38] = 9
        with self.assertRaisesRegex(EvidenceError, "NV_CACHE_EVIDENCE_SCHEMA_INVALID"):
            decode_e7(bytes(bad), V53)


def e8(source, *, ok=3, resyncs=1, junk=b"\xfe\x7c", state=0):
    """V57 B1E8: RX frame resync evidence; inbound bytes only, never NV data."""
    raw = bytearray(248)
    raw[:6] = b"B1E8\x01\xf8"
    raw[6] = (1 if ok else 0) | (2 if resyncs else 0) | (4 if state else 0)
    raw[8:12] = bytes.fromhex(source[:8])
    put = lambda offset, value: raw.__setitem__(slice(offset, offset + 4), value.to_bytes(4, "little"))
    put(12, 9000000); put(16, ok); put(20, 1); put(24, resyncs); put(32, len(junk)); put(40, 4)
    put(44, 6970000 if ok else 0)
    if resyncs:
        put(48, 6960000); put(52, 6960000)
        raw[60] = 1; raw[61] = 0x7C  # CMD1: SOF and length collected
    raw[65] = state; raw[66] = len(junk); raw[67] = 250
    raw[68:68 + len(junk)] = junk
    raw[76:78] = (500).to_bytes(2, "little")
    return bytes(raw)


class V57RxFrameEvidence(unittest.TestCase):
    V57 = "57" * 20

    def setUp(self):
        import p7u_r4_startup_observer as observer
        self.observer = observer
        saved = observer.V57_SOURCES
        observer.V57_SOURCES = frozenset({self.V57})
        self.addCleanup(setattr, observer, "V57_SOURCES", saved)

    def test_decode_e8_first_resync_and_boot_bytes(self):
        value = self.observer.decode_e8(e8(self.V57), self.V57)
        self.assertEqual((value["frames_ok"], value["resyncs"], value["fcs_failures"]), (3, 1, 1))
        self.assertEqual(value["first_resync"], {"state": "CMD1", "length": 0x7C, "cmd0": 0,
                                                 "cmd1": 0, "collected": 0})
        self.assertEqual((value["boot_discarded"], value["parser_state"]), ("fe7c", "SOP"))
        self.assertEqual((value["length_max"], value["idle_ms"]), (250, 500))
        self.assertEqual(self.observer.Q10, b"B1Q1\x01\x08\x04\x06")

    def test_decode_e8_rejects_older_source_and_schema_drift(self):
        for source in (V53, V54, V55, V56):
            with self.assertRaisesRegex(EvidenceError, "RX_FRAME_EVIDENCE_UNSUPPORTED_SOURCE"):
                self.observer.decode_e8(e8(source), source)
        with self.assertRaisesRegex(EvidenceError, "SOURCE_DIGEST_MISMATCH_B1E8"):
            self.observer.decode_e8(e8(V56), self.V57)
        for offset, value in ((7, 1), (6, 0), (67, 249), (76, 0), (100, 1), (70, 1), (65, 6)):
            bad = bytearray(e8(self.V57)); bad[offset] = value
            with self.assertRaisesRegex(EvidenceError, "RX_FRAME_EVIDENCE_SCHEMA_INVALID"):
                self.observer.decode_e8(bytes(bad), self.V57)
        clean = e8(self.V57, resyncs=0)
        self.assertIsNone(self.observer.decode_e8(clean, self.V57)["first_resync"])
        for offset, value in ((60, 0), (62, 0x21), (64, 1)):  # SOP, or fields CMD1 has not collected
            bad = bytearray(e8(self.V57)); bad[offset] = value
            with self.assertRaisesRegex(EvidenceError, "RX_FRAME_EVIDENCE_SCHEMA_INVALID"):
                self.observer.decode_e8(bytes(bad), self.V57)
        bad = bytearray(e8(self.V57)); bad[60] = 3  # LEN state cannot carry a length
        with self.assertRaisesRegex(EvidenceError, "RX_FRAME_EVIDENCE_SCHEMA_INVALID"):
            self.observer.decode_e8(bytes(bad), self.V57)
        bad = bytearray(clean); bad[61] = 5  # first-resync record without a resync
        with self.assertRaisesRegex(EvidenceError, "RX_FRAME_EVIDENCE_SCHEMA_INVALID"):
            self.observer.decode_e8(bytes(bad), self.V57)


if __name__ == "__main__":
    unittest.main()
