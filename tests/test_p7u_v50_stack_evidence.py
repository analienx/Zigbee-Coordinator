"""V50 B1E2 decode and observer sampling; acceptance gates stay unchanged."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/release"))
from p7u_r4_startup_observer import (EvidenceError, Q0, Q2, Q3, Q4, V50_SOURCES,
                                     decode_e2, stack_profile)
from p7u_r4_startup_transport import observe_after_srsp
from tests.test_p7u_r4_startup_observer import evidence as legacy_e1

V50 = next(iter(V50_SOURCES))
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
    def __init__(self, source, *, running=6, fail_post_ready_e2=False):
        self.source = None
        self.now = 0.0
        self.history = []
        self.sent = []
        self.e1_left = running
        self.e2_count = 0
        self.ready_sent = False
        self.fail_post_ready_e2 = fail_post_ready_e2
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
        # Polls 1 and 5 while RUNNING, then exactly two after terminal proof.
        self.assertEqual(result["frame_counts"]["B1E2"], 4)
        order = [p for _, _, p in znp.sent if p in (Q0, Q2, Q4)]
        self.assertEqual(order[-4:], [Q2, Q0, Q4, Q4])
        self.assertIn("stack_profile", result)
        self.assertGreater(result["stack_profile"]["last_interval"]["stack_busy_percent"], 90)

    def test_post_ready_stack_evidence_failure_is_readonly_incomplete(self):
        znp = FakeZnp(V50, running=2, fail_post_ready_e2=True)
        result = observe_after_srsp(znp, V50, 0.0, sleep=lambda s: None)
        self.assertEqual(result["status"], "FAILED_STOP_NO_RETRY")
        self.assertEqual(result["failure_category"], "READY_OBSERVED_VERIFICATION_INCOMPLETE")
        self.assertEqual(result["incomplete_detail"], "POST_READY_STACK_EVIDENCE")
        self.assertEqual(result["frame_counts"]["UTIL"], 1)

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
        self.assertEqual(result["frame_counts"]["B1E2"], 0)


if __name__ == "__main__":
    unittest.main()
