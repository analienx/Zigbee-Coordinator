"""R4-01a diagnostic contracts (stdlib unittest only, offline, synthetic-only).

No hardware, no network, no secrets, no serial/MQTT. All fixtures are
synthetic values constructed inline, never field captures.
Covers Deliverable D: strict B0-D decoder hostile tests (items 1-4)
plus negative safety oracle (item 5).
"""
import struct
import unittest

VERSION = 2
NCOUNTERS = 25
SIZE = 2 + NCOUNTERS * 4  # 102
UNKNOWN = 0xFFFFFFFF
# Donor-strict flags mask (P10 npi_diag_decode.py): bits 0-2 defined,
# any other bit rejected. B0-D adopts donor strictness exactly.
FLAGS_KNOWN_MASK = 0x07
SRSP_BURST_N = 8  # default tunable burst threshold (see recorder contract)

NAMES = [
    "srsp_depth", "srsp_high_water", "async_depth", "async_high_water",
    "srsp_enqueued", "srsp_uart_accepted", "async_uart_accepted",
    "tx_immediate_rejects", "tx_rejected_drops", "stack_frame_failures",
    "stack_queue_failures", "srsp_allocation_failures",
    "srsp_enqueue_failures", "rx_frame_failures", "srsp_queue_fallbacks",
    "af_direct_accepted", "af_direct_buffer_full", "af_direct_memory_failure",
    "af_direct_other", "af_source_accepted", "af_source_buffer_full",
    "af_confirm_cca_failure", "af_confirm_other_failure",
    "rx_overflow_events", "rx_overflow_discarded_bytes",
]


def decode(frame: bytes):
    """Strict B0-D v2 decoder: 102 bytes exactly (u8 version, u8 flags,
    25 x u32 LE, matching the proven P10 F0 v2 wire format).
    Donor-strict: unknown flag bits are rejected, never preserved."""
    if len(frame) != SIZE:
        raise ValueError("length must be exactly %d, got %d" % (SIZE, len(frame)))
    version, flags = struct.unpack_from("<BB", frame, 0)
    if version != VERSION:
        raise ValueError("unsupported version %d" % version)
    if flags & ~FLAGS_KNOWN_MASK:
        raise ValueError("unknown flags bits 0x%02x" % flags)
    counters = list(struct.unpack_from("<%dI" % NCOUNTERS, frame, 2))
    return {"version": version, "flags": flags,
            "srsp_priority_queue_enabled": bool(flags & 1),
            "uart_retry_pending": bool(flags & 2),
            "uart_transport_busy": bool(flags & 4),
            "counters": dict(zip(NAMES, counters))}


def make_frame(counters=None, version=VERSION, flags=0):
    vals = list(counters) if counters is not None else [0] * NCOUNTERS
    assert len(vals) == NCOUNTERS
    return struct.pack("<BB", version, flags) + struct.pack("<%dI" % NCOUNTERS, *vals)


def delta(new, old):
    """Unsigned u32 delta (wrap-safe)."""
    return (new - old) & 0xFFFFFFFF


def classify(sreq_timeouts, zcl_timeouts, d_enq, d_af_confirm, sigterm=False,
             ota_overlap=False, f0_present=True, same_boot_epoch=True,
             counters_unknown=False):
    """Synthetic fault classifier (Deliverable C logic). Fail-closed
    guards first: teardown beats everything; without an F0 read, with
    a boot-epoch change, or with UNKNOWN-sentinel inputs the answer is
    unknown_needs_counters, never a radio-fault label."""
    if sigterm:
        return {"label": "host_teardown", "ota_causal": False}
    if not f0_present or not same_boot_epoch or counters_unknown:
        return {"label": "unknown_needs_counters", "ota_causal": False}
    if sreq_timeouts >= SRSP_BURST_N and d_enq <= 0:
        return {"label": "srsp_absence_burst",
                "ota_causal": False}  # OTA overlap never implies cause
    if sreq_timeouts == 0 and d_af_confirm > 0 and zcl_timeouts > 0:
        return {"label": "af_confirm_failure", "ota_causal": False}
    return {"label": "unknown_needs_counters", "ota_causal": False}


class DecoderStrictTests(unittest.TestCase):
    def test_item1_accepts_exact_102b_v2(self):
        frame = make_frame([1] * NCOUNTERS)
        out = decode(frame)
        self.assertEqual(out["version"], 2)
        self.assertEqual(len(out["counters"]), 25)

    def test_item2_rejects_bad_lengths(self):
        good = make_frame()
        self.assertEqual(len(good), SIZE)
        for bad_len in (0, 1, 4, 101):
            with self.assertRaises(ValueError):
                decode(good[:bad_len])
        # Overlong frames are built by APPENDING bytes (slicing a longer
        # buffer clamps back to SIZE and would vacuously pass).
        for over_len in (103, 104, 204):
            with self.assertRaises(ValueError):
                decode(good + b"\x00" * (over_len - SIZE))

    def test_item3_rejects_wrong_version_and_strict_flags(self):
        # u8 version: only 2 accepted. 0xFFFF is unrepresentable on the
        # wire, so it is tested as a constructor error, not a decode.
        for v in (0, 1, 3, 255):
            with self.assertRaises(ValueError):
                decode(make_frame(version=v))
        with self.assertRaises(struct.error):
            make_frame(version=0xFFFF)
        # Raw hostile version byte (not via make_frame).
        with self.assertRaises(ValueError):
            decode(bytes([7, 0]) + b"\x00" * 100)
        # Donor-strict flags: bits 0-2 defined, all others rejected.
        out = decode(make_frame(flags=0x07))
        self.assertEqual(out["flags"], 0x07)
        self.assertTrue(out["srsp_priority_queue_enabled"])
        self.assertTrue(out["uart_retry_pending"])
        self.assertTrue(out["uart_transport_busy"])
        for bad_flags in (0x08, 0xA5, 0x80, 0xFF):
            with self.assertRaises(ValueError):
                decode(make_frame(flags=bad_flags))

    def test_item4_hostile_bytes_and_wrap(self):
        # all-0xFF decodes (UNKNOWN sentinel), does not raise
        out = decode(b"\x02\x00" + b"\xff" * 100)
        self.assertEqual(out["counters"]["srsp_depth"], UNKNOWN)
        # wrap delta: 0xFFFFFFFE -> 3 crosses 2^32
        self.assertEqual(delta(3, 0xFFFFFFFE), 5)
        # truncated + overlong hostile frames rejected
        with self.assertRaises(ValueError):
            decode(b"\x02\x00" + b"\x00" * 200)
        with self.assertRaises(ValueError):
            decode(b"")


class SafetyOracleTests(unittest.TestCase):
    def test_item5_negative_safety_oracle(self):
        # Oracle: classifier must never blame OTA, never fill UNKNOWN
        # as measured zero, never label teardown as radio fault.
        r = classify(sreq_timeouts=64, zcl_timeouts=69, d_enq=0,
                     d_af_confirm=0, ota_overlap=True)
        self.assertEqual(r["label"], "srsp_absence_burst")
        self.assertFalse(r["ota_causal"])
        r2 = classify(0, 0, 0, 0, sigterm=True)
        self.assertEqual(r2["label"], "host_teardown")
        # UNKNOWN sentinel is not a measurement
        frame = make_frame([UNKNOWN] * NCOUNTERS)
        out = decode(frame)
        unmeasured = [k for k, v in out["counters"].items() if v == UNKNOWN]
        self.assertEqual(len(unmeasured), 25)
        # Fail-closed guards: no F0, epoch change, or UNKNOWN inputs
        # can ever yield a radio-fault label.
        for kw in ({"f0_present": False}, {"same_boot_epoch": False},
                   {"counters_unknown": True}):
            r = classify(sreq_timeouts=64, zcl_timeouts=69, d_enq=0,
                         d_af_confirm=0, **kw)
            self.assertEqual(r["label"], "unknown_needs_counters")
            self.assertFalse(r["ota_causal"])


class FixtureTests(unittest.TestCase):
    def test_f1_synthetic_srsp_absence(self):
        r = classify(sreq_timeouts=64, zcl_timeouts=69, d_enq=0,
                     d_af_confirm=0)
        self.assertEqual(r["label"], "srsp_absence_burst")

    def test_f2_synthetic_af_confirm(self):
        r = classify(sreq_timeouts=0, zcl_timeouts=20, d_enq=5,
                     d_af_confirm=18)
        self.assertEqual(r["label"], "af_confirm_failure")

    def test_f3_synthetic_teardown(self):
        r = classify(sreq_timeouts=64, zcl_timeouts=69, d_enq=0,
                     d_af_confirm=0, sigterm=True)
        self.assertEqual(r["label"], "host_teardown")

    def test_f4_synthetic_ota_overlap(self):
        r = classify(sreq_timeouts=64, zcl_timeouts=69, d_enq=0,
                     d_af_confirm=0, ota_overlap=True)
        self.assertEqual(r["label"], "srsp_absence_burst")
        self.assertFalse(r["ota_causal"])


if __name__ == "__main__":
    unittest.main()
