"""Adversarial offline tests for P7U F2 freshness without radio/HA access."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from p7u_f2_freshness import analyze
from p7u_f2_acceptance import EvidenceHold, canonical


OWNER = "00000000-0000-4000-8000-000000000003"
HOST = "00000000-0000-4000-8000-000000000002"
OTHER = "00000000-0000-4000-8000-000000000004"


def record(at, kind="SKIPPED", reason="ADAPTER_QUEUE_PENDING", host=HOST, owner=OWNER, **extra):
    return {
        "schema": "p7u-b4-native-sample-v1", "kind": kind, "utc": at,
        "hostRunId": host, "ownerGeneration": owner,
        "monotonicReceiveNs": str(at * 1_000_000),
        "reason": reason, **extra,
    }


def f2(at, seq=1, **extra):
    fields = dict(sequence=seq, validityMask=0x2c, asyncDepth=0, asyncHighWater=148,
                  srspDepth=None, srspHighWater=None, uartTxFinishedEvents=43092)
    fields.update(extra)
    return record(at, kind="VALID", reason=None, **fields)


def progress(ok, timeout):
    return {"srsp": {name: {"ok": ok, "timeout": timeout} for name in
                      ("AF", "ZDO", "SYS", "UTIL")}}


def write_chain(root, rows):
    prev = "0" * 64
    lines = []
    last_valid = None
    for i, row in enumerate(rows, 1):
        entry = {"seq": i, "previous": prev, "data": row}
        h = hashlib.sha256(canonical(entry)).hexdigest()
        lines.append(json.dumps({**entry, "sha": h}, separators=(",", ":")) + "\n")
        prev = h
        if row["kind"] == "VALID":
            last_valid = i
    raw = "".join(lines).encode()
    (root / "events-v2.jsonl").write_bytes(raw)
    (root / "manifest-v2.json").write_text(json.dumps({
        "schema": "p7u-f2-worker-v2", "sequence": len(rows),
        "committedBytes": len(raw), "head": prev,
        "lastValidSeq": last_valid,
        "lastValidHostRun": rows[last_valid-1]["hostRunId"] if last_valid else None,
    }))


class FreshnessTests(unittest.TestCase):
    def test_jitter_retains_one_minute_lower_bound_and_existing_queue_gates(self):
        source = Path(__file__).with_name("b4_v4_live_collector_overlay.py").read_text()
        self.assertIn("randomInt(60_000, 90_001)", source)
        self.assertIn("Math.max(60_000, delay)", source)
        self.assertIn("this.b4ProbeReadOnlyDiagnosticsV4(true, reserveAtBoundary)", source)
        self.assertIn("performance.now() - origin >= 900_000", source)
        self.assertIn("this.#b4NativeCommittedCount < 3", source)
        self.assertIn("Math.min(3, this.#b4NativeCommittedCount + 1)", source)
        self.assertIn("this.#b4Schedule(60_000)", source)
        self.assertIn("this.#b4SamplerDisabled", source)
        self.assertNotIn("new Znp(", source)
        self.assertIn("P7U F2 NATIVE_30M_MISSED", source)
        self.assertIn("const nativeCommittedUtc = this.#b4PendingNativeValidUtc.get(message.id)", source)
        self.assertIn("this.#b4LastNativeCommittedUtc = nativeCommittedUtc", source)
        self.assertIn("this.#b4PendingNativeValidUtc.delete(id)", source)
        self.assertIn("now - origin < 1_800_000", source)
        self.assertIn("DO NOT reset radio on F2 staleness", source)

    def test_skipped_sampling_with_advancing_srsp_is_not_a_hang(self):
        rows = [f2(1_000_000), record(1_150_000, hostEvidence=progress(10, 2)),
                record(1_240_000, reason="ZNP_WAITRESS_PENDING",
                       hostEvidence=progress(90, 2))]
        q = analyze(rows, now_ms=1_400_000, fresh_after_ms=300_000)
        self.assertEqual(q["f2_freshness"], "STALE")
        self.assertEqual(q["collector_feed"], "FRESH")
        self.assertEqual(q["passive_srsp_progress"], "OBSERVED_HOST_COUNTERS")
        self.assertEqual(q["passive_srsp_delta"]["AF"], {"ok": 80, "timeout": 0})
        self.assertFalse(q["automatic_recovery_permitted"])
        self.assertEqual(q["retained_network_serving"], "NOT_ASSESSED")
        self.assertIsNone(q["last_native"]["srsp_depth"])

    def test_valid_restarts_freshness_without_claiming_serving(self):
        q = analyze([f2(1000, 1), f2(250000, 2)], now_ms=300000)
        self.assertEqual(q["f2_freshness"], "FRESH")
        self.assertEqual(q["valid_f2_current_owner_count"], 2)
        self.assertEqual(q["last_native"]["uart_tx_finished_events"], 43092)
        self.assertEqual(q["retained_network_serving"], "NOT_ASSESSED")

    def test_owner_change_never_borrows_previous_valid(self):
        rows = [f2(1000), record(290000, owner=OTHER)]
        q = analyze(rows, now_ms=300000)
        self.assertEqual(q["f2_freshness"], "NO_CURRENT_OWNER_VALID")
        self.assertIsNone(q["last_native"])

    def test_only_latest_consecutive_owner_run_counts(self):
        rows = [f2(1000), record(2000, owner=OTHER), record(3000)]
        q = analyze(rows, now_ms=4000)
        self.assertEqual(q["f2_freshness"], "NO_CURRENT_OWNER_VALID")

    def test_no_rows_is_unknown_and_inert(self):
        q = analyze([], now_ms=1000)
        self.assertEqual(q["collector_feed"], "NO_RECORDS")
        self.assertEqual(q["passive_srsp_progress"], "UNKNOWN")
        self.assertFalse(q["automatic_recovery_permitted"])

    def test_counter_discontinuity_not_negative_progress(self):
        rows = [record(1000, hostEvidence=progress(120, 4)),
                record(2000, hostEvidence=progress(1, 0))]
        q = analyze(rows, now_ms=3000)
        self.assertEqual(q["passive_srsp_progress"], "COUNTER_DISCONTINUITY")
        self.assertIsNone(q["passive_srsp_delta"])

    def test_native_30m_window_and_collector_feed_are_separate(self):
        # A healthy passive feed must NEVER conceal a >30m native blackout.
        rows = [f2(1_000), record(1_820_000, processUptimeMs=1_820_000)]
        q = analyze(rows, now_ms=1_850_000)
        self.assertEqual(q["collector_feed"], "FRESH")
        self.assertEqual(q["f2_freshness"], "STALE")
        self.assertEqual(q["native_f2_30m_objective"], "BREACHED")
        self.assertEqual(q["native_f2_in_last_30m"], 0)
        self.assertFalse(q["automatic_recovery_permitted"])
        self.assertEqual(q["retained_network_serving"], "NOT_ASSESSED")

    def test_native_30m_met_by_valid_commit_not_skipped_sampling(self):
        q = analyze([record(1_000), f2(1_710_000, 2),
                     record(1_810_000)], now_ms=1_820_000)
        self.assertEqual(q["native_f2_30m_objective"], "MET")
        self.assertEqual(q["native_f2_in_last_30m"], 1)
        self.assertEqual(q["collector_feed"], "FRESH")

    def test_previous_owner_native_cannot_satisfy_30m(self):
        rows = [f2(1_000), record(2_000, owner=OTHER, processUptimeMs=100_000)]
        q = analyze(rows, now_ms=3_000)
        self.assertEqual(q["native_f2_in_last_30m"], 0)
        self.assertEqual(q["native_f2_30m_objective"], "NOT_YET_OBSERVED_FOR_30M")
        self.assertFalse(q["automatic_recovery_permitted"])

    def test_no_first_native_for_over_30m_is_breach_not_false_fresh(self):
        q = analyze([record(10_000, processUptimeMs=1_910_000)],
                    now_ms=20_000)
        self.assertEqual(q["f2_freshness"], "NO_CURRENT_OWNER_VALID")
        self.assertEqual(q["native_f2_30m_objective"], "BREACHED")

    def test_passive_wire_boundary_silence_after_host_queue(self):
        def ev(rx, parsed, tx):
            return {**progress(100, 0), "wire": {
                "rxRawBytes": rx, "rxChunks": rx // 10,
                "unpiParsedFrames": parsed, "unpiParseErrors": 0,
                "unpiBufferedBytes": 0, "txQueuedBytes": tx,
                "txQueuedFrames": tx // 20, "txQueuedRawBuffers": 0,
                "measurement": "EXISTING_OWNER_STREAM_ONLY"}}
        q = analyze([record(1000, hostEvidence=ev(100, 5, 120)),
                     record(2000, hostEvidence=ev(100, 5, 220))], now_ms=3000)
        self.assertEqual(q["wire_boundary_status"], "NO_RAW_RX_WHILE_HOST_QUEUES_TX")
        self.assertEqual(q["wire_boundary_deltas"]["rxRawBytes"], 0)
        self.assertFalse(q["automatic_recovery_permitted"])
        self.assertEqual(q["retained_network_serving"], "NOT_ASSESSED")

    def test_passive_wire_raw_bytes_without_valid_unpi(self):
        def ev(rx, parsed, errors):
            return {**progress(100, 0), "wire": {
                "rxRawBytes": rx, "rxChunks": 2, "unpiParsedFrames": parsed,
                "unpiParseErrors": errors, "unpiBufferedBytes": 8,
                "txQueuedBytes": 100, "txQueuedFrames": 4,
                "txQueuedRawBuffers": 0,
                "measurement": "EXISTING_OWNER_STREAM_ONLY"}}
        q = analyze([record(1000, hostEvidence=ev(100, 2, 0)),
                     record(2000, hostEvidence=ev(350, 2, 3))], now_ms=3000)
        self.assertEqual(q["wire_boundary_status"], "RAW_RX_WITHOUT_VALID_UNPI_FRAMES")
        self.assertEqual(q["wire_boundary_deltas"]["unpiParseErrors"], 3)

    def test_passive_wire_parsed_frames_without_AF_srsp(self):
        def ev(rx, parsed, timeout):
            e = progress(40, timeout)
            e["wire"] = {"rxRawBytes": rx, "rxChunks": rx // 10,
                         "unpiParsedFrames": parsed, "unpiParseErrors": 0,
                         "unpiBufferedBytes": 0, "txQueuedBytes": 100,
                         "txQueuedFrames": 1, "txQueuedRawBuffers": 0,
                         "measurement": "EXISTING_OWNER_STREAM_ONLY"}
            return e
        q = analyze([record(1000, hostEvidence=ev(200, 4, 1)),
                     record(2000, hostEvidence=ev(500, 7, 5))], now_ms=3000)
        self.assertEqual(q["wire_boundary_status"], "VALID_UNPI_BUT_AF_SRSP_NOT_PROGRESSING")
        self.assertEqual(q["passive_srsp_delta"]["AF"]["timeout"], 4)

    def test_wire_legacy_absent_and_tampering_hold(self):
        q = analyze([record(1000, hostEvidence=progress(1, 1)),
                     record(2000, hostEvidence=progress(2, 1))], now_ms=3000)
        self.assertEqual(q["wire_boundary_status"], "NOT_INSTALLED_OR_INSUFFICIENT")
        bad = progress(1, 1)
        bad["wire"] = {"rxRawBytes": 1, "rawPayload": "FE...", "measurement": "EXISTING_OWNER_STREAM_ONLY"}
        with self.assertRaises(EvidenceHold):
            analyze([record(1000, hostEvidence=bad),
                     record(2000, hostEvidence=bad)], now_ms=3000)

    def test_waitress_legacy_map_occupancy_not_active_requests(self):
        accounting = {"active": 2, "timedOut": 2026, "resolved": 0,
                      "rawMapEntries": 2028}
        x = progress(1, 0)
        x["waitressAccounting"] = accounting
        x["waitressPending"] = 2028
        q = analyze([record(1000, hostEvidence=x)], now_ms=2000)
        self.assertEqual(q["waitress_live_vs_expired"]["active"], 2)
        self.assertEqual(q["waitress_live_vs_expired"]["timedOut"], 2026)
        self.assertFalse(q["automatic_recovery_permitted"])
        bad = dict(x)
        bad["waitressAccounting"] = {**accounting, "active": 3}
        with self.assertRaises(EvidenceHold):
            analyze([record(1000, hostEvidence=bad)], now_ms=2000)

    def test_f2_v42_stage_deltas_and_epoch_scope(self):
        fields = ("allProduced", "allEnqueued", "allAllocFailed",
                  "allSendFailed", "allNpiReceived", "allFramedQueued",
                  "allFramingFailed", "allTlSubmitted", "allTlRejected",
                  "afDataProduced", "afDataEnqueued", "afDataAllocFailed",
                  "afDataSendFailed", "afDataNpiReceived", "afDataFramedQueued",
                  "afDataFramingFailed", "afDataTlSubmitted", "afDataTlRejected")
        a = {k: 10 for k in fields}
        b = {k: 20 for k in fields}
        q = analyze([f2(1000, 1, minor=2, validityMask=0x00ffffec,
                        mtLifecycle=a, radioEpochTag="epoch-a"),
                     f2(2000, 2, minor=2, validityMask=0x00ffffec,
                        mtLifecycle=b, radioEpochTag="epoch-a")],
                    now_ms=3000)
        self.assertEqual(q["native_mt_lifecycle"]["allTlSubmitted"],20)
        self.assertEqual(q["native_mt_lifecycle_delta"]["allTlSubmitted"],10)
        self.assertEqual(q["native_mt_delta_status"],
                         "SAME_OWNER_TOKEN_OBSERVATION_NOT_HARDWARE_ATTESTED")
        q = analyze([f2(1000, 1, minor=2, validityMask=0x00ffffec,
                        mtLifecycle=a, radioEpochTag="epoch-a"),
                     f2(2000, 2, minor=2, validityMask=0x00ffffec,
                        mtLifecycle=b, radioEpochTag="epoch-b")],
                    now_ms=3000)
        self.assertIsNone(q["native_mt_lifecycle_delta"])
        with self.assertRaises(EvidenceHold):
            analyze([f2(1000, 1, minor=2, validityMask=0x2c,
                        mtLifecycle=a)], now_ms=2000)
        with self.assertRaises(EvidenceHold):
            analyze([f2(1000, 1, minor=2, validityMask=0x00ffffec,
                        mtLifecycle={**a, "rawPayload":123})], now_ms=2000)

    def test_future_clock_never_fabricates_freshness(self):
        q = analyze([f2(2_000)], now_ms=1_000)
        self.assertEqual(q["f2_freshness"], "CLOCK_UNCERTAIN")
        self.assertEqual(q["collector_feed"], "CLOCK_UNCERTAIN")

    def test_unsupported_srsp_metrics_remain_null(self):
        q = analyze([f2(1000)], now_ms=1000)
        self.assertEqual(q["last_native"]["validity_mask"], 0x2c)
        self.assertIsNone(q["last_native"]["srsp_high_water"])

    def test_invalid_mask_or_nan_native_is_held(self):
        with self.assertRaises(EvidenceHold):
            analyze([f2(1000, validityMask=0x40)], now_ms=1000)
        with self.assertRaises(EvidenceHold):
            analyze([f2(1000, asyncDepth=-1)], now_ms=1000)

    def test_untrusted_reason_sanitized(self):
        q = analyze([record(1000, reason="secret_or_ieee_user_string")], now_ms=2000)
        self.assertEqual(q["recent_skip_reasons"], {"OTHER_OR_UNKNOWN": 1})
        self.assertNotIn("secret_or_ieee", json.dumps(q))

    def test_synthetic_chain_cli_and_tamper_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            write_chain(path, [f2(1000), record(2000)])
            cmd = [sys.executable, str(Path(__file__).with_name("p7u_f2_freshness.py")),
                   "--history-dir", str(path), "--now-ms", "400000",
                   "--fresh-seconds", "300"]
            r = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            d = json.loads(r.stdout)
            self.assertEqual(d["f2_freshness"], "STALE")
            self.assertFalse(d["automatic_recovery_permitted"])
            data = path / "events-v2.jsonl"
            data.write_bytes(data.read_bytes().replace(b"ADAPTER_QUEUE_PENDING", b"DIAGNOSTIC_QUARANTINED"))
            bad = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(bad.returncode, 2)
            self.assertEqual(json.loads(bad.stdout)["evidence_trust"], "HOLD")


if __name__ == "__main__":
    unittest.main()
