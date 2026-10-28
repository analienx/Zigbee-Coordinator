"""GH-hosted F2 protocol evaluator negative controls; all synthetic."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

p = Path(__file__).with_name("p7u_f2_acceptance.py")
spec = importlib.util.spec_from_file_location("p7u_f2_acceptance", p)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

HOST = "8e2cdca6-17b6-4a4c-a951-a78742ad89e1"
OWNER = "28ca5f87-b319-4c93-93d3-23d0f46a316d"


def valid(seq, kind="VALID", host=HOST, owner=OWNER, epoch=None):
    x = {"schema": "p7u-b4-native-sample-v1", "kind": kind,
         "utc": 1792700000000 + seq, "monotonicReceiveNs": str(seq * 1000000000),
         "hostRunId": host, "ownerGeneration": owner, "probeLatencyMs": 21,
         "radioEpochTag": epoch}
    if kind == "VALID":
        x.update({"abi": 4, "sequence": seq, "validityMask": 0x2c})
    return x


def write_history(directory, rows):
    previous = "0" * 64
    lines = []
    for i, row in enumerate(rows, 1):
        entry = {"seq": i, "previous": previous, "data": row}
        previous = hashlib.sha256(m.canonical(entry)).hexdigest()
        lines.append(m.canonical({**entry, "sha": previous}) + b"\n")
    raw = b"".join(lines)
    (directory / "events-v2.jsonl").write_bytes(raw)
    last = next((i for i in range(len(rows), 0, -1)
                 if rows[i-1]["kind"] == "VALID"), None)
    (directory / "manifest-v2.json").write_text(json.dumps({
        "schema": "p7u-f2-worker-v2", "sequence": len(rows),
        "committedBytes": len(raw), "head": previous,
        "lastValidSeq": last,
        "lastValidHostRun": rows[last-1]["hostRunId"] if last else None,
    }))


class Tests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)

    def rows(self, rows):
        write_history(self.root, rows)
        return m.read_verified_history(self.root)

    def test_three_valid_null_epoch_protocol_pass_radio_unknown(self):
        v = m.evaluate(self.rows([valid(1), valid(2), valid(3)]), serving="PASS")
        self.assertEqual((v.protocol, v.radio_epoch, v.serving), ("PASS", "UNKNOWN", "PASS"))
        self.assertEqual(v.native_sequences, (1, 2, 3))

    def test_stable_software_epoch_does_not_claim_radio_continuity(self):
        v = m.evaluate(self.rows([valid(1, epoch="opaque"),
                                  valid(2, epoch="opaque"),
                                  valid(3, epoch="opaque")]))
        self.assertEqual(v.radio_epoch, "UNKNOWN")
        self.assertEqual(v.protocol, "PASS")

    def test_skipped_or_failed_do_not_imply_radio_failure_or_host_rollback(self):
        rows = self.rows([valid(1), valid(2), valid(3, kind="SKIPPED")])
        verdict = m.evaluate(rows, serving="PASS")
        self.assertEqual(verdict.protocol, "INSUFFICIENT")
        self.assertEqual(verdict.serving, "PASS")

    def test_three_valid_across_host_restart_do_not_pass(self):
        another = "3492d844-8d6b-454e-8e2c-45925f3d5641"
        verdict = m.evaluate(self.rows([valid(1), valid(2), valid(3, host=another)]))
        self.assertEqual(verdict.protocol, "INSUFFICIENT")

    def test_busy_skips_between_native_reads_and_after_last_do_not_erase_acceptance(self):
        rows = [valid(1), valid(2, kind="SKIPPED"), valid(3),
                valid(4, kind="SKIPPED"), valid(5), valid(6, kind="SKIPPED")]
        verdict = m.evaluate(self.rows(rows))
        self.assertEqual(verdict.protocol, "PASS")
        self.assertEqual(verdict.native_sequences, (1, 3, 5))

    def test_failed_quarantined_or_closed_after_valid_reads_invalidates_acceptance(self):
        for kind in ("FAILED", "QUARANTINED", "OWNER_CLOSED"):
            with self.subTest(kind=kind):
                rows = [valid(1), valid(2), valid(3), valid(4, kind=kind)]
                self.assertEqual(m.evaluate(self.rows(rows)).protocol, "INSUFFICIENT")

    def test_new_owner_skip_cannot_reuse_previous_owner_valid_reads(self):
        another = "3492d844-8d6b-454e-8e2c-45925f3d5641"
        rows = [valid(1), valid(2), valid(3), valid(4, kind="SKIPPED", host=another)]
        self.assertEqual(m.evaluate(self.rows(rows)).protocol, "INSUFFICIENT")

    def test_native_seq_or_monotonic_time_not_advancing_refused(self):
        a = valid(1); b = valid(2); c = valid(3)
        c["sequence"] = 2
        self.assertEqual(m.evaluate(self.rows([a,b,c])).protocol, "INSUFFICIENT")
        c["sequence"] = 3
        c["monotonicReceiveNs"] = b["monotonicReceiveNs"]
        self.assertEqual(m.evaluate(self.rows([a,b,c])).protocol, "INSUFFICIENT")

    def test_counter_unqualified_still_passes_without_inventing_srsp_hwm(self):
        a,b,c = [valid(i) for i in (1,2,3)]
        for r in (a,b,c):
            r["srspDepth"] = None
            r["srspHighWater"] = None
        self.assertEqual(m.evaluate(self.rows([a,b,c])).protocol, "PASS")

    def test_corrupt_history_never_automatically_repaired(self):
        self.rows([valid(1)])
        path=self.root / "events-v2.jsonl"
        before=path.read_bytes()+b"garbage"
        path.write_bytes(before)
        with self.assertRaisesRegex(m.EvidenceHold, "TAIL"):
            m.read_verified_history(self.root)
        self.assertEqual(path.read_bytes(), before)

    def test_manifest_tamper_refused(self):
        self.rows([valid(1),valid(2),valid(3)])
        p=self.root / "manifest-v2.json"
        doc=json.loads(p.read_text())
        doc["head"]="f"*64
        p.write_text(json.dumps(doc))
        with self.assertRaisesRegex(m.EvidenceHold, "MANIFEST_CHAIN"):
            m.read_verified_history(self.root)

    def test_missing_manifest_is_hold(self):
        self.rows([valid(1)])
        (self.root / "manifest-v2.json").unlink()
        with self.assertRaisesRegex(m.EvidenceHold, "MISSING"):
            m.read_verified_history(self.root)

    def pointed(self):
        self.rows([valid(1), valid(2), valid(3)])
        name = "generation-8e2cdca6-17b6-4a4c-a951-a78742ad89e1"
        directory = self.root / name
        directory.mkdir()
        for filename in ("events-v2.jsonl", "manifest-v2.json"):
            (self.root / filename).rename(directory / filename)
        (self.root / "current-v2.json").write_text(json.dumps({
            "schema": "p7u-f2-pointer-v1", "active": name, "previous": None,
        }))
        return directory

    def test_pointer_selects_generation_without_reading_legacy_v1(self):
        self.pointed()
        (self.root / "history.json").write_text("unrelated preserved v1 evidence")
        self.assertEqual(m.evaluate(m.read_verified_history(self.root)).protocol, "PASS")

    def test_pending_pointer_or_orphan_generation_never_becomes_evidence(self):
        self.pointed()
        pending = self.root / ".current-v2.pending"
        pending.write_text("uncommitted pointer")
        with self.assertRaisesRegex(m.EvidenceHold, "ORPHANED_POINTER"):
            m.read_verified_history(self.root)
        pending.unlink()
        (self.root / "generation-3492d844-8d6b-454e-8e2c-45925f3d5641").mkdir()
        with self.assertRaisesRegex(m.EvidenceHold, "ORPHANED_GENERATION"):
            m.read_verified_history(self.root)

    def test_pointer_cannot_escape_or_select_a_symlinked_directory(self):
        selected = self.pointed()
        pointer = self.root / "current-v2.json"
        document = json.loads(pointer.read_text())
        document["active"] = "../outside"
        pointer.write_text(json.dumps(document))
        with self.assertRaisesRegex(m.EvidenceHold, "POINTER_SCHEMA"):
            m.read_verified_history(self.root)
        document["active"] = selected.name
        pointer.write_text(json.dumps(document))
        moved = self.root / "elsewhere"
        selected.rename(moved)
        selected.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(m.EvidenceHold, "ACTIVE_DIRECTORY"):
            m.read_verified_history(self.root)


def paired(depth, submitted, finished, cb, flags=0):
    return {"kind": "VALID", "asyncDepth": depth,
            "uartTxFinishedEvents": finished,
            "mtLifecycle": {"allTlSubmitted": submitted, "afDataTlSubmitted": 0},
            "uartProgress": {"uartCallbackOk": cb, "stateFlags": flags}}


class TestPairedShape(unittest.TestCase):
    def test_single_reply_is_unverified(self):
        self.assertEqual(m.assess_paired_replies(paired(69, 100, 50, 80))[0],
                         "UNVERIFIED")

    def test_lost_wake_needs_paired_idle(self):
        self.assertEqual(
            m.assess_paired_replies(paired(69, 100, 50, 80),
                                    paired(70, 100, 50, 80))[0],
            "LOST_WAKE_CANDIDATE")
        self.assertEqual(
            m.assess_paired_replies(paired(69, 100, 50, 80),
                                    paired(70, 101, 51, 81))[0],
            "THROUGHPUT")

    def test_bridge_candidate(self):
        self.assertEqual(
            m.assess_paired_replies(paired(0, 100, 50, 80),
                                    paired(0, 100, 50, 90))[0],
            "BRIDGE_CANDIDATE")


if __name__ == "__main__":
    unittest.main()
