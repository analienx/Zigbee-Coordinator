from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("t832_incident", HERE / "t832_incident.py")
assert SPEC and SPEC.loader
incident = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(incident)


def packet_hex(
    *,
    export_sequence: int = 1,
    uptime_ms: int = 12345,
    event_kind: int = 19,
    a: int = 7,
    b: int = 8,
    c: int = 9,
) -> str:
    header = struct.pack(
        "<4sBBHHQIIHHH",
        b"T8D1",
        1,
        1,
        export_sequence,
        1,
        uptime_ms,
        8320001,
        0x1FFF,
        0,
        0,
        0,
    )
    record = struct.pack(
        "<IIHBBHHHH",
        100,
        101,
        export_sequence,
        event_kind,
        0,
        a,
        b,
        c,
        1,
    )
    return (header + record).hex().upper()


def packet_v2_hex(
    *,
    export_sequence: int = 1,
    uptime_ms: int = 12345,
    build_id: int = 0xA5A50001,
    records: list[tuple[int, int, int, int]] | None = None,
) -> str:
    header = struct.pack(
        "<4sBBHHQIIHHH",
        b"T8D1",
        2,
        1,
        export_sequence,
        1,
        uptime_ms,
        build_id,
        0x3FFFFF,
        0,
        0,
        0,
    )
    body = [header, bytes([len(records or [(19, 0, 7, 8)])])]
    for kind, a, b, c in records or [(19, 0, 7, 8)]:
        body.append(
            struct.pack("<IIHBBHHHH", 100, 101, export_sequence, kind, 0, a, b, c, 1)
        )
    return b"".join(body).hex().upper()


def buffer_line(payload_text: str, uptime_note: str = "2026-10-03T09:00:00Z") -> str:
    """Stock pinned-herdsman shape: ZpiObject.toString() of AREQ DEBUG msg,
    i.e. `AREQ: DEBUG - msg - {"length":N,"string":{"type":"Buffer",...}}`."""
    raw = payload_text.encode("ascii")
    data = ",".join(str(b) for b in raw)
    return (
        f"{uptime_note} zh:zstack:znp: AREQ: DEBUG - msg - "
        '{"length":' + str(len(raw)) + ',"string":{"type":"Buffer","data":['
        + data
        + "]}}"
        "\n"
    )


class DecodeTests(unittest.TestCase):
    def test_packet_round_trip(self) -> None:
        decoded = incident.decode_packet(packet_hex(event_kind=24, a=1, b=9))
        self.assertEqual(decoded["signature"], "T8D1")
        self.assertEqual(decoded["record"]["kind_name"], "NETWORK_STATE")
        self.assertEqual(decoded["record"]["a"], 1)
        self.assertEqual(decoded["record"]["b"], 9)

    def test_bad_packet_rejected(self) -> None:
        with self.assertRaises(ValueError):
            incident.decode_packet("00")

    def test_schema2_batch_decodes(self) -> None:
        frame, records = incident.decode_frame_payload(
            "T832D2:" + packet_v2_hex(export_sequence=9, records=[(19, 1, 2, 3), (28, 4, 5, 6)])
        )
        self.assertEqual(frame["schema"], 2)
        self.assertEqual(frame["export_sequence"], 9)
        self.assertEqual(frame["firmware_build_id"], 0xA5A50001)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["kind_name"], "HEALTH")
        self.assertEqual(records[1]["kind_name"], "AF_STATE")

    def test_schema2_bad_count_rejected(self) -> None:
        raw = bytes.fromhex(packet_v2_hex())
        bad = bytearray(raw)
        bad[32] = 5
        with self.assertRaises(ValueError):
            incident.decode_frame_payload("T832D2:" + bytes(bad).hex().upper())
        with self.assertRaises(ValueError):
            incident.decode_frame_payload("T832D2:" + raw.hex().upper() + "00")


class CollectorTests(unittest.TestCase):
    def test_file_only_collection_and_continuity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp DEBUG.msg "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n"
                "2026-10-03T09:00:05Z serial timeout "
                f"T832D1:{packet_hex(export_sequence=3, uptime_ms=6000)}\n",
                encoding="utf-8",
            )
            result = incident.collect(
                store,
                [str(log)],
                config_fingerprint="cfg",
                initial_tail_bytes=1024 * 1024,
                retain_days=7,
                max_bytes=1 << 30,
            )
            self.assertEqual(result["diag_records"], 2)
            day = incident.utcnow().strftime("%Y-%m-%d")
            rows = [
                json.loads(line)
                for line in (store.stream / f"diag-{day}.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[0]["sequence_gap_before"], 0)
            self.assertEqual(rows[1]["sequence_gap_before"], 1)
            self.assertEqual(rows[1]["config_fingerprint"], "cfg")
            self.assertTrue((store.stream / f"host-{day}.jsonl").exists())

    def test_missing_source_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            result = incident.collect(
                store,
                [str(Path(td) / "missing.log")],
                config_fingerprint=None,
                initial_tail_bytes=1024,
                retain_days=7,
                max_bytes=1 << 20,
            )
            self.assertEqual(result["sources_seen"], 0)
            self.assertTrue(result["missing_sources"])

    def test_herdsman_buffer_repr_decodes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                buffer_line("T832D2:" + packet_v2_hex(export_sequence=4, uptime_ms=9000)),
                encoding="utf-8",
            )
            result = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertEqual(result["diag_records"], 1)
            day = incident.utcnow().strftime("%Y-%m-%d")
            row = json.loads((store.stream / f"diag-{day}.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(row["repr"], "herdsman-buffer-v1")
            self.assertEqual(row["export_sequence"], 4)
            self.assertEqual(row["record"]["kind_name"], "HEALTH")

    def test_one_line_appends_never_lose(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("", encoding="utf-8")
            total = 0
            for seq in range(1, 6):
                with log.open("a", encoding="utf-8") as fh:
                    fh.write(
                        "2026-10-03T09:00:00Z zh:zstack:znp "
                        f"T832D1:{packet_hex(export_sequence=seq, uptime_ms=seq * 1000)}\n"
                    )
                result = incident.collect(
                    store, [str(log)], config_fingerprint=None,
                    initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
                )
                total += result["diag_records"]
                self.assertEqual(result["diag_records"], 1)
            self.assertEqual(total, 5)

    def test_partial_line_buffered_durably(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            chunk = "2026-10-03T09:00:00Z zh:zstack:znp " f"T832D1:{packet_hex(export_sequence=1)}"
            log.write_text(chunk, encoding="utf-8")
            first = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertEqual(first["diag_records"], 0)
            cursor = json.loads((root / "private" / "state" / "collector.json").read_text(encoding="utf-8"))
            self.assertTrue(cursor["files"][str(log)]["partial"])
            with log.open("a", encoding="utf-8") as fh:
                fh.write("\n")
            second = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertEqual(second["diag_records"], 1)
            third = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertEqual(third["diag_records"], 0)

    def test_rotation_and_truncation_reset(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
                encoding="utf-8",
            )
            incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            log.unlink()
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
                encoding="utf-8",
            )
            again = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertEqual(again["diag_records"], 1)
            self.assertTrue(any(n.startswith("rotated:") for n in again["notes"]))
            # Same inode, same size, new mtime (in-place rewrite without
            # unlink): identity and size checks are blind, the mtime guard
            # must still reset to zero instead of resuming at stale EOF.
            with log.open("w", encoding="utf-8") as fh:
                fh.write(
                    "2026-10-03T09:00:00Z zh:zstack:znp "
                    f"T832D1:{packet_hex(export_sequence=2, uptime_ms=2000)}\n"
                )
            # Deterministic mtime step even on coarse-grained filesystems.
            anchor = log.stat()
            os.utime(log, (anchor.st_atime + 2, anchor.st_mtime + 2))
            rewritten = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertEqual(rewritten["diag_records"], 1)
            self.assertTrue(any(n.startswith("rotated:") for n in rewritten["notes"]))
            with log.open("w", encoding="utf-8") as fh:
                fh.write("short\n")
            trunc = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertTrue(
                any(n.startswith("truncated:") for n in trunc["notes"])
                or trunc["diag_records"] == 0
            )

    def test_collect_budget_marks_partial(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            # Two lines: the first fits the 10-byte budget check at loop top
            # and is collected; the second trips the budget, so the remainder
            # is honestly reported as partial. A single fully-collected line
            # is complete, not partial, even when it exceeds the budget.
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n"
                "2026-10-03T09:00:01Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=2, uptime_ms=2000)}\n",
                encoding="utf-8",
            )
            result = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
                max_collect_bytes=10,
            )
            self.assertTrue(result["partial"])
            self.assertEqual(result["diag_records"], 1)
            self.assertTrue(
                any(n.startswith("collect-budget-exceeded:") for n in result["notes"])
            )


def stream_rows(store: Store) -> list[dict]:
    day = incident.utcnow().strftime("%Y-%m-%d")
    path = store.stream / f"diag-{day}.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class ContinuityTests(unittest.TestCase):
    def collect_lines(self, store: Store, log: Path, lines: list[str]) -> list[dict]:
        with log.open("a", encoding="utf-8") as fh:
            fh.writelines(lines)
        result = incident.collect(
            store, [str(log)], config_fingerprint=None,
            initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
        )
        self.assertGreater(result["diag_records"], 0)
        return stream_rows(store)

    def test_wrap_replay_duplicate_boot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("", encoding="utf-8")

            def line(seq: int, up: int, kind: int = 19) -> str:
                return (
                    "2026-10-03T09:00:00Z zh:zstack:znp "
                    f"T832D1:{packet_hex(export_sequence=seq, uptime_ms=up, event_kind=kind)}\n"
                )

            rows = self.collect_lines(store, log, [line(65530, 1000), line(65531, 2000)])
            self.assertEqual(rows[-1]["continuity_kind"], "normal")
            rows = self.collect_lines(store, log, [line(5, 3000)])
            self.assertEqual(rows[-1]["continuity_kind"], "wrap")
            self.assertFalse(rows[-1]["session_reset_detected"])
            self.assertEqual(rows[-1]["sequence_gap_before"], (0xFFFF - 65531) + 5)
            rows = self.collect_lines(store, log, [line(5, 3000)])
            self.assertEqual(rows[-1]["continuity_kind"], "duplicate")
            session = rows[-1]["host_session"]
            rows = self.collect_lines(store, log, [line(4, 4000)])
            self.assertEqual(rows[-1]["continuity_kind"], "replay")
            self.assertEqual(rows[-1]["host_session"], session)
            self.assertFalse(rows[-1]["session_reset_detected"])
            rows = self.collect_lines(store, log, [line(6, 500), line(7, 600)])
            self.assertEqual(rows[-2]["continuity_kind"], "reboot")
            self.assertTrue(rows[-2]["session_reset_detected"])
            boot_session = rows[-2]["host_session"]
            rows = self.collect_lines(store, log, [line(1, 700, kind=1)])
            self.assertEqual(rows[-1]["continuity_kind"], "boot")
            self.assertNotEqual(rows[-1]["host_session"], boot_session)
            self.assertEqual(rows[-1]["boot_index"], rows[-2]["boot_index"] + 1)

    def test_seven_day_stream_with_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("", encoding="utf-8")
            seq = 65530
            uptime = 0
            expected = 0
            dups = 0
            for day in range(7):
                lines = []
                for _ in range(40):
                    seq = (seq + 1) % 65536
                    uptime += 5 * 60 * 1000
                    stamp = f"2026-10-{day + 1:02d}T09:00:00Z"
                    lines.append(
                        f"{stamp} zh:zstack:znp "
                        f"T832D1:{packet_hex(export_sequence=seq, uptime_ms=uptime)}\n"
                    )
                    expected += 1
                if day == 3:
                    lines.append(lines[-1])
                    dups += 1
                    expected += 1
                with log.open("a", encoding="utf-8") as fh:
                    fh.writelines(lines)
                result = incident.collect(
                    store, [str(log)], config_fingerprint=None,
                    initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
                )
                self.assertGreaterEqual(result["diag_records"], 0)
                if day == 4:
                    rotated = root / "z2m.log.1"
                    log.rename(rotated)
                    log.write_text("", encoding="utf-8")
            rows = stream_rows(store)
            self.assertEqual(len(rows), expected)
            kinds = [r["continuity_kind"] for r in rows]
            self.assertEqual(kinds.count("duplicate"), dups)
            self.assertGreater(kinds.count("wrap"), 0)
            self.assertFalse(any(r["session_reset_detected"] for r in rows))


class CollectorExactnessTests(unittest.TestCase):
    """S08/S09/S13/S16: byte-exact replay, bounded reads, honest continuity."""

    def do_collect(self, store: Store, log: Path, **kw) -> dict:
        params = dict(
            config_fingerprint=None,
            initial_tail_bytes=1024 * 1024,
            retain_days=7,
            max_bytes=1 << 30,
        )
        params.update(kw)
        return incident.collect(store, [str(log)], **params)

    def test_split_utf8_line_decodes_once_byte_exact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            full = (
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)} caf\u00e9\n"
            )
            blob = full.encode("utf-8")
            # Split inside the two-byte \u00e9 so poll 1 ends mid-character.
            cut = len(blob) - 3
            assert blob[cut:cut + 1] == "\u00e9".encode("utf-8")[:1]
            log.write_bytes(blob[:cut])
            first = self.do_collect(store, log)
            self.assertEqual(first["diag_records"], 0)
            with log.open("ab") as fh:
                fh.write(blob[cut:])
            second = self.do_collect(store, log)
            self.assertEqual(second["diag_records"], 1)
            rows = stream_rows(store)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["raw_line"], full.rstrip("\n"))
            day_file = store.stream / f"diag-{incident.utcnow().strftime('%Y-%m-%d')}.jsonl"
            day_lines = day_file.read_text(encoding="utf-8").splitlines()
            self.assertTrue(day_lines)
            self.assertTrue(all(json.loads(line)["type"] == "t832_diag" for line in day_lines))

    def test_oversized_line_skipped_with_note(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            log = root / "z2m.log"
            short = (
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=2, uptime_ms=2000)}\n"
            )
            # A real diag line is ~148 bytes: the cap must clear it while
            # still catching the 400-byte monster.
            log.write_bytes(b"A" * 400 + b"\n" + short.encode("utf-8"))
            rows, cursor, notes = incident.read_increment(
                log, {}, initial_tail_bytes=1 << 20, max_line_bytes=160
            )
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], 401)
            self.assertTrue(any(n.startswith("line-too-large:") for n in notes))
            # Cursor commits past the drained line: no re-read, no hang.
            rows2, _, _ = incident.read_increment(
                log, cursor, initial_tail_bytes=1 << 20, max_line_bytes=160
            )
            self.assertEqual(rows2, [])

    def test_budget_rewind_recovers_unread_without_duplication(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n"
                "2026-10-03T09:00:01Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=2, uptime_ms=2000)}\n",
                encoding="utf-8",
            )
            first = self.do_collect(store, log, max_collect_bytes=10)
            self.assertEqual(first["diag_records"], 1)
            self.assertTrue(first["partial"])
            second = self.do_collect(store, log)
            self.assertEqual(second["diag_records"], 1)
            rows = stream_rows(store)
            self.assertEqual([r["export_sequence"] for r in rows], [1, 2])

    def test_multirecord_boot_frame_counts_one_boot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                "T832D2:" + packet_v2_hex(export_sequence=1, uptime_ms=100,
                                         records=[(1, 0, 0, 0), (19, 1, 2, 3)]) + "\n"
                "2026-10-03T09:00:01Z zh:zstack:znp "
                "T832D2:" + packet_v2_hex(export_sequence=2, uptime_ms=200,
                                         records=[(19, 4, 5, 6)]) + "\n",
                encoding="utf-8",
            )
            result = self.do_collect(store, log)
            self.assertEqual(result["diag_records"], 3)
            rows = stream_rows(store)
            boot_rows = rows[:2]
            self.assertTrue(all(r["continuity_kind"] == "boot" for r in boot_rows))
            self.assertEqual(boot_rows[0]["host_session"], boot_rows[1]["host_session"])
            self.assertEqual(boot_rows[0]["boot_index"], boot_rows[1]["boot_index"])
            self.assertEqual(rows[2]["continuity_kind"], "normal")
            self.assertEqual(rows[2]["host_session"], boot_rows[0]["host_session"])

    def test_boot_clean_continuation_no_double_boot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                "T832D2:" + packet_v2_hex(export_sequence=1, uptime_ms=700,
                                         records=[(1, 0, 0, 0)]) + "\n"
                "2026-10-03T09:00:01Z zh:zstack:znp "
                "T832D2:" + packet_v2_hex(export_sequence=2, uptime_ms=800,
                                         records=[(1, 0, 0, 0)]) + "\n",
                encoding="utf-8",
            )
            self.do_collect(store, log)
            rows = stream_rows(store)
            self.assertEqual(rows[0]["continuity_kind"], "boot")
            self.assertEqual(rows[1]["continuity_kind"], "normal")
            self.assertEqual(rows[1]["host_session"], rows[0]["host_session"])

    def test_clean_counter_wrap_is_wrap_gap_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=65535, uptime_ms=1000)}\n"
                "2026-10-03T09:00:01Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=0, uptime_ms=2000)}\n",
                encoding="utf-8",
            )
            self.do_collect(store, log)
            rows = stream_rows(store)
            self.assertEqual(rows[-1]["continuity_kind"], "wrap")
            self.assertEqual(rows[-1]["sequence_gap_before"], 0)
            self.assertFalse(rows[-1]["session_reset_detected"])
            self.assertEqual(rows[-1]["host_session"], rows[0]["host_session"])

    def test_retention_deletions_audited(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
                encoding="utf-8",
            )
            self.do_collect(store, log)
            squeezed = self.do_collect(store, log, max_bytes=1)
            self.assertTrue(any(n.startswith("retention-size:") for n in squeezed["notes"]))
            cursor = json.loads((root / "private" / "state" / "collector.json").read_text(encoding="utf-8"))
            self.assertTrue(any(n.startswith("retention-size:") for n in cursor["collector_notes"]))

    def test_lock_timeout_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            with store.locked():
                fd2 = os.open(store.lock_path, os.O_RDWR)
                try:
                    with self.assertRaises(incident.LockError):
                        incident._acquire_lock_bounded(fd2, timeout_s=0.05)
                finally:
                    os.close(fd2)


class IncidentTests(unittest.TestCase):
    def test_capture_and_one_reset_latch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(event_kind=13)}\n",
                encoding="utf-8",
            )
            captured = incident.capture(
                store,
                "mesh_outage",
                sources=[str(log)],
                config_fingerprint="cfg",
                initial_tail_bytes=1024 * 1024,
                retain_days=7,
                max_bytes=1 << 30,
                window_seconds=15 * 60,
                deadline_seconds=30,
            )
            self.assertEqual(captured["status"], "captured")
            bundle = Path(captured["bundle"])
            self.assertTrue((bundle / "manifest.json").exists())
            self.assertTrue((bundle / "SHA256.json").exists())

            authorized = incident.authorize_reset(store)
            self.assertTrue(authorized["reset_used"])
            with self.assertRaises(RuntimeError):
                incident.authorize_reset(store)

            # A fresh Store instance sees the same persistent latch.
            store2 = incident.Store(root / "private")
            status = store2.load(store2.latch, {})
            self.assertEqual(status["status"], "reset_authorized")

    def test_failed_recovery_stays_latched(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            store.atomic_json(
                store.latch,
                {
                    "status": "reset_authorized",
                    "incident_id": "x",
                    "reset_used": True,
                },
            )
            failed = incident.recovery_result(
                store, success=False, normal_traffic=False, zdo_ok=False
            )
            self.assertEqual(failed["status"], "failed")
            with self.assertRaises(RuntimeError):
                incident.authorize_reset(store)

    def test_sys_only_recovery_needs_zdo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            store.atomic_json(
                store.latch, {"status": "recovering", "incident_id": "x", "reset_used": True}
            )
            failed = incident.recovery_result(store, success=True, normal_traffic=True, zdo_ok=False)
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["failure_reason"], "no-zdo-verification")

    def test_corrupt_latch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            (root / "private" / "state" / "incident-latch.json").write_text(
                "{corrupt", encoding="utf-8"
            )
            with self.assertRaises(RuntimeError):
                incident.capture(
                    store, "x", sources=[str(log)], config_fingerprint=None,
                    initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                    window_seconds=900, deadline_seconds=30,
                )
            with self.assertRaises(RuntimeError):
                incident.manual_clear(store, "operator")
            cleared = incident.manual_clear(store, "operator", force=True)
            self.assertEqual(cleared["status"], "cleared")

    def test_tampered_bundle_blocks_authorize(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(event_kind=13)}\n",
                encoding="utf-8",
            )
            captured = incident.capture(
                store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
                window_seconds=900, deadline_seconds=30,
            )
            bundle = Path(captured["bundle"])
            (bundle / "manifest.json").write_text('{"tampered": true}\n', encoding="utf-8")
            with self.assertRaises(RuntimeError):
                incident.authorize_reset(store)
            status = store.load(store.latch, {})
            self.assertEqual(status["status"], "captured")

    def test_missing_bundle_blocks_authorize(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            captured = incident.capture(
                store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
                window_seconds=900, deadline_seconds=30,
            )
            import shutil

            shutil.rmtree(Path(captured["bundle"]))
            with self.assertRaises(RuntimeError):
                incident.authorize_reset(store)

    def test_concurrent_capture_single_winner(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            outcomes: list[str] = []

            def attempt() -> None:
                store = incident.Store(root / "private")
                try:
                    incident.capture(
                        store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                        initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                        window_seconds=900, deadline_seconds=30,
                    )
                    outcomes.append("ok")
                except RuntimeError:
                    outcomes.append("refused")

            threads = [threading.Thread(target=attempt) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(outcomes.count("ok"), 1)
            self.assertEqual(outcomes.count("refused"), 3)

    def test_capture_deadline_and_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            with self.assertRaises(TimeoutError):
                incident.capture(
                    store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                    initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                    window_seconds=900, deadline_seconds=-1,
                )
            status = store.load(store.latch, {})
            self.assertEqual(status, {})
            captured = incident.capture(
                store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                window_seconds=900, deadline_seconds=30, max_window_rows=0,
            )
            manifest = json.loads(
                (Path(captured["bundle"]) / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertTrue(manifest["window_truncated"] or manifest["diag_record_count"] == 0)

    def test_unknown_time_kept_out_of_window(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "no timestamp here " f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
                encoding="utf-8",
            )
            captured = incident.capture(
                store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
                window_seconds=900, deadline_seconds=30,
            )
            manifest = json.loads(
                (Path(captured["bundle"]) / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["diag_record_count"], 0)
            self.assertGreaterEqual(manifest["diag_unknown_time_count"], 1)

    def test_empty_hash_inventory_blocks_authorize(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            captured = incident.capture(
                store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
                window_seconds=900, deadline_seconds=30,
            )
            bundle = Path(captured["bundle"])
            (bundle / "SHA256.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                incident.authorize_reset(store)
            self.assertEqual(store.load(store.latch, {})["status"], "captured")

    def test_uninventoried_manifest_blocks_authorize(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
                encoding="utf-8",
            )
            captured = incident.capture(
                store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
                window_seconds=900, deadline_seconds=30,
            )
            bundle = Path(captured["bundle"])
            recorded = json.loads((bundle / "SHA256.json").read_text(encoding="utf-8"))
            del recorded["manifest.json"]
            (bundle / "SHA256.json").write_text(json.dumps(recorded) + "\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                incident.authorize_reset(store)

    def test_unknown_latch_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            store.atomic_json(
                store.latch,
                {"schema": 99, "status": "reset_authorized", "incident_id": "x"},
            )
            with self.assertRaises(RuntimeError):
                incident.mark_recovering(store)
            with self.assertRaises(RuntimeError):
                incident.recovery_result(
                    store, success=True, normal_traffic=True, zdo_ok=False
                )

    def test_bind_firmware_gates_capture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            artifact = root / "fw.hex"
            artifact.write_text(":020000040000FA\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                incident.capture(
                    store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                    initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                    window_seconds=900, deadline_seconds=30,
                    require_firmware_binding=True,
                )
            bound = incident.bind_firmware(store, artifact, role="deployed")
            self.assertTrue(bound["ok"])
            captured = incident.capture(
                store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                window_seconds=900, deadline_seconds=30,
                require_firmware_binding=True,
            )
            self.assertNotIn("firmware_sha256", captured)
            manifest = json.loads(
                (Path(captured["bundle"]) / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["firmware_sha256"], bound["sha256"])

    def test_candidate_role_never_gates_capture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            artifact = root / "fw.hex"
            artifact.write_text(":020000040000FA\n", encoding="utf-8")
            bound = incident.bind_firmware(store, artifact, role="candidate")
            self.assertTrue(bound["ok"])
            with self.assertRaises(RuntimeError):
                incident.capture(
                    store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                    initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                    window_seconds=900, deadline_seconds=30,
                    require_firmware_binding=True,
                )

    def test_swapped_artifact_fails_binding(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            artifact = root / "fw.hex"
            artifact.write_text(":020000040000FA\n", encoding="utf-8")
            incident.bind_firmware(store, artifact, role="deployed")
            artifact.write_text(":020000040001F9\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                incident.capture(
                    store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                    initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                    window_seconds=900, deadline_seconds=30,
                    require_firmware_binding=True,
                )

    def test_observed_build_mismatch_noted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
                encoding="utf-8",
            )
            artifact = root / "fw.hex"
            artifact.write_text(":020000040000FA\n", encoding="utf-8")
            incident.bind_firmware(store, artifact, role="deployed", build_id=1)
            result = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertEqual(result["diag_records"], 1)
            self.assertTrue(
                any(n.startswith("firmware-build-mismatch:") for n in result["notes"]),
                result["notes"],
            )

    def test_matching_build_silent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
                encoding="utf-8",
            )
            artifact = root / "fw.hex"
            artifact.write_text(":020000040000FA\n", encoding="utf-8")
            incident.bind_firmware(store, artifact, role="deployed", build_id=8320001)
            result = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertFalse(
                any(n.startswith("firmware-build-mismatch:") for n in result["notes"]),
                result["notes"],
            )


class StabilityTests(unittest.TestCase):
    def stabilizing_latch(self, store: Store, base_mono: float) -> None:
        store.atomic_json(
            store.latch,
            {
                "status": "stabilizing",
                "incident_id": "x",
                "reset_used": True,
                "normal_traffic_observed": True,
                "zdo_verified": True,
                "recovery_succeeded_mono": base_mono,
                "stable_after_mono": base_mono + 600.0,
                "stable_after_utc": "2000-01-01T00:00:00Z",
                "observations": [
                    {
                        "utc": "2000-01-01T00:00:00Z",
                        "mono": base_mono + offset,
                        "bridge_up": True,
                        "normal_traffic": True,
                        "zdo_ok": True,
                    }
                    for offset in (30, 120, 210, 300, 390, 480, 570)
                ],
            },
        )

    def test_close_happy_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            self.stabilizing_latch(store, time.monotonic() - 700.0)
            closed = incident.close_if_stable(store, bridge_up=True, normal_traffic=True)
            self.assertEqual(closed["status"], "closed")

    def test_close_mid_window_outage_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            base = time.monotonic() - 700.0
            self.stabilizing_latch(store, base)
            latch = store.load(store.latch, {})
            latch["observations"][3]["bridge_up"] = False
            store.atomic_json(store.latch, latch)
            failed = incident.close_if_stable(store, bridge_up=True, normal_traffic=True)
            self.assertEqual(failed["status"], "failed")

    def test_close_coverage_gap_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            base = time.monotonic() - 700.0
            self.stabilizing_latch(store, base)
            latch = store.load(store.latch, {})
            latch["observations"] = [latch["observations"][0]]
            store.atomic_json(store.latch, latch)
            failed = incident.close_if_stable(store, bridge_up=True, normal_traffic=True)
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["failure_reason"], "stability-coverage-gap")

    def test_close_restart_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            base = time.monotonic() - 700.0
            self.stabilizing_latch(store, base)
            latch = store.load(store.latch, {})
            latch["observations"].append(
                {
                    "utc": "2000-01-01T00:00:00Z",
                    "mono": base - 50.0,
                    "bridge_up": True,
                    "normal_traffic": True,
                    "zdo_ok": True,
                }
            )
            store.atomic_json(store.latch, latch)
            failed = incident.close_if_stable(store, bridge_up=True, normal_traffic=True)
            self.assertEqual(failed["status"], "failed")

    def test_close_stale_traffic_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            base = time.monotonic() - 700.0
            self.stabilizing_latch(store, base)
            latch = store.load(store.latch, {})
            for obs in latch["observations"]:
                obs["normal_traffic"] = False
            store.atomic_json(store.latch, latch)
            failed = incident.close_if_stable(store, bridge_up=True, normal_traffic=True)
            self.assertEqual(failed["status"], "failed")

    def test_close_window_not_complete(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            self.stabilizing_latch(store, time.monotonic())
            latch = store.load(store.latch, {})
            latch["stable_after_utc"] = "2999-01-01T00:00:00Z"
            store.atomic_json(store.latch, latch)
            with self.assertRaises(RuntimeError):
                incident.close_if_stable(store, bridge_up=True, normal_traffic=True)


class ProtocolEdgeTests(unittest.TestCase):
    def test_malformed_and_unknown_schema_rejected(self) -> None:
        with self.assertRaises(ValueError):
            incident.decode_packet("00" * 10)
        bad_magic = bytearray(bytes.fromhex(packet_hex()))
        bad_magic[0:4] = b"BAD!"
        with self.assertRaises(ValueError):
            incident.decode_packet(bytes(bad_magic).hex().upper())
        bad_schema = bytearray(bytes.fromhex(packet_hex()))
        bad_schema[4] = 99
        with self.assertRaises(ValueError):
            incident.decode_packet(bytes(bad_schema).hex().upper())

    def test_sequence_rollover_and_restart_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=65534, uptime_ms=1000)}\n"
                "2026-10-03T09:00:01Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=2, uptime_ms=500)}\n",
                encoding="utf-8",
            )
            result = incident.collect(
                store,
                [str(log)],
                config_fingerprint=None,
                initial_tail_bytes=1024 * 1024,
                retain_days=7,
                max_bytes=1 << 30,
            )
            self.assertEqual(result["diag_records"], 2)
            day = incident.utcnow().strftime("%Y-%m-%d")
            rows = [
                json.loads(line)
                for line in (store.stream / f"diag-{day}.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertTrue(rows[1]["session_reset_detected"])
            self.assertEqual(rows[1]["sequence_gap_before"], 0)

    def test_dropped_sequence_reports_gap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=10, uptime_ms=1000)}\n"
                "2026-10-03T09:00:05Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=14, uptime_ms=6000)}\n",
                encoding="utf-8",
            )
            incident.collect(
                store,
                [str(log)],
                config_fingerprint=None,
                initial_tail_bytes=1024 * 1024,
                retain_days=7,
                max_bytes=1 << 30,
            )
            day = incident.utcnow().strftime("%Y-%m-%d")
            rows = [
                json.loads(line)
                for line in (store.stream / f"diag-{day}.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[1]["sequence_gap_before"], 3)

    def test_corrupt_record_yields_decode_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp T832D1:" + "00" * 52 + "\n",
                encoding="utf-8",
            )
            result = incident.collect(
                store,
                [str(log)],
                config_fingerprint=None,
                initial_tail_bytes=1024,
                retain_days=7,
                max_bytes=1 << 20,
            )
            self.assertEqual(result["diag_records"], 1)
            day = incident.utcnow().strftime("%Y-%m-%d")
            row = json.loads((store.stream / f"diag-{day}.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(row["type"], "decode_error")

    def test_startup_breadcrumb_kinds_decode(self) -> None:
        for kind, name in ((13, "STARTUP_FROM_APP_ENTRY"), (14, "STARTUP_BDB_REQUEST"), (15, "STARTUP_BDB_RETURN"), (16, "STARTUP_SRSP_QUEUE")):
            decoded = incident.decode_packet(packet_hex(event_kind=kind))
            self.assertEqual(decoded["record"]["kind_name"], name)

    def test_gap_closure_kinds_decode(self) -> None:
        for kind, name in ((26, "TASK_EVENTS"), (27, "NV_EVENT"), (28, "AF_STATE"), (29, "NV_FAULT")):
            decoded = incident.decode_packet(packet_hex(event_kind=kind))
            self.assertEqual(decoded["record"]["kind_name"], name)

    def test_new_kinds_decode(self) -> None:
        for kind, name in (
            (30, "TX_MISMATCH"), (31, "SYNC_ABANDON"), (32, "AF_REJECT"),
            (33, "AF_ANOMALY"), (34, "DIAG_LOSS"), (35, "NPI_TRAP"),
            (36, "NPI_ALLOC_FAIL"), (37, "BOOT_CAPTURE_INVALID"),
            (38, "TIMING_APPROX"),
        ):
            frame, records = incident.decode_frame_payload(
                "T832D2:" + packet_v2_hex(records=[(kind, 1, 2, 3)])
            )
            self.assertEqual(records[0]["kind_name"], name)

    def test_rotation_cap_and_collector_restart(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
                encoding="utf-8",
            )
            first = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertEqual(first["diag_records"], 1)
            store2 = incident.Store(root / "private")
            second = incident.collect(
                store2, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertEqual(second["diag_records"], 0)
            incident.rotate(store, retain_days=7, max_bytes=1)
            remaining = list(store.stream.glob("*.jsonl"))
            self.assertEqual(remaining, [])

    def test_repeated_collects_stay_bounded_and_audited(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("", encoding="utf-8")
            saw_retention = False
            for seq in range(1, 7):
                with log.open("a", encoding="utf-8") as fh:
                    fh.write(
                        "2026-10-03T09:00:00Z zh:zstack:znp "
                        f"T832D1:{packet_hex(export_sequence=seq, uptime_ms=seq * 1000)}\n"
                    )
                result = incident.collect(
                    store, [str(log)], config_fingerprint=None,
                    initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1500,
                )
                saw_retention = saw_retention or any(
                    n.startswith("retention-size:") for n in result["notes"]
                )
            total = sum(
                p.stat().st_size for p in store.stream.glob("*.jsonl") if p.is_file()
            )
            self.assertLessEqual(total, 1500)
            self.assertTrue(saw_retention)

    def test_latched_bundle_survives_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            for i in range(35):
                (store.incidents / f"bundle-{i:03d}").mkdir(parents=True, exist_ok=True)
            oldest = store.incidents / "bundle-000"
            store.atomic_json(
                store.latch, {"status": "captured", "bundle": str(oldest)}
            )
            pruned = incident.rotate(store, retain_days=7, max_bytes=1 << 30)
            remaining = sorted(
                p.name for p in store.incidents.iterdir()
                if p.is_dir() and not p.name.startswith(".")
            )
            self.assertIn("bundle-000", remaining)
            self.assertEqual(len(remaining), 33)
            self.assertTrue(any(n.startswith("retention-bundle:") for n in pruned))


class RecoveryEdgeTests(unittest.TestCase):
    def test_repeated_trigger_while_latched_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            log = Path(td) / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            incident.capture(
                store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                window_seconds=900, deadline_seconds=30,
            )
            with self.assertRaises(RuntimeError):
                incident.capture(
                    store, "bridge_offline", sources=[str(log)], config_fingerprint=None,
                    initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                    window_seconds=900, deadline_seconds=30,
                )

    def test_partial_sys_only_recovery_stays_failed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            store.atomic_json(store.latch, {"status": "recovering", "incident_id": "x", "reset_used": True})
            result = store.load(store.latch, {})
            self.assertEqual(result["status"], "recovering")
            failed = incident.recovery_result(
                store, success=True, normal_traffic=False, zdo_ok=False
            )
            self.assertEqual(failed["status"], "failed")
            with self.assertRaises(RuntimeError):
                incident.authorize_reset(store)

    def test_host_event_correlation_without_serial(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "2026-10-03T09:00:00Z serial port RTS asserted, zigbee2mqtt bridge offline\n",
                encoding="utf-8",
            )
            result = incident.collect(
                store, [str(log)], config_fingerprint=None,
                initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
            )
            self.assertEqual(result["host_events"], 1)


class TriggerEvaluatorTests(unittest.TestCase):
    def test_state_triggers_are_trusted_firings(self) -> None:
        for trigger_id in ("mesh_outage", "bridge_offline"):
            verdict = incident.evaluate_trigger(trigger_id, None, topic=None, payload=None)
            self.assertTrue(verdict["qualifying"])
            self.assertEqual(verdict["reason"], "state-trigger-fired")

    def test_unknown_trigger_never_qualifies(self) -> None:
        verdict = incident.evaluate_trigger("bogus", None, topic=None, payload=None)
        self.assertFalse(verdict["qualifying"])
        self.assertTrue(str(verdict["reason"]).startswith("unknown-trigger:"))

    def test_radio_timeout_family(self) -> None:
        topic = incident.RADIO_TIMEOUT_TOPIC
        ok, reason = incident.evaluate_radio_timeout(
            topic=topic, payload={"status": "ok"})
        self.assertFalse(ok)
        self.assertEqual(reason, "healthy-removal")
        for error in (
            "Failed to remove device: SRSP timeout",
            "request timed out after 10000ms",
            "TIMEOUT waiting for response",
        ):
            ok, reason = incident.evaluate_radio_timeout(
                topic=topic, payload={"status": "error", "error": error})
            self.assertTrue(ok, error)
            self.assertEqual(reason, "timeout-error")
        ok, reason = incident.evaluate_radio_timeout(
            topic=topic, payload={"status": "error", "error": "device not found"})
        self.assertFalse(ok)
        self.assertEqual(reason, "non-timeout-error")
        ok, reason = incident.evaluate_radio_timeout(topic=topic, payload="{oops")
        self.assertFalse(ok)
        self.assertEqual(reason, "malformed-payload")
        ok, reason = incident.evaluate_radio_timeout(
            topic="zigbee2mqtt/bridge/response/permit_join",
            payload={"status": "ok", "transaction": "x"},
        )
        self.assertFalse(ok)
        self.assertTrue(reason.startswith("topic-mismatch:"))

    def test_capture_stores_verdict_and_authorize_gates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                incident.capture(
                    store, "bogus", sources=[str(log)], config_fingerprint=None,
                    initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                    window_seconds=900, deadline_seconds=30,
                )
            captured = incident.capture(
                store, "radio_timeout", sources=[str(log)], config_fingerprint=None,
                initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                window_seconds=900, deadline_seconds=30,
                trigger_topic=incident.RADIO_TIMEOUT_TOPIC,
                trigger_payload={"status": "ok"},
            )
            manifest = json.loads(
                (Path(str(captured["bundle"])) / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["trigger_qualification"]["qualifying"])
            self.assertEqual(
                manifest["trigger_qualification"]["reason"], "healthy-removal")
            with self.assertRaises(RuntimeError):
                incident.authorize_reset(store)
            latch = store.load(store.latch, {})
            self.assertEqual(latch["status"], "captured")

    def test_load_trigger_defs_pins_source_sha(self) -> None:
        here = Path(__file__).resolve().parent
        repo = here.parent.parent
        barrier = repo / "deploy" / "t832_capture_barrier.yaml"
        defs, sha = incident.load_trigger_defs(barrier)
        self.assertEqual(sha, hashlib.sha256(barrier.read_bytes()).hexdigest())
        self.assertEqual(defs["mesh_outage"]["kind"], "state")
        self.assertEqual(defs["mesh_outage"]["for_seconds"], 300)
        self.assertEqual(defs["radio_timeout"]["kind"], "mqtt")
        verdict = incident.evaluate_trigger(
            "radio_timeout", defs,
            topic=incident.RADIO_TIMEOUT_TOPIC,
            payload={"status": "error", "error": "srsp timeout"},
        )
        self.assertTrue(verdict["qualifying"])
        self.assertEqual(verdict["source"], "candidate-yaml")
        self.assertEqual(verdict["source_sha256"], sha)


class ZdoProofTests(unittest.TestCase):
    def recovering_store(self, root: Path) -> object:
        store = incident.Store(root / "private")
        store.atomic_json(
            store.latch, {"status": "recovering", "incident_id": "x", "reset_used": True}
        )
        return store

    def test_claim_without_proof_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = self.recovering_store(Path(td))
            failed = incident.recovery_result(
                store, success=True, normal_traffic=True, zdo_ok=True,
                zdo_transaction="ha-t832-barrier",
            )
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["failure_reason"], "no-zdo-verification")
            self.assertFalse(failed["zdo_verified"])
            self.assertEqual(failed["zdo_proof"], "missing")

    def test_proof_then_matching_claim_stabilizes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = self.recovering_store(Path(td))
            proof = incident.record_zdo_proof(store, "ha-t832-barrier")
            self.assertEqual(proof["zdo_proof"]["transaction"], "ha-t832-barrier")
            value = incident.recovery_result(
                store, success=True, normal_traffic=True, zdo_ok=True,
                zdo_transaction="ha-t832-barrier",
            )
            self.assertEqual(value["status"], "stabilizing")
            self.assertTrue(value["zdo_verified"])

    def test_stale_proof_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = self.recovering_store(Path(td))
            incident.record_zdo_proof(store, "ha-t832-barrier")
            latch = store.load(store.latch, {})
            latch["zdo_proof"]["mono"] = (
                time.monotonic() - incident.ZDO_PROOF_MAX_AGE_S - 1.0
            )
            store.atomic_json(store.latch, latch)
            failed = incident.recovery_result(
                store, success=True, normal_traffic=True, zdo_ok=True,
                zdo_transaction="ha-t832-barrier",
            )
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["zdo_proof"], "stale")

    def test_transaction_mismatch_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = self.recovering_store(Path(td))
            incident.record_zdo_proof(store, "ha-t832-barrier")
            failed = incident.recovery_result(
                store, success=True, normal_traffic=True, zdo_ok=True,
                zdo_transaction="stale-or-foreign",
            )
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["zdo_proof"], "mismatch")

    def test_empty_transaction_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = self.recovering_store(Path(td))
            with self.assertRaises(RuntimeError):
                incident.record_zdo_proof(store, "  ")


class RtsSingletonTests(unittest.TestCase):
    def test_second_rts_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            store.atomic_json(
                store.latch, {"status": "recovering", "incident_id": "x", "reset_used": True}
            )
            first = incident.record_rts_used(store)
            self.assertTrue(first["rts_used"])
            with self.assertRaises(RuntimeError):
                incident.record_rts_used(store)

    def test_rts_outside_recovering_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            store.atomic_json(store.latch, {"status": "captured", "incident_id": "x"})
            with self.assertRaises(RuntimeError):
                incident.record_rts_used(store)


class StabilityCloseOnceTests(unittest.TestCase):
    def test_close_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            base = time.monotonic() - 700.0
            store.atomic_json(
                store.latch,
                {
                    "status": "stabilizing",
                    "incident_id": "x",
                    "reset_used": True,
                    "normal_traffic_observed": True,
                    "zdo_verified": True,
                    "recovery_succeeded_mono": base,
                    "stable_after_mono": base + 600.0,
                    "stable_after_utc": "2000-01-01T00:00:00Z",
                    "observations": [
                        {
                            "utc": "2000-01-01T00:00:00Z",
                            "mono": base + offset,
                            "bridge_up": True,
                            "normal_traffic": True,
                            "zdo_ok": True,
                        }
                        for offset in (30, 120, 210, 300, 390, 480, 570)
                    ],
                },
            )
            closed = incident.close_if_stable(store, bridge_up=True, normal_traffic=True)
            self.assertEqual(closed["status"], "closed")
            with self.assertRaises(RuntimeError):
                incident.close_if_stable(store, bridge_up=True, normal_traffic=True)
            latch = store.load(store.latch, {})
            self.assertEqual(latch["status"], "closed")


if __name__ == "__main__":
    unittest.main()
