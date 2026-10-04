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


def stage_binding(
    root: Path,
    artifact: Path,
    *,
    variant: str = "T832-DIAG-R0",
    build_id: int = 8320001,
    commit: str = "a" * 40,
) -> Path:
    """Stage a build manifest that actually lists the artifact digest.

    B12 oracle support: bind_firmware() verifies the manifest contents
    (variant match, 40-hex commit, artifact digest listed), so tests
    stage a real manifest file instead of asserting on hash strings.
    """
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = root / "build-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "variant": variant,
                "repository_commit": commit,
                "artifacts": {"T832-DIAG-R0.hex": {"sha256": digest}},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


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

    def test_wrap_replay_duplicate_ambiguous_reboot(self) -> None:
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
            # B10: a clock step-back with no BOOT marker proves nothing —
            # the frontier holds and both frames are explicitly ambiguous.
            rows = self.collect_lines(store, log, [line(6, 500), line(7, 600)])
            self.assertEqual(rows[-2]["continuity_kind"], "ambiguous")
            self.assertFalse(rows[-2]["session_reset_detected"])
            self.assertEqual(rows[-2]["host_session"], session)
            self.assertEqual(rows[-1]["continuity_kind"], "ambiguous")
            self.assertEqual(rows[-1]["host_session"], session)
            # B10: regressed counter and clock plus a fresh BOOT marker is
            # the only proved reboot signature.
            rows = self.collect_lines(store, log, [line(1, 700, kind=1)])
            self.assertEqual(rows[-1]["continuity_kind"], "reboot")
            self.assertTrue(rows[-1]["session_reset_detected"])
            self.assertNotEqual(rows[-1]["host_session"], session)
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

    def test_three_poll_partial_decodes_once(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            full = (
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n"
            )
            blob = full.encode("utf-8")
            first_cut, second_cut = 20, len(blob) - 30
            log.write_bytes(blob[:first_cut])
            self.assertEqual(self.do_collect(store, log)["diag_records"], 0)
            with log.open("ab") as fh:
                fh.write(blob[first_cut:second_cut])
            self.assertEqual(self.do_collect(store, log)["diag_records"], 0)
            with log.open("ab") as fh:
                fh.write(blob[second_cut:])
            self.assertEqual(self.do_collect(store, log)["diag_records"], 1)
            rows = stream_rows(store)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["raw_line"], full.rstrip("\n"))
            self.assertEqual(rows[0]["source_byte_offset"], 0)

    def test_rotation_discards_stale_partial(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            line1 = (
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n"
            )
            log.write_text(line1 + "STALE-PARTIAL-NO-NEWLINE", encoding="utf-8")
            self.assertEqual(self.do_collect(store, log)["diag_records"], 1)
            # In-place rewrite with a same-size line: packet lines are fixed
            # width, so only the mtime guard can tell. Bump mtime explicitly.
            line2 = (
                "2026-10-03T09:00:00Z zh:zstack:znp "
                f"T832D1:{packet_hex(export_sequence=9, uptime_ms=9000)}\n"
            )
            self.assertEqual(len(line2), len(line1))
            log.write_text(line2, encoding="utf-8")
            anchor = log.stat()
            os.utime(log, (anchor.st_atime + 2, anchor.st_mtime + 2))
            result = self.do_collect(store, log)
            self.assertEqual(result["diag_records"], 1)
            self.assertTrue(any(n.startswith("rotated:") for n in result["notes"]))
            rows = stream_rows(store)
            self.assertEqual([r["export_sequence"] for r in rows], [1, 9])

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
                    "schema": 1,
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
                store.latch, {"schema": 1, "status": "recovering", "incident_id": "x", "reset_used": True}
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
            bound = incident.bind_firmware(
                store,
                artifact,
                role="deployed",
                variant="T832-DIAG-R0",
                manifest=stage_binding(root, artifact),
                build_id=8320001,
            )
            self.assertTrue(bound["ok"])
            captured = incident.capture(
                store, "mesh_outage", sources=[str(log)], config_fingerprint=None,
                initial_tail_bytes=1024, retain_days=7, max_bytes=1 << 20,
                window_seconds=900, deadline_seconds=30,
                require_firmware_binding=True,
            )
            manifest = json.loads(
                (Path(captured["bundle"]) / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["firmware_sha256"], bound["sha256"])
            self.assertEqual(manifest["firmware_binding_role"], "deployed")

    def test_candidate_role_never_gates_capture(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            artifact = root / "fw.hex"
            artifact.write_text(":020000040000FA\n", encoding="utf-8")
            bound = incident.bind_firmware(
                store,
                artifact,
                role="candidate",
                variant="T832-DIAG-R0",
                manifest=stage_binding(root, artifact),
                build_id=8320001,
            )
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
            incident.bind_firmware(
                store,
                artifact,
                role="deployed",
                variant="T832-DIAG-R0",
                manifest=stage_binding(root, artifact),
                build_id=8320001,
            )
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
            incident.bind_firmware(
                store,
                artifact,
                role="deployed",
                variant="T832-DIAG-R0",
                manifest=stage_binding(root, artifact),
                build_id=1,
            )
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
            incident.bind_firmware(
                store,
                artifact,
                role="deployed",
                variant="T832-DIAG-R0",
                manifest=stage_binding(root, artifact),
                build_id=8320001,
            )
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
                "schema": 1,
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

    def test_sequence_rollover_with_clock_back_is_ambiguous(self) -> None:
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
            # B10: a wrap-window crossing with a stepped-back clock and no
            # BOOT marker proves nothing — the frontier holds explicitly.
            self.assertEqual(rows[1]["continuity_kind"], "ambiguous")
            self.assertFalse(rows[1]["session_reset_detected"])
            self.assertEqual(rows[1]["sequence_gap_before"], 0)
            self.assertEqual(rows[1]["host_session"], rows[0]["host_session"])

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
                store.latch, {"schema": 1, "status": "captured", "bundle": str(oldest)}
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
            store.atomic_json(store.latch, {"schema": 1, "status": "recovering", "incident_id": "x", "reset_used": True})
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
            store.latch, {"schema": 1, "status": "recovering", "incident_id": "x", "reset_used": True}
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

    def test_corrupt_proof_clock_is_missing_not_rebooted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = self.recovering_store(Path(td))
            incident.record_zdo_proof(store, "ha-t832-barrier")
            latch = store.load(store.latch, {})
            latch["zdo_proof"]["mono"] = float("nan")
            store.atomic_json(store.latch, latch)
            failed = incident.recovery_result(
                store, success=True, normal_traffic=True, zdo_ok=True,
                zdo_transaction="ha-t832-barrier",
            )
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["zdo_proof"], "missing")

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
                store.latch, {"schema": 1, "status": "recovering", "incident_id": "x", "reset_used": True}
            )
            first = incident.record_rts_used(store)
            self.assertTrue(first["rts_used"])
            with self.assertRaises(RuntimeError):
                incident.record_rts_used(store)

    def test_rts_outside_recovering_refused(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            store.atomic_json(store.latch, {"schema": 1, "status": "captured", "incident_id": "x"})
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
                    "schema": 1,
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


class R3M2ReadBoundsTests(unittest.TestCase):
    """B04: bounded scans, resumable budgets, enforced deadlines."""

    def diag_line(self, seq: int, up: int = 1000) -> str:
        return (
            "2026-10-03T09:00:00Z zh:zstack:znp "
            f"T832D1:{packet_hex(export_sequence=seq, uptime_ms=up)}\n"
        )

    def test_budget_exhaustion_resumes_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "z2m.log"
            lines = [self.diag_line(1), self.diag_line(2), self.diag_line(3)]
            log.write_text("".join(lines), encoding="utf-8")
            budget = len(lines[0].encode("utf-8"))
            rows1, cursor1, notes1 = incident.read_increment(
                log, {}, initial_tail_bytes=1 << 20, max_new_bytes=budget
            )
            self.assertEqual([r[1] for r in rows1], [lines[0].rstrip("\n")])
            self.assertTrue(
                any(n.startswith("read-budget-exhausted:") for n in notes1)
            )
            rows2, cursor2, _ = incident.read_increment(
                log, cursor1, initial_tail_bytes=1 << 20, max_new_bytes=budget
            )
            self.assertEqual([r[1] for r in rows2], [lines[1].rstrip("\n")])
            self.assertEqual(cursor1["offset"], len(lines[0].encode("utf-8")))
            self.assertEqual(
                cursor2["offset"], 2 * len(lines[0].encode("utf-8"))
            )
            rows3, _, notes3 = incident.read_increment(
                log, cursor2, initial_tail_bytes=1 << 20
            )
            self.assertEqual([r[1] for r in rows3], [lines[2].rstrip("\n")])
            self.assertFalse(
                any(n.startswith("read-budget-exhausted:") for n in notes3)
            )

    def test_deadline_raises_timeout_and_leaves_no_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "z2m.log"
            log.write_text(
                "".join(self.diag_line(i) for i in range(300)), encoding="utf-8"
            )
            with self.assertRaises(TimeoutError):
                incident.read_increment(
                    log, {}, initial_tail_bytes=1 << 20,
                    deadline_s=time.monotonic() - 1.0,
                )
            rows, _, _ = incident.read_increment(
                log, {}, initial_tail_bytes=1 << 20
            )
            self.assertEqual(len(rows), 300)

    def test_newline_free_flood_tail_skip_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "z2m.log"
            log.write_bytes(
                b"X" * (3 * 1024 * 1024) + b"\n" + self.diag_line(9).encode()
            )
            rows, _, notes = incident.read_increment(
                log, {}, initial_tail_bytes=1 << 20
            )
            # The whole flood is the partial first line inside the tail
            # window: it is skipped boundedly (one capped chunk) and the
            # trailing valid line is recovered exactly once.
            self.assertTrue(any(n.startswith("initial-tail:") for n in notes))
            self.assertEqual(
                [r[1] for r in rows], [self.diag_line(9).rstrip("\n")]
            )

    def test_oversized_line_in_window_is_drained_boundedly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "z2m.log"
            log.write_bytes(
                self.diag_line(8).encode()
                + b"X" * (3 * 1024 * 1024)
                + b"\n"
                + self.diag_line(9).encode()
            )
            rows, cursor, notes = incident.read_increment(
                log, {}, initial_tail_bytes=8 * 1024 * 1024
            )
            self.assertTrue(any(n.startswith("line-too-large:") for n in notes))
            self.assertEqual(
                [r[1] for r in rows],
                [self.diag_line(8).rstrip("\n"), self.diag_line(9).rstrip("\n")],
            )
            rows2, _, _ = incident.read_increment(
                log, cursor, initial_tail_bytes=8 * 1024 * 1024
            )
            self.assertEqual(rows2, [])

    def test_exact_cap_line_consumes_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "z2m.log"
            log.write_bytes(b"Y" * 11 + b"\n" + b"short\n")
            rows, cursor, notes = incident.read_increment(
                log, {}, initial_tail_bytes=1 << 20, max_line_bytes=10
            )
            self.assertTrue(any(n.startswith("line-too-large:") for n in notes))
            self.assertEqual([r[1] for r in rows], ["short"])
            self.assertEqual(cursor["offset"], 18)
            rows2, _, _ = incident.read_increment(
                log, cursor, initial_tail_bytes=1 << 20, max_line_bytes=10
            )
            self.assertEqual(rows2, [])

    def test_locked_timeout_bounds_contention(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            with store.locked():
                rival = incident.Store(Path(td) / "private")
                with self.assertRaises(incident.LockError):
                    with rival.locked(timeout_s=0.05):
                        pass

    def test_window_newest_first_sheds_oldest(self) -> None:
        import datetime

        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            day = incident.utcnow().strftime("%Y-%m-%d")
            old = store.stream / "diag-2000-01-01.jsonl"
            old.write_text(
                '{"source_utc": "2026-10-03T09:00:00Z", "marker": "old"}\n',
                encoding="utf-8",
            )
            new = store.stream / f"diag-{day}.jsonl"
            new.write_text(
                '{"source_utc": "2026-10-03T09:00:00Z", "marker": "new"}\n',
                encoding="utf-8",
            )
            os.utime(old, (1_000_000, 1_000_000))
            cutoff = datetime.datetime(
                2000, 1, 2, tzinfo=datetime.timezone.utc
            )
            rows, _, _, truncated, _ = incident.recent_rows(
                store, "diag", cutoff, max_rows=1
            )
            self.assertEqual([r["marker"] for r in rows], ["new"])
            self.assertTrue(truncated)


class R3M2LatchTests(unittest.TestCase):
    """B05: every latch entry validates before any read-modify-write."""

    def good(self, **kw: object) -> dict:
        latch: dict = {
            "schema": 1,
            "status": "captured",
            "incident_id": "i",
            "reset_used": False,
        }
        latch.update(kw)
        return latch

    def test_validate_matrix(self) -> None:
        self.assertEqual(incident.validate_latch(self.good()), self.good())
        self.assertEqual(
            incident.validate_latch(
                {"schema": 1, "status": "reset_authorized",
                 "incident_id": "x", "reset_used": True}
            )["status"],
            "reset_authorized",
        )
        cases = [
            ("string", "not-an-object"),
            ({"status": "captured", "incident_id": "x"}, "unknown-schema"),
            ({"schema": 99, "status": "captured", "incident_id": "x"},
             "unknown-schema"),
            ({"schema": 1, "status": "bogus", "incident_id": "x"},
             "unknown-status"),
            ({"schema": 1, "status": "captured", "incident_id": "x",
              "reset_used": "yes"}, "reset-used-not-bool"),
            ({"schema": 1, "status": "captured", "incident_id": "x",
              "reset_used": True}, "permit-consumed-but-captured"),
            ({"schema": 1, "status": "recovering", "reset_used": False},
             "missing-incident-id"),
            ({"schema": 1, "status": "captured", "incident_id": "",
              "reset_used": False}, "missing-incident-id"),
        ]
        for value, fragment in cases:
            with self.assertRaises(RuntimeError, msg=repr(value)) as ctx:
                incident.validate_latch(value)
            self.assertIn(fragment, str(ctx.exception))
        cleared = {"schema": 1, "status": "cleared"}
        self.assertEqual(incident.validate_latch(cleared), cleared)

    def test_capture_refuses_invalid_latch_before_work(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            store.atomic_json(store.latch, {"schema": 1, "status": "bogus"})
            before = {p.name for p in store.incidents.iterdir()}
            with self.assertRaises(RuntimeError):
                incident.capture(
                    store, "mesh_outage", sources=[str(log)],
                    config_fingerprint=None, initial_tail_bytes=1024,
                    retain_days=7, max_bytes=1 << 20, window_seconds=900,
                    deadline_seconds=30,
                )
            self.assertEqual({p.name for p in store.incidents.iterdir()}, before)

    def test_force_clear_audits_and_unbricks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            (root / "private" / "state" / "incident-latch.json").write_text(
                "{corrupt", encoding="utf-8"
            )
            cleared = incident.manual_clear(store, "operator", force=True)
            self.assertEqual(cleared["status"], "cleared")
            self.assertEqual(cleared["schema"], 1)
            kinds = [
                json.loads(line)["kind"]
                for line in store.host_events.read_text(
                    encoding="utf-8").splitlines()
            ]
            self.assertIn("incident_manual_clear_forced", kinds)
            captured = incident.capture(
                store, "mesh_outage", sources=[str(log)],
                config_fingerprint=None, initial_tail_bytes=1024,
                retain_days=7, max_bytes=1 << 20, window_seconds=900,
                deadline_seconds=30,
            )
            self.assertEqual(captured["status"], "captured")


class R3M2BundleTests(unittest.TestCase):
    """B06: exact bundle inventory, digest format, counts, provenance."""

    def fresh(self, td: str) -> tuple:
        root = Path(td)
        store = incident.Store(root / "private")
        log = root / "z2m.log"
        log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
        captured = incident.capture(
            store, "mesh_outage", sources=[str(log)],
            config_fingerprint=None, initial_tail_bytes=1024 * 1024,
            retain_days=7, max_bytes=1 << 30, window_seconds=900,
            deadline_seconds=30,
        )
        return store, Path(str(captured["bundle"]))

    def recorded(self, bundle: Path) -> dict:
        return json.loads(
            (bundle / "SHA256.json").read_text(encoding="utf-8")
        )

    def rewrite_recorded(self, bundle: Path, recorded: dict) -> None:
        (bundle / "SHA256.json").write_text(
            json.dumps(recorded) + "\n", encoding="utf-8"
        )

    def test_swizzled_digest_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, bundle = self.fresh(td)
            recorded = self.recorded(bundle)
            recorded["diag-15m.jsonl"] = "f" * 64
            self.rewrite_recorded(bundle, recorded)
            with self.assertRaises(RuntimeError) as ctx:
                incident.authorize_reset(store)
            self.assertIn("reset-permit-hash-mismatch", str(ctx.exception))

    def test_padded_inventory_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, bundle = self.fresh(td)
            recorded = self.recorded(bundle)
            recorded["extra.json"] = "a" * 64
            self.rewrite_recorded(bundle, recorded)
            with self.assertRaises(RuntimeError) as ctx:
                incident.authorize_reset(store)
            self.assertIn("reset-permit-inventory-inexact", str(ctx.exception))

    def test_thinned_inventory_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, bundle = self.fresh(td)
            recorded = self.recorded(bundle)
            del recorded["host-events-15m.jsonl"]
            self.rewrite_recorded(bundle, recorded)
            with self.assertRaises(RuntimeError) as ctx:
                incident.authorize_reset(store)
            self.assertIn("reset-permit-inventory-inexact", str(ctx.exception))

    def test_bad_digest_format_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, bundle = self.fresh(td)
            recorded = self.recorded(bundle)
            recorded["diag-15m.jsonl"] = "xyz"
            self.rewrite_recorded(bundle, recorded)
            with self.assertRaises(RuntimeError) as ctx:
                incident.authorize_reset(store)
            self.assertIn("reset-permit-digest-format", str(ctx.exception))

    def test_count_mismatch_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store, bundle = self.fresh(td)
            with (bundle / "diag-15m.jsonl").open("a", encoding="utf-8") as fh:
                fh.write('{"smuggled": true}\n')
            # Re-seal the hashes so only the manifest counts disagree.
            recorded = self.recorded(bundle)
            recorded["diag-15m.jsonl"] = incident.sha256_file(
                bundle / "diag-15m.jsonl"
            )
            self.rewrite_recorded(bundle, recorded)
            with self.assertRaises(RuntimeError) as ctx:
                incident.authorize_reset(store)
            self.assertIn("reset-permit-count-mismatch", str(ctx.exception))

    def test_supplement_truncation_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "no timestamp here "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
                encoding="utf-8",
            )
            captured = incident.capture(
                store, "mesh_outage", sources=[str(log)],
                config_fingerprint=None, initial_tail_bytes=1024 * 1024,
                retain_days=7, max_bytes=1 << 30, window_seconds=900,
                deadline_seconds=30,
            )
            bundle = Path(str(captured["bundle"]))
            manifest = json.loads(
                (bundle / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertGreater(manifest["unknown_supplement_count"], 0)
            (bundle / "unknown-time-supplement.jsonl").write_text(
                "", encoding="utf-8"
            )
            # Re-seal the hashes so only the supplement counts disagree.
            recorded = self.recorded(bundle)
            recorded["unknown-time-supplement.jsonl"] = incident.sha256_file(
                bundle / "unknown-time-supplement.jsonl"
            )
            self.rewrite_recorded(bundle, recorded)
            with self.assertRaises(RuntimeError) as ctx:
                incident.authorize_reset(store)
            self.assertIn("reset-permit-count-mismatch", str(ctx.exception))

    def test_foreign_bundle_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            evil = root / "evil-id"
            evil.mkdir(parents=True, exist_ok=True)
            store.atomic_json(
                store.latch,
                {"schema": 1, "status": "captured", "incident_id": "evil-id",
                 "bundle": str(evil), "reset_used": False},
            )
            with self.assertRaises(RuntimeError) as ctx:
                incident.authorize_reset(store)
            self.assertIn("reset-permit-bundle-foreign", str(ctx.exception))


class R3M2ContinuityTests(unittest.TestCase):
    """B10: the frontier moves only on proved same-boot evidence."""

    def test_ambiguous_pair_holds_frontier(self) -> None:
        cont = incident.Continuity("t")
        first = cont.annotate(5, 3000, False)
        self.assertEqual(first["continuity_kind"], "boot")
        session = first["host_session"]
        boot_index = first["boot_index"]
        amb = cont.annotate(4, 2000, False)
        self.assertEqual(amb["continuity_kind"], "ambiguous")
        self.assertFalse(amb["session_reset_detected"])
        self.assertEqual(amb["host_session"], session)
        self.assertEqual(amb["boot_index"], boot_index)
        proved = cont.annotate(1, 700, True)
        self.assertEqual(proved["continuity_kind"], "reboot")
        self.assertTrue(proved["session_reset_detected"])
        self.assertNotEqual(proved["host_session"], session)
        self.assertEqual(proved["boot_index"], boot_index + 1)
        clean = cont.annotate(2, 800, False)
        self.assertEqual(clean["continuity_kind"], "normal")
        self.assertEqual(clean["host_session"], proved["host_session"])

    def test_delayed_boot_keeps_session(self) -> None:
        cont = incident.Continuity("t")
        first = cont.annotate(10, 1000, False)
        late = cont.annotate(14, 6000, True)
        self.assertEqual(late["continuity_kind"], "delayed_boot")
        self.assertFalse(late["session_reset_detected"])
        self.assertEqual(late["sequence_gap_before"], 3)
        self.assertEqual(late["host_session"], first["host_session"])
        self.assertEqual(late["boot_index"], first["boot_index"])

    def test_uptime_wrap_keeps_boot(self) -> None:
        cont = incident.Continuity("t")
        first = cont.annotate(5, 0xFFFFFF00, False)
        wrapped = cont.annotate(6, 200, False)
        self.assertEqual(wrapped["continuity_kind"], "uptime_wrap")
        self.assertFalse(wrapped["session_reset_detected"])
        clean = cont.annotate(7, 300, False)
        self.assertEqual(clean["continuity_kind"], "normal")
        self.assertEqual(clean["host_session"], first["host_session"])

    def test_replay_keeps_session(self) -> None:
        cont = incident.Continuity("t")
        first = cont.annotate(5, 3000, False)
        dup = cont.annotate(5, 3000, False)
        self.assertEqual(dup["continuity_kind"], "duplicate")
        stale = cont.annotate(4, 4000, False)
        self.assertEqual(stale["continuity_kind"], "replay")
        self.assertFalse(stale["session_reset_detected"])
        self.assertEqual(stale["host_session"], first["host_session"])

    def test_expected_seq_clock_back_is_ambiguous(self) -> None:
        cont = incident.Continuity("t")
        first = cont.annotate(5, 3000, False)
        amb = cont.annotate(6, 500, False)
        self.assertEqual(amb["continuity_kind"], "ambiguous")
        self.assertFalse(amb["session_reset_detected"])
        self.assertEqual(amb["host_session"], first["host_session"])


class R3M2RetentionTests(unittest.TestCase):
    """B11: supplement always committed, aggregate cap with exemptions."""

    def cap(self, store: Path, log: Path, trigger: str = "mesh_outage") -> dict:
        return incident.capture(
            store, trigger, sources=[str(log)],
            config_fingerprint=None, initial_tail_bytes=1024 * 1024,
            retain_days=7, max_bytes=1 << 30, window_seconds=900,
            deadline_seconds=30,
        )

    def test_supplement_committed_when_unknown_present(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text(
                "no timestamp here "
                f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
                encoding="utf-8",
            )
            captured = self.cap(store, log)
            bundle = Path(str(captured["bundle"]))
            supp = bundle / "unknown-time-supplement.jsonl"
            self.assertTrue(supp.is_file())
            rows = [
                json.loads(line)
                for line in supp.read_text(encoding="utf-8").splitlines()
            ]
            self.assertGreater(len(rows), 0)
            self.assertTrue(
                all(r["time_provenance"] == "unknown" for r in rows)
            )
            self.assertTrue(all("supplement_stream_file" in r for r in rows))
            manifest = json.loads(
                (bundle / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                manifest["unknown_supplement_count"], len(rows)
            )
            authorized = incident.authorize_reset(store)
            self.assertTrue(authorized["reset_used"])

    def test_supplement_committed_when_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            captured = self.cap(store, log)
            bundle = Path(str(captured["bundle"]))
            supp = bundle / "unknown-time-supplement.jsonl"
            self.assertTrue(supp.is_file())
            self.assertEqual(supp.stat().st_size, 0)
            authorized = incident.authorize_reset(store)
            self.assertTrue(authorized["reset_used"])

    def test_aggregate_cap_prunes_oldest_first(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            day = incident.utcnow().strftime("%Y-%m-%d")
            first = store.stream / "diag-2000-01-01.jsonl"
            first.write_bytes(b"1" * 100 + b"\n")
            second = store.stream / "diag-2000-01-02.jsonl"
            second.write_bytes(b"2" * 100 + b"\n")
            today = store.stream / f"diag-{day}.jsonl"
            today.write_bytes(b"3" * 100 + b"\n")
            now = time.time()
            os.utime(first, (now - 300, now - 300))
            os.utime(second, (now - 200, now - 200))
            os.utime(today, (now - 100, now - 100))
            notes = incident.rotate(
                store, retain_days=7, max_bytes=1 << 30, max_store_bytes=150
            )
            self.assertFalse(first.exists())
            self.assertFalse(second.exists())
            self.assertTrue(today.exists())
            self.assertTrue(
                any(
                    n.startswith("retention-store:stream:diag-2000-01-01")
                    for n in notes
                )
            )

    def test_latched_bundle_exempt_reports_over_budget(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = root / "z2m.log"
            log.write_text("2026-10-03T09:00:00Z boot\n", encoding="utf-8")
            captured = self.cap(store, log)
            bundle = Path(str(captured["bundle"]))
            notes = incident.rotate(
                store, retain_days=7, max_bytes=1 << 30, max_store_bytes=1
            )
            self.assertTrue(bundle.is_dir())
            self.assertTrue(
                any(n.startswith("retention-store-over-budget:") for n in notes)
            )

    def test_abandoned_tmp_reclaimed_but_fresh_survives(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            stale = store.incidents / ".20200101T000000.1.2.3.tmp"
            stale.mkdir(parents=True, exist_ok=True)
            (stale / "part.json").write_bytes(b"0" * 50)
            old = time.time() - 90000.0
            os.utime(stale / "part.json", (old, old))
            os.utime(stale, (old, old))
            fresh = store.incidents / ".fresh.1.2.3.tmp"
            fresh.mkdir(parents=True, exist_ok=True)
            (fresh / "part.json").write_bytes(b"0" * 50)
            notes = incident.rotate(
                store, retain_days=7, max_bytes=1 << 30, max_store_bytes=1
            )
            self.assertFalse(stale.exists())
            self.assertTrue(fresh.is_dir())
            self.assertTrue(
                any("abandoned-tmp" in n for n in notes)
            )

    def test_rotated_log_count_cap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = incident.Store(Path(td) / "private")
            for i in range(3):
                (store.root / f"host-events-2020010{i}T000000Z.log").write_bytes(
                    b"0" * 10
                )
            notes = incident.rotate(
                store, retain_days=7, max_bytes=1 << 30, max_rotated_logs=1
            )
            remaining = sorted(
                p.name for p in store.root.glob("host-events-*.log")
            )
            self.assertEqual(remaining, ["host-events-20200102T000000Z.log"])
            pruned = [n for n in notes if n.startswith("retention-rotated-log:")]
            self.assertEqual(len(pruned), 2)


class R3M2BindingTests(unittest.TestCase):
    """B12: binding is an explicit declaration, verified, hashed once."""

    def artifact(self, root: Path, body: str = ":020000040000FA\n") -> Path:
        path = root / "fw.hex"
        path.write_text(body, encoding="utf-8")
        return path

    def bind(self, store: object, root: Path, artifact: Path, **kw: object) -> dict:
        params: dict = {
            "role": "deployed",
            "variant": "T832-DIAG-R0",
            "build_id": 8320001,
        }
        params.update(kw)
        # Stage the default manifest only when the caller did not supply
        # one: staging writes root/build-manifest.json, so pre-staging
        # would clobber a caller-staged manifest at the same path.
        if "manifest" not in params:
            params["manifest"] = stage_binding(root, artifact)
        return incident.bind_firmware(store, artifact, **params)

    def diag_log(self, root: Path) -> Path:
        log = root / "z2m.log"
        log.write_text(
            "2026-10-03T09:00:00Z zh:zstack:znp "
            f"T832D1:{packet_hex(export_sequence=1, uptime_ms=1000)}\n",
            encoding="utf-8",
        )
        return log

    def collect(self, store: object, log: Path) -> dict:
        return incident.collect(
            store, [str(log)], config_fingerprint=None,
            initial_tail_bytes=1024 * 1024, retain_days=7, max_bytes=1 << 30,
        )

    def test_declaration_required(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            artifact = self.artifact(root)
            manifest = stage_binding(root, artifact)
            bad_manifest = root / "missing.json"
            garbage = root / "garbage.json"
            garbage.write_text("not json\n", encoding="utf-8")
            array = root / "array.json"
            array.write_text("[1]\n", encoding="utf-8")
            cases = [
                {"variant": "", "manifest": manifest, "build_id": 1},
                {"variant": None, "manifest": manifest, "build_id": 1},
                {"variant": "T832-DIAG-R0", "manifest": manifest,
                 "build_id": None},
                {"variant": "T832-DIAG-R0", "manifest": manifest,
                 "build_id": True},
                {"variant": "T832-DIAG-R0", "manifest": manifest,
                 "build_id": "1"},
                {"variant": "T832-DIAG-R0", "manifest": None, "build_id": 1},
                {"variant": "T832-DIAG-R0", "manifest": bad_manifest,
                 "build_id": 1},
                {"variant": "T832-DIAG-R0", "manifest": garbage, "build_id": 1},
                {"variant": "T832-DIAG-R0", "manifest": array, "build_id": 1},
            ]
            for kw in cases:
                with self.assertRaises(RuntimeError, msg=repr(kw)):
                    incident.bind_firmware(
                        store, artifact, role="deployed", **kw
                    )

    def test_manifest_contents_verified(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            artifact = self.artifact(root)
            with self.assertRaises(RuntimeError) as ctx:
                self.bind(store, root, artifact,
                          manifest=stage_binding(root, artifact, variant="OTHER"))
            self.assertIn("variant-mismatch", str(ctx.exception))
            with self.assertRaises(RuntimeError) as ctx:
                self.bind(store, root, artifact,
                          manifest=stage_binding(root, artifact, commit="zzz"))
            self.assertIn("commit-invalid", str(ctx.exception))
            with self.assertRaises(RuntimeError) as ctx:
                self.bind(store, root, artifact,
                          manifest=stage_binding(root, artifact, commit="b" * 39))
            self.assertIn("commit-invalid", str(ctx.exception))
            foreign = root / "foreign-manifest.json"
            foreign.write_text(
                json.dumps({
                    "variant": "T832-DIAG-R0",
                    "repository_commit": "c" * 40,
                    "artifacts": {"other.hex": {"sha256": "d" * 64}},
                }) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError) as ctx:
                self.bind(store, root, artifact, manifest=foreign)
            self.assertIn("artifact-not-in-manifest", str(ctx.exception))

    def test_records_carry_declared_and_observed_identity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = self.diag_log(root)
            bound = self.bind(store, root, self.artifact(root))
            result = self.collect(store, log)
            rows = stream_rows(store)
            self.assertEqual(result["diag_records"], 1)
            self.assertEqual(result["firmware_sha256"], bound["sha256"])
            self.assertEqual(result["firmware_binding_role"], "deployed")
            self.assertIsInstance(result["firmware_binding_mtime_ns"], int)
            self.assertEqual(rows[0]["firmware_sha256"], bound["sha256"])
            self.assertEqual(rows[0]["firmware_binding_role"], "deployed")
            self.assertEqual(rows[0]["observed_build_id"], 8320001)

    def test_mismatch_never_relabels_observed_frame(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = incident.Store(root / "private")
            log = self.diag_log(root)
            bound = self.bind(store, root, self.artifact(root), build_id=1)
            result = self.collect(store, log)
            self.assertTrue(
                any(n.startswith("firmware-build-mismatch:")
                    for n in result["notes"])
            )
            rows = stream_rows(store)
            self.assertEqual(rows[0]["observed_build_id"], 8320001)
            self.assertEqual(rows[0]["firmware_sha256"], bound["sha256"])


if __name__ == "__main__":
    unittest.main()
