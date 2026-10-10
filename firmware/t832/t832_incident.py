#!/usr/bin/env python3
"""T832-DIAG-R0 file-log collector, evidence barrier, and persistent incident latch.

The tool never opens the coordinator serial port. It consumes already-written
Zigbee2MQTT/Home Assistant/host logs, writes private JSONL, and gates recovery.

Wire schema 2 (firmware T832_DIAG_SCHEMA_VERSION 2): the DEBUG.msg payload is
one length byte followed by ASCII "T832D2:" plus hex of a 32-byte header, a
record-count byte and up to 4 packed 20-byte records. Schema 1 ("T832D1:" plus
104 hex chars, exactly one record) still decodes for old captures.

Two log representations are accepted:
- herdsman-buffer-v1: the stock pinned-herdsman ZpiObject serialization where
  the DEBUG msg string arrives as {"type":"Buffer","data":[...]}.
- text-fallback-v1: a plain-text line already containing the T832D1:/T832D2:
  payload (documented fallback, never the stock herdsman shape).
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
from collections import deque

class LockError(OSError):
    """Raised when the collector lock cannot be acquired in time."""


#: Seconds to wait for a contended collector lock before failing loudly.
#: A stuck or crashed holder must never wedge the collector forever.
LOCK_TIMEOUT_S = 30.0

try:
    import fcntl

    def _lock_exclusive(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _try_lock_exclusive(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        return True

    def _lock_release(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

except ImportError:  # Windows: no fcntl; msvcrt locking is the OS primitive.
    import msvcrt

    def _lock_exclusive(fd: int) -> None:
        if os.fstat(fd).st_size == 0:
            try:
                os.write(fd, b"\x00")
            except OSError:
                # Lost a creation race: another locker filled the byte and
                # already holds this region. Fall through to the blocking
                # lock below, which then serializes correctly.
                pass
        # Lock a fixed region: the fill above leaves the offset at 1, which
        # would lock a disjoint byte and silently disable exclusion.
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)

    def _try_lock_exclusive(fd: int) -> bool:
        if os.fstat(fd).st_size == 0:
            try:
                os.write(fd, b"\x00")
            except OSError:
                pass
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    def _lock_release(fd: int) -> None:
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


def _acquire_lock_bounded(fd: int, timeout_s: float = LOCK_TIMEOUT_S) -> None:
    """Acquire the exclusive lock, failing loudly on a stuck holder."""
    deadline = time.monotonic() + timeout_s
    while not _try_lock_exclusive(fd):
        if time.monotonic() >= deadline:
            raise LockError(
                f"collector lock busy after {timeout_s:.0f}s; "
                "refusing to overlap another writer"
            )
        time.sleep(0.05)
import hashlib
import json
import os
import re
import struct
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Iterable

PREFIX_V1_RE = re.compile(r"T832D1:([0-9A-Fa-f]{104})(?![0-9A-Fa-f])")
PREFIX_V2_RE = re.compile(r"T832D2:([0-9A-Fa-f]+)(?![0-9A-Fa-f])")
BUFFER_RE = re.compile(
    r'"(msg|string)"\s*:\s*\{\s*"type"\s*:\s*"Buffer"\s*,\s*"data"\s*:\s*\[([0-9,\s]*)\]\s*\}'
)
DEBUG_MARK_RE = re.compile(r"\bDEBUG\b")
ISO_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-6]\d"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
HOST_EVENT_RE = re.compile(
    r"(usb|tty|serial|cdc|disconnect|enumerat|zigbee2mqtt|addon|supervisor|"
    r"bridge|startupfromapp|srsp|timeout|rts|dtr|reset)",
    re.IGNORECASE,
)
HEADER = struct.Struct("<4sBBHHQIIHHH")
RECORD = struct.Struct("<IIHBBHHHH")
PACKET_V1_BYTES = HEADER.size + RECORD.size
FRAME_V2_MAX = 33 + 4 * RECORD.size
SEQ_MOD = 0x10000
WRAP_HIGH = 0xF000
WRAP_LOW = 0x0FFF
STABILITY_WINDOW_SECONDS = 600
# B09: the /5 scheduler samples every 300 seconds, so the gap budget must
# cover one healthy cadence interval plus scheduling jitter while still
# catching a single missed tick (600s). 180 made every healthy window fail.
STABILITY_MAX_GAP_SECONDS = 360
STABILITY_MAX_OBSERVATIONS = 512
# B09: observations at or just past the window end are admissible (the
# closing tick itself observes seconds after end_mono); anything a full
# cadence late is out-of-window evidence and fails closed.
# R4-F03: the grace is one full /5 scheduler period (300s), not a fitted
# constant. HA fires minutes:/5 on fixed wall-clock boundaries independent
# of the recovery anchor, so the first tick at or past the 600s window end
# lands up to one period late; a shorter grace fails healthy windows based
# purely on recovery phase. The gap budget below still catches a missed
# tick, and post-close ticks never observe (status leaves stabilizing).
STABILITY_OBS_GRACE_S = 300.0
# B09: wall-clock/mono cross-check tolerance for close decisions.
# Scheduling jitter is seconds; a real wall jump or suspend skews minutes.
STABILITY_WALL_SKEW_S = 120.0

EVENT_NAMES = {
    1: "BOOT",
    2: "MT_COMMAND_RX",
    3: "MT_COMMAND_DISPATCH",
    4: "MT_COMMAND_COMPLETE",
    5: "RESPONSE_QUEUED",
    6: "RESPONSE_ALLOC_FAIL",
    7: "NPI_RX_PROGRESS",
    8: "NPI_RX_OVERFLOW",
    9: "NPI_WRITE_REJECT",
    10: "NPI_TX_FINISHED",
    11: "TASK_SCHEDULE",
    12: "TASK_WORK",
    13: "STARTUP_FROM_APP_ENTRY",
    14: "STARTUP_BDB_REQUEST",
    15: "STARTUP_BDB_RETURN",
    16: "STARTUP_SRSP_QUEUE",
    17: "BDB_DISPATCH",
    18: "BDB_RETURN",
    19: "HEALTH",
    20: "RESOURCE",
    21: "EXPORT_SKIP",
    22: "FIRST_FAULT",
    23: "RX_BUFFER_FULL",
    24: "NETWORK_STATE",
    25: "TRANSPORT_CONFIG",
    26: "TASK_EVENTS",
    27: "NV_EVENT",
    28: "AF_STATE",
    29: "NV_FAULT",
    30: "TX_MISMATCH",
    31: "SYNC_ABANDON",
    32: "AF_REJECT",
    33: "AF_ANOMALY",
    34: "DIAG_LOSS",
    35: "NPI_TRAP",
    36: "NPI_ALLOC_FAIL",
    37: "BOOT_CAPTURE_INVALID",
    38: "TIMING_APPROX",
    39: "BLOCK_SNAPSHOT",
    40: "PIPELINE",
    41: "UART_EVENT",
    42: "NWK_PRESSURE",
    43: "TASK_STAT",
    44: "BOOT_TIMING",
    45: "NWK_LIMIT",
    46: "NV_TOPOLOGY",
    47: "NV_SPACE",
    48: "NV_COUNTERS",
    49: "NV_RESULT",
    50: "NPI_WRITE_COMPLETE",
    51: "NV_FIRST_V1",
    52: "STARTUP_V1",
    53: "RUNTIME_V1",
    54: "R12_RETENTION_V1",
}


R11_KINDS = {51, 52, 53}
R11_VERSION = 1


def decode_r11_group(records):
    strict = "exactly four records of one kind 51/52/53, parts 0..3, one version, reserved bit 11 clear"
    if len(records) != 4:
        raise ValueError("r11-count:" + str(len(records)))
    kinds = set()
    for r in records:
        kinds.add(r["kind"])
    if len(kinds) != 1 or next(iter(kinds)) not in R11_KINDS:
        raise ValueError("r11-kind:" + str(sorted(kinds)))
    kind = records[0]["kind"]
    parts = sorted(r["a"] & 0x3 for r in records)
    if parts != [0, 1, 2, 3]:
        raise ValueError("r11-parts:" + str(parts))
    versions = set(r["a"] >> 12 for r in records)
    if len(versions) != 1 or next(iter(versions)) != R11_VERSION:
        raise ValueError("r11-version:" + str(sorted(versions)))
    for r in records:
        if r["a"] & 0x0800:
            raise ValueError("r11-reserved-bit")
    if kind in (51, 52):
        for r in records:
            if r["a"] != (0x1000 | (r["a"] & 0x3)):
                raise ValueError("r11-flags-5152:" + hex(r["a"]))
    else:
        bases = set(r["a"] & ~0x3 for r in records)
        if len(bases) != 1:
            raise ValueError("r11-flags-53-nonuniform")
    ordered = sorted(records, key=lambda r: r["a"] & 0x3)
    p0, p1, p2, p3 = ordered
    if kind == 51:
        return {"kind": kind, "kind_name": EVENT_NAMES[kind], "fault_id": (p0["b"] | (p0["c"] << 16)), "item_id": p1["b"], "sub_id": p1["c"], "requested": p2["b"], "system_id": (p2["c"] >> 8) & 0xFF, "api": p2["c"] & 0xFF, "known_flags": (p3["b"] >> 8) & 0xFF, "phase_domain": p3["b"] & 0xFF, "site": (p3["c"] >> 8) & 0xFF, "status": p3["c"] & 0xFF}
    if kind == 52:
        return {"kind": kind, "kind_name": EVENT_NAMES[kind], "generation": (p0["b"] | (p0["c"] << 16)), "entry_mask": p1["b"], "exit_mask": p1["c"], "site": (p2["b"] >> 8) & 0xFF, "phase": p2["b"] & 0xFF, "status": p2["c"], "dev_state": (p3["b"] >> 8) & 0xFF, "nwk_state": p3["b"] & 0xFF, "valid": p3["c"]}
    flags = p0["a"]
    return {"kind": kind, "kind_name": EVENT_NAMES[kind], "seen_sync": bool(flags & (1 << 2)), "seen_transport": bool(flags & (1 << 3)), "seen_diag": bool(flags & (1 << 4)), "seen_normal_pending": bool(flags & (1 << 5)), "seen_txfull": bool(flags & (1 << 6)), "zstack_known": bool(flags & (1 << 7)), "uart_accepted_seen": bool(flags & (1 << 8)), "saturated": bool(flags & (1 << 9)), "unknown": bool(flags & (1 << 10)), "mt_schedule_delta": p0["b"], "mt_work_delta": p0["c"], "zstack_age_10ms": p1["b"], "npi_wake_delta": p1["c"], "uart_rx_byte_delta": p2["b"], "write_completion_delta": p2["c"], "normal_pending": p3["b"], "oldest_pending_age_10ms": p3["c"]}

DEFAULT_SOURCES = [
    "/addon_configs/45df7312_zigbee2mqtt/log",
    "/addon_configs/45df7312_zigbee2mqtt",
    "/config/zigbee2mqtt/log",
    "/config/home-assistant.log",
    "/config/.private/t832-diag/host-events.log",
]


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime | None = None) -> str:
    value = value or utcnow()
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def current_boot_id() -> str | None:
    """Host boot identity for B09 boot-bound evidence.

    The kernel boot id changes on every host reboot (container restarts
    keep it: the monotonic clock they share keeps running too, so that is
    correctly accepted as continuous). Unavailable off Linux: fail closed
    downstream, never silently accepted.
    """
    try:
        ident = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8")
    except OSError:
        return None
    return ident.strip() or None


def check_boot_continuity(stored: object, current: str | None) -> tuple[bool, str]:
    """Pure B09 comparator: stored boot ids must all equal the live one.

    A rebooted host with greater uptime keeps monotonic continuity, so the
    mono checks alone would accept prior-boot proof: the boot id is what
    fails closed. Missing identity on either side never passes.
    """
    ids = stored if isinstance(stored, list) else [stored]
    if not current:
        return False, "boot-unknown"
    for ident in ids:
        if not ident or ident != current:
            return False, "boot-mismatch"
    return True, "ok"


def check_wall_skew(utc_overshoot_s: float, mono_overshoot_s: float) -> tuple[bool, str]:
    """Pure B09 comparator: wall and monotonic overshoot past the window
    end must agree within tolerance. A wall jump or suspend/resume skews
    the wall side while monotonic stays put: fail closed."""
    if abs(utc_overshoot_s - mono_overshoot_s) > STABILITY_WALL_SKEW_S:
        return False, "wall-skew"
    return True, "ok"


def parse_timestamp(text: str) -> dt.datetime | None:
    """Parse an aware log timestamp. Naive timestamps are rejected: the
    collector never invents a timezone, and unknown event time is kept
    distinct from ingestion time."""
    match = ISO_RE.search(text)
    if not match:
        return None
    raw = match.group("ts").replace(" ", "T")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    elif re.search(r"[+-]\d{4}$", raw):
        raw = raw[:-5] + raw[-5:-2] + ":" + raw[-2:]
    try:
        value = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if value.tzinfo is None:
        return None
    return value.astimezone(dt.timezone.utc)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class Store:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.state = root / "state"
        self.stream = root / "stream"
        self.incidents = root / "incidents"
        self.cursor = self.state / "collector.json"
        self.latch = self.state / "incident-latch.json"
        self.lock_path = self.state / "collector.lock"
        self.firmware = root / "firmware.json"
        self.host_events = root / "host-events.log"
        for path in (self.root, self.state, self.stream, self.incidents):
            path.mkdir(parents=True, exist_ok=True)
            try:
                path.chmod(0o700)
            except OSError:
                pass
        self._lock_depth = 0
        self._lock_fd: int | None = None

    @contextlib.contextmanager
    def locked(self, timeout_s: float = LOCK_TIMEOUT_S):
        """OS-owned exclusive lock, re-entrant within this process.

        B04: the wait is bounded by timeout_s so a positive end-to-end
        deadline is enforceable under real contention — callers with a
        deadline pass the remaining budget instead of the fixed 30 s.
        """
        if self._lock_depth == 0:
            self.lock_path.touch(exist_ok=True)
            try:
                self.lock_path.chmod(0o600)
            except OSError:
                pass
            fd = os.open(self.lock_path, os.O_RDWR)
            try:
                _acquire_lock_bounded(fd, max(0.0, timeout_s))
            except Exception:
                os.close(fd)
                raise
            self._lock_fd = fd
        self._lock_depth += 1
        try:
            yield self
        finally:
            self._lock_depth -= 1
            if self._lock_depth == 0 and self._lock_fd is not None:
                try:
                    _lock_release(self._lock_fd)
                finally:
                    os.close(self._lock_fd)
                    self._lock_fd = None

    @staticmethod
    def load(path: Path, default: object) -> object:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

    @staticmethod
    def load_strict(path: Path) -> object:
        """Validated read: missing and corrupt are distinct failures."""
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise RuntimeError(f"state-missing:{path.name}")
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"state-corrupt:{path.name}:{exc}")

    @staticmethod
    def fsync_dir(path: Path) -> None:
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass

    def tmp_unique(self, path: Path, suffix: str) -> Path:
        Store._tmp_counter = getattr(Store, "_tmp_counter", 0) + 1
        return path.with_name(
            f"{path.name}.{os.getpid()}.{time.monotonic_ns()}.{Store._tmp_counter}{suffix}"
        )

    def atomic_json(self, path: Path, value: object) -> None:
        tmp = self.tmp_unique(path, ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(value, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        try:
            tmp.chmod(0o600)
        except OSError:
            pass
        os.replace(tmp, path)
        self.fsync_dir(path.parent)

    @staticmethod
    def append_jsonl(path: Path, rows: Iterable[dict[str, object]]) -> int:
        count = 0
        with path.open("a", encoding="utf-8") as fh:
            try:
                path.chmod(0o600)
            except OSError:
                pass
            for row in rows:
                fh.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
                count += 1
            fh.flush()
            os.fsync(fh.fileno())
        return count

    def append_host_event(self, kind: str, **fields: object) -> None:
        row = {"utc": iso(), "kind": kind, **fields}
        with self.host_events.open("a", encoding="utf-8") as fh:
            try:
                self.host_events.chmod(0o600)
            except OSError:
                pass
            fh.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())


def decode_record(raw: bytes, offset: int) -> dict[str, object]:
    rec = RECORD.unpack_from(raw, offset)
    result = {
        "first_ms": rec[0],
        "last_ms": rec[1],
        "sequence": rec[2],
        "kind": rec[3],
        "kind_name": EVENT_NAMES.get(rec[3], "UNKNOWN"),
        "flags": rec[4],
        "critical": bool(rec[4] & 1),
        "snapshot": bool(rec[4] & 2),
        "original_kind": (rec[4] >> 2) if rec[3] == 22 else None,
        "a": rec[5],
        "b": rec[6],
        "c": rec[7],
        "repeat_count": rec[8],
    }
    if rec[3] == 1:
        # Pinned cc13x4_cc26x4 AON_PMCTL reset-source enumerations.
        classes = {0: "PWR_ON", 1: "PIN_RESET", 2: "VDDS_LOSS", 4: "VDDR_LOSS",
                   5: "CLK_LOSS", 6: "SYSRESET", 7: "WARMRESET",
                   8: "WAKEUP_FROM_SHUTDOWN", 9: "WAKEUP_FROM_TCK_NOISE"}
        result["reset_class"] = classes.get(rec[5], "UNKNOWN") if rec[7] else "UNAVAILABLE"
    elif rec[3] == 44:
        result["elapsed_boot_ms"] = rec[6] | (rec[7] << 16)
    elif rec[3] in (39, 40, 41):
        result["saturation_note"] = "0xFFFF is saturated/unavailable; consult schema and RAM snapshot"
    elif rec[3] in (51, 52, 53):
        result["r11_version"] = (rec[5] >> 12) & 0xF
        result["r11_part"] = rec[5] & 0x3
        result["saturation_note"] = "0xFFFF is saturated/unavailable; consult schema and RAM snapshot"
    return result


def decode_frame_payload(text: str) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Decode one T832D1:/T832D2: text payload. Returns (frame, records)."""
    if text.startswith("T832D1:"):
        raw = bytes.fromhex(text[len("T832D1:"):])
        if len(raw) != PACKET_V1_BYTES:
            raise ValueError(f"packet-size:{len(raw)}")
        hdr = HEADER.unpack_from(raw)
        if hdr[0] != b"T8D1":
            raise ValueError("bad-signature")
        if hdr[1] != 1:
            raise ValueError(f"unsupported-schema:{hdr[1]}")
        frame = {
            "signature": "T8D1",
            "schema": 1,
            "packet_kind": hdr[2],
            "export_sequence": hdr[3],
            "firmware_boot_session": hdr[4],
            "firmware_uptime_ms": hdr[5],
            "firmware_revision": hdr[6],
            "capability_bitmap": f"0x{hdr[7]:08x}",
            "critical_overwrite": hdr[8],
            "routine_overwrite": hdr[9],
            "export_skipped": hdr[10],
        }
        return frame, [decode_record(raw, HEADER.size)]
    if text.startswith("T832D2:"):
        raw = bytes.fromhex(text[len("T832D2:"):])
        if len(raw) < HEADER.size + 1 or len(raw) > FRAME_V2_MAX:
            raise ValueError(f"packet-size:{len(raw)}")
        hdr = HEADER.unpack_from(raw)
        if hdr[0] != b"T8D1":
            raise ValueError("bad-signature")
        if hdr[1] != 2:
            raise ValueError(f"unsupported-schema:{hdr[1]}")
        count = raw[HEADER.size]
        if count < 1 or count > 4:
            raise ValueError(f"record-count:{count}")
        if len(raw) != HEADER.size + 1 + count * RECORD.size:
            raise ValueError(f"packet-size:{len(raw)}-count:{count}")
        frame = {
            "signature": "T8D1",
            "schema": 2,
            "packet_kind": hdr[2],
            "export_sequence": hdr[3],
            "firmware_boot_session": hdr[4],
            "firmware_uptime_ms": hdr[5],
            "firmware_build_id": hdr[6],
            "firmware_revision": hdr[6],
            "capability_bitmap": f"0x{hdr[7]:08x}",
            "critical_overwrite": hdr[8],
            "routine_overwrite": hdr[9],
            "export_skipped": hdr[10],
        }
        records = [
            decode_record(raw, HEADER.size + 1 + i * RECORD.size)
            for i in range(count)
        ]
        if any(record['kind'] in R11_KINDS for record in records):
            frame['r11_group'] = decode_r11_group(records)
        elif any(record['kind'] == 54 for record in records):
            from r12.r12_decode import decode_r12_group
            frame['r12_group'] = decode_r12_group(records)
        return frame, records
    raise ValueError("no-t832-prefix")


def decode_packet(hex_payload: str) -> dict[str, object]:
    """Legacy single-record decode (schema 1 only), kept for compatibility."""
    frame, records = decode_frame_payload("T832D1:" + hex_payload)
    return {**frame, "record": records[0]}


#: Belt-and-suspenders cap: one hostile log line can otherwise force
#: unbounded regex scanning and row emission out of a single read.
MAX_TEXT_MATCHES_PER_LINE = 64


def iter_text_payloads(line: str) -> Iterable[tuple[str, str]]:
    """Yield (repr, payload_text) for every diagnostic payload in a log line.

    The stock herdsman shape is the DEBUG command's length-prefixed string
    parameter serialized as {"length":N,"string":{"type":"Buffer","data":[...]}};
    only lines carrying a DEBUG marker are considered, and only payloads with
    the T832 text prefix decode further. At most MAX_TEXT_MATCHES_PER_LINE
    payloads are yielded per line; the excess is dropped (a single log line
    is one write, never a batch carrier)."""
    yielded = 0
    if DEBUG_MARK_RE.search(line):
        for match in BUFFER_RE.finditer(line):
            if yielded >= MAX_TEXT_MATCHES_PER_LINE:
                return
            try:
                data = bytes(int(v) for v in match.group(2).split(",") if v.strip())
            except ValueError:
                continue
            try:
                text = data.decode("ascii")
            except UnicodeDecodeError:
                continue
            if text.startswith("T832D1:") or text.startswith("T832D2:"):
                yield ("herdsman-buffer-v1", text)
                yielded += 1
    for match in PREFIX_V1_RE.finditer(line):
        if yielded >= MAX_TEXT_MATCHES_PER_LINE:
            return
        yield ("text-fallback-v1", "T832D1:" + match.group(1))
        yielded += 1
    for match in PREFIX_V2_RE.finditer(line):
        if yielded >= MAX_TEXT_MATCHES_PER_LINE:
            return
        yield ("text-fallback-v1", "T832D2:" + match.group(1))
        yielded += 1


class Continuity:
    """Wrap/duplicate/replay-aware boot association across one stream.

    Annotation is per FRAME: the caller passes one frame's export
    sequence, firmware uptime, and whether any record in the frame is a
    BOOT record. Boot membership is a frame property shared by every
    record in the frame; annotating per record mislabels same-frame
    siblings (the frame that carries BOOT is one boot, not N boots).

    The frontier moves only on proved same-boot evidence. A lower
    uptime alone never proves a reboot (replayed stale data also runs
    the clock backwards), and a delayed BOOT marker on a forward gap
    never proves one either (uptime monotonicity already proves the
    same boot). The only proved reboot signature is a fresh BOOT
    marker together with a regressed counter and a regressed clock.
    Kinds:
    - boot: first frame observed (opens host session 1);
    - reboot: proved signature above (new session, frontier moves);
    - duplicate/replay: exact redelivery or stale counter step — the
      frontier holds, the session is kept;
    - ambiguous: regressed counter and clock without a marker, a
      wrap-window crossing on a stepped-back clock, an expected
      counter with a stepped-back clock, or a forward jump on a
      regressed clock — undecidable, so the frontier holds explicitly;
    - delayed_boot: late BOOT marker on a forward gap with a monotonic
      clock — same boot, frontier moves;
    - uptime_wrap: expected counter with a >2**31 clock step-back (the
      32-bit firmware clock wrapped) — same boot, frontier moves;
    - wrap: counter crossing inside the wrap window on a live clock.
    A frame carrying BOOT as a clean continuation (exact redelivery or
    the already-counted next frame) never opens a second boot.
    """

    #: 16-bit export-sequence space; the firmware counter wraps mod 2**16.
    #: Aliases of the module constants so the window cannot drift.
    SEQ_MOD = SEQ_MOD
    #: A backwards step is only a wrap when the old value sits in the top
    #: 1/16th of the space and the new value in the bottom 1/16th.
    WRAP_HIGH = WRAP_HIGH
    WRAP_LOW = WRAP_LOW

    def __init__(self, collector_id: str) -> None:
        self.collector_id = collector_id
        self.host_session = 0
        self.boot_index = 0
        self.last_export_sequence: int | None = None
        self.last_uptime_ms: int | None = None

    def annotate(
        self, export_sequence: int, uptime_ms: int, boot_in_frame: bool
    ) -> dict[str, object]:
        """Classify one frame against the stream frontier.

        B10 policy: the frontier only moves on proved-same-boot evidence.
        A lower uptime no longer proves a reboot (replayed stale data also
        runs the clock backwards), and a delayed BOOT marker on a forward
        gap no longer proves one either (uptime monotonicity already proves
        the same boot). Only a fresh BOOT marker together with regressed
        sequence and clock proves a reboot. Anything genuinely undecidable
        is marked ambiguous with the frontier held stable, never silently
        absorbed into a boot.
        """
        reset = False
        kind = "normal"
        gap = 0
        last_seq = self.last_export_sequence
        last_uptime = self.last_uptime_ms
        expected: int | None = None
        if last_seq is not None:
            expected = (last_seq + 1) % self.SEQ_MOD
        in_wrap_window = (
            last_seq is not None
            and last_seq >= self.WRAP_HIGH
            and export_sequence <= self.WRAP_LOW
        )
        seq_regressed = (
            last_seq is not None
            and export_sequence < last_seq
            and not in_wrap_window
        )
        clock_regressed = last_uptime is not None and uptime_ms < last_uptime
        if last_seq is None or last_uptime is None:
            # First frame this stream ever saw: it opens host session 1.
            # Starting to observe mid-stream is itself a session boundary;
            # the BOOT marker is not required.
            self.host_session += 1
            self.boot_index += 1
            kind = "boot"
        elif export_sequence == last_seq and uptime_ms == last_uptime:
            kind = "duplicate"
        elif seq_regressed and clock_regressed and boot_in_frame:
            # Fresh BOOT marker plus regressed counter and clock: the only
            # proved reboot signature.
            self.host_session += 1
            self.boot_index += 1
            reset = True
            kind = "reboot"
        elif seq_regressed and clock_regressed:
            # Both regressed but no BOOT marker: replayed stale data and
            # a reboot with a lost marker are indistinguishable. Hold the
            # frontier stable and say so explicitly.
            kind = "ambiguous"
        elif seq_regressed:
            # Old counter on a live-or-ahead clock: stale duplicate-stream
            # or rotation copy, never a reboot.
            kind = "replay"
        elif (
            expected is not None
            and export_sequence == expected
            and not clock_regressed
        ):
            # Exact next counter value with a non-regressed clock. A
            # 0xFFFF -> 0x0000 step is still a wrap event (gap 0), so wrap
            # crossings stay explicit in evidence instead of vanishing
            # into "normal".
            if export_sequence < last_seq:
                kind = "wrap"
            else:
                kind = "normal"
        elif expected is not None and export_sequence == expected:
            # Expected counter but the clock stepped back (short of a
            # 32-bit wrap): clock anomaly, not a reboot — the counter
            # proves continuity of the stream. Hold stable, mark explicit.
            if last_uptime is not None and (last_uptime - uptime_ms) > 0x7FFFFFFF:
                kind = "uptime_wrap"
            else:
                kind = "ambiguous"
        elif in_wrap_window:
            if clock_regressed:
                # Counter crossed inside the wrap window but the clock
                # stepped back with no BOOT marker: a reboot with a lost
                # marker and replayed stale data are indistinguishable.
                # Hold the frontier stable and say so explicitly.
                kind = "ambiguous"
            else:
                kind = "wrap"
                gap = (0xFFFF - last_seq) + export_sequence
        elif last_seq is not None and export_sequence > last_seq:
            if clock_regressed:
                # Forward jump with a regressed clock: neither clean
                # continuation nor provable reboot. Hold stable.
                kind = "ambiguous"
            else:
                gap = export_sequence - last_seq - 1
                if boot_in_frame:
                    # Delayed BOOT marker on a forward gap with a
                    # monotonic clock: uptime already proves the same
                    # boot, so this is a late marker, not a new boot.
                    kind = "delayed_boot"
        else:
            kind = "replay"
        if kind in ("duplicate", "replay", "ambiguous"):
            pass
        else:
            self.last_export_sequence = export_sequence
            self.last_uptime_ms = uptime_ms
        return {
            "collector_id": self.collector_id,
            "host_session": self.host_session,
            "boot_index": self.boot_index,
            "sequence_gap_before": gap,
            "session_reset_detected": reset,
            "continuity_kind": kind,
        }


def source_files(values: list[str]) -> tuple[list[Path], list[str]]:
    found: dict[str, Path] = {}
    missing: list[str] = []
    for raw in values:
        path = Path(raw)
        if not path.exists():
            missing.append(str(path))
            continue
        if path.is_file():
            found[str(path)] = path
            continue
        try:
            for child in path.rglob("*"):
                if not child.is_file():
                    continue
                low = child.name.lower()
                if low.endswith((".log", ".txt", ".jsonl")):
                    found[str(child)] = child
        except OSError as exc:
            missing.append(f"{path}:{exc}")
    files = sorted(
        found.values(),
        key=lambda p: p.stat().st_mtime_ns if p.exists() else 0,
    )
    return files[-64:], sorted(set(missing))


def _deadline_exceeded(deadline_s: float | None) -> bool:
    """One shared time source for every scan budget: a single monotonic
    read. R4-F07: all scan loops observe the same deadline value through
    this helper instead of spreading ad-hoc clock reads."""
    return deadline_s is not None and time.monotonic() >= deadline_s


def read_increment(
    path: Path,
    cursor: dict[str, object],
    initial_tail_bytes: int,
    max_line_bytes: int = 1 << 20,
    max_new_bytes: int | None = None,
    deadline_s: float | None = None,
) -> tuple[list[tuple[int, str]], dict[str, object], list[str]]:
    """Read newly committed lines from path.

    The cursor carries file identity (dev/ino) plus the last committed
    complete-line boundary. A saved boundary is resumed exactly (no first-line
    discard); only a fresh mid-file tail skips forward to the next newline.
    An incomplete trailing chunk is buffered in the cursor, never committed
    past. Replacement/truncation/rewrite resets to zero, discards any prior
    partial (it belongs to the old file) with an explicit rotation note.
    Every returned row is byte-exact file content at its offset: a former
    partial is re-read from the file on the next poll, never prepended from
    cursor state, so split lines (including split UTF-8) decode exactly once.
    Logical lines beyond max_line_bytes are consumed but skipped with an
    explicit note, bounding memory regardless of writer behavior.

    B04 bounds: max_new_bytes caps total scanned bytes (returned rows plus
    drained oversized spans); when it trips, the cursor stops at the last
    complete-line boundary with an explicit read-budget-exhausted note, so
    the next poll resumes exactly once with no line split or skipped.
    deadline_s is a monotonic end time observed through _deadline_exceeded
    (one shared time source): passing it aborts only the current chunk —
    already-scanned rows commit at their boundary with an explicit note
    instead of being lost to an exception. The initial-tail skip is
    chunk-bounded (an unbounded readline would swallow newline-free
    floods), and a peeked byte equal to the line's own newline ends an
    exactly-cap-sized line there instead of draining into the next valid
    line.
    """
    notes: list[str] = []
    try:
        stat = path.stat()
    except OSError as exc:
        return [], cursor, [f"unreadable:{path}:{exc}"]
    identity = (stat.st_dev, stat.st_ino)
    saved_identity = (cursor.get("dev"), cursor.get("ino"))
    offset = int(cursor.get("offset", 0) or 0)
    if saved_identity != (None, None) and tuple(saved_identity) != tuple(identity):
        notes.append(f"rotated:{path}")
        offset = 0
    elif stat.st_size < offset:
        notes.append(f"truncated:{path}")
        offset = 0
    elif (
        offset
        and stat.st_size == offset
        and cursor.get("mtime_ns") is not None
        and int(cursor.get("mtime_ns")) != stat.st_mtime_ns
    ):
        # Same inode and same size but rewritten (Linux reuses inode numbers
        # on quick recreate): the committed prefix is stale, reread it.
        notes.append(f"rotated:{path}")
        offset = 0
    pending = ""
    rows: list[tuple[int, str]] = []
    try:
        fh = path.open("rb")
    except OSError as exc:
        return [], cursor, [f"unreadable:{path}:{exc}"]
    with fh:
        # R4-F07: opened-by-identity — the scan below runs on this opened
        # file only. If the path was replaced between the stat above and
        # this open, rescan from zero under the opened file's own identity
        # instead of applying a stale offset to foreign bytes.
        live = os.fstat(fh.fileno())
        if (live.st_dev, live.st_ino) != tuple(identity):
            notes.append(f"rotated:{path}")
            offset = 0
            stat = live
            identity = (live.st_dev, live.st_ino)
        if offset == 0 and stat.st_size > initial_tail_bytes:
            fh.seek(stat.st_size - initial_tail_bytes)
            # Bounded skip of the partial first line: at most the tail
            # window is scanned, one capped chunk at a time.
            remaining = initial_tail_bytes
            while remaining > 0:
                piece = fh.readline(min(max_line_bytes + 1, remaining))
                if not piece:
                    break
                remaining -= len(piece)
                if piece.endswith(b"\n"):
                    break
            offset = fh.tell()
            notes.append(f"initial-tail:{path}:{offset}")
        else:
            fh.seek(offset)
        chunk_start = fh.tell()
        boundary = chunk_start
        scanned = 0
        checks = 0
        broke_budget = False
        while True:
            pos = fh.tell()
            if max_new_bytes is not None and scanned >= max_new_bytes and rows:
                notes.append(f"read-budget-exhausted:{path}:{boundary}")
                broke_budget = True
                break
            checks += 1
            if checks % 64 == 0 and _deadline_exceeded(deadline_s):
                # R4-F07: abort only this chunk — rows scanned so far
                # commit at their boundary with an explicit note.
                notes.append(f"collect-deadline-exceeded:{path}:{boundary}")
                broke_budget = True
                break
            # Bounded first read: no single read ever holds more than
            # max_line_bytes + 1, regardless of writer behavior.
            raw = fh.readline(max_line_bytes + 1)
            if not raw:
                break
            scanned += len(raw)
            if raw.endswith(b"\n"):
                rows.append((pos, raw.decode("utf-8", errors="replace").rstrip("\r\n")))
                boundary = fh.tell()
                continue
            # No newline inside the bounded window: either the file's
            # incomplete tail or an oversized logical line. Peek one byte:
            # EOF means a partial tail to buffer; the line's own newline
            # means it ended exactly at the cap boundary; more data means
            # the line is oversized and must be drained boundedly.
            peeked = fh.read(1)
            if not peeked:
                pending = raw.decode("utf-8", errors="replace")
                chunk_start = pos
                break
            if peeked == b"\n":
                scanned += 1
                notes.append(f"line-too-large:{path}:{pos}:{len(raw) + 1}")
                boundary = fh.tell()
                continue
            size = len(raw) + 1
            piece = b""
            while True:
                if _deadline_exceeded(deadline_s):
                    notes.append(f"collect-deadline-exceeded:{path}:{boundary}")
                    broke_budget = True
                    piece = b"deadline"
                    break
                piece = fh.readline(max_line_bytes + 1)
                if not piece:
                    break
                size += len(piece)
                scanned += len(piece)
                if piece.endswith(b"\n"):
                    break
                if max_new_bytes is not None and scanned >= max_new_bytes:
                    break
            if piece.endswith(b"\n"):
                notes.append(f"line-too-large:{path}:{pos}:{size}")
                boundary = fh.tell()
                continue
            if piece == b"deadline":
                # Deadline tripped mid-drain: stop at the last complete
                # boundary with the deadline note above; the oversized
                # span is re-drained (boundedly) on the next poll.
                pending = ""
                break
            if piece:
                # Budget tripped mid-drain with more data still unread:
                # stop at the last complete boundary; the oversized span
                # is re-drained (boundedly) on the next poll. At EOF
                # (empty piece) the unterminated oversized tail is
                # discarded with an explicit note, as before.
                notes.append(f"read-budget-exhausted:{path}:{boundary}")
                broke_budget = True
                pending = ""
                break
            notes.append(f"partial-too-large:{path}:{pos}:{size}")
            pending = ""
            chunk_start = fh.tell()
            boundary = chunk_start
            break
        if broke_budget:
            committed = boundary
            pending = ""
        else:
            committed = chunk_start if pending else fh.tell()
    new_cursor: dict[str, object] = {
        "offset": committed,
        "dev": stat.st_dev,
        "ino": stat.st_ino,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "partial": pending if pending else "",
    }
    return rows, new_cursor, notes


def collect(
    store: Store,
    sources: list[str],
    *,
    config_fingerprint: str | None,
    initial_tail_bytes: int,
    retain_days: int,
    max_bytes: int,
    max_collect_bytes: int = 256 * 1024 * 1024,
    max_host_events_bytes: int = 64 * 1024 * 1024,
    deadline_seconds: float | None = None,
    max_store_bytes: int = 2 * 1024 * 1024 * 1024,
    max_rotated_logs: int = 32,
) -> dict[str, object]:
    with store.locked():
        deadline_s = (
            time.monotonic() + deadline_seconds if deadline_seconds is not None else None
        )
        return _collect_locked(
            store,
            sources,
            config_fingerprint=config_fingerprint,
            initial_tail_bytes=initial_tail_bytes,
            retain_days=retain_days,
            max_bytes=max_bytes,
            max_collect_bytes=max_collect_bytes,
            max_host_events_bytes=max_host_events_bytes,
            deadline_s=deadline_s,
            max_store_bytes=max_store_bytes,
            max_rotated_logs=max_rotated_logs,
        )


def _collect_locked(
    store: Store,
    sources: list[str],
    *,
    config_fingerprint: str | None,
    initial_tail_bytes: int,
    retain_days: int,
    max_bytes: int,
    max_collect_bytes: int,
    max_host_events_bytes: int,
    deadline_s: float | None = None,
    max_store_bytes: int = 2 * 1024 * 1024 * 1024,
    max_rotated_logs: int = 32,
) -> dict[str, object]:
    try:
        state = json.loads(store.cursor.read_text(encoding="utf-8"))
    except FileNotFoundError:
        state = {}
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"state-corrupt:collector.json:{exc}")
    if not isinstance(state, dict):
        raise RuntimeError("state-corrupt:collector.json:not-an-object")
    cursors = state.setdefault("files", {})
    continuity_state = state.setdefault(
        "continuity",
        {
            "host_session": 0,
            "boot_index": 0,
            "last_export_sequence": None,
            "last_uptime_ms": None,
            "collector_sequence": 0,
        },
    )
    continuity = Continuity("t832-file-collector")
    continuity.host_session = int(continuity_state.get("host_session") or 0)
    continuity.boot_index = int(continuity_state.get("boot_index") or 0)
    last_seq = continuity_state.get("last_export_sequence")
    continuity.last_export_sequence = int(last_seq) if last_seq is not None else None
    last_up = continuity_state.get("last_uptime_ms")
    continuity.last_uptime_ms = int(last_up) if last_up is not None else None
    files, missing = source_files(sources)
    diag_rows: list[dict[str, object]] = []
    host_rows: list[dict[str, object]] = []
    notes: list[str] = []
    budget = max_collect_bytes
    partial = False
    # Observed-vs-bound build identity: frames carry the firmware's own
    # build id; when an image is bound, any differing observed id is
    # explicit evidence of a swap, never silently absorbed.
    bound_build_id: int | None = None
    bound = bound_firmware(store)
    if isinstance(bound, dict) and isinstance(bound.get("build_id"), int):
        bound_build_id = int(bound["build_id"])
    build_mismatch_noted: set[int] = set()
    # B04/B12: the bound artifact is hashed once per collection, not once
    # per record. The lock is held for the whole transaction, so no other
    # tool writer can rebind mid-collection; the binding mtime is recorded
    # so any out-of-band change is detectable afterwards. Recomputing on
    # every collect() call is the explicit invalidation boundary.
    fw_hash = firmware_hash(store)
    try:
        binding_mtime_ns: int | None = store.firmware.stat().st_mtime_ns
    except OSError:
        binding_mtime_ns = None

    for path in files:
        key = str(path)
        prior = cursors.get(key, {}) if isinstance(cursors, dict) else {}
        file_cursor = prior if isinstance(prior, dict) else {}
        try:
            rows, new_cursor, file_notes = read_increment(
                path,
                file_cursor,
                initial_tail_bytes,
                max_new_bytes=max(0, budget),
                deadline_s=deadline_s,
            )
            stat = path.stat()
        except OSError as exc:
            missing.append(f"{path}:{exc}")
            continue
        notes.extend(file_notes)
        if any(n.startswith("read-budget-exhausted:") for n in file_notes):
            partial = True
            # The scan stopped because this file's share of the collect
            # budget ran out: keep the collector-level note alongside the
            # read-level one so budget exhaustion stays visible at both
            # layers.
            notes.append(f"collect-budget-exceeded:{path}")
        cursors[key] = {
            **new_cursor,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
        }
        processed = 0
        for byte_offset, line in rows:
            if budget <= 0:
                partial = True
                notes.append(f"collect-budget-exceeded:{path}")
                break
            budget -= len(line.encode("utf-8", errors="replace")) + 1
            source_time = parse_timestamp(line)
            if HOST_EVENT_RE.search(line):
                host_rows.append(
                    {
                        "type": "host_event",
                        "collector_utc": iso(),
                        "source_utc": iso(source_time) if source_time else None,
                        "source_file": key,
                        "source_byte_offset": byte_offset,
                        "raw_line": line,
                    }
                )
            for repr_name, payload in iter_text_payloads(line):
                continuity_state["collector_sequence"] = int(
                    continuity_state.get("collector_sequence") or 0
                ) + 1
                collector_seq = int(continuity_state["collector_sequence"])
                try:
                    frame, records = decode_frame_payload(payload)
                except ValueError as exc:
                    diag_rows.append(
                        {
                            "type": "decode_error",
                            "collector_utc": iso(),
                            "collector_sequence": collector_seq,
                            "repr": repr_name,
                            "source_utc": iso(source_time) if source_time else None,
                            "source_file": key,
                            "source_byte_offset": byte_offset,
                            "raw_line": line,
                            "raw_payload": payload,
                            "error": str(exc),
                        }
                    )
                    continue
                # B12: every frame carries both the declared binding (if
                # any) and its own observed build id, separately: an
                # observed frame is never silently labeled with another
                # image's hash. Schema 1 frames name the same wire field
                # firmware_revision; schema 2 calls it firmware_build_id.
                try:
                    observed_build: int | None = int(
                        frame.get(
                            "firmware_build_id",
                            frame.get("firmware_revision", -1),
                        )
                    )
                except (TypeError, ValueError):
                    observed_build = None
                if (
                    bound_build_id is not None
                    and observed_build is not None
                    and observed_build != bound_build_id
                    and observed_build not in build_mismatch_noted
                ):
                    build_mismatch_noted.add(observed_build)
                    # R4-F11: the mismatch note carries the observed
                    # capability bitmap so the phase explains the
                    # capabilities difference, not just the id.
                    caps = frame.get("capability_bitmap")
                    notes.append(
                        "firmware-build-mismatch:"
                        f"{observed_build}:{bound_build_id}:"
                        f"caps={caps if isinstance(caps, str) else 'unknown'}"
                    )
                # One continuity annotation per frame: records sharing a
                # frame share boot association (boot membership is a frame
                # property, and per-record annotation mislabels same-frame
                # records as duplicates).
                boot_marker = any(
                    str(item.get("kind_name")) == "BOOT" for item in records
                )
                annotation = continuity.annotate(
                    int(frame["export_sequence"]),
                    int(frame["firmware_uptime_ms"]),
                    boot_marker,
                )
                for record in records:
                    diag_rows.append(
                        {
                            **frame,
                            "record": record,
                            "type": "t832_diag",
                            "collector_utc": iso(),
                            "collector_sequence": collector_seq,
                            "repr": repr_name,
                            "host_session": annotation["host_session"],
                            "boot_index": annotation["boot_index"],
                            "session_reset_detected": annotation["session_reset_detected"],
                            "sequence_gap_before": annotation["sequence_gap_before"],
                            "continuity_kind": annotation["continuity_kind"],
                            "source_utc": iso(source_time) if source_time else None,
                            "source_file": key,
                            "source_byte_offset": byte_offset,
                            "raw_line": line,
                            "raw_payload": payload,
                            "firmware_sha256": fw_hash,
                            "firmware_binding_role": (
                                str(bound.get("role"))
                                if isinstance(bound, dict)
                                else None
                            ),
                            "observed_build_id": observed_build,
                            "config_fingerprint": config_fingerprint,
                        }
                    )
            processed += 1
        if processed < len(rows):
            # The budget stopped mid-file: rewind the cursor past only the
            # processed rows. Unread data is recovered by the next poll,
            # never marked consumed.
            first_unprocessed = rows[processed][0]
            cursors[key] = {
                **cursors[key],
                "offset": first_unprocessed,
                "partial": "",
            }
            notes.append(f"collect-budget-rewind:{path}:{first_unprocessed}")
    continuity_state["host_session"] = continuity.host_session
    continuity_state["boot_index"] = continuity.boot_index
    continuity_state["last_export_sequence"] = continuity.last_export_sequence
    continuity_state["last_uptime_ms"] = continuity.last_uptime_ms

    day = utcnow().strftime("%Y-%m-%d")
    diag_count = store.append_jsonl(store.stream / f"diag-{day}.jsonl", diag_rows) if diag_rows else 0
    host_count = store.append_jsonl(store.stream / f"host-{day}.jsonl", host_rows) if host_rows else 0
    state["files"] = cursors
    state["continuity"] = continuity_state
    state["last_collect_utc"] = iso()
    state["missing_sources"] = sorted(set(missing))
    state["collector_notes"] = sorted(set(notes))
    state["collect_partial"] = partial
    retention_notes = rotate(
        store,
        retain_days=retain_days,
        max_bytes=max_bytes,
        max_host_events_bytes=max_host_events_bytes,
        max_store_bytes=max_store_bytes,
        max_rotated_logs=max_rotated_logs,
    )
    notes.extend(retention_notes)
    state["collector_notes"] = sorted(set(notes))
    store.atomic_json(store.cursor, state)
    return {
        "ok": True,
        "diag_records": diag_count,
        "host_events": host_count,
        "sources_seen": len(files),
        "missing_sources": sorted(set(missing)),
        "partial": partial,
        "notes": sorted(set(notes)),
        "collector_utc": iso(),
        "firmware_sha256": fw_hash,
        "firmware_binding_mtime_ns": binding_mtime_ns,
        "firmware_binding_role": (
            str(bound.get("role")) if isinstance(bound, dict) else None
        ),
    }


def rotate(
    store: Store, *, retain_days: int, max_bytes: int, max_host_events_bytes: int = 64 * 1024 * 1024,
    max_store_bytes: int = 2 * 1024 * 1024 * 1024, max_rotated_logs: int = 32
) -> list[str]:
    """Enforce store-wide retention, returning one audit note per deletion.

    Deletions are evidence loss: every removed file (and its byte size)
    is reported so the collector persists it in collector_notes instead
    of dropping rows silently. Oldest mtime first; today's active file
    is newest, so it is always deleted last.
    """
    notes: list[str] = []
    cutoff = time.time() - retain_days * 86400
    files = [p for p in store.stream.glob("*.jsonl") if p.is_file()]
    for path in files:
        try:
            if path.stat().st_mtime < cutoff:
                size = path.stat().st_size
                path.unlink()
                notes.append(f"retention-age:{path.name}:{size}")
        except OSError:
            pass
    files = sorted(
        (p for p in store.stream.glob("*.jsonl") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
    )
    try:
        total = sum(p.stat().st_size for p in files)
    except OSError:
        total = 0
    for path in files:
        if total <= max_bytes:
            break
        try:
            size = path.stat().st_size
        except OSError:
            continue
        try:
            path.unlink()
            total -= size
            notes.append(f"retention-size:{path.name}:{size}")
        except OSError:
            pass
    # Incident bundles: keep the newest 32, never delete the latched one.
    try:
        latch = store.load(store.latch, {})
        active = str(latch.get("bundle", "")) if isinstance(latch, dict) else ""
    except Exception:
        active = ""
    bundles = sorted(
        (p for p in store.incidents.iterdir() if p.is_dir() and not p.name.startswith(".")),
        key=lambda p: p.name,
    )
    for path in bundles[:-32] if len(bundles) > 32 else []:
        if str(path) == active or (active and str(path) == active):
            continue
        try:
            for child in path.iterdir():
                if child.is_file():
                    child.unlink()
            path.rmdir()
            notes.append(f"retention-bundle:{path.name}")
        except OSError:
            pass
    # host-events.log rotation: protect the active tail, retain rotated parts.
    try:
        if store.host_events.exists() and store.host_events.stat().st_size > max_host_events_bytes:
            rotated = store.root / f"host-events-{utcnow().strftime('%Y%m%dT%H%M%SZ')}.log"
            os.replace(store.host_events, rotated)
            try:
                rotated.chmod(0o600)
            except OSError:
                pass
            notes.append(f"retention-host-events:{rotated.name}")
    except OSError:
        pass
    # B11 aggregate store cap: stream files, incident bundles, rotated
    # host logs and abandoned crash tmp dirs share one budget. Oldest
    # first, abandoned tmp first; active evidence is never deleted — if
    # only exempt evidence remains above the cap, the over-budget state
    # is noted explicitly instead of deleting blindly.
    try:
        latched = store.load(store.latch, {})
        latched_bundle = str(latched.get("bundle", "")) if isinstance(latched, dict) else ""
    except Exception:
        latched_bundle = ""
    today_prefix = utcnow().strftime("%Y-%m-%d")
    candidates: list[tuple[float, int, str, Path]] = []
    store_total = 0
    for path in store.stream.glob("*.jsonl"):
        if not path.is_file():
            continue
        try:
            st = path.stat()
        except OSError:
            continue
        store_total += st.st_size
        if not path.name.startswith(today_prefix):
            candidates.append((float(st.st_mtime), st.st_size, "stream", path))
    if store.incidents.is_dir():
        for path in store.incidents.iterdir():
            if not path.is_dir():
                continue
            if path.name.startswith("."):
                # Hidden staging dirs come from tmp_unique (capture staging
                # residue). Only .tmp-suffixed dirs older than a day are
                # abandoned; anything else is active or foreign and is
                # left alone.
                if not path.name.endswith(".tmp"):
                    continue
                try:
                    mtime = path.stat().st_mtime
                except OSError:
                    continue
                if time.time() - mtime < 86400:
                    continue
                try:
                    size = sum(c.stat().st_size for c in path.rglob("*") if c.is_file())
                except OSError:
                    continue
                store_total += size
                candidates.append((mtime - 1e10, size, "abandoned-tmp", path))
                continue
            if ".tmp" in path.name:
                try:
                    mtime = path.stat().st_mtime
                except OSError:
                    continue
                if time.time() - mtime < 86400:
                    continue
                try:
                    size = sum(c.stat().st_size for c in path.rglob("*") if c.is_file())
                except OSError:
                    continue
                store_total += size
                candidates.append((mtime - 1e10, size, "abandoned-tmp", path))
                continue
            try:
                children = [c for c in path.iterdir() if c.is_file()]
                size = sum(c.stat().st_size for c in children)
            except OSError:
                continue
            store_total += size
            if str(path) == latched_bundle:
                continue
            try:
                oldest = min(c.stat().st_mtime for c in children)
            except (OSError, ValueError):
                continue
            candidates.append((float(oldest), size, "bundle", path))
    for path in store.root.glob("host-events-*.log"):
        if not path.is_file():
            continue
        try:
            st = path.stat()
        except OSError:
            continue
        store_total += st.st_size
        candidates.append((float(st.st_mtime), st.st_size, "rotated-log", path))
    rotated = sorted(
        (p for p in store.root.glob("host-events-*.log") if p.is_file()),
        key=lambda p: p.name,
    )
    excess = len(rotated) - max(0, max_rotated_logs)
    for path in rotated[:excess] if excess > 0 else []:
        try:
            size = path.stat().st_size
            path.unlink()
            store_total -= size
            notes.append(f"retention-rotated-log:{path.name}:{size}")
        except OSError:
            pass
    for path in list(rotated):
        try:
            if not path.exists() or path.stat().st_mtime >= cutoff:
                continue
            size = path.stat().st_size
            path.unlink()
            store_total -= size
            notes.append(f"retention-rotated-age:{path.name}:{size}")
        except OSError:
            pass
    for _, size, kind, path in sorted(candidates):
        if store_total <= max_store_bytes:
            break
        try:
            if kind in ("bundle", "abandoned-tmp"):
                for child in sorted(path.rglob("*"), reverse=True):
                    try:
                        if child.is_file() or child.is_symlink():
                            child.unlink()
                        elif child.is_dir():
                            child.rmdir()
                    except OSError:
                        pass
                path.rmdir()
            else:
                path.unlink()
            store_total -= size
            notes.append(f"retention-store:{kind}:{path.name}:{size}")
        except OSError:
            pass
    if store_total > max_store_bytes:
        notes.append(f"retention-store-over-budget:{store_total}:{max_store_bytes}")
    return notes


def recent_rows(
    store: Store,
    prefix: str,
    cutoff: dt.datetime,
    *,
    max_rows: int = 20000,
    max_unknown_rows: int = 2000,
    max_scan_lines: int | None = None,
    deadline_s: float | None = None,
) -> tuple[
    list[dict[str, object]], list[dict[str, object]], int, bool, list[str]
]:
    """Stream the incident window with bounded cost and no silent drops.

    Only rows with a parseable SOURCE timestamp participate in the timed
    window; rows with unknown event time are preserved separately as
    bounded raw supplement rows (with stream provenance, never backdated
    with ingestion time) instead of being counted-and-dropped.

    R4-F08: files stream oldest-first and qualifying rows keep a bounded
    newest-tail (a maxlen ring sheds the oldest above max_rows), then the
    retained tail is stable-sorted ascending by SOURCE time. Above-cap and
    midnight/multiple-file windows therefore preserve the uniquely marked
    newest fault/command, and diag[-1] selects the actual latest
    diagnostic state. (The ring sheds in file-mtime traversal order, so a
    file whose mtime skews older than its rows' source times can shed
    newer-timestamped rows before the sort; rotation is daily, which
    bounds the skew to same-day clock adjustments.)

    B04/B11 bounds: max_scan_lines caps total scanned lines and deadline_s
    (monotonic end, observed through _deadline_exceeded) aborts the scan —
    either sets truncated with an explicit note naming the file. Unknown
    rows are capped
    separately; beyond the cap they are counted only, noted explicitly.
    Returns (in-window rows, unknown-time supplement rows, unknown total,
    truncated, notes).
    """
    tail: deque[tuple[dt.datetime, dict[str, object]]] = deque(
        maxlen=max(max_rows, 0)
    )
    unknown_rows: list[dict[str, object]] = []
    unknown = 0
    unknown_capped = False
    rows_capped = False
    truncated = False
    notes: list[str] = []
    if max_scan_lines is None:
        max_scan_lines = 8 * (max_rows + max_unknown_rows)
    scanned = 0
    files = sorted(
        store.stream.glob(f"{prefix}-*.jsonl"),
        key=lambda p: (p.stat().st_mtime_ns if p.exists() else 0),
    )
    for path in files:
        try:
            fh = path.open("r", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            lineno = 0
            for line in fh:
                lineno += 1
                scanned += 1
                if scanned > max_scan_lines:
                    truncated = True
                    notes.append(f"window-scan-capped:{path.name}:{lineno}")
                    break
                if lineno % 4096 == 0 and _deadline_exceeded(deadline_s):
                    truncated = True
                    notes.append(f"window-deadline:{path.name}:{lineno}")
                    break
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(item, dict):
                    continue
                stamp = item.get("source_utc")
                when = parse_timestamp(str(stamp)) if stamp else None
                if when is None:
                    unknown += 1
                    if len(unknown_rows) < max_unknown_rows:
                        unknown_rows.append(
                            {
                                **item,
                                "time_provenance": "unknown",
                                "supplement_stream_file": path.name,
                                "supplement_stream_line": lineno,
                            }
                        )
                    elif not unknown_capped:
                        unknown_capped = True
                        notes.append(
                            f"unknown-supplement-capped:{path.name}:{lineno}"
                        )
                    continue
                if when >= cutoff:
                    if len(tail) >= max_rows:
                        if not rows_capped:
                            rows_capped = True
                            notes.append(
                                f"window-rows-capped:{path.name}:{lineno}"
                            )
                    tail.append((when, item))
        if truncated:
            break
    if unknown_capped:
        truncated = True
    if rows_capped:
        truncated = True
    # Stable ascending sort by SOURCE time: the tail already streams
    # chronologically, so ties keep stream order and the result no longer
    # depends on which file was traversed first.
    out = [item for _, item in sorted(tail, key=lambda t: t[0])]
    return out, unknown_rows, unknown, truncated, notes


#: Latch statuses that block a new capture. "observed" (non-qualifying
#: evidence preserved without a reset permit), "closed" and "cleared"
#: never block: a later genuine trigger must still capture.
LATCH_BLOCKING_STATUSES = (
    "captured",
    "reset_authorized",
    "recovering",
    "stabilizing",
    "failed",
)


def active_latch(value: object) -> bool:
    return isinstance(value, dict) and value.get("status") in LATCH_BLOCKING_STATUSES


#: Latch statuses the tool itself ever writes. Anything else on disk is
#: foreign or corrupt and must never be trusted or silently overwritten.
LATCH_STATUSES = (
    "captured",
    "reset_authorized",
    "recovering",
    "stabilizing",
    "failed",
    "observed",
    "closed",
    "cleared",
)


def validate_latch(value: object) -> dict[str, object]:
    """Refuse an invalid existing latch without touching it.

    B05: every latch entry point calls this before any read-modify-write.
    A present latch must be an object with the known schema, a known
    status, an explicit boolean permit flag (R4-F06: never defaulted), and
    a non-empty incident id for every status that represents a live
    incident flow (a forced clear of missing state is the only id-less
    latch, written by the explicit manual-repair path). Missing schema is
    corrupt — never defaulted.
    A consumed permit (reset_used True) with status rewound to captured
    is inconsistent: it would re-authorize an already-used reset.
    B07: "observed" (non-qualifying evidence, no reset permit) validates
    like the other id-bearing statuses but never blocks a later capture.
    Raises RuntimeError; returns the latch unchanged when valid.
    """
    if not isinstance(value, dict):
        raise RuntimeError("incident-latch-corrupt:not-an-object")
    if value.get("schema") != LATCH_SCHEMA:
        raise RuntimeError("incident-latch-corrupt:unknown-schema")
    status = value.get("status")
    if status not in LATCH_STATUSES:
        raise RuntimeError(f"incident-latch-corrupt:unknown-status:{status!r}")
    # R4-F06: the permit flag is never defaulted — every present latch
    # must carry an explicit boolean, so an incomplete incident state can
    # never stand in for an explicitly unused permit.
    if "reset_used" not in value:
        raise RuntimeError("incident-latch-corrupt:reset-used-missing")
    reset_used = value.get("reset_used")
    if not isinstance(reset_used, bool):
        raise RuntimeError("incident-latch-corrupt:reset-used-not-bool")
    if reset_used and status == "captured":
        raise RuntimeError("incident-latch-inconsistent:permit-consumed-but-captured")
    if status in (
        "captured",
        "reset_authorized",
        "recovering",
        "stabilizing",
        "failed",
        "observed",
    ):
        incident_id = value.get("incident_id")
        if not isinstance(incident_id, str) or not incident_id:
            raise RuntimeError("incident-latch-corrupt:missing-incident-id")
    return value


#: Candidate barrier automation id in the trigger-definitions file.
BARRIER_AUTOMATION_ID = "zigbee2mqtt_t832_capture_barrier"
#: Trigger ids the candidate barrier automation defines. capture() refuses
#: anything else: reset authorization must only ever follow a production
#: trigger firing, never a free-form string.
CANDIDATE_TRIGGER_IDS = ("mesh_outage", "bridge_offline", "radio_timeout", "startup_health")
#: mqtt topic whose payloads the radio_timeout trigger evaluates. B07:
#: the candidate listens on the same permit_join response topic as the
#: production outage automation — never device/remove.
RADIO_TIMEOUT_TOPIC = "zigbee2mqtt/bridge/response/permit_join"
#: Production radio-timeout predicate (B07): a status-error response
#: qualifies only when its text carries BOTH the 'SRSP -' signature and
#: the 'after 6000ms' timeout marker. Compared case-SENSITIVELY to mirror
#: the production value_template verbatim ('SRSP -' in error). Anything
#: else on the topic (healthy responses, unrelated errors) is explicitly
#: non-qualifying.
TIMEOUT_ERROR_MARKERS = ("SRSP -", "after 6000ms")
#: A recorded ZDO proof is only fresh for this long (mono seconds). The
#: monotonic anchor also fails closed across a host reboot (mono resets).
ZDO_PROOF_MAX_AGE_S = 300.0


def parse_for_seconds(value: object) -> int | None:
    """Parse an HA `for:` duration ("HH:MM:SS") to seconds."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        parts = value.strip().split(":")
        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return None
        if len(nums) == 3:
            return nums[0] * 3600 + nums[1] * 60 + nums[2]
        if len(nums) == 2:
            return nums[0] * 60 + nums[1]
    return None


def load_trigger_defs(path: Path) -> tuple[dict[str, dict[str, object]], str]:
    """Load candidate trigger definitions from the barrier automation file.

    Returns ({trigger_id: {kind, entity_id/topic, to, for_seconds}}, sha256
    of the exact file evaluated), so every qualification verdict is pinned
    to the reviewed source it was evaluated against.
    """
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(f"trigger-defs-require-pyyaml:{exc}")
    try:
        text = path.read_text(encoding="utf-8")
        automations = yaml.safe_load(text)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"trigger-defs-unreadable:{path}:{exc}")
    if not isinstance(automations, list):
        raise RuntimeError(f"trigger-defs-malformed:{path}")
    automation = next(
        (a for a in automations
         if isinstance(a, dict) and a.get("id") == BARRIER_AUTOMATION_ID),
        None,
    )
    if automation is None:
        raise RuntimeError(f"trigger-defs-no-barrier:{path}")
    triggers = automation.get("triggers")
    if not isinstance(triggers, list):
        raise RuntimeError(f"trigger-defs-no-triggers:{path}")
    defs: dict[str, dict[str, object]] = {}
    for entry in triggers:
        if not isinstance(entry, dict):
            continue
        tid = entry.get("id")
        kind = entry.get("trigger")
        if not isinstance(tid, str) or not isinstance(kind, str):
            continue
        spec: dict[str, object] = {"kind": kind}
        if kind == "state":
            spec["entity_id"] = entry.get("entity_id")
            spec["to"] = entry.get("to")
            spec["for_seconds"] = parse_for_seconds(entry.get("for"))
        elif kind == "mqtt":
            spec["topic"] = entry.get("topic")
        defs[tid] = spec
    sha = sha256_file(path)
    for spec in defs.values():
        spec["source_sha256"] = sha
    return defs, sha


def evaluate_radio_timeout(*, topic: str | None, payload: object) -> tuple[bool, str]:
    """Qualify a permit_join response as a production radio-timeout event.

    B07: only a status-error response on exactly the permit_join response
    topic whose text carries BOTH the 'SRSP -' signature and the
    'after 6000ms' timeout marker qualifies. Healthy responses, unrelated
    errors, wrong topics and malformed payloads are non-qualifying, each
    with its own reason, so a healthy mesh can never arm reset
    authorization through this trigger.
    """
    if topic != RADIO_TIMEOUT_TOPIC:
        return False, f"topic-mismatch:{topic}"
    if not isinstance(payload, dict):
        return False, "malformed-payload"
    status = payload.get("status")
    if status == "ok":
        return False, "healthy-response"
    if status != "error":
        return False, f"unexpected-status:{status}"
    error = str(payload.get("error", ""))
    if all(marker in error for marker in TIMEOUT_ERROR_MARKERS):
        return True, "timeout-error"
    return False, "non-timeout-error"


def evaluate_trigger(
    trigger_id: str,
    defs: dict[str, dict[str, object]] | None,
    *,
    topic: str | None,
    payload: object,
    malformed_payload: bool = False,
) -> dict[str, object]:
    """Evaluate one trigger firing against the candidate definitions.

    State triggers (mesh_outage/bridge_offline) are trusted firings: Home
    Assistant enforces their `to` state plus the `for` duration before the
    tool ever runs, and the tool cannot re-observe that wait. The mqtt
    trigger (radio_timeout) carries no such enforcement in the automation,
    so its payload is evaluated here and only a timeout-family error
    qualifies. The verdict always records the definitions source and its
    SHA so evidence links the decision to the reviewed file.
    """
    base: dict[str, object] = {"trigger_id": trigger_id, "topic": topic}
    if trigger_id == "startup_health":
        # Startup is qualified inside capture, using persisted independent
        # owner/add-on evidence. Caller-supplied success/failure is not trusted.
        return {**base, "qualifying": False, "reason": "startup-evidence-required"}
    if trigger_id not in CANDIDATE_TRIGGER_IDS:
        return {**base, "qualifying": False, "reason": f"unknown-trigger:{trigger_id}"}
    spec = (defs or {}).get(trigger_id, {})
    kind = spec.get("kind")
    if trigger_id == "radio_timeout" or kind == "mqtt":
        if malformed_payload:
            verdict: dict[str, object] = {"qualifying": False, "reason": "malformed-payload"}
        else:
            qualifying, reason = evaluate_radio_timeout(topic=topic, payload=payload)
            verdict = {"qualifying": qualifying, "reason": reason}
        return {
            **base,
            **verdict,
            "source": "candidate-yaml" if defs else "builtin-rule",
            "source_sha256": spec.get("source_sha256"),
            "required_topic": RADIO_TIMEOUT_TOPIC,
        }
    return {
        **base,
        "qualifying": True,
        "reason": "state-trigger-fired",
        "source": "candidate-yaml" if defs else "builtin-ids",
        "source_sha256": spec.get("source_sha256"),
        "entity_id": spec.get("entity_id"),
        "to": spec.get("to"),
        "for_seconds": spec.get("for_seconds"),
    }


def check_deadline(started_monotonic: float, deadline_seconds: int, phase: str) -> None:
    elapsed = time.monotonic() - started_monotonic
    if elapsed > deadline_seconds:
        raise TimeoutError(f"capture-deadline:{phase}:{elapsed:.3f}s")


def coerce_trigger_payload(raw: str | dict[str, object] | None) -> tuple[object, bool]:
    """Coerce a --trigger-payload argument to (payload, malformed).

    A malformed JSON string is not an error here: it is itself a verdict
    input (malformed payloads never qualify), so capture keeps the
    evidence instead of crashing on a sick automation variable.
    """
    if raw is None or isinstance(raw, dict):
        return raw, False
    if isinstance(raw, str):
        if not raw.strip():
            return None, False
        try:
            return json.loads(raw), False
        except json.JSONDecodeError:
            return raw, True
    return raw, True


def capture(
    store: Store,
    trigger: str,
    *,
    sources: list[str],
    config_fingerprint: str | None,
    initial_tail_bytes: int,
    retain_days: int,
    max_bytes: int,
    window_seconds: int,
    deadline_seconds: int,
    max_collect_bytes: int = 256 * 1024 * 1024,
    max_window_rows: int = 20000,
    max_host_events_bytes: int = 64 * 1024 * 1024,
    max_store_bytes: int = 2 * 1024 * 1024 * 1024,
    max_rotated_logs: int = 32,
    require_firmware_binding: bool = False,
    triggers_path: Path | None = None,
    trigger_topic: str | None = None,
    trigger_payload: str | dict[str, object] | None = None,
) -> dict[str, object]:
    started_monotonic = time.monotonic()
    started_utc = utcnow()
    # B04: the lock wait itself is deadline-bounded — a contended lock
    # must fail fast instead of consuming the whole capture deadline.
    with store.locked(timeout_s=min(LOCK_TIMEOUT_S, float(deadline_seconds))):
        collection_deadline_s = started_monotonic + deadline_seconds
        try:
            latch = store.load_strict(store.latch)
            latch_present = True
        except RuntimeError as exc:
            if str(exc).startswith("state-missing:"):
                latch = {}
                latch_present = False
            else:
                raise
        if latch_present:
            # B05: an existing latch is validated before anything else.
            # Invalid content raises here, before any work is done and
            # before the final atomic_json could overwrite it.
            # R4-F06: file absence (latch_present False) is the ONLY path
            # that permits initial state — every present value, including
            # falsy JSON ({}, [], null, false, 0), is validated, so corrupt
            # bytes can never be silently overwritten with a new latch.
            validate_latch(latch)
        if active_latch(latch):
            raise RuntimeError(f"incident-latch-active:{latch.get('status')}")
        bound = bound_firmware(store) if require_firmware_binding else None
        if require_firmware_binding and (
            bound is None or bound.get("role") not in BINDING_AUTHORIZED_ROLES
        ):
            # Missing, swapped, or non-deployed bindings never gate: the
            # artifact is re-hashed on every use, and candidate/test roles
            # bind for bookkeeping only.
            raise RuntimeError("capture-requires-firmware-binding")
        if trigger not in CANDIDATE_TRIGGER_IDS:
            raise RuntimeError(f"unknown-trigger:{trigger}")
        defs: dict[str, dict[str, object]] | None = None
        defs_sha: str | None = None
        if triggers_path is not None:
            defs, defs_sha = load_trigger_defs(Path(triggers_path))
        payload, malformed = coerce_trigger_payload(trigger_payload)
        verdict = evaluate_trigger(
            trigger, defs, topic=trigger_topic, payload=payload,
            malformed_payload=malformed,
        )

        # Independent evidence belongs in every capture without depending on
        # an operator remembering an extra --source deployment argument.
        capture_sources = list(sources)
        if store.host_events.exists() and str(store.host_events) not in capture_sources:
            capture_sources.append(str(store.host_events))
        collection = _collect_locked(
            store,
            capture_sources,
            config_fingerprint=config_fingerprint,
            initial_tail_bytes=initial_tail_bytes,
            retain_days=retain_days,
            max_bytes=max_bytes,
            max_collect_bytes=max_collect_bytes,
            max_host_events_bytes=max_host_events_bytes,
            deadline_s=collection_deadline_s,
            max_store_bytes=max_store_bytes,
            max_rotated_logs=max_rotated_logs,
        )
        check_deadline(started_monotonic, deadline_seconds, "collect")
        cutoff = utcnow() - dt.timedelta(seconds=window_seconds)
        window_deadline_s = started_monotonic + deadline_seconds
        diag, diag_supp, diag_unknown, diag_truncated, diag_notes = recent_rows(
            store, "diag", cutoff, max_rows=max_window_rows,
            deadline_s=window_deadline_s,
        )
        host, host_supp, host_unknown, host_truncated, host_notes = recent_rows(
            store, "host", cutoff, max_rows=max_window_rows,
            deadline_s=window_deadline_s,
        )
        # B04: scan-budget notes join the window evidence explicitly.
        window_notes = sorted(set(diag_notes + host_notes))
        check_deadline(started_monotonic, deadline_seconds, "window")
        cursor = store.load(store.cursor, {})
        missing = cursor.get("missing_sources", []) if isinstance(cursor, dict) else []

        incident_id = utcnow().strftime("%Y%m%dT%H%M%S.%fZ")
        tmp = store.tmp_unique(store.incidents / f".{incident_id}", ".tmp")
        final = store.incidents / incident_id
        tmp.mkdir(parents=False, exist_ok=False)
        try:
            store.append_jsonl(tmp / "diag-15m.jsonl", diag)
            store.append_jsonl(tmp / "host-events-15m.jsonl", host)
            # B11: unknown-time rows are preserved as bounded raw
            # supplement with stream provenance, never backdated. The
            # file always exists (possibly empty) so the committed set
            # is stable and verifiable.
            store.append_jsonl(
                tmp / "unknown-time-supplement.jsonl", diag_supp + host_supp
            )

            # Last stages are selected within the latest boot group using
            # record chronology, not file arrival order.
            last_stages: dict[str, object] = {}
            # Also support importlib-based callers outside this directory.
            module_path = str(Path(__file__).resolve().parent)
            if module_path not in sys.path:
                sys.path.insert(0, module_path)
            import t832_sideband
            bridge_events = t832_sideband.extract(host)
            bridge_summary = t832_sideband.correlate(bridge_events)
            if trigger == "startup_health":
                startup_id = payload.get("startup_id") if isinstance(payload, dict) else None
                startup = t832_sideband.startup_verdict(bridge_events, startup_id, utcnow())
                verdict = {"trigger_id": trigger, "qualifying": startup["qualifies"],
                           "reason": startup["reason"], "evidence": startup,
                           "source": "persisted-owner-and-addon-evidence"}
            latest_boot = -1
            for item in diag:
                boot = item.get("boot_index")
                if isinstance(boot, int) and boot > latest_boot:
                    latest_boot = boot
            interesting = {
                "MT_COMMAND_RX",
                "MT_COMMAND_DISPATCH",
                "MT_COMMAND_COMPLETE",
                "RESPONSE_QUEUED",
                "NPI_TX_FINISHED",
                "STARTUP_FROM_APP_ENTRY",
                "STARTUP_BDB_REQUEST",
                "STARTUP_BDB_RETURN",
                "STARTUP_SRSP_QUEUE",
                "BDB_DISPATCH",
                "BDB_RETURN",
            }
            for item in diag:
                if item.get("boot_index") != latest_boot:
                    continue
                rec = item.get("record")
                if isinstance(rec, dict):
                    name = str(rec.get("kind_name", "UNKNOWN"))
                    if name in interesting:
                        prev = last_stages.get(name)
                        prev_ms = -1
                        if isinstance(prev, dict):
                            prev_rec = prev.get("record")
                            if isinstance(prev_rec, dict):
                                prev_ms = int(prev_rec.get("last_ms", -1) or -1)
                        cur_ms = int(rec.get("last_ms", -1) or -1)
                        if cur_ms >= prev_ms:
                            last_stages[name] = item

            check_deadline(started_monotonic, deadline_seconds, "assemble")
            manifest = {
                "schema": 1,
                "incident_id": incident_id,
                "trigger_reason": trigger,
                "capture_started_utc": iso(started_utc),
                "capture_completed_utc": iso(),
                "window_seconds": window_seconds,
                "deadline_seconds": deadline_seconds,
                "diag_record_count": len(diag),
                "host_event_count": len(host),
                "diag_unknown_time_count": diag_unknown,
                "host_unknown_time_count": host_unknown,
                "unknown_supplement_count": len(diag_supp) + len(host_supp),
                "window_truncated": bool(diag_truncated or host_truncated),
                "window_notes": window_notes,
                "collect_partial": bool(collection.get("partial")),
                "latest_boot_index": latest_boot,
                "bridge_reset_evidence": bridge_summary,
                "sideband_event_count": len(bridge_events),
                # R4-F08: diag is ascending SOURCE-time order, so [-1]
                # selects the actual latest diagnostic state rather than
                # whatever the traversal visited last.
                "latest_diagnostic_state": diag[-1] if diag else None,
                "last_successful_command_stages": last_stages,
                "collector_result": collection,
                "missing_sources": missing,
                # B12: the collection-cached binding hash, not a fresh
                # re-hash — same transaction, same value, one hash.
                "firmware_sha256": collection.get("firmware_sha256"),
                "firmware_binding_role": collection.get("firmware_binding_role"),
                "firmware_binding_mtime_ns": collection.get(
                    "firmware_binding_mtime_ns"
                ),
                "config_fingerprint": config_fingerprint,
                "trigger_qualification": verdict,
                "trigger_definitions_sha256": defs_sha,
                "observability_note": (
                    "Missing telemetry is loss of observability, not proof of CPU failure."
                ),
            }
            store.atomic_json(tmp / "manifest.json", manifest)
            hashes = {
                item.name: sha256_file(item)
                for item in sorted(tmp.iterdir())
                if item.is_file()
            }
            store.atomic_json(tmp / "SHA256.json", hashes)
            check_deadline(started_monotonic, deadline_seconds, "commit")
            Store.fsync_dir(tmp)
            os.replace(tmp, final)
            Store.fsync_dir(store.incidents)

            # B07: non-qualifying evidence is preserved (bundle and
            # manifest are committed) without consuming the incident
            # latch: "observed" never blocks a later genuine trigger.
            latch_value = {
                "schema": 1,
                "incident_id": incident_id,
                "bundle": str(final),
                "status": (
                    "captured"
                    if verdict.get("qualifying") is True
                    else "observed"
                ),
                "captured_utc": iso(),
                "reset_used": False,
                "trigger_reason": trigger,
                "trigger_qualifying": bool(verdict.get("qualifying")),
                "trigger_qualification_reason": str(verdict.get("reason")),
                "trigger_definitions_sha256": defs_sha,
            }
            store.atomic_json(store.latch, latch_value)
            store.append_host_event("incident_captured", incident_id=incident_id, trigger=trigger)
            return {
                "ok": True,
                **latch_value,
                "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
            }
        except Exception:
            try:
                for child in tmp.iterdir():
                    child.unlink()
                tmp.rmdir()
            except OSError:
                pass
            raise


#: Latch schema version the tool reads and writes. Unknown schemas fail
#: closed: a latch from a newer or foreign writer is never acted on.
LATCH_SCHEMA = 1


def update_latch(store: Store, expected: set[str], update: dict[str, object]) -> dict[str, object]:
    latch = store.load_strict(store.latch)
    # B05: full validation first — missing schema is corrupt, never
    # defaulted; unknown status or inconsistent permit/state refuses
    # before any field is touched.
    validate_latch(latch)
    status = str(latch.get("status"))
    if status not in expected:
        raise RuntimeError(f"incident-latch-state:{status}")
    latch.update(update)
    latch["updated_utc"] = iso()
    store.atomic_json(store.latch, latch)
    return latch


#: Files every incident bundle must commit. The inventory must name
#: exactly this set (plus nothing else): a thinned, padded, or renamed
#: bundle refuses. Empty evidence files are valid only when inventoried
#: here and their absence is declared in the manifest counts.
COMMITTED_BUNDLE_FILES = frozenset(
    {
        "manifest.json",
        "diag-15m.jsonl",
        "host-events-15m.jsonl",
        "unknown-time-supplement.jsonl",
    }
)


def _count_jsonl_lines(path: Path) -> int:
    count = 0
    with path.open("rb") as fh:
        for _ in fh:
            count += 1
    return count


def verify_bundle(store: Store, latch: dict[str, object]) -> Path:
    """Validate that the latched incident's committed bundle exists, names
    exactly the committed file set with well-formed digests, still matches
    every hash, resolves beneath the incidents root (no traversal), and is
    semantically consistent with the manifest and the latch.

    B06: swizzled digests (right length, wrong value), thinned or padded
    inventories, non-file entries, missing/wrong-typed digest formats,
    foreign bundle paths, and count/digest inconsistencies all refuse.
    """
    bundle = Path(str(latch.get("bundle", "")))
    incident_id = str(latch.get("incident_id", ""))
    if not incident_id or bundle.name != incident_id or not bundle.is_dir():
        raise RuntimeError("reset-permit-bundle-missing")
    try:
        resolved = bundle.resolve()
        root = store.incidents.resolve()
    except OSError as exc:
        raise RuntimeError(f"reset-permit-bundle-unresolvable:{exc}")
    if resolved != root / incident_id or not str(resolved).startswith(str(root)):
        raise RuntimeError("reset-permit-bundle-foreign")
    try:
        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        recorded = json.loads((bundle / "SHA256.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"reset-permit-bundle-unreadable:{exc}")
    if not isinstance(manifest, dict) or manifest.get("incident_id") != incident_id:
        raise RuntimeError("reset-permit-bundle-mismatch")
    if not isinstance(recorded, dict):
        raise RuntimeError("reset-permit-hashes-missing")
    # Exact inventory membership: thinned inventories verify nothing, and
    # padded ones smuggle unverified files — both refuse.
    if set(recorded) != set(COMMITTED_BUNDLE_FILES):
        raise RuntimeError(
            "reset-permit-inventory-inexact:"
            f"{sorted(set(COMMITTED_BUNDLE_FILES) - set(recorded))}:"
            f"{sorted(set(recorded) - set(COMMITTED_BUNDLE_FILES))}"
        )
    for name, expected in recorded.items():
        # Names are plain committed filenames: no separators, no absolute
        # paths, no traversal — the entry must resolve to the bundle dir.
        if (
            not isinstance(name, str)
            or not isinstance(expected, str)
            or PurePosixPath(name).name != name
            or name in ("", ".", "..")
        ):
            raise RuntimeError(f"reset-permit-inventory-name:{name!r}")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            raise RuntimeError(f"reset-permit-digest-format:{name}")
        item = bundle / name
        try:
            if not item.is_file() or sha256_file(item) != expected.lower():
                raise RuntimeError(f"reset-permit-hash-mismatch:{name}")
        except OSError as exc:
            raise RuntimeError(f"reset-permit-hash-unreadable:{name}:{exc}")
    # Semantic consistency: the evidence files' actual row counts must
    # match the manifest's declared counts (an empty evidence file is
    # valid only when the manifest declares zero rows for it), the
    # supplement must hold exactly the declared unknown rows, and the
    # latch's own copies must agree with the manifest. Non-integer
    # declared counts are corruption, not zero.
    try:
        diag_lines = _count_jsonl_lines(bundle / "diag-15m.jsonl")
        host_lines = _count_jsonl_lines(bundle / "host-events-15m.jsonl")
        supp_lines = _count_jsonl_lines(bundle / "unknown-time-supplement.jsonl")
    except OSError as exc:
        raise RuntimeError(f"reset-permit-evidence-unreadable:{exc}")
    raw_counts = [
        manifest.get("diag_record_count", -1),
        manifest.get("host_event_count", -1),
        manifest.get("diag_unknown_time_count", -1),
        manifest.get("host_unknown_time_count", -1),
        manifest.get("unknown_supplement_count", -2),
    ]
    # Counts must be plain integers: bools, floats and strings are
    # corruption even when int() would coerce them.
    if any(isinstance(v, bool) or not isinstance(v, int) for v in raw_counts):
        raise RuntimeError("reset-permit-count-unparseable")
    (
        declared_diag,
        declared_host,
        declared_diag_unknown,
        declared_host_unknown,
        declared_supp,
    ) = raw_counts
    declared_unknown = declared_diag_unknown + declared_host_unknown
    if diag_lines != declared_diag:
        raise RuntimeError(
            f"reset-permit-count-mismatch:diag:{diag_lines}:{declared_diag}"
        )
    if host_lines != declared_host:
        raise RuntimeError(
            f"reset-permit-count-mismatch:host:{host_lines}:{declared_host}"
        )
    if supp_lines != declared_unknown or supp_lines != declared_supp:
        raise RuntimeError(
            f"reset-permit-count-mismatch:supplement:{supp_lines}:{declared_unknown}"
        )
    verdict = manifest.get("trigger_qualification")
    if (
        not isinstance(verdict, dict)
        or verdict.get("qualifying") is not True
        or latch.get("trigger_qualifying") is not True
    ):
        raise RuntimeError("reset-permit-qualification-mismatch")
    # Definitions identity must agree between the committed manifest and
    # the latch. Both None (builtin rules, no definitions file) agrees.
    if manifest.get("trigger_definitions_sha256") != latch.get(
        "trigger_definitions_sha256"
    ):
        raise RuntimeError("reset-permit-defs-mismatch")
    # R4-F11 firmware identity: only after the bundle proves intact
    # (hashes and inventory above) are incident fields decoded for the
    # observed-vs-bound verdict. Hashes prove integrity, not identity: a
    # swapped image with a self-consistent bundle still refuses here.
    bound_state = bound_firmware(store)
    bound_id = bound_state.get("build_id") if isinstance(bound_state, dict) else None
    if isinstance(bound_id, bool):
        bound_id = None
    if isinstance(bound_id, int):
        try:
            with (bundle / "diag-15m.jsonl").open(
                "r", encoding="utf-8", errors="replace"
            ) as fh:
                foreign: dict[int, object] = {}
                for line in fh:
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(item, dict):
                        continue
                    observed = item.get("observed_build_id")
                    if (
                        isinstance(observed, bool)
                        or not isinstance(observed, int)
                        or observed == bound_id
                    ):
                        continue
                    caps = item.get("capability_bitmap")
                    foreign[observed] = caps if isinstance(caps, str) else "unknown"
        except OSError as exc:
            raise RuntimeError(f"reset-permit-evidence-unreadable:{exc}")
        for observed_id, observed_caps in sorted(
            foreign.items(), key=lambda kv: kv[0]
        ):
            raise RuntimeError(
                "reset-permit-build-mismatch:"
                f"{observed_id}:{bound_id}:caps={observed_caps}"
            )
    return bundle


def authorize_reset(store: Store) -> dict[str, object]:
    with store.locked():
        latch = store.load_strict(store.latch)
        # B05: validate before trusting status — an unknown schema or
        # status, or an already-consumed permit, never authorizes.
        validate_latch(latch)
        if latch.get("status") != "captured":
            raise RuntimeError("reset-requires-captured-incident")
        if latch.get("reset_used"):
            raise RuntimeError("automatic-reset-already-consumed")
        verify_bundle(store, latch)
        # Only a qualifying trigger firing reaches reset authorization. The
        # verdict was recorded at capture; a missing verdict (pre-qualifier
        # latch) fails closed rather than inheriting trust.
        if latch.get("trigger_qualifying") is not True:
            raise RuntimeError(
                "reset-trigger-not-qualifying:"
                f"{latch.get('trigger_qualification_reason')}"
            )
        value = update_latch(
            store,
            {"captured"},
            {
                "status": "reset_authorized",
                "reset_used": True,
                "reset_authorized_utc": iso(),
            },
        )
        store.append_host_event("reset_authorized", incident_id=value.get("incident_id"))
        return value


def mark_recovering(store: Store) -> dict[str, object]:
    with store.locked():
        value = update_latch(
            store,
            {"reset_authorized"},
            {"status": "recovering", "recovery_started_utc": iso()},
        )
        store.append_host_event("recovery_started", incident_id=value.get("incident_id"))
        return value


def record_zdo_proof(store: Store, transaction: str) -> dict[str, object]:
    """Record real ZDO evidence: a permit_join response whose transaction
    matched the barrier's unique id with status ok.

    An outage-derived Boolean alone is never ZDO proof: only this recorded
    proof (fresh, mono-anchored, transaction-bound) lets recovery_result
    accept a zdo_ok claim. The mono anchor also fails closed across a host
    reboot, since the monotonic clock resets.
    """
    cleaned = str(transaction or "").strip()
    if not cleaned:
        raise RuntimeError("zdo-proof-transaction-required")
    with store.locked():
        value = update_latch(
            store,
            {"reset_authorized", "recovering"},
            {
                "zdo_proof": {
                    "transaction": cleaned,
                    "utc": iso(),
                    "mono": time.monotonic(),
                    # B09: proof is bound to the boot that observed it.
                    "boot_id": current_boot_id(),
                },
            },
        )
        store.append_host_event("zdo_proved", incident_id=value.get("incident_id"))
        return value


def query_zdo_proof(store: Store, transaction: str | None) -> dict[str, object]:
    """Read-only ZDO proof probe (R4-F02): report whether the latch's
    recorded proof verifies for the transaction, using the same
    zdo_proof_state check the recovery verdict applies — probe and verdict
    agree by construction. Never mutates: no latch write, no host event.
    An absent or unusable latch fails closed (proof_ok False) instead of
    raising, so the barrier's wait-timeout path can still reach its
    proof-gated terminal verdict."""
    cleaned = str(transaction or "").strip()
    with store.locked():
        try:
            latch = store.load_strict(store.latch)
        except RuntimeError as exc:
            return {
                "ok": True,
                "proof_ok": False,
                "transaction": cleaned,
                "detail": f"no-latch:{exc}",
            }
    proof_ok, detail = zdo_proof_state(latch, cleaned)
    return {
        "ok": True,
        "proof_ok": proof_ok,
        "transaction": cleaned,
        "detail": detail,
    }


def record_rts_used(store: Store) -> dict[str, object]:
    """Mark the single RTS reset consumed. A second call raises: the latch
    permits at most one RTS invocation per incident, so retries and
    duplicate automation runs cannot reset the coordinator twice."""
    with store.locked():
        latch = store.load_strict(store.latch)
        # B05: validate before consuming the single RTS permit — an
        # unknown schema or status never passes, even once.
        validate_latch(latch)
        if latch.get("rts_used"):
            raise RuntimeError("rts-already-used")
        value = update_latch(
            store,
            {"recovering"},
            {"rts_used": True, "rts_used_utc": iso()},
        )
        store.append_host_event("rts_used", incident_id=value.get("incident_id"))
        return value


def zdo_proof_state(latch: object, zdo_transaction: str | None) -> tuple[bool, str]:
    """Check the recorded ZDO proof: fresh, and transaction-bound when asked.

    Returns (proof_ok, proof_detail) where detail is one of ok / missing /
    stale / mismatch / rebooted. A negative mono age means the host
    rebooted after the proof was recorded: never accepted.
    """
    proof = latch.get("zdo_proof") if isinstance(latch, dict) else None
    if not isinstance(proof, dict):
        return False, "missing"
    try:
        mono = float(proof["mono"])
    except (KeyError, TypeError, ValueError):
        return False, "missing"
    age = time.monotonic() - mono
    if age != age:
        return False, "missing"
    if age < 0.0:
        return False, "rebooted"
    if age > ZDO_PROOF_MAX_AGE_S:
        return False, "stale"
    if zdo_transaction is not None and str(proof.get("transaction")) != str(zdo_transaction):
        return False, "mismatch"
    return True, "ok"


def recovery_result(
    store: Store, *, success: bool, normal_traffic: bool, zdo_ok: bool,
    zdo_transaction: str | None = None,
    failure_reason: str | None = None,
    failure_phase: str | None = None,
) -> dict[str, object]:
    with store.locked():
        latch = store.load_strict(store.latch)
        # B05: validate before reasoning about the latch — terminal
        # failures persist reason/phase only for valid incidents.
        validate_latch(latch)
        proof_ok, proof_detail = zdo_proof_state(latch, zdo_transaction)
        effective_zdo = bool(zdo_ok and proof_ok)
        if not success or not normal_traffic or not effective_zdo:
            # B08: automation gates report the failing phase explicitly;
            # direct CLI use keeps the derived reason and no phase. An
            # empty string means absent, matching the shell template's
            # default('') for unreported failures.
            if failure_reason:
                reason = failure_reason
            elif not success:
                reason = "verification-failed"
            elif not normal_traffic:
                reason = "no-normal-traffic"
            else:
                reason = "no-zdo-verification"
            failed: dict[str, object] = {
                "status": "failed",
                "recovery_failed_utc": iso(),
                "normal_traffic_observed": bool(normal_traffic),
                "zdo_verified": effective_zdo,
                "zdo_proof": proof_detail,
                "failure_reason": reason,
            }
            # Empty CLI defaults ("") mean absent, matching the shell
# template's default('') for unreported failures.
            if failure_phase:
                failed["failure_phase"] = failure_phase
            try:
                value = update_latch(
                    store,
                    {"reset_authorized", "recovering", "stabilizing"},
                    failed,
                )
            except OSError as exc:
                # R4-F05: the terminal verdict was determined but is not
                # durable — report that honestly instead of a bare I/O
                # error so the barrier log names the missing terminal
                # state (reason and phase included).
                raise RuntimeError(
                    f"recovery-result-unpersisted:{reason}:"
                    f"{failure_phase or ''}:{exc}"
                )
            try:
                store.append_host_event("recovery_failed", incident_id=value.get("incident_id"))
            except OSError:
                value = dict(value)
                value["recovery_event_unpersisted"] = True
            return value

        stable_after = utcnow() + dt.timedelta(seconds=STABILITY_WINDOW_SECONDS)
        now_mono = time.monotonic()
        proof = latch.get("zdo_proof") if isinstance(latch, dict) else None
        try:
            value = update_latch(
                store,
                {"reset_authorized", "recovering"},
                {
                    "status": "stabilizing",
                    "recovery_succeeded_utc": iso(),
                    "recovery_succeeded_mono": now_mono,
                    "normal_traffic_observed": True,
                    "zdo_verified": True,
                    # B09: the structured transaction-bound proof recorded by
                    # record_zdo_proof is preserved as-is; the check verdict
                    # rides alongside instead of replacing it with "ok".
                    "zdo_proof": proof if isinstance(proof, dict) else {},
                    "zdo_proof_check": proof_detail,
                    "zdo_transaction": zdo_transaction,
                    "stable_after_utc": iso(stable_after),
                    "stable_after_mono": now_mono + STABILITY_WINDOW_SECONDS,
                    # B09: the window is bound to this host boot; a rebooted
                    # host must fail closed even with greater uptime.
                    "boot_id": current_boot_id(),
                    "observations": [],
                },
            )
        except OSError as exc:
            # R4-F05: same honest-unpersisted contract as the failed path.
            raise RuntimeError(f"recovery-result-unpersisted:stabilizing:recovery:{exc}")
        try:
            store.append_host_event(
                "recovery_stabilizing",
                incident_id=value.get("incident_id"),
                stable_after_utc=value.get("stable_after_utc"),
            )
        except OSError:
            value = dict(value)
            value["recovery_event_unpersisted"] = True
        return value


def stability_observation(
    store: Store, *, bridge_up: bool, normal_traffic: bool, zdo_ok: bool
) -> dict[str, object]:
    with store.locked():
        latch = store.load_strict(store.latch)
        # B05: validate before touching observations.
        validate_latch(latch)
        if latch.get("status") != "stabilizing":
            raise RuntimeError("incident-not-stabilizing")
        observations = latch.get("observations")
        if not isinstance(observations, list):
            raise RuntimeError("stability-observations-corrupt")
        if len(observations) >= STABILITY_MAX_OBSERVATIONS:
            raise RuntimeError("stability-observations-full")
        now_mono = time.monotonic()
        anomaly = False
        if observations:
            try:
                last_mono = float(observations[-1].get("mono", 0.0))
            except (TypeError, ValueError):
                last_mono = 0.0
            if now_mono < last_mono:
                anomaly = True
        try:
            base_mono = float(latch.get("recovery_succeeded_mono", 0.0))
        except (TypeError, ValueError):
            base_mono = 0.0
        if now_mono < base_mono:
            anomaly = True
        proof = latch.get("zdo_proof") if isinstance(latch, dict) else None
        observations.append(
            {
                "utc": iso(),
                "mono": now_mono,
                "bridge_up": bool(bridge_up),
                "normal_traffic": bool(normal_traffic),
                "zdo_ok": bool(zdo_ok),
                # B09: each observation is bound to the incident's real
                # proof transaction and the boot that recorded it. The
                # per-tick zdo_ok is continuity evidence (no
                # counter-evidence since proof), never proof itself:
                # close still requires the recorded transaction proof.
                "zdo_transaction": proof.get("transaction") if isinstance(proof, dict) else None,
                "boot_id": current_boot_id(),
            }
        )
        update: dict[str, object] = {"observations": observations}
        if anomaly:
            update["clock_anomaly"] = True
        value = update_latch(store, {"stabilizing"}, update)
        return {"ok": True, "observations": len(observations), "clock_anomaly": anomaly,
                "incident_id": value.get("incident_id")}


def _fail_close(store: Store, reason: str) -> dict[str, object]:
    """Terminal close verdict: the window did not hold, persist why."""
    try:
        value = update_latch(
            store,
            {"stabilizing"},
            {
                "status": "failed",
                "recovery_failed_utc": iso(),
                "failure_reason": reason,
            },
        )
    except OSError as exc:
        # R4-F05: same honest-unpersisted contract as recovery_result.
        raise RuntimeError(f"recovery-result-unpersisted:{reason}:close:{exc}")
    try:
        store.append_host_event("stability_failed", incident_id=value.get("incident_id"))
    except OSError:
        value = dict(value)
        value["recovery_event_unpersisted"] = True
    return value


def close_if_stable(store: Store, *, bridge_up: bool, normal_traffic: bool) -> dict[str, object]:
    with store.locked():
        latch = store.load_strict(store.latch)
        # B05: validate before closing over the latch.
        validate_latch(latch)
        if latch.get("status") != "stabilizing":
            raise RuntimeError("incident-not-stabilizing")
        stable_after = parse_timestamp(str(latch.get("stable_after_utc", "")))
        if stable_after is None or utcnow() < stable_after:
            raise RuntimeError("stability-window-not-complete")
        observations = latch.get("observations")
        if not isinstance(observations, list):
            raise RuntimeError("stability-observations-corrupt")

        def fail(reason: str) -> dict[str, object]:
            return _fail_close(store, reason)

        # B09: the monotonic window must also be complete — a wall-clock
        # jump forward must not open the close gate early.
        try:
            base_mono = float(latch.get("recovery_succeeded_mono", 0.0))
            end_mono = float(latch.get("stable_after_mono", 0.0))
        except (TypeError, ValueError):
            return fail("stability-window-failed")
        now_mono = time.monotonic()
        if now_mono < end_mono:
            raise RuntimeError("stability-window-not-complete")
        # B09: wall and monotonic overshoot past the window end must agree;
        # a wall jump or suspend/resume skews the wall side only.
        now_utc = utcnow()
        skew_ok, _skew_detail = check_wall_skew(
            (now_utc - stable_after).total_seconds(), now_mono - end_mono
        )
        if not skew_ok:
            return fail("stability-clock-anomaly")
        # B09: the window, its proof, and every observation are bound to
        # one host boot. A rebooted host with greater uptime keeps
        # monotonic continuity, so only the boot id fails it closed.
        live_boot = current_boot_id()
        boot_ids: list[object] = [latch.get("boot_id")]
        proof = latch.get("zdo_proof") if isinstance(latch, dict) else None
        boot_ids.append(proof.get("boot_id") if isinstance(proof, dict) else None)
        for obs in observations:
            boot_ids.append(obs.get("boot_id") if isinstance(obs, dict) else None)
        boot_ok, _boot_detail = check_boot_continuity(boot_ids, live_boot)
        if not boot_ok:
            return fail("stability-boot-mismatch")

        if latch.get("clock_anomaly"):
            return fail("stability-clock-anomaly")
        if not bridge_up or not normal_traffic or not latch.get("normal_traffic_observed"):
            return fail("stability-window-failed")
        if not latch.get("zdo_verified"):
            return fail("stability-window-failed")
        points: list[tuple[float, bool, bool, bool]] = []
        for obs in observations:
            if not isinstance(obs, dict):
                return fail("stability-window-failed")
            # B09: every observation stays bound to the incident's proof
            # transaction; evidence from another incident never counts.
            if obs.get("zdo_transaction") != (proof.get("transaction") if isinstance(proof, dict) else None):
                return fail("stability-window-failed")
            try:
                points.append(
                    (
                        float(obs.get("mono", -1.0)),
                        bool(obs.get("bridge_up")),
                        bool(obs.get("normal_traffic")),
                        bool(obs.get("zdo_ok")),
                    )
                )
            except (TypeError, ValueError):
                return fail("stability-window-failed")
        points.sort()
        if any(m < base_mono for m, _, _, _ in points):
            return fail("stability-clock-anomaly")
        # B09: observations past the window (beyond the closing tick's
        # grace) are out-of-window evidence: fail closed, never silently
        # dropped or counted toward coverage.
        if any(m > end_mono + STABILITY_OBS_GRACE_S for m, _, _, _ in points):
            return fail("stability-out-of-window")
        # R4-F04: every recorded observation must hold bridge, traffic
        # AND continuity — a single false point in any half is
        # counterevidence, even when other points in that half are good.
        # (The per-half existence checks below remain as coverage rules.)
        if any(not (up and t and z) for _, up, t, z in points):
            return fail("stability-window-failed")
        edges = [base_mono] + [m for m, _, _, _ in points] + [end_mono]
        if any(b - a > STABILITY_MAX_GAP_SECONDS for a, b in zip(edges, edges[1:])):
            return fail("stability-coverage-gap")
        mid = (base_mono + end_mono) / 2.0
        # R4-F03: the midpoint observation belongs to both halves. A strict
        # split fails a healthy window whose recovery lands just after a
        # scheduler tick (first observation at ~mid, none strictly before)
        # based purely on phase; a midpoint point genuinely evidences both
        # sides' continuity. (Counterevidence still rejects via the
        # all-must-hold rule above, not via coverage.)
        first_half = [p for p in points if p[0] <= mid]
        second_half = [p for p in points if p[0] >= mid]
        if not any(t and z for _, _, t, z in first_half):
            return fail("stability-no-traffic-first-half")
        if not any(t and z for _, _, t, z in second_half):
            return fail("stability-no-traffic-second-half")
        value = update_latch(store, {"stabilizing"}, {"status": "closed", "closed_utc": iso()})
        store.append_host_event("incident_closed", incident_id=value.get("incident_id"))
        return value


def manual_clear(store: Store, reason: str, *, force: bool = False) -> dict[str, object]:
    with store.locked():
        try:
            value = store.load_strict(store.latch)
            latch_present = True
        except RuntimeError as exc:
            if str(exc).startswith("state-missing:"):
                value = {}
                latch_present = False
            elif not force:
                raise
            else:
                # --force is the explicit audited repair path for corrupt
                # bytes too (not only missing state): discard the
                # unparseable value, record the forced repair, and write a
                # fresh cleared latch below.
                store.append_host_event(
                    "incident_manual_clear_forced", reason=reason
                )
                value = {}
                latch_present = False
        if latch_present:
            if not force:
                # B05: without --force, an existing latch must validate —
                # unknown schema/status or inconsistent permit refuses,
                # never gets repaired over. R4-F06: every present value is
                # validated, falsy JSON included — corrupt bytes are never
                # silently repaired over. --force stays the explicit
                # manual-repair path and records itself.
                validate_latch(value)
            else:
                try:
                    validate_latch(value)
                except RuntimeError:
                    store.append_host_event(
                        "incident_manual_clear_forced", reason=reason
                    )
                    value = {}
        else:
            value = {}
        if not isinstance(value, dict):
            raise RuntimeError("incident-latch-corrupt:not-an-object")
        # The cleared latch keeps the schema so the tool's own gate
        # accepts the state its repair path wrote: a schema-less latch
        # would brick the next capture with incident-latch-corrupt.
        # R4-F06: the cleared state carries an explicit boolean permit
        # (unused), so the validator's explicit-permit rule accepts the
        # state the repair path wrote.
        value.update(
            {
                "schema": LATCH_SCHEMA,
                "status": "cleared",
                "reset_used": False,
                "manual_clear_reason": reason,
                "manual_clear_utc": iso(),
            }
        )
        store.atomic_json(store.latch, value)
        store.append_host_event("incident_manual_clear", reason=reason)
        return value


#: Roles allowed to satisfy --require-firmware-binding. Anything else
#: (candidate builds, test fixtures) binds for bookkeeping but never
#: authorizes capture: only the deployed image gates the barrier.
BINDING_AUTHORIZED_ROLES = ("deployed",)


def bound_firmware(store: Store) -> dict[str, object] | None:
    """Return the bound firmware record, or None when unusable.

    The recorded SHA is re-hashed against the artifact on disk: an image
    swapped or modified after binding fails closed here, never silently.
    """
    value = store.load(store.firmware, {})
    if not isinstance(value, dict):
        return None
    sha = value.get("sha256")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
        return None
    path = Path(str(value.get("path", "")))
    try:
        if not path.is_file() or sha256_file(path) != sha.lower():
            return None
    except OSError:
        return None
    return value


def firmware_hash(store: Store) -> str | None:
    bound = bound_firmware(store)
    if bound is None:
        return None
    return str(bound["sha256"]).lower()


def bind_firmware(
    store: Store,
    artifact: Path,
    *,
    role: str,
    variant: str,
    manifest: Path,
    build_id: int,
) -> dict[str, object]:
    """Bind an image as an explicit operator declaration.

    B12: binding is not a file hash alone — the operator declares the
    image variant, the expected wire build ID, and the build manifest
    the image was verified against (variant match, 40-hex repository
    commit, and the artifact's own digest listed in the manifest). The
    recorded binding therefore distinguishes the declared image from
    the observed runtime identity and from any flashing proof; a
    candidate/test/default role never authorizes operational capture.
    """
    with store.locked():
        if not artifact.is_file():
            raise RuntimeError(f"firmware-artifact-missing:{artifact}")
        size = artifact.stat().st_size
        if size == 0:
            raise RuntimeError(f"firmware-artifact-empty:{artifact}")
        if not variant or not variant.strip():
            raise RuntimeError("firmware-bind-variant-required")
        if isinstance(build_id, bool) or not isinstance(build_id, int):
            raise RuntimeError("firmware-bind-build-id-required")
        # R4-F11: the wire build id is an unsigned 32-bit field. An
        # out-of-range declaration can never match observed identity, so
        # binding it would manufacture a permanently-mismatched binding.
        if not 0 <= build_id <= 0xFFFFFFFF:
            raise RuntimeError(f"firmware-bind-build-id-range:{build_id}")
        if manifest is None:
            raise RuntimeError("firmware-bind-manifest-required")
        try:
            manifest_text = manifest.read_bytes()
            manifest_doc = json.loads(manifest_text.decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"firmware-bind-manifest-unreadable:{exc}")
        if not isinstance(manifest_doc, dict):
            raise RuntimeError("firmware-bind-manifest-not-an-object")
        if manifest_doc.get("variant") != variant:
            raise RuntimeError(
                f"firmware-bind-variant-mismatch:{manifest_doc.get('variant')}:{variant}"
            )
        commit = manifest_doc.get("repository_commit")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            raise RuntimeError("firmware-bind-manifest-commit-invalid")
        artifacts = manifest_doc.get("artifacts")
        if not isinstance(artifacts, dict):
            raise RuntimeError("firmware-bind-manifest-artifacts-invalid")
        image_sha = sha256_file(artifact)
        listed = {
            str(entry.get("sha256", "")).lower()
            for entry in artifacts.values()
            if isinstance(entry, dict)
        }
        if image_sha.lower() not in listed:
            raise RuntimeError("firmware-bind-artifact-not-in-manifest")
        value = {
            "schema": 1,
            "sha256": image_sha,
            "bytes": size,
            "path": str(artifact),
            "role": role,
            "variant": variant,
            "build_id": build_id,
            "manifest_sha256": hashlib.sha256(manifest_text).hexdigest(),
            "manifest_path": str(manifest),
            "repository_commit": commit.lower(),
            "bound_utc": iso(),
        }
        store.atomic_json(store.firmware, value)
        return {"ok": True, **value}


def bool_arg(value: str) -> bool:
    value = value.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError("expected true/false")


def common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(os.environ.get("T832_INCIDENT_ROOT", "/config/.private/t832-diag")),
    )
    parser.add_argument("--source", action="append", dest="sources")
    parser.add_argument("--config-fingerprint")
    parser.add_argument("--initial-tail-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--retain-days", type=int, default=7)
    parser.add_argument("--max-bytes", type=int, default=1 << 30)
    parser.add_argument("--max-collect-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--max-window-rows", type=int, default=20000)
    parser.add_argument("--max-host-events-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--max-store-bytes", type=int, default=2 * 1024 * 1024 * 1024)
    parser.add_argument("--max-rotated-logs", type=int, default=32)


def main() -> int:
    ap = argparse.ArgumentParser()
    common_args(ap)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("collect")
    cap = sub.add_parser("capture")
    cap.add_argument("--trigger", required=True)
    cap.add_argument("--triggers", type=Path, default=None)
    cap.add_argument("--trigger-topic", default=None)
    cap.add_argument("--trigger-payload", default=None)
    cap.add_argument("--window-seconds", type=int, default=15 * 60)
    cap.add_argument("--deadline-seconds", type=int, default=30)
    cap.add_argument("--require-firmware-binding", action="store_true")
    sub.add_parser("authorize-reset")
    sub.add_parser("mark-recovering")
    proof = sub.add_parser("record-zdo-proof")
    proof.add_argument("--transaction", required=True)
    # R4-F02: read-only late-proof probe for the wait-timeout path: reports
    # whether recorded proof verifies for the transaction without mutating
    # anything, so a missed wait can still reach the proof-gated verdict.
    probe = sub.add_parser("zdo-proof-state")
    probe.add_argument("--transaction", default="")
    sub.add_parser("record-rts-used")
    rr = sub.add_parser("recovery-result")
    rr.add_argument("--success", type=bool_arg, required=True)
    rr.add_argument("--normal-traffic", type=bool_arg, required=True)
    rr.add_argument("--zdo-ok", type=bool_arg, default=False)
    rr.add_argument("--zdo-transaction", default=None)
    rr.add_argument("--failure-reason", default=None)
    rr.add_argument("--failure-phase", default=None)
    obs = sub.add_parser("stability-observation")
    obs.add_argument("--bridge-up", type=bool_arg, required=True)
    obs.add_argument("--normal-traffic", type=bool_arg, required=True)
    obs.add_argument("--zdo-ok", type=bool_arg, required=True)
    close = sub.add_parser("close-if-stable")
    close.add_argument("--bridge-up", type=bool_arg, required=True)
    close.add_argument("--normal-traffic", type=bool_arg, required=True)
    clear = sub.add_parser("manual-clear")
    clear.add_argument("--reason", required=True)
    clear.add_argument("--force", action="store_true")
    bind = sub.add_parser("bind-firmware")
    bind.add_argument("--artifact", type=Path, required=True)
    bind.add_argument(
        "--role",
        default="candidate",
        help="Binding role. Only an explicit --role deployed (with variant, manifest"
        " and build-id) can authorize operational capture; the default binds for"
        " bookkeeping only.",
    )
    bind.add_argument("--variant", default=None)
    bind.add_argument("--manifest", type=Path, default=None)
    bind.add_argument("--build-id", type=lambda v: int(v, 0), default=None)
    evt = sub.add_parser("host-event")
    evt.add_argument("--kind", required=True)
    evt.add_argument("--detail", default="")
    sub.add_parser("status")
    args = ap.parse_args()

    store = Store(args.root)
    sources = args.sources or DEFAULT_SOURCES
    try:
        if args.command == "collect":
            result = collect(
                store,
                sources,
                config_fingerprint=args.config_fingerprint,
                initial_tail_bytes=args.initial_tail_bytes,
                retain_days=args.retain_days,
                max_bytes=args.max_bytes,
                max_collect_bytes=args.max_collect_bytes,
                max_host_events_bytes=args.max_host_events_bytes,
                max_store_bytes=args.max_store_bytes,
                max_rotated_logs=args.max_rotated_logs,
            )
        elif args.command == "capture":
            result = capture(
                store,
                args.trigger,
                sources=sources,
                config_fingerprint=args.config_fingerprint,
                initial_tail_bytes=args.initial_tail_bytes,
                retain_days=args.retain_days,
                max_bytes=args.max_bytes,
                window_seconds=args.window_seconds,
                deadline_seconds=args.deadline_seconds,
                max_collect_bytes=args.max_collect_bytes,
                max_window_rows=args.max_window_rows,
                max_host_events_bytes=args.max_host_events_bytes,
                max_store_bytes=args.max_store_bytes,
                max_rotated_logs=args.max_rotated_logs,
                require_firmware_binding=args.require_firmware_binding,
                triggers_path=args.triggers,
                trigger_topic=args.trigger_topic,
                trigger_payload=args.trigger_payload,
            )
        elif args.command == "authorize-reset":
            result = authorize_reset(store)
        elif args.command == "mark-recovering":
            result = mark_recovering(store)
        elif args.command == "record-zdo-proof":
            result = record_zdo_proof(store, args.transaction)
        elif args.command == "zdo-proof-state":
            result = query_zdo_proof(store, args.transaction)
        elif args.command == "record-rts-used":
            result = record_rts_used(store)
        elif args.command == "recovery-result":
            result = recovery_result(
                store,
                success=args.success,
                normal_traffic=args.normal_traffic,
                zdo_ok=args.zdo_ok,
                zdo_transaction=args.zdo_transaction,
                failure_reason=args.failure_reason,
                failure_phase=args.failure_phase,
            )
        elif args.command == "stability-observation":
            result = stability_observation(
                store,
                bridge_up=args.bridge_up,
                normal_traffic=args.normal_traffic,
                zdo_ok=args.zdo_ok,
            )
        elif args.command == "close-if-stable":
            result = close_if_stable(
                store,
                bridge_up=args.bridge_up,
                normal_traffic=args.normal_traffic,
            )
        elif args.command == "manual-clear":
            result = manual_clear(store, args.reason, force=args.force)
        elif args.command == "bind-firmware":
            result = bind_firmware(
                store,
                args.artifact,
                role=args.role,
                variant=args.variant,
                manifest=args.manifest,
                build_id=args.build_id,
            )
        elif args.command == "host-event":
            with store.locked():
                store.append_host_event(args.kind, detail=args.detail)
            result = {"ok": True, "kind": args.kind, "utc": iso()}
        else:
            result = store.load(store.latch, {"status": "none"})
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": f"{type(exc).__name__}:{exc}",
                    "command": args.command,
                    "utc": iso(),
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
