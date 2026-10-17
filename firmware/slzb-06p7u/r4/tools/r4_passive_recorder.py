"""R4 passive host forensic recorder -- OFFLINE LIBRARY ONLY, not installed.

Only a future source-verified, in-process Z2M/herdsman integration may feed
normalized, strictly allowlisted metadata to offer(). The ingest path does
no filesystem/network/MT work and does NOT open serial, MQTT, USB or Zigbee.
No device addresses, raw log lines, payloads or key material are accepted.
"""
from collections import deque
import json
import math
import os
import tempfile
from pathlib import Path

from r4_diag_reference import classify_host_observation

EVENT_KINDS = frozenset((
    "AF_SREQ_TIMEOUT", "ZDO_SREQ_TIMEOUT", "SYS_SREQ_TIMEOUT",
    "ZCL_TIMEOUT", "HOST_SIGTERM", "USB_DISCONNECTED", "OTA_START",
    "OTA_STOP", "DIAG_F0_RESPONSIVE",
))
WAITER_KINDS = frozenset(("AF_SREQ_TIMEOUT", "ZDO_SREQ_TIMEOUT", "SYS_SREQ_TIMEOUT"))
WINDOW_MS = 120_000


def _int(value, label):
    if type(value) is not int or value < 0 or value > 9_007_199_254_740_991:
        raise ValueError("%s must be an unsigned safe integer" % label)
    return value


def normalize(event):
    """Strictly copy only non-identifying fields before touching queues.

    A future hook must allocate a fresh per-host-process numeric request
    ID for each unique SREQ waiter. A node NWK/IEEE address is NEVER an ID.
    """
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")
    kind = event.get("kind")
    if type(kind) is not str or kind not in EVENT_KINDS:
        raise ValueError("unsupported event kind")
    allowed = {"kind", "at_ms", "waiter_id"} if kind in WAITER_KINDS else {"kind", "at_ms"}
    if set(event) != allowed:
        raise ValueError("extra/missing fields forbidden (never accept raw payloads)")
    at = _int(event["at_ms"], "at_ms")
    if kind in WAITER_KINDS:
        waiter = _int(event["waiter_id"], "waiter_id")
        return (at, kind, waiter)
    return (at, kind, None)


class PassiveR4Recorder:
    """Fail-closed, finite synthetic recorder.

    offer() is O(1) and never performs disk I/O. drain() is performed by a
    distinct, lower priority host worker in a future owner integration.
    Both methods have one caller/owner per instance; threading safety
    and a verified nonblocking in-process callback are integration gates.
    """

    def __init__(self, *, process_generation, max_pending=128, max_history=256,
                 retention_ms=86_400_000):
        self.process_generation = _int(process_generation, "process_generation")
        self.max_pending = _int(max_pending, "max_pending")
        self.max_history = _int(max_history, "max_history")
        self.retention_ms = _int(retention_ms, "retention_ms")
        if not self.max_pending or not self.max_history or self.retention_ms < WINDOW_MS:
            raise ValueError("invalid recorder bounds")
        if self.max_pending > 4096 or self.max_history > 4096:
            raise ValueError("recorder bounds exceed reviewed maximum")
        self.pending = deque()
        self.history = deque(maxlen=self.max_history)
        self.waiters = set()
        self.window_events = deque(maxlen=self.max_history)
        self.dropped = 0
        self.last_time = None
        self.ota = False
        self.sigterm = False
        self.usb_disconnected = False
        self.last_good = None

    def offer(self, event):
        """Entry point for already-normalized events; bounded no-I/O enqueue."""
        record = normalize(event)
        if len(self.pending) >= self.max_pending:
            self.dropped += 1
            return False
        self.pending.append(record)
        return True

    def drain(self, limit=None):
        """Bounded worker step. No serial/adapter interactions."""
        if limit is None:
            limit = min(128, self.max_pending)
        if type(limit) is not int or not 1 <= limit <= self.max_pending:
            raise ValueError("bad drain limit")
        count = 0
        while self.pending and count < limit:
            self._consume(self.pending.popleft())
            count += 1
        return count

    def _consume(self, record):
        at, kind, waiter_id = record
        if self.last_time is not None and at < self.last_time:
            self.dropped += 1  # out-of-order clocks cannot create fake bursts
            return
        if self.last_time is not None and at - self.last_time > self.retention_ms:
            self.waiters.clear()  # avoid indefinite unbounded IDs
        self.last_time = at
        expire = at - WINDOW_MS
        while self.window_events and self.window_events[0][0] < expire:
            self.window_events.popleft()
        if kind in WAITER_KINDS:
            key = (kind, waiter_id)
            if key in self.waiters:
                self.dropped += 1  # duplicate waiter completion is not a new timeout
                return
            self.waiters.add(key)
            if len(self.waiters) > self.max_history * 16:
                # Fail closed: no new burst conclusions from a truncated identity set.
                self.waiters.clear()
                self.window_events.clear()
                self.dropped += 1
                return
        self.history.append({"at_ms": at, "kind": kind})  # never persist waiter ID
        while self.history and self.history[0]["at_ms"] < at - self.retention_ms:
            self.history.popleft()
        self.window_events.append((at, kind))
        if kind == "OTA_START":
            self.ota = True
        elif kind == "OTA_STOP":
            self.ota = False
        elif kind == "HOST_SIGTERM":
            self.sigterm = True
        elif kind == "USB_DISCONNECTED":
            self.usb_disconnected = True
        self.last_good = self.snapshot()

    def snapshot(self):
        """Finite sanitized numeric/event metadata; no raw event payloads."""
        af = sum(kind == "AF_SREQ_TIMEOUT" for _, kind in self.window_events)
        zdo = sum(kind == "ZDO_SREQ_TIMEOUT" for _, kind in self.window_events)
        sys = sum(kind == "SYS_SREQ_TIMEOUT" for _, kind in self.window_events)
        f0 = any(kind == "DIAG_F0_RESPONSIVE" for _, kind in self.window_events)
        zcl = sum(kind == "ZCL_TIMEOUT" for _, kind in self.window_events)
        signals = classify_host_observation(
            af_sreq_timeouts=af, zdo_sreq_timeouts=zdo,
            sys_sreq_timeouts=sys, zcl_timeouts=zcl, window_seconds=WINDOW_MS / 1000,
            sigterm=self.sigterm, usb_disconnected=self.usb_disconnected,
            ota_overlap=self.ota,
        )
        if f0:
            signals["signals"].append("F0_RESPONSIVE_OBSERVED")
        return {
            "schema": "r4-offline-host-observation-v1",
            "process_generation": self.process_generation,
            "recent_events": list(self.history),
            "last_at_ms": self.last_time,
            "window_ms": WINDOW_MS,
            "af_sreq_timeouts": af,
            "zdo_sreq_timeouts": zdo,
            "sys_sreq_timeouts": sys,
            "zcl_timeouts": zcl,
            "dropped": self.dropped,
            "signals": signals["signals"],
            "root_cause": "UNDETERMINED",
            "ota_temporal_overlap": self.ota,
            "ota_causal": False,
            "radio_boot_identity": "UNKNOWN",
            "source": "SYNTHETIC_REFERENCE_MODEL",
        }

    def persist(self, path, *, max_bytes=32_768):
        """Worker only: replace bounded sanitized last-good snapshot atomically.

        A failed replace preserves the prior snapshot. No log files, tokens,
        network identifiers or queue IDs are serialized. Directory must
        already exist; does not create or deploy any HA path.
        """
        target = Path(path)
        if target.is_symlink() or target.parent.is_symlink():
            raise ValueError("symlink target refused")
        if not target.parent.is_dir():
            raise ValueError("parent must preexist")
        if type(max_bytes) is not int or not 1024 <= max_bytes <= 1_048_576:
            raise ValueError("invalid bounded size")
        # last_good is a cache of the last accepted event; drop-only
        # paths (duplicate, out-of-order, queue overflow) update the
        # live dropped counter without refreshing it. Persist current
        # sanitized counters, never raw events or waiter identities.
        snapshot = self.snapshot()
        snapshot = dict(snapshot)
        snapshot["recent_events"] = list(snapshot["recent_events"])
        frame = json.dumps(snapshot, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")
        while len(frame) > max_bytes and snapshot["recent_events"]:
            snapshot["recent_events"].pop(0)  # discard oldest only
            frame = json.dumps(snapshot, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")
        if len(frame) > max_bytes:
            raise ValueError("snapshot size cap exceeded")
        # mkstemp uses exclusive random-name creation, avoiding a predictable
        # .pending symlink/hardlink race. Never open a user-controlled temp
        # filename with O_TRUNC in a recorder worker.
        fd, temp_name = tempfile.mkstemp(prefix=target.name + ".pending-",
                                         dir=target.parent)
        tmp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(frame)
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, target)
            # Rename is not a durability barrier on POSIX. If the parent
            # directory cannot be fsynced, report failure, not success.
            if os.name == "posix":
                fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        return len(frame)

    @staticmethod
    def read_last_good(path):
        """Read only the allowlisted snapshot schema; never execute stored data."""
        target = Path(path)
        if target.is_symlink() or target.parent.is_symlink():
            raise ValueError("symlink snapshot refused")
        # Never read an unbounded or malicious persisted JSON blob.
        # O_NOFOLLOW closes the TOCTOU gap after the initial symlink check
        # for the last path component. Keep all recovered input bounded.
        flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0) if os.name == "posix" else 0)
        fd = os.open(target, flags)
        with os.fdopen(fd, "rb") as src:
            raw = src.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("snapshot file exceeds maximum supported size")
        obj = json.loads(raw.decode("utf-8"))
        if (not isinstance(obj, dict) or obj.get("schema") != "r4-offline-host-observation-v1"
                or obj.get("root_cause") != "UNDETERMINED"
                or obj.get("source") != "SYNTHETIC_REFERENCE_MODEL"
                or obj.get("radio_boot_identity") != "UNKNOWN"):
            raise ValueError("untrusted snapshot schema")
        expected = {
            "schema", "process_generation", "last_at_ms", "window_ms", "recent_events",
            "af_sreq_timeouts", "zdo_sreq_timeouts", "sys_sreq_timeouts", "zcl_timeouts", "dropped",
            "signals", "root_cause", "ota_temporal_overlap", "ota_causal",
            "radio_boot_identity", "source",
        }
        if set(obj) != expected:
            raise ValueError("untrusted snapshot fields")
        if (not isinstance(obj["recent_events"], list) or len(obj["recent_events"]) > 4096
                or any(not isinstance(e, dict) or set(e) != {"at_ms", "kind"}
                       or type(e["kind"]) is not str or e["kind"] not in EVENT_KINDS
                       or type(e["at_ms"]) is not int or e["at_ms"] < 0
                       for e in obj["recent_events"])):
            raise ValueError("untrusted history")
        if (not isinstance(obj["signals"], list)
                or len(obj["signals"]) > 7
                or any(s not in (
                    "AF_SREQ_TIMEOUT_BURST_OBSERVED", "ZDO_SREQ_TIMEOUT_OBSERVED",
                    "ZCL_TIMEOUT_OBSERVED", "SYS_SREQ_TIMEOUT_OBSERVED",
                    "F0_RESPONSIVE_OBSERVED", "HOST_SIGTERM_OBSERVED",
                    "USB_DISCONNECTED_OBSERVED", "NO_MATCHING_HOST_SYMPTOM"
                ) for s in obj["signals"])):
            raise ValueError("untrusted signals")
        if (type(obj["ota_temporal_overlap"]) is not bool
                or obj["ota_causal"] is not False):
            raise ValueError("untrusted boolean state")
        for field in ("process_generation", "window_ms", "af_sreq_timeouts",
                      "zdo_sreq_timeouts", "sys_sreq_timeouts", "zcl_timeouts", "dropped"):
            _int(obj[field], field)
        if obj["last_at_ms"] is not None:
            _int(obj["last_at_ms"], "last_at_ms")
        if obj["window_ms"] != WINDOW_MS:
            raise ValueError("unexpected window")
        # A forged large integer, reordered history or time beyond the
        # last accepted event must not be treated as recovered evidence.
        previous = None
        for event in obj["recent_events"]:
            _int(event["at_ms"], "event.at_ms")
            if previous is not None and event["at_ms"] < previous:
                raise ValueError("snapshot history clock reversed")
            if obj["last_at_ms"] is None or event["at_ms"] > obj["last_at_ms"]:
                raise ValueError("history exceeds last event")
            previous = event["at_ms"]
        if obj["last_at_ms"] is None and obj["recent_events"]:
            raise ValueError("history without timestamp")
        if len(set(obj["signals"])) != len(obj["signals"]):
            raise ValueError("duplicate classification signal")
        return obj
