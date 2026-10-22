"""Bounded, passive, durable health history and one-shot incident evidence.

Never opens a serial port, publishes Zigbee commands or controls hardware.
A failed/ambiguous evidence write stays marked and is NOT retried under
a different incident identity. Logs and native summaries remain private.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
from persistence import atomic_json

MAX_ROWS = 2048
MAX_BYTES = 16 * 1024 * 1024
HISTORY_SECONDS = 24 * 3600
MAX_LOG_BYTES = 32768
SAFE_FIELDS = ("utc", "epoch_id", "epoch_start_utc", "phase",
    "observation_valid", "rx_valid", "mqtt_reachable", "srsp_120s",
    "affected_devices_120s", "fresh_device_topics_120s", "ota_active",
    "ota_unknown", "resets_enabled")
_RELEVANT = re.compile(r"SRSP|timeout|timed out|BUFFER_FULL|adapter|error|failed", re.I)
_SECRET = re.compile(r"(?i)(?:0x)?[0-9a-f]{16}|\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")


def _directory(path: Path):
    if not path.is_dir() or path.is_symlink():
        raise ValueError("PRIVATE_EVIDENCE_DIRECTORY_INVALID")


def _intent_once(directory: Path, name: str) -> bool:
    _directory(directory)
    if not re.fullmatch(r"[a-z0-9-]{8,96}", name):
        raise ValueError("BAD_EVIDENCE_NAME")
    path = directory / (name + ".intent.json")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"schema":"p7u-evidence-intent-v1", "name":name,
                   "created_utc":int(time.time())},f)
        f.flush()
        os.fsync(f.fileno())
    if os.name == "posix":
        directory_fd = os.open(str(directory), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return True


def _logs(supervisor, slug: str) -> dict:
    try:
        _, tail = supervisor.log_window(slug)
        # Selected lines only, with identities redacted. The SHA lets a
        # private operator compare an independently preserved full log.
        raw = tail.encode("utf-8",errors="replace")
        selected = [_SECRET.sub("[redacted-id]", s)[:400]
                    for s in tail.splitlines() if _RELEVANT.search(s)]
        lines = []
        size = 0
        for s in reversed(selected):
            size += len(s.encode("utf-8"))
            if size > MAX_LOG_BYTES:
                break
            lines.append(s)
        return {"tail_sha256": hashlib.sha256(raw).hexdigest(),
                "relevant_lines": list(reversed(lines)),
                "truncated":len(lines) < len(selected)}
    except Exception as exc:
        return {"unavailable":type(exc).__name__}


class PassiveForensics:
    def __init__(self, data: Path, supervisor, slug: str):
        self.root = data / "passive-forensics"
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _directory(self.root)
        self.history = self.root / "history.json"
        self.supervisor, self.slug = supervisor, slug

    def record(self, payload: dict):
        """Durably maintain <=24h, <=2048 rows, <=16MiB; freeze first error."""
        row = {k: payload.get(k) for k in SAFE_FIELDS}
        now = row["utc"]
        if type(now) is not int or now <= 0:
            raise ValueError("BAD_OBSERVATION_TIMESTAMP")
        old = []
        if self.history.exists():
            raw = self.history.read_bytes()
            if len(raw) > MAX_BYTES or self.history.is_symlink():
                raise ValueError("HISTORY_TOO_LARGE_OR_SYMLINK")
            doc = json.loads(raw)
            if doc.get("schema") != "p7u-passive-history-v1" or not isinstance(doc.get("rows"),list):
                raise ValueError("INVALID_HISTORY")
            old = doc["rows"]
        previous = old[-1] if old else None
        if previous and now < previous["utc"]:
            raise ValueError("BACKWARD_OBSERVATION_TIME")
        # A completed replacement always includes the newest observation.
        kept = [x for x in old if type(x.get("utc")) is int
                and now - HISTORY_SECONDS <= x["utc"] <= now]
        kept.append(row)
        kept = kept[-MAX_ROWS:]
        while len(json.dumps(kept, separators=(",",":")).encode()) > MAX_BYTES - 1024:
            kept.pop(0)
        atomic_json(self.history, {"schema":"p7u-passive-history-v1","rows":kept})
        if (previous is not None and previous.get("epoch_id") == row.get("epoch_id")
            and previous.get("srsp_120s") == 0 and type(row.get("srsp_120s")) is int
            and row["srsp_120s"] > 0):
            self.freeze("first-error-" + str(now), row)
        return len(kept)

    def freeze(self, name: str, summary: dict):
        """Exactly one filesystem intent precedes each bounded read-only freeze."""
        if not _intent_once(self.root,name):
            return False
        redacted = {k:summary.get(k) for k in SAFE_FIELDS}
        # Advisory only: no raw native frame, boot token or key is captured.
        native = self.root.parent / "r4-native-last-good.json"
        native_summary = None
        if native.is_file() and not native.is_symlink() and native.stat().st_size <= 4096:
            try:
                candidate = json.loads(native.read_text(encoding="utf-8"))
                native_summary = {k:candidate.get(k) for k in (
                    "utc","abi","sequence","validityMask",
                    "srspDepth","srspHighWater","uartTxFinishedEvents")}
            except (ValueError,OSError):
                native_summary = None
        atomic_json(self.root/(name+".json"),{
            "schema":"p7u-passive-evidence-v1",
            "created_utc":int(time.time()),
            "summary":redacted, "host":_logs(self.supervisor,self.slug),
            "native_last_good_advisory":native_summary})
        return True

    def incident(self, state, observation):
        name = "shadow-" + state.incident_id
        if not re.fullmatch(r"shadow-[a-f0-9]{32}",name):
            raise ValueError("MISSING_SHADOW_INCIDENT_ID")
        summary = {"utc":observation.utc,"phase":state.phase,
            "observation_valid":observation.observation_valid,
            "rx_valid":observation.rx_valid,
            "mqtt_reachable":observation.mqtt_reachable,
            "srsp_120s":observation.srsp_120s,
            "affected_devices_120s":observation.affected_devices_120s,
            "fresh_device_topics_120s":observation.fresh_device_topics_120s}
        return self.freeze(name,summary)
