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


NATIVE_ROOT = Path("/homeassistant/zigbee2mqtt/p7u-b4-diagnostics")
_NATIVE_COUNTERS = ("srspDepth", "srspHighWater", "asyncDepth", "asyncHighWater", "srspEnqueued", "uartTxFinishedEvents")
_TIMEOUT_KINDS = frozenset(("AF_SREQ_TIMEOUT", "ZDO_SREQ_TIMEOUT", "SYS_SREQ_TIMEOUT", "UTIL_SREQ_TIMEOUT"))


def _native_require(ok, reason):
    if not ok:
        raise ValueError("NATIVE_V2_" + reason)


def _native_bytes(path, limit):
    _native_require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit, "FILE_UNSAFE")
    raw = path.read_bytes()
    _native_require(len(raw) <= limit, "FILE_OVERSIZED")
    return raw


def committed_native_summary(root: Path, observed: dict, now: int) -> dict:
    """Read-only bounded freeze; legacy v1 last-good is never current evidence.

    The pointer and manifest must stay byte-identical across this read. A live
    append or rotation race is UNAVAILABLE, never an excuse to select an orphan.
    Native source/boot identity are advisory, never hardware attestation.
    """
    try:
        _native_require(root.is_dir() and not root.is_symlink(), "NO_COMMITTED_WORKER_V2")
        pending = root / ".current-v2.pending"
        _native_require(not pending.exists() and not pending.is_symlink(), "UNCOMMITTED_POINTER")
        pointer = root / "current-v2.json"
        before = None
        active = root
        if pointer.exists() or pointer.is_symlink():
            before = _native_bytes(pointer, 4096)
            selected = json.loads(before)
            name = selected.get("active")
            _native_require(selected.get("schema") == "p7u-f2-pointer-v1" and isinstance(name, str) and
                            re.fullmatch(r"generation-[a-f0-9-]{36}", name) is not None, "POINTER_INVALID")
            active = root / name
            _native_require(active.is_dir() and not active.is_symlink(), "GENERATION_UNSAFE")
        md = active / "manifest-v2.json"
        manifest_raw = _native_bytes(md, 4096)
        manifest = json.loads(manifest_raw)
        raw = _native_bytes(active / "events-v2.jsonl", 4 * 1024 * 1024)
        _native_require(manifest.get("schema") == "p7u-f2-worker-v2" and
                        manifest.get("committedBytes") == len(raw) and (not raw or raw.endswith(b"\n")), "UNCOMMITTED_LOG")
        previous = "0" * 64
        rows = []
        for number, line in enumerate(raw.splitlines(), 1):
            frame = json.loads(line)
            data = frame.get("data")
            _native_require(type(data) is dict and frame.get("seq") == number and frame.get("previous") == previous,
                            "CHAIN_INVALID")
            body = {"seq": number, "previous": previous, "data": data}
            current = hashlib.sha256(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
            _native_require(frame.get("sha") == current, "HASH_INVALID")
            rows.append(data)
            previous = current
        _native_require(len(rows) <= 4096 and manifest.get("sequence") == len(rows) and manifest.get("head") == previous,
                        "MANIFEST_INVALID")
        last_valid = next((i for i in range(len(rows), 0, -1) if rows[i-1].get("kind") == "VALID"), None)
        _native_require(manifest.get("lastValidSeq") == last_valid and manifest.get("lastValidHostRun") ==
                        (rows[last_valid-1].get("hostRunId") if last_valid else None), "LAST_GOOD_POINTER_INVALID")
        _native_require(_native_bytes(md, 4096) == manifest_raw and
                        ((before is None and not pointer.exists() and not pointer.is_symlink()) or
                         (before is not None and _native_bytes(pointer, 4096) == before)) and
                        not pending.exists() and not pending.is_symlink(), "CHANGED_DURING_READ")
        owner = ((rows[-1].get("hostRunId"), rows[-1].get("ownerGeneration")) if rows else (None, None))
        current_rows = [r for r in rows if (r.get("hostRunId"), r.get("ownerGeneration")) == owner]
        good = next((r for r in reversed(current_rows) if r.get("kind") == "VALID" and
                     type(r.get("utc")) is int and now * 1000 - HISTORY_SECONDS * 1000 <= r["utc"] <= now * 1000 + 2000), None)
        last_good = None
        if good is not None:
            mask = good.get("validityMask")
            _native_require(type(mask) is int and mask in (0x2c, 0x3f) and good.get("abi") == 4, "COUNTER_SCHEMA_INVALID")
            last_good = {k: good.get(k) for k in ("utc", "abi", "sequence", "validityMask", "hostRunId", "ownerGeneration")}
            for bit, key in enumerate(_NATIVE_COUNTERS):
                value = good.get(key)
                last_good[key] = value if mask & (1 << bit) and type(value) is int and 0 <= value <= 0xffffffff else None
            last_good["age_ms"] = max(0, now * 1000 - good["utc"])
            epoch = observed.get("epoch_start_utc")
            last_good["matches_observed_process_start"] = good["utc"] >= epoch * 1000 if type(epoch) in (int, float) and epoch > 0 else None
        failures = []
        for row in current_rows:
            if row.get("kind") == "FAILED" and row.get("hostTimeoutKind") in _TIMEOUT_KINDS:
                failures.append({k: row.get(k) for k in ("utc", "hostTimeoutKind", "hostTimeoutAtMs", "hostTimeoutDropped")})
        return {"schema": "p7u-frozen-worker-v2-advisory-v1", "status": "VERIFIED_COMMITTED_HISTORY",
                "history_head": previous, "history_records": len(rows), "last_good": last_good,
                "host_timeouts": failures[-4:], "radio_epoch": "UNKNOWN", "hardware_source_attestation": "UNPROVEN"}
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        reason = str(exc) if type(exc) is ValueError and str(exc).startswith("NATIVE_V2_") else "NATIVE_V2_UNAVAILABLE_OR_INVALID"
        return {"status": "UNAVAILABLE", "reason": reason, "radio_epoch": "UNKNOWN"}


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
            if len(old) > MAX_ROWS or any(not isinstance(x, dict) or
                    type(x.get("utc")) is not int for x in old):
                raise ValueError("INVALID_HISTORY_ROWS")
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
        # Freeze only verified worker-v2 data, never the preserved retired v1
        # last-good.json. No reader opens serial or promotes an orphaned log.
        native_summary = committed_native_summary(NATIVE_ROOT, summary, int(time.time()))
        atomic_json(self.root/(name+".json"),{
            "schema":"p7u-passive-evidence-v1",
            "created_utc":int(time.time()),
            "summary":redacted, "host":_logs(self.supervisor,self.slug),
            "native_last_good_advisory":None,
            "native_worker_v2_advisory":native_summary})
        # Only first-error captures are retired; retain exclusive intent
        # markers to prevent crash/restart duplicate captures.
        if name.startswith("first-error-"):
            saved = sorted(self.root.glob("first-error-*.json"),
                           key=lambda p: p.stat().st_mtime, reverse=True)
            for path in saved[64:]:
                if path.is_file() and not path.is_symlink():
                    path.unlink()
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
