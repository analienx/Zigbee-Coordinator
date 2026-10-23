#!/usr/bin/env python3
"""P7U lifecycle core: immutable owner identity, exclusive lock, fsynced log.

This module has NO adapter, Docker mutator, Supervisor mutator, or radio access.
It must be composed with an independently source-qualified HA manager and
reviewed privilege boundary before it can perform a production cutover.
"""
from __future__ import annotations
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

MAX_JOURNAL = 4 * 1024 * 1024
PHASES = frozenset({
    "PREFLIGHT", "STOP_INTENT", "STOP_ACK_UNKNOWN", "OWNER_ABSENT",
    "START_INTENT", "START_ACK_UNKNOWN", "OWNER_SERVING",
    "DB_APPROVED", "HOLD", "COMMITTED",
})
SHA = re.compile(r"^[0-9a-f]{64}$")
DOCKER_ID = re.compile(r"^[a-f0-9]{64}$")


class LifecycleHold(RuntimeError):
    """Ambiguous state requires inspection, not automatic recovery."""


def guard(test: bool, reason: str) -> None:
    if not test:
        raise LifecycleHold("P7U_HOLD_" + reason)


@dataclass(frozen=True)
class Owner:
    container_id: str
    pid: int
    started_at: str
    image_digest: str

    @classmethod
    def from_inspect(cls, result: dict[str, Any]) -> Owner:
        guard(type(result) is dict, "INSPECT_SHAPE")
        state = result.get("State")
        guard(type(state) is dict, "INSPECT_STATE")
        cid = result.get("Id")
        pid = state.get("Pid")
        started_at = state.get("StartedAt")
        image = result.get("Image")
        guard(isinstance(cid, str) and DOCKER_ID.fullmatch(cid) is not None, "IDENTITY_ID")
        guard(type(pid) is int and 1 < pid < 2**31, "IDENTITY_PID")
        guard(state.get("Running") is True, "NOT_RUNNING")
        guard(isinstance(started_at, str) and len(started_at) >= 20
              and started_at != "0001-01-01T00:00:00Z", "IDENTITY_START")
        guard(isinstance(image, str) and (DOCKER_ID.fullmatch(image.removeprefix("sha256:")) is not None),
              "IDENTITY_IMAGE")
        return cls(cid, pid, started_at, image)

    def require_same_generation(self, observed: Owner) -> None:
        guard(self == observed, "OWNER_IDENTITY_CHANGED")


def require_no_replacement(pinned: Owner, new_inspect: dict | None) -> None:
    """A reused name/slug is not an absent old owner."""
    if new_inspect is None:
        return
    observed = Owner.from_inspect(new_inspect)
    pinned.require_same_generation(observed)


def canonical(event: dict) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def signature(event: dict) -> str:
    return hashlib.sha256(canonical(event)).hexdigest()


class Journal:
    """Crash-aware append log; torn tails and unknown transitions HOLD.

    A trusted manager alone supplies evidence for each phase. This library
    does not infer successful stop from a missing Supervisor API response.
    """

    def __init__(self, directory: Path):
        self.directory = directory
        self.fd: int | None = None
        self.lock_fd: int | None = None
        self.seq = 0
        self.head = "0" * 64
        self.phase: str | None = None

    def __enter__(self) -> Journal:
        guard(not self.directory.is_symlink(), "JOURNAL_SYMLINK")
        guard(self.directory.is_dir(), "JOURNAL_MISSING_DIRECTORY")
        guard((self.directory.stat().st_mode & 0o077) == 0, "JOURNAL_PERMISSIONS")
        lock = self.directory / "exclusive.lock"
        guard(not lock.is_symlink(), "LOCK_SYMLINK")
        self.lock_fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise LifecycleHold("P7U_HOLD_MANAGER_ALREADY_RUNNING") from exc
        try:
            path = self.directory / "events.jsonl"
            guard(not path.is_symlink(), "EVENTS_SYMLINK")
            self.fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            guard(stat.S_ISREG(os.fstat(self.fd).st_mode), "EVENTS_NOT_FILE")
            self._replay()
            # fsync containing directory to cover first file/link creation.
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def _replay(self) -> None:
        guard(self.fd is not None, "NOT_LOCKED")
        size = os.fstat(self.fd).st_size
        guard(size <= MAX_JOURNAL, "JOURNAL_FULL")
        os.lseek(self.fd, 0, os.SEEK_SET)
        raw = os.read(self.fd, MAX_JOURNAL + 1)
        guard(len(raw) == size, "JOURNAL_CHANGED_WHILE_READING")
        if not raw:
            return
        guard(raw.endswith(b"\n"), "TORN_JOURNAL_TAIL")
        for item in raw.splitlines():
            try:
                obj = json.loads(item)
            except (ValueError, UnicodeError) as exc:
                raise LifecycleHold("P7U_HOLD_JOURNAL_CORRUPT") from exc
            guard(type(obj) is dict and
                  set(obj) == {"seq", "prev", "phase", "evidence", "hash"},
                  "JOURNAL_SCHEMA")
            header = {k: v for k, v in obj.items() if k != "hash"}
            guard(type(obj["seq"]) is int and obj["seq"] == self.seq + 1, "JOURNAL_SEQUENCE")
            guard(obj["prev"] == self.head and
                  obj["hash"] == signature(header), "JOURNAL_CHAIN")
            guard(obj["phase"] in PHASES and type(obj["evidence"]) is dict,
                  "JOURNAL_PHASE")
            self.seq += 1
            self.head = obj["hash"]
            self.phase = obj["phase"]
        guard(self.phase in PHASES, "JOURNAL_EMPTY")

    def append(self, phase: str, evidence: dict) -> str:
        guard(self.fd is not None and self.lock_fd is not None, "NOT_LOCKED")
        guard(phase in PHASES, "UNKNOWN_PHASE")
        guard(type(evidence) is dict, "INVALID_EVIDENCE")
        # A prior interrupted stop/start cannot be replayed as a new intent.
        # A lost Supervisor response is an evidence state, NEVER a reason
        # to repeat the operation. Only observed owner/holder evidence may
        # advance the journal past the original intent.
        transitions = {
            "STOP_INTENT": ("STOP_ACK_UNKNOWN", "OWNER_ABSENT", "HOLD"),
            "STOP_ACK_UNKNOWN": ("OWNER_ABSENT", "HOLD"),
            "START_INTENT": ("START_ACK_UNKNOWN", "OWNER_SERVING", "HOLD"),
            "START_ACK_UNKNOWN": ("OWNER_SERVING", "HOLD"),
            "HOLD": ("HOLD",),
        }
        if self.phase in transitions:
            guard(phase in transitions[self.phase], "AMBIGUOUS_PREVIOUS_INTENT")
        seq = self.seq + 1
        header = {"seq": seq, "prev": self.head, "phase": phase, "evidence": evidence}
        record = {**header, "hash": signature(header)}
        raw = canonical(record) + b"\n"
        guard(os.fstat(self.fd).st_size + len(raw) <= MAX_JOURNAL, "JOURNAL_FULL")
        # A partial write is never truncated/repaired automatically.
        written = os.write(self.fd, raw)
        guard(written == len(raw), "SHORT_JOURNAL_WRITE")
        os.fsync(self.fd)
        self.seq = seq
        self.head = record["hash"]
        self.phase = phase
        return record["hash"]

    def __exit__(self, *_exc) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.lock_fd is not None:
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            os.close(self.lock_fd)
            self.lock_fd = None


def require_host_capabilities(capabilities: dict) -> None:
    """No cutover without exact attestations of BOTH protected host images."""
    required = ("diagnostic_profile_sha", "fallback_profile_sha",
                "identity_inspection", "tty_fd_inspection",
                "source_database_gate", "save_before_adapter_close")
    guard(type(capabilities) is dict and set(required) <= set(capabilities), "CAPABILITIES_MISSING")
    for field in ("diagnostic_profile_sha", "fallback_profile_sha"):
        guard(isinstance(capabilities[field], str) and
              SHA.fullmatch(capabilities[field]) is not None, "PROFILE_SHA_MISSING")
    for field in required[2:]:
        guard(capabilities[field] is True, "CAPABILITY_UNQUALIFIED")
    guard(capabilities["diagnostic_profile_sha"] != capabilities["fallback_profile_sha"],
          "FALLBACK_NOT_INDEPENDENT")
