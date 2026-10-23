"""P7U single-owner transition state machine, ports injected, no device I/O.

A production port MUST be a separately reviewed narrow privileged helper.
No shell-command string, Docker kill-by-name, UART access, NV restore,
or implicit fallback exists in this module. Synthetic hosted tests only.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, Any
from .p7u_lifecycle_core import Journal, Owner, LifecycleHold, guard, require_host_capabilities


@dataclass(frozen=True)
class Presence:
    running: bool
    owner: Owner | None


class Port(Protocol):
    """Trusted single-owner host adapter, NEVER a generic command executor."""
    def inspect(self, slot: str) -> Presence: ...
    def tty_holders(self) -> frozenset[int]: ...
    def stop(self, slot: str, *, timeout_seconds: int) -> bool: ...
    def start(self, slot: str, *, expected_image_sha: str) -> bool: ...
    def serving_evidence(self, slot: str, *, max_seconds: int) -> dict[str, Any]: ...


def require_absent(p: Presence, slot: str):
    guard(type(p) is Presence and not p.running and p.owner is None, slot + "_NOT_ABSENT")


def require_running(p: Presence, slot: str) -> Owner:
    guard(type(p) is Presence and p.running and type(p.owner) is Owner,
          slot + "_NOT_RUNNING")
    return p.owner


def zero_tty_three_times(port: Port) -> None:
    """Three genuinely independent observations, provided by privilege port.

    A delayed probe can observe delayed udev teardown; do not sleep here or
    disguise three queries to the same cached snapshot as proof.
    The narrow port MUST collect fresh /proc holder data on every call.
    """
    for i in range(3):
        holders = port.tty_holders()
        guard(type(holders) is frozenset and len(holders) == 0, "TTY_HOLDERS_" + str(i))


class Manager:
    def __init__(self, journal: Journal, port: Port, capabilities: dict[str, Any]):
        self.journal = journal
        self.port = port
        require_host_capabilities(capabilities)
        self.cap = capabilities

    def preflight(self, *, original_slot: str, target_slot: str,
                  database_approved: bool, guard_passive: bool) -> Owner:
        guard(self.journal.fd is not None and self.journal.lock_fd is not None,
              "MANAGER_LOCK_MISSING")
        guard(self.journal.phase in (None, "COMMITTED"), "UNRECONCILED_JOURNAL")
        guard(original_slot in ("official", "fallback", "diagnostic") and
              target_slot in ("fallback", "diagnostic") and
              original_slot != target_slot, "SLOT_INVALID")
        guard(database_approved is True and guard_passive is True,
              "DATABASE_OR_GUARD_UNQUALIFIED")
        pinned = require_running(self.port.inspect(original_slot), original_slot)
        require_absent(self.port.inspect(target_slot), target_slot)
        holders = self.port.tty_holders()
        guard(type(holders) is frozenset and holders == frozenset([pinned.pid]),
              "UNEXPECTED_SERIAL_OWNER")
        self.journal.append("PREFLIGHT", {
            "original": original_slot, "target": target_slot,
            "original_container_id": pinned.container_id,
            "original_pid": pinned.pid, "original_started_at": pinned.started_at,
            "target_profile_sha": self.cap["diagnostic_profile_sha"]
                if target_slot == "diagnostic" else self.cap["fallback_profile_sha"],
            "database_approved": True,
        })
        return pinned

    def switch_once(self, *, original_slot: str, target_slot: str,
                    database_approved: bool, guard_passive: bool) -> str:
        old = self.preflight(original_slot=original_slot, target_slot=target_slot,
                             database_approved=database_approved,
                             guard_passive=guard_passive)
        self.journal.append("STOP_INTENT", {"pinned_container_id": old.container_id})
        try:
            acknowledged = self.port.stop(original_slot, timeout_seconds=60)
        except Exception:
            acknowledged = False
        if not acknowledged:
            self.journal.append("STOP_ACK_UNKNOWN", {"one_request_only": True})
        # Never repeat stop just because the Supervisor returned no ACK.
        observed = self.port.inspect(original_slot)
        if observed.running:
            guard(observed.owner == old, "ORIGINAL_REPLACED_DURING_STOP")
            self.journal.append("HOLD", {"reason": "original still running; no forced stop"})
            raise LifecycleHold("P7U_HOLD_STOP_NOT_VERIFIED")
        require_absent(observed, original_slot)
        zero_tty_three_times(self.port)
        require_absent(self.port.inspect(target_slot), target_slot)
        self.journal.append("OWNER_ABSENT", {
            "old_container_id": old.container_id, "holder_free_checks": 3
        })
        image = (self.cap["diagnostic_profile_sha"]
                 if target_slot == "diagnostic" else self.cap["fallback_profile_sha"])
        self.journal.append("START_INTENT", {"slot": target_slot, "profile_sha": image})
        try:
            started_ack = self.port.start(target_slot, expected_image_sha=image)
        except Exception:
            started_ack = False
        if not started_ack:
            self.journal.append("START_ACK_UNKNOWN", {"one_request_only": True})
        try:
            new = require_running(self.port.inspect(target_slot), target_slot)
            require_absent(self.port.inspect(original_slot), original_slot)
            holders = self.port.tty_holders()
            guard(holders == frozenset([new.pid]), "TARGET_SERIAL_OWNER_UNCERTAIN")
            serving = self.port.serving_evidence(target_slot, max_seconds=180)
            guard(type(serving) is dict and serving.get("fresh_devices") >= 3 and
                  serving.get("mqtt_messages_fresh") is True and
                  serving.get("non_actuating_read") is True, "SERVING_UNVERIFIED")
            guard(self.port.inspect(target_slot).owner == new, "TARGET_CHANGED_DURING_SERVING")
            self.journal.append("OWNER_SERVING", {
                "target_container_id": new.container_id,
                "target_pid": new.pid, "fresh_devices": serving["fresh_devices"],
                "read_only": True,
            })
            self.journal.append("COMMITTED", {"desired_owner": target_slot,
                                               "container_id": new.container_id})
            return "COMMITTED"
        except (LifecycleHold, Exception):
            # One started host remains untouched; never restart old or
            # terminate new solely because optional F2/serving is sparse.
            if self.journal.phase != "HOLD":
                self.journal.append("HOLD", {"reason": "post-start evidence incomplete"})
            raise
