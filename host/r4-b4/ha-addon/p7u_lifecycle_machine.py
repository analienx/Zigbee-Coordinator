"""P7U single-owner transition state machine, ports injected, no device I/O.

A production port MUST be a separately reviewed narrow privileged helper.
No shell-command string, Docker kill-by-name, UART access, NV restore,
or implicit fallback exists in this module. Synthetic hosted tests only.
"""
from __future__ import annotations
from dataclasses import dataclass
import time
from typing import Protocol, Any
from p7u_lifecycle_core import Journal, Owner, LifecycleHold, guard, require_host_capabilities


@dataclass(frozen=True)
class Presence:
    running: bool
    owner: Owner | None


class Port(Protocol):
    """Trusted single-owner host adapter, NEVER a generic command executor."""
    def inspect(self, slot: str) -> Presence: ...
    def tty_holders(self) -> frozenset[int]: ...
    def prove_owner_holders(self, owner: Owner, holders: frozenset[int]) -> None: ...
    def validate_profiles(self, *, original_slot: str, target_slot: str) -> None: ...
    def preflight_database(self) -> dict[str, Any]: ...
    def approve_quiesced_database(self, baseline: dict[str, Any]) -> dict[str, Any]: ...
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
        if i:
            time.sleep(0.5)  # genuinely spaced /proc holder inspections
        holders = port.tty_holders()
        guard(type(holders) is frozenset and len(holders) == 0, "TTY_HOLDERS_" + str(i))


def await_target_owner(port: Port, target_slot: str, image: str) -> Owner:
    """Observe one start job; its HTTP ACK does not prove UART readiness.

    Pin the first running generation and allow bounded normal startup time.
    Never repeat a start or accept a replacement/foreign owner while waiting.
    """
    pinned = None
    deadline = time.monotonic() + 90
    for attempt in range(91):
        if attempt and time.monotonic() >= deadline:
            break
        for slot in ("official", "diagnostic", "fallback"):
            if slot != target_slot:
                require_absent(port.inspect(slot), slot)
        observed = port.inspect(target_slot)
        holders = port.tty_holders()
        guard(type(holders) is frozenset, "TARGET_SERIAL_OWNER_UNCERTAIN")
        if observed.running:
            new = require_running(observed, target_slot)
            guard(new.image_digest.removeprefix("sha256:") == image,
                  "TARGET_UNEXPECTED_IMAGE")
            if pinned is None:
                pinned = new
            pinned.require_same_generation(new)
            if holders:
                port.prove_owner_holders(new, holders)
                return new
        else:
            require_absent(observed, target_slot)
            guard(pinned is None, "TARGET_EXITED_DURING_START")
            guard(not holders, "START_FOREIGN_UART_OWNER")
        if attempt < 90:
            time.sleep(1)
    raise LifecycleHold("P7U_HOLD_TARGET_OWNER_NOT_READY")


class Manager:
    def __init__(self, journal: Journal, port: Port, capabilities: dict[str, Any]):
        self.journal = journal
        self.port = port
        require_host_capabilities(capabilities)
        self.cap = capabilities
        self.database_baseline: dict[str, Any] | None = None

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
        guard(type(holders) is frozenset and holders,
              "UNEXPECTED_SERIAL_OWNER")
        self.port.prove_owner_holders(pinned, holders)
        self.port.validate_profiles(original_slot=original_slot, target_slot=target_slot)
        baseline = self.port.preflight_database()
        guard(type(baseline) is dict, "DATABASE_BASELINE_MISSING")
        # Recheck identity after reading the still-live DB; no stop is issued
        # if the original generation or passive policy changed during preflight.
        pinned.require_same_generation(require_running(self.port.inspect(original_slot), original_slot))
        self.database_baseline = baseline
        self.journal.append("PREFLIGHT", {
            "original": original_slot, "target": target_slot,
            "original_container_id": pinned.container_id,
            "original_pid": pinned.pid, "original_started_at": pinned.started_at,
            "target_profile_sha": self.cap["diagnostic_profile_sha"]
                if target_slot == "diagnostic" else self.cap["fallback_profile_sha"],
            "database_approved": True,
            "database_baseline": baseline,
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
        # A timed-out HTTP request does not cancel Supervisor's stop job.
        # Observe that same pinned generation for at most another minute;
        # never send a second stop while the first may still be completing.
        for _ in range(60):
            if not observed.running:
                break
            guard(observed.owner == old, "ORIGINAL_REPLACED_DURING_STOP")
            time.sleep(1)
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
        try:
            guard(self.database_baseline is not None, "DATABASE_BASELINE_MISSING")
            receipt = self.port.approve_quiesced_database(self.database_baseline)
            guard(type(receipt) is dict and receipt.get("schema") == "p7u-quiesced-approval-v1",
                  "QUIESCED_DATABASE_RECEIPT_MISSING")
            self.journal.append("DB_APPROVED", receipt)
        except Exception:
            self.journal.append("HOLD", {"reason": "quiesced database admission failed; no start"})
            raise
        return self.start_and_verify(target_slot)

    def start_quiescent_once(self, *, target_slot: str, reconciliation: dict) -> str:
        """Start-only continuation; the privileged caller validates prior HOLD.

        It must preserve the predecessor journal and claim its exclusive
        continuation intent before invoking this method. No owner stop here.
        """
        guard(self.journal.fd is not None and self.journal.lock_fd is not None
              and self.journal.phase is None, "RECONCILIATION_JOURNAL_NOT_FRESH")
        guard(target_slot in ("diagnostic", "fallback") and type(reconciliation) is dict
              and reconciliation.get("prior_hold_verified") is True,
              "RECONCILIATION_UNQUALIFIED")
        self.port.validate_profiles(original_slot="official", target_slot=target_slot)
        for slot in ("official", "diagnostic", "fallback"):
            require_absent(self.port.inspect(slot), slot)
        baseline = self.port.preflight_database()
        guard(type(baseline) is dict and type(baseline.get("existing_approval")) is dict,
              "RECONCILIATION_CURRENT_APPROVAL_REQUIRED")
        self.journal.append("PREFLIGHT", reconciliation)
        zero_tty_three_times(self.port)
        self.journal.append("OWNER_ABSENT", {"holder_free_checks": 3, "reconciled": True})
        try:
            receipt = self.port.approve_quiesced_database(baseline)
            guard(type(receipt) is dict and receipt.get("reused") is True,
                  "RECONCILIATION_APPROVAL_MUST_BE_REUSED")
            self.journal.append("DB_APPROVED", receipt)
            return self.start_and_verify(target_slot)
        except Exception:
            if self.journal.phase != "HOLD":
                self.journal.append("HOLD", {"reason": "reconciled start incomplete; no automatic retry"})
            raise

    def start_and_verify(self, target_slot: str) -> str:
        guard(self.journal.phase == "DB_APPROVED", "START_WITHOUT_JOURNALED_APPROVAL")
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
            new = await_target_owner(self.port, target_slot, image)
            serving = self.port.serving_evidence(target_slot, max_seconds=180)
            guard(type(serving) is dict and serving.get("fresh_devices") >= 3 and
                  serving.get("mqtt_messages_fresh") is True and
                  serving.get("non_actuating_read") is True, "SERVING_UNVERIFIED")
            guard(self.port.inspect(target_slot).owner == new, "TARGET_CHANGED_DURING_SERVING")
            for slot in ("official", "diagnostic", "fallback"):
                if slot != target_slot:
                    require_absent(self.port.inspect(slot), slot)
            # The observation window is long enough for a competing service
            # to appear. Reprove current holders before committing ownership.
            self.port.prove_owner_holders(new, self.port.tty_holders())
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
