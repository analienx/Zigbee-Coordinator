"""Narrow privileged HA Supervisor port for the P7U *single-owner* controller.

No shell, subprocess mutation, serial open, NV operation or Docker kill.
The only durable host mutations exposed are ONE Supervisor POST /stop for
the pinned original add-on and ONE POST /start for an already-installed,
source-attested, diagnostics/fallback target add-on. All other API methods
and targets are denied. Never imported/called by a live add-on by default.
Run only in an audited host-PID namespace helper, not the existing SSH app.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from p7u_host_integrity import verify_committed, AdmissionHold
from p7u_db_quiesced import inventory_baseline, seal_quiesced
import re
from typing import Any, Callable
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from p7u_lifecycle_core import LifecycleHold, Owner, guard, SHA
from p7u_lifecycle_machine import Presence, zero_tty_three_times
from p7u_ha_readonly_inspector import (
    SLUGS, inspect_docker, tty_holders, prove_container, bind_tty_to_owner,
    inspect_addon, check_host_namespace,
    run_argv,
)

ALLOWED_ACTIONS = frozenset({"start", "stop"})
ALLOWED_SLOTS = frozenset({"official", "diagnostic", "fallback"})
IMAGE_REPOSITORIES = {
    "diagnostic": "localhost:50144/p7u-r4-diagnostic",
    "fallback": "localhost:50144/p7u-r4-fallback",
}
LEGACY_OWNER_AUTOMATIONS = frozenset({
    "automation.boot_deterministic_emqx_then_zigbee2mqtt",
    "automation.zigbee2mqtt_mesh_communication_outage_alert",
})


def read_automation_policy() -> dict[str, str]:
    """Read only the two known Core automations that can restart an owner."""
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    guard(len(token) >= 20 and not any(c.isspace() for c in token),
          "AUTOMATION_POLICY_TOKEN_MISSING")
    states: dict[str, str] = {}
    for entity in sorted(LEGACY_OWNER_AUTOMATIONS):
        request = Request("http://supervisor/core/api/states/" + entity,
                          method="GET", headers={"Authorization": "Bearer " + token})
        try:
            with urlopen(request, timeout=7) as response:
                raw = response.read(32 * 1024 + 1)
        except OSError as exc:
            raise LifecycleHold("P7U_HOLD_AUTOMATION_POLICY_UNAVAILABLE") from exc
        guard(len(raw) <= 32 * 1024, "AUTOMATION_POLICY_SIZE")
        try:
            state = json.loads(raw)
        except ValueError as exc:
            raise LifecycleHold("P7U_HOLD_AUTOMATION_POLICY_JSON") from exc
        guard(type(state) is dict and state.get("entity_id") == entity and
              type(state.get("state")) is str, "AUTOMATION_POLICY_ENTITY")
        states[entity] = state["state"]
    return states


class Supervisor:
    def __init__(self, *, transport: Callable | None = None):
        self.transport = transport or self._real_http

    @staticmethod
    def _real_http(method: str, slug: str, action: str,
                   timeout_seconds: int) -> dict:
        token = os.environ.get("SUPERVISOR_TOKEN", "")
        guard(len(token) >= 20 and not any(c.isspace() for c in token),
              "NO_PRIVILEGED_SUPERVISOR_TOKEN")
        guard(method in ("GET", "POST"), "SUPERVISOR_VERB")
        guard(slug in (SLUGS[x] for x in ALLOWED_SLOTS), "SUPERVISOR_SLUG")
        guard(action in ALLOWED_ACTIONS | {"info"}, "SUPERVISOR_PATH")
        guard((method == "GET") == (action == "info"), "SUPERVISOR_MUTATION_BOUNDARY")
        url = "http://supervisor/addons/" + slug + "/" + action
        req = Request(url, data=b"{}" if method == "POST" else None,
                      headers={"Authorization": "Bearer " + token,
                               "Content-Type": "application/json"},
                      method=method)
        try:
            with urlopen(req, timeout=timeout_seconds) as stream:
                raw = stream.read(128 * 1024 + 1)
        except (OSError, URLError, HTTPError) as exc:
            # Never output headers/token or URL containing credentials.
            raise LifecycleHold("P7U_HOLD_SUPERVISOR_RESPONSE_UNKNOWN") from exc
        guard(len(raw) <= 128 * 1024, "SUPERVISOR_RESPONSE_SIZE")
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise LifecycleHold("P7U_HOLD_SUPERVISOR_RESPONSE_BAD_JSON") from exc
        guard(type(data) is dict, "SUPERVISOR_RESPONSE_SHAPE")
        return data

    def call(self, *, method: str, slot: str, action: str,
             timeout_seconds: int = 20) -> dict:
        guard(slot in ALLOWED_SLOTS and action in ALLOWED_ACTIONS | {"info"},
              "UNAPPROVED_OPERATION")
        guard((method == "GET") == (action == "info"),
              "UNAPPROVED_METHOD")
        result = self.transport(method, SLUGS[slot], action, timeout_seconds)
        guard(type(result) is dict and result.get("result") == "ok",
              "SUPERVISOR_UNCONFIRMED")
        return result


class HaSupervisorPort:
    """Only intended adapter of p7u_lifecycle_machine.Port.

    The caller must use an OS-exclusive fsynced Journal and an immutable
    review receipt before entering Manager.switch_once. The adapter is NOT
    itself an authority to execute; an audited one-shot helper owns that gate.
    """

    def __init__(self, serial_path: str, *,
                 database: Path | None = None,
                 image_references: dict[str, str] | None = None,
                 automation_probe: Callable[[], dict[str, str]] | None = None,
                 client: Supervisor | None = None,
                 serving_probe: Callable[[str, int], dict] | None = None):
        check_host_namespace()
        self.serial_path = serial_path
        self.client = client or Supervisor()
        self.serving_probe = serving_probe
        self.database = database
        self.image_references = dict(image_references or {})
        self.automation_probe = automation_probe or read_automation_policy
        self.database_receipt: dict[str, Any] | None = None
        self.pinned: dict[str, Owner] = {}
        self.events: list[str] = []

    def inspect(self, slot: str) -> Presence:
        guard(slot in ALLOWED_SLOTS, "UNRECOGNIZED_SLOT")
        raw = inspect_docker(slot)
        if raw is None or raw.get("State", {}).get("Running") is not True:
            return Presence(False, None)
        proof = prove_container(raw)
        return Presence(True, proof.owner)

    def tty_holders(self) -> frozenset[int]:
        return tty_holders(self.serial_path)

    @staticmethod
    def _require_passive_guard() -> None:
        guardian = inspect_addon("guard")
        guard(guardian.get("state") in ("started", "running") and
              guardian.get("passive") is True, "GUARD_NOT_PASSIVE")

    def _require_manual_profiles(self) -> None:
        self._require_passive_guard()
        policy = self.automation_probe()
        guard(type(policy) is dict and set(policy) == LEGACY_OWNER_AUTOMATIONS and
              all(state == "off" for state in policy.values()),
              "LEGACY_OWNER_AUTOMATION_NOT_DISABLED")
        for slot in ALLOWED_SLOTS:
            info = self.client.call(method="GET", slot=slot, action="info").get("data")
            guard(type(info) is dict and info.get("boot") == "manual" and
                  info.get("watchdog") is False, "AUTOMATIC_OWNER_RESTART_ENABLED")

    def validate_profiles(self, *, original_slot: str, target_slot: str) -> None:
        guard(original_slot in ALLOWED_SLOTS and target_slot in ("diagnostic", "fallback") and
              original_slot != target_slot, "SLOT_INVALID")
        self._require_manual_profiles()
        for slot in ALLOWED_SLOTS - {original_slot}:
            guard(not self.inspect(slot).running, "PREFLIGHT_COMPETING_CONTAINER")

    def _database_path(self) -> Path:
        guard(isinstance(self.database, Path), "DATABASE_PATH_MISSING")
        database = self.database
        guard(database.is_absolute() and database.name == "database.db" and
              database.parent.name == "zigbee2mqtt" and not database.parent.is_symlink(),
              "DATABASE_PATH_UNQUALIFIED")
        return database

    def preflight_database(self) -> dict[str, Any]:
        database = self._database_path()
        for name in (".p7u-approved.json.pending", "database.db.tmp"):
            path = database.with_name(name)
            guard(not path.exists() and not path.is_symlink(), "DATABASE_UNRECONCILED_RECEIPT_OR_TEMP")
        baseline = inventory_baseline(database)
        manifest = database.with_name(".p7u-approved.json")
        guard(not manifest.is_symlink(), "DATABASE_APPROVAL_SYMLINK")
        if manifest.exists():
            # A later protected switch may reuse a receipt only while it is
            # still CURRENT. Never silently reseal a stale live generation.
            approved = verify_committed(database, manifest)
            guard(approved.database_sha256 == baseline["database_sha256"],
                  "DATABASE_CHANGED_DURING_PREFLIGHT")
            baseline["existing_approval"] = {
                "generation": approved.approval_generation,
                "database_sha256": approved.database_sha256,
            }
        return baseline

    def approve_quiesced_database(self, baseline: dict[str, Any]) -> dict[str, Any]:
        self._require_manual_profiles()
        guard(all(not self.inspect(slot).running for slot in ALLOWED_SLOTS),
              "DB_APPROVAL_COMPETING_CONTAINER")
        zero_tty_three_times(self)
        database = self._database_path()
        existing = baseline.get("existing_approval")
        if existing is None:
            receipt = seal_quiesced(database=database, baseline=baseline,
                                   all_slots_stopped=True, no_tty_holders=True)
        else:
            guard(type(existing) is dict, "DATABASE_EXISTING_APPROVAL_SHAPE")
            pending = database.with_name(".p7u-approved.json.pending")
            guard(not pending.exists() and not pending.is_symlink(), "DATABASE_APPROVAL_PENDING")
            approved = verify_committed(database, database.with_name(".p7u-approved.json"))
            guard(approved.approval_generation == existing.get("generation"),
                  "DATABASE_APPROVAL_GENERATION_CHANGED")
            current = inventory_baseline(database)
            guard(all(current[key] == baseline.get(key) for key in
                      ("inventory_sha256", "devices", "rows", "groups")) and
                  current["database_sha256"] == approved.database_sha256,
                  "DATABASE_CHANGED_SINCE_PRESTOP")
            receipt = {"schema": "p7u-quiesced-approval-v1",
                       "database_sha256": approved.database_sha256,
                       "inventory_sha256": approved.inventory_sha256,
                       "approved_rows": approved.rows, "approved_devices": approved.devices,
                       "generation": approved.approval_generation, "reused": True}
        # Another host could have started while the receipt was written.
        # Do not authorize start from a receipt issued during that race.
        guard(all(not self.inspect(slot).running for slot in ALLOWED_SLOTS) and
              not self.tty_holders(), "DB_APPROVAL_OWNER_RETURNED")
        self.database_receipt = receipt
        return receipt

    def prove_owner_holders(self, owner: Owner, holders: frozenset[int]) -> None:
        candidates = []
        for slot in ALLOWED_SLOTS:
            raw = inspect_docker(slot)
            if raw and raw.get("State", {}).get("Running") is True:
                if Owner.from_inspect(raw) == owner:
                    candidates.append((slot, raw))
        guard(len(candidates) == 1, "OWNER_CONTAINER_NOT_UNIQUE")
        slot, raw = candidates[0]
        proof = prove_container(raw)
        owner.require_same_generation(proof.owner)
        bind_tty_to_owner(holders, proof)
        self.pinned[slot] = owner

    def _must_still_be_owner(self, slot: str) -> Owner:
        guard(slot in self.pinned, "STOP_WITHOUT_PINNED_OWNER")
        expected = self.pinned[slot]
        current = self.inspect(slot)
        guard(current.running and current.owner == expected,
              "STOP_IDENTITY_CHANGED")
        self.prove_owner_holders(expected, self.tty_holders())
        # A protected start/stop requires the guardian to be passive, not
        # carrying any independent Zigbee radio owner or reset capability.
        self._require_manual_profiles()
        return expected

    def stop(self, slot: str, *, timeout_seconds: int) -> bool:
        guard(slot in ALLOWED_SLOTS and timeout_seconds == 60,
              "STOP_OPERATION_NOT_QUALIFIED")
        self._must_still_be_owner(slot)
        info = self.client.call(method="GET", slot=slot, action="info")
        data = info.get("data")
        guard(type(data) is dict and data.get("state") in ("started", "running"),
              "STOP_SUPERVISOR_OWNER_MISMATCH")
        # Called only once following durable STOP_INTENT. No retries, no
        # direct Docker kill and no forced SIGKILL on timed-out stop.
        self.events.append("STOP_SENT")
        response = self.client.call(method="POST", slot=slot, action="stop",
                                    timeout_seconds=timeout_seconds)
        return response.get("result") == "ok"

    def qualify_image(self, slot: str, *, expected_image_sha: str) -> dict:
        guard(slot in IMAGE_REPOSITORIES and isinstance(expected_image_sha, str) and
              SHA.fullmatch(expected_image_sha) is not None, "IMAGE_SCOPE_UNQUALIFIED")
        reference = self.image_references.get(slot)
        repository = IMAGE_REPOSITORIES[slot]
        guard(isinstance(reference, str) and reference.startswith(repository + ":"),
              "TARGET_IMAGE_REFERENCE_UNQUALIFIED")
        version = reference[len(repository) + 1:]
        guard(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}", version) is not None,
              "TARGET_IMAGE_VERSION_UNQUALIFIED")
        data = self.client.call(method="GET", slot=slot, action="info").get("data")
        guard(type(data) is dict and data.get("version") == version and
              data.get("build") is False and data.get("boot") == "manual" and
              data.get("watchdog") is False, "TARGET_SUPERVISOR_PROFILE_UNQUALIFIED")
        # Supervisor removes stopped add-on containers. Qualify the exact
        # source-pinned registry image used by the installed add-on metadata.
        inspected = run_argv(["docker", "image", "inspect", reference])
        guard(inspected.returncode == 0, "TARGET_INSTALLED_IMAGE_MISSING")
        try:
            images = json.loads(inspected.stdout)
        except ValueError as exc:
            raise LifecycleHold("P7U_HOLD_TARGET_INSTALLED_IMAGE_INVALID") from exc
        guard(type(images) is list and len(images) == 1 and type(images[0]) is dict and
              images[0].get("Id") == "sha256:" + expected_image_sha,
              "TARGET_STAGED_IMAGE_UNVERIFIED")
        return data

    def start(self, slot: str, *, expected_image_sha: str) -> bool:
        guard(slot in ("diagnostic", "fallback") and
              type(expected_image_sha) is str and
              SHA.fullmatch(expected_image_sha) is not None,
              "START_NOT_APPROVED")
        self._require_manual_profiles()
        guard(self.database_receipt is not None, "START_WITHOUT_QUIESCED_DATABASE")
        database = self._database_path()
        try:
            approved = verify_committed(database, database.with_name(".p7u-approved.json"))
        except AdmissionHold as exc:
            raise LifecycleHold("P7U_HOLD_START_DATABASE_CHANGED") from exc
        guard(approved.database_sha256 == self.database_receipt["database_sha256"] and
              approved.approval_generation == self.database_receipt["generation"],
              "START_DATABASE_RECEIPT_CHANGED")
        guard(len(self.tty_holders()) == 0, "START_SERIAL_HOLDER_PRESENT")
        guard(all(not self.inspect(name).running for name in ALLOWED_SLOTS),
              "START_COMPETING_CONTAINER")
        data = self.qualify_image(slot, expected_image_sha=expected_image_sha)
        guard(data.get("state") in ("stopped", "error"), "TARGET_SUPERVISOR_NOT_STOPPED")
        raw = inspect_docker(slot)
        guard(raw is None or (raw.get("State", {}).get("Running") is False and
              raw.get("Image", "").removeprefix("sha256:") == expected_image_sha),
              "TARGET_STOPPED_CONTAINER_IMAGE_UNVERIFIED")
        self.events.append("START_SENT")
        response = self.client.call(method="POST", slot=slot, action="start",
                                    timeout_seconds=90)
        return response.get("result") == "ok"

    def serving_evidence(self, slot: str, *, max_seconds: int) -> dict[str, Any]:
        guard(slot in ("diagnostic", "fallback") and max_seconds == 180,
              "INVALID_SERVING_SCOPE")
        guard(self.serving_probe is not None, "NO_INDEPENDENT_SERVING_MONITOR")
        return self.serving_probe(slot, max_seconds)
