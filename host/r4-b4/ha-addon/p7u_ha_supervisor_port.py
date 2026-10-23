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
from p7u_host_integrity import verify_committed
from p7u_db_quiesced import inventory_baseline, seal_quiesced
import re
from typing import Any, Callable
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from p7u_lifecycle_core import LifecycleHold, Owner, guard, SHA
from p7u_lifecycle_machine import Presence
from p7u_ha_readonly_inspector import (
    SLUGS, inspect_docker, tty_holders, prove_container, bind_tty_to_owner,
    inspect_addon, check_host_namespace,
)

ALLOWED_ACTIONS = frozenset({"start", "stop"})
ALLOWED_SLOTS = frozenset({"official", "diagnostic", "fallback"})


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
                 client: Supervisor | None = None,
                 serving_probe: Callable[[str, int], dict] | None = None):
        check_host_namespace()
        self.serial_path = serial_path
        self.client = client or Supervisor()
        self.serving_probe = serving_probe
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
        guardian = inspect_addon("guard")
        guard(guardian.get("state") in ("started", "running"),
              "PASSIVE_GUARD_NOT_RUNNING")
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

    def start(self, slot: str, *, expected_image_sha: str) -> bool:
        guard(slot in ("diagnostic", "fallback") and
              type(expected_image_sha) is str and
              SHA.fullmatch(expected_image_sha) is not None,
              "START_NOT_APPROVED")
        guard(len(self.tty_holders()) == 0, "START_SERIAL_HOLDER_PRESENT")
        guard(all(not self.inspect(name).running for name in ALLOWED_SLOTS),
              "START_COMPETING_CONTAINER")
        raw = inspect_docker(slot)
        # Require an existing stopped Docker container with the *exact*
        # image; an uninstalled target is NOT magically qualified by an
        # old build artifact or free-form supplied image string.
        guard(raw is not None and raw.get("State", {}).get("Running") is False and
              raw.get("Image", "").removeprefix("sha256:") == expected_image_sha,
              "TARGET_STAGED_IMAGE_UNVERIFIED")
        info = self.client.call(method="GET", slot=slot, action="info")
        data = info.get("data")
        guard(type(data) is dict and data.get("state") in ("stopped", "error") and
              data.get("boot") == "manual" and data.get("watchdog") is False,
              "TARGET_SUPERVISOR_PROFILE_UNQUALIFIED")
        self.events.append("START_SENT")
        response = self.client.call(method="POST", slot=slot, action="start",
                                    timeout_seconds=90)
        return response.get("result") == "ok"

    def serving_evidence(self, slot: str, *, max_seconds: int) -> dict[str, Any]:
        guard(slot in ("diagnostic", "fallback") and max_seconds == 180,
              "INVALID_SERVING_SCOPE")
        guard(self.serving_probe is not None, "NO_INDEPENDENT_SERVING_MONITOR")
        return self.serving_probe(slot, max_seconds)
