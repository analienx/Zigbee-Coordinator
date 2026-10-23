"""Passive P7U host/transport incident classifier; NO actuator or serial client.

Independent observers provide monotonic timestamps and source-quality flags.
A host loop stall is never relabeled as a proven radio failure. A five-minute
re-arm requires genuine consecutive observations, not five timer callbacks.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass, asdict
from typing import Literal

KINDS = frozenset({
    "AF_SREQ_TIMEOUT", "ZDO_SREQ_TIMEOUT", "SYS_SREQ_TIMEOUT",
    "UTIL_SREQ_TIMEOUT", "USB_DISCONNECT", "PARSER_STALE",
    "HOST_HEARTBEAT_STALE", "F2_REPLY_UNCERTAIN",
})
SOURCE = frozenset({"host", "usb", "parser", "mqtt", "f2"})
MAX_EVENTS = 256
HEALTH_MIN_MS = 300_000
MAX_GAP_MS = 70_000
MIN_GAP_MS = 50_000


@dataclass(frozen=True)
class Observation:
    at_mono_ms: int
    host_heartbeat_fresh: bool
    usb_connected: bool
    parser_progress_fresh: bool
    mqtt_traffic_fresh: bool
    # Independent source attestation is required to call a minute healthy.
    host_independent: bool
    usb_independent: bool

    def is_healthy(self) -> bool:
        return (self.host_heartbeat_fresh and self.usb_connected and
                self.parser_progress_fresh and self.mqtt_traffic_fresh and
                self.host_independent and self.usb_independent)


@dataclass(frozen=True)
class Incident:
    kind: str
    first_mono_ms: int
    last_mono_ms: int
    count: int
    attribution: str
    initial_source: str


class Ledger:
    def __init__(self):
        self.incidents: dict[str, Incident] = {}
        self.events: deque[dict] = deque(maxlen=MAX_EVENTS)
        self.dropped = 0
        self.last_seen_mono: int | None = None
        self.healthy_start: int | None = None
        self.last_healthy: int | None = None
        self.generation = 0

    def _add(self, event: dict):
        if len(self.events) == MAX_EVENTS:
            self.dropped += 1
        self.events.append(event)

    def _clock(self, now: int):
        if type(now) is not int or now < 0 or (
            self.last_seen_mono is not None and now < self.last_seen_mono
        ):
            raise ValueError("P7U_INCIDENT_HOLD_UNTRUSTED_CLOCK")
        self.last_seen_mono = now

    def fault(self, now: int, kind: str, source: str, *,
              host_heartbeat_fresh: bool, usb_connected: bool) -> Incident:
        self._clock(now)
        if kind not in KINDS or source not in SOURCE:
            raise ValueError("P7U_INCIDENT_HOLD_KIND_SOURCE")
        # Host pause/USB detach create uncertainty, not proof of radio state.
        attribution = ("HOST_TIMING_UNCERTAIN" if not host_heartbeat_fresh else
                       "USB_TRANSPORT" if not usb_connected else
                       "RADIO_SUSPECT_NOT_PROVEN" if "SREQ_TIMEOUT" in kind else
                       "HOST_OR_SERIAL_UNKNOWN")
        initial = self.incidents.get(kind)
        incident = Incident(
            kind, initial.first_mono_ms if initial else now,
            now, (initial.count + 1) if initial else 1,
            initial.attribution if initial else attribution,
            initial.initial_source if initial else source,
        )
        self.incidents[kind] = incident
        self._add({"at_mono_ms": now, "kind": kind, "attribution": attribution,
                   "first": initial is None, "generation": self.generation})
        self.healthy_start = None
        self.last_healthy = None
        return incident

    def observe(self, sample: Observation) -> bool:
        """Return True only when every previously latched incident re-arms."""
        self._clock(sample.at_mono_ms)
        if not self.incidents:
            return False
        if not sample.is_healthy():
            self.healthy_start = None
            self.last_healthy = None
            return False
        now = sample.at_mono_ms
        if self.last_healthy is None:
            self.healthy_start = now
            self.last_healthy = now
            return False
        gap = now - self.last_healthy
        if gap < MIN_GAP_MS or gap > MAX_GAP_MS:
            # A burst of five near-identical observations must never rearm.
            self.healthy_start = now
            self.last_healthy = now
            return False
        self.last_healthy = now
        if self.healthy_start is not None and now - self.healthy_start >= HEALTH_MIN_MS:
            old = tuple(sorted(self.incidents))
            self.incidents.clear()
            self.healthy_start = None
            self.last_healthy = None
            self.generation += 1
            self._add({"at_mono_ms": now, "kind": "REARMED_AFTER_VALID_HEALTH",
                       "closed": old, "generation": self.generation})
            return True
        return False

    def snapshot(self) -> dict:
        """Numeric + enum-only diagnostics, deliberately no device/keys/payloads."""
        return {
            "schema": "p7u-passive-incident-ledger-v1",
            "active": [asdict(self.incidents[k]) for k in sorted(self.incidents)],
            "events": list(self.events), "dropped": self.dropped,
            "generation": self.generation,
            "radio_epoch": "UNKNOWN", "physical_recovery_allowed": False,
        }
