"""Passive process-scoped Zigbee evidence; no serial ownership or MQTT writes.

Delivery alone is not RF: Z2M also publishes cached and optimistic state.
Only advancing current last_seen:epoch on inventoried devices counts. Device
identifiers and message contents stay in bounded transient RAM.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime
from threading import Lock
from typing import Iterable
import json
import math
import re
import time
from zoneinfo import ZoneInfo

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

_STAMP = re.compile(r"\[(20\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\]")
_SRSP = re.compile(r"SRSP - (AF|ZDO|UTIL|SYS) - (\w+) after \d+ms")
_TARGETS = (
    re.compile(r"Failed to (?:read state of|ping|send to|bind) '([^']+)'"),
    re.compile(r"Publish '(?:set|get)' '[^']+' to '([^']+)' failed:"),
    re.compile(r"Failed to configure '([^']+)'"),
    re.compile(r"Failed to poll \S+ from (.+?) \(ZCL command"),
)
_DEVICE_IEEE = re.compile(r"(?:ZCL command|CommandResponse|Read response to)\s+(0x[0-9a-fA-F]{16})(?:/|\s)")
_IEEE = re.compile(r"0x[0-9a-fA-F]{16}\Z")
_BOOT = "Starting Zigbee2MQTT version "
_OTA_START = re.compile(r"(?:OTA updating|Updating) '([^']+)' to (?:latest|previous) firmware")
_OTA_END = re.compile(r"(?:Finished update of|OTA update of) '([^']+)'(?:$| failed \()")
_MAX_EVENTS = 1500
_MAX_HISTORY_BYTES = 512 * 1024 * 1024
_ZONE = ZoneInfo("Europe/Prague")


def timestamp(line: str) -> float | None:
    match = _STAMP.search(line[:70])
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=_ZONE).timestamp()
    except ValueError:
        return None


def _origin(line: str) -> bool:
    return "MQTT publish: topic" not in line and "bridge/response/" not in line


class PassiveObserver:
    def __init__(self, root_topic: str = "zigbee2mqtt", *, last_seen_epoch: bool = False,
                 admission_floor: float | None = None):
        if not root_topic or any(c in root_topic for c in ("+", "#", "\0")):
            raise ValueError("INVALID_MQTT_BASE_TOPIC")
        self.root = root_topic.rstrip("/")
        self.mutex = Lock()
        self.recent = deque(maxlen=_MAX_EVENTS)
        self.errors = deque(maxlen=500)
        self.bridge_on_at = self.received_at = self.last_log_read_at = 0.0
        self.connected = self.subscribed = False
        self._subscription_mid = None
        self.client = None
        self._admission_floor = time.time() if admission_floor is None else admission_floor
        self._rx_cutoff = self._admission_floor
        self._epoch_start_at = self._herdsman_started_at = self._app_started_at = 0.0
        self._epoch_known = self._manual_stop = False
        self._startup_error = (0.0, "")
        self._seen_errors: dict[tuple, float] = {}
        self._devices: dict[str, str] = {}
        self._known_ieee: set[str] = set()
        self._inventory_valid = False
        self._last_seen_epoch = last_seen_epoch is True
        self._last_seen: dict[str, int] = {}
        self._calibrated: set[str] = set()
        self._ota: dict[str, str] = {}
        self._ota_at: dict[str, float] = {}
        self._ota_bootstrap_unknown = True
        self._last_log_event_at = 0.0
        self._log_gap = False
        self._rx_invalid_at = 0.0

    def set_last_seen_epoch(self, enabled: bool):
        with self.mutex:
            self._last_seen_epoch = enabled is True
            if not self._last_seen_epoch:
                self.recent.clear()
                self._calibrated.clear()

    def _new_epoch(self, started: float, *, actual: bool):
        self._epoch_start_at, self._epoch_known = started, actual
        self._rx_cutoff = max(self._admission_floor, started)
        self.recent.clear()
        self.errors.clear()
        self._seen_errors.clear()
        self._last_seen.clear()
        self._startup_error = (0.0, "")
        self._herdsman_started_at = self._app_started_at = self.bridge_on_at = 0.0
        self._manual_stop = False

    def begin_startup(self, now: float | None = None):
        """New owner-requested start cutoff; acknowledgement is not success."""
        now = time.time() if now is None else now
        with self.mutex:
            self._admission_floor = now
            self._new_epoch(now, actual=False)
            self._ota_bootstrap_unknown = True

    def seed_process_epoch(self, current_log_prefix: str, now: float | None = None):
        """Seed actual time from a source-verified CURRENT file's prefix.

        Prefix alone cannot establish intervening OTA lifecycle. Complete the
        streaming history bootstrap before arming automatic recovery.
        """
        now = time.time() if now is None else now
        with self.mutex:
            starts = [t for line in current_log_prefix.splitlines() if _BOOT in line and _origin(line)
                      and (t := timestamp(line)) is not None and t <= now + 2]
            if not starts:
                raise ValueError("CURRENT_PROCESS_START_NOT_FOUND")
            started = max(starts)
            if self._epoch_known and started == self._epoch_start_at:
                return
            self._new_epoch(started, actual=True)
            self._ota_bootstrap_unknown = True
            self._log_gap = True

    def seed_process_history(self, lines: Iterable[str], now: float | None = None):
        """Replay complete current-file lifecycle without retaining raw history.

        Caller binds the file's startup prefix to the current process. A failed
        or oversized replay leaves OTA UNKNOWN. Old OTA starts still matter.
        """
        now = time.time() if now is None else now
        with self.mutex:
            self._ota_bootstrap_unknown = True
            found, total, latest = False, 0, 0.0
            expected_epoch = self._epoch_start_at if self._epoch_known else None
            for line in lines:
                total += len(line.encode("utf-8", "replace"))
                if total > _MAX_HISTORY_BYTES:
                    raise ValueError("PROCESS_HISTORY_TOO_LARGE")
                t = timestamp(line)
                if t is None or t > now + 2 or not _origin(line):
                    continue
                if _BOOT in line:
                    if not self._epoch_known or t != self._epoch_start_at:
                        self._new_epoch(t, actual=True)
                    self._ota.clear()
                    self._ota_at.clear()
                    found = True
                if found and t >= self._epoch_start_at:
                    self._lifecycle(line, t)
                    latest = max(latest, t)
            if not found:
                raise ValueError("CURRENT_PROCESS_START_NOT_FOUND")
            if expected_epoch is not None and expected_epoch != self._epoch_start_at:
                raise ValueError("PROCESS_HISTORY_EPOCH_MISMATCH")
            self._ota_bootstrap_unknown = False
            self._last_log_event_at = latest
            self._log_gap = False

    def start(self, host: str, port: int, username: str, password: str):
        if mqtt is None:
            raise RuntimeError("PAHO_MQTT_NOT_INSTALLED")
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                             client_id="p7u-recovery-readonly", clean_session=True)
        if username:
            client.username_pw_set(username, password)

        def on_connect(_client, _userdata, _flags, reason, _properties):
            with self.mutex:
                self.connected = getattr(reason, "value", reason) == 0
                self.subscribed = False
                self._subscription_mid = None
            if self.connected:
                result, mid = client.subscribe(self.root + "/#", qos=0)
                with self.mutex:
                    if result == 0:
                        self._subscription_mid = mid

        def on_subscribe(_client, _userdata, mid, reasons, _properties):
            codes = [getattr(r, "value", r) for r in reasons]
            with self.mutex:
                self.subscribed = bool(self.connected and mid == self._subscription_mid
                                       and len(codes) == 1 and codes[0] in (0, 1, 2))

        def on_disconnect(_client, _userdata, _flags, _reason, _properties):
            with self.mutex:
                self.connected = self.subscribed = False
                self._subscription_mid = None
                self._inventory_valid = False
                self.bridge_on_at = 0
                self.recent.clear()
                self._calibrated.clear()
                self._rx_cutoff = max(self._rx_cutoff, time.time())
                self._ota_bootstrap_unknown = True

        def on_message(_client, _userdata, msg):
            self.ingest_mqtt(msg.topic, msg.payload, retained=msg.retain)

        client.on_connect, client.on_subscribe = on_connect, on_subscribe
        client.on_disconnect, client.on_message = on_disconnect, on_message
        client.connect(host, port, keepalive=30)
        client.loop_start()
        self.client = client

    def close(self):
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()

    def ingest_mqtt(self, topic: str, payload: bytes | str, *, retained: bool = False,
                    now: float | None = None):
        now = time.time() if now is None else now
        if len(payload) > 1_000_000:
            return
        try:
            data = json.loads(payload)
        except (ValueError, TypeError, UnicodeError):
            with self.mutex:
                if not retained and topic[len(self.root) + 1:] in self._devices and topic.startswith(self.root + "/"):
                    self._rx_invalid_at = now
            return
        with self.mutex:
            if topic == self.root + "/bridge/devices":
                self._inventory(data)  # retained identity metadata is allowed
                return
            if retained or not self.subscribed:
                return
            if not isinstance(data, dict):
                if topic.startswith(self.root + "/") and topic[len(self.root) + 1:] in self._devices:
                    self._rx_invalid_at = now
                return
            if topic == self.root + "/bridge/state":
                state = data.get("state")
                if state in ("online", "offline"):
                    self.bridge_on_at = now if state == "online" else 0
                return
            if topic == self.root + "/bridge/logging":
                if data.get("namespace") == "z2m" and data.get("level") in (
                    "info", "warning", "error", "debug"
                ) and isinstance(data.get("message"), str):
                    self._ota_event(data["message"], now)
                return
            if not topic.startswith(self.root + "/"):
                return
            name = topic[len(self.root) + 1:]
            device = self._devices.get(name)
            if not self._inventory_valid or device is None:
                return
            update = data.get("update")
            if isinstance(update, dict) and update.get("state") in (
                "updating", "idle", "available", "scheduled"
            ):
                self._set_ota(name, update["state"], now)
            value = data.get("last_seen")
            if not self._last_seen_epoch:
                return
            if type(value) is not int or value <= 0:
                self._rx_invalid_at = now
                return
            try:
                event_at = value / 1000.0
            except OverflowError:
                self._rx_invalid_at = now
                return
            if not math.isfinite(event_at) or event_at > now + 2:
                self._rx_invalid_at = now
                return
            if event_at < self._rx_cutoff:
                return
            if value <= self._last_seen.get(device, 0):
                return
            self._last_seen[device] = value
            if 0 <= now - event_at <= 120:
                self.recent.append((event_at, device))
                self._calibrated.add(device)
                self.received_at = now
                self._rx_invalid_at = 0.0

    def _inventory(self, data):
        if not isinstance(data, list) or not 1 <= len(data) <= 2000:
            self._inventory_valid = False
            return
        devices = {}
        for row in data:
            if not isinstance(row, dict):
                self._inventory_valid = False
                return
            if row.get("type") == "Coordinator":
                continue
            name, ieee = row.get("friendly_name"), row.get("ieee_address")
            if (row.get("type") not in ("Router", "EndDevice", "GreenPower")
                or not isinstance(name, str) or not 1 <= len(name) <= 256
                or name.startswith("bridge/") or any(c in name for c in ("+", "#", "\0"))
                or not isinstance(ieee, str) or not _IEEE.fullmatch(ieee) or name in devices):
                self._inventory_valid = False
                return
            devices[name] = ieee.lower()
        self._devices, self._known_ieee = devices, set(devices.values())
        self._inventory_valid = len(self._known_ieee) == len(devices) and bool(devices)
        self._calibrated.intersection_update(self._known_ieee)

    def _set_ota(self, name: str, state: str, at: float):
        if at >= self._ota_at.get(name, 0) and (name in self._ota or len(self._ota) < 2000):
            self._ota[name], self._ota_at[name] = state, at

    def _ota_event(self, message: str, at: float):
        if len(message) > 16384:
            return
        start, end = _OTA_START.match(message), _OTA_END.match(message)
        if start:
            self._set_ota(start.group(1), "updating", at)
        elif end:
            self._set_ota(end.group(1), "idle", at)

    def _lifecycle(self, line: str, t: float):
        if "zigbee-herdsman started" in line:
            self._herdsman_started_at = max(self._herdsman_started_at, t)
        if "Zigbee2MQTT started!" in line:
            self._app_started_at = max(self._app_started_at, t)
        if "Stopping Zigbee2MQTT" in line and re.search(r"signal=SIG(?:TERM|INT)\)", line):
            self._manual_stop = True
        self._ota_event(re.split(r"\bz2m:\s*", line, maxsplit=1)[-1].strip(), t)

    def read_log(self, raw: str, now: float | None = None):
        now = time.time() if now is None else now
        with self.mutex:
            # Coverage includes old lines: a quiet application must not look
            # like a dropped tail merely because its prior line aged out.
            times = [t for line in raw.splitlines() if (t := timestamp(line)) is not None
                     and 0 <= now - t]
            if times and self._last_log_event_at and min(times) > self._last_log_event_at + 1:
                self._log_gap = True
                self._ota_bootstrap_unknown = True
            newest = max(times, default=0)
            advanced = newest > self._last_log_event_at
            for line in raw.splitlines():
                t = timestamp(line)
                if t is None or not 0 <= now - t <= 900 or not _origin(line):
                    continue
                if (_BOOT in line and (not self._epoch_known or t > self._epoch_start_at)
                    and t >= self._admission_floor - 1):
                    self._new_epoch(t, actual=True)
                    self._ota.clear()
                    self._ota_at.clear()
                    self._ota_bootstrap_unknown = True
                if not self._epoch_known or t < max(self._epoch_start_at, self._admission_floor):
                    continue
                self._lifecycle(line, t)
                failure = _failure(line)
                if failure and t >= self._startup_error[0]:
                    self._startup_error = (t, failure)
                match = _SRSP.search(line)
                if not match:
                    continue
                direct = _DEVICE_IEEE.search(line)
                device = direct.group(1).lower() if direct else None
                if device not in self._known_ieee:
                    device = None
                    for pattern in _TARGETS:
                        target = pattern.search(line)
                        if target:
                            device = self._devices.get(target.group(1))
                            break
                if device is None or not self._inventory_valid:
                    continue
                key = (self._epoch_start_at, int(t), *match.groups(), device)
                if key not in self._seen_errors:
                    self._seen_errors[key] = t
                    self.errors.append((t, match.group(1), device))
            if advanced:
                self.last_log_read_at = now
                self._last_log_event_at = newest
            self._seen_errors = {k: t for k, t in self._seen_errors.items() if now - t < 900}

    def sample(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self.mutex:
            recent = {k for t, k in self.recent if 0 <= now - t <= 120}
            events = [(t, sub, dev) for t, sub, dev in self.errors if 0 <= now - t <= 120]
            subscribed = self.connected and self.subscribed
            log_fresh = bool(self.last_log_read_at and 0 <= now - self.last_log_read_at <= 40)
            valid = bool(subscribed and self._inventory_valid and self._epoch_known
                         and log_fresh and not self._manual_stop and not self._log_gap)
            rx_valid = bool(subscribed and self._inventory_valid and self._last_seen_epoch
                            and len(self._calibrated) >= 3 and not (
                                self._rx_invalid_at and 0 <= now - self._rx_invalid_at <= 120))
            error_at, error = self._startup_error
            return {
                "mqtt_reachable": subscribed,
                "fresh_device_topics_120s": len(recent),
                "srsp_120s": len(events),
                "affected_devices_120s": len({dev for _, _, dev in events}),
                "health_fresh": valid, "observation_valid": valid, "rx_valid": rx_valid,
                "epoch_id": str(int(self._epoch_start_at)) if self._epoch_known else "",
                "bridge_online_fresh": bool(self.bridge_on_at >= self._rx_cutoff and self.bridge_on_at > 0),
                "herdsman_started_fresh": bool(self._herdsman_started_at >= self._epoch_start_at
                                               and self._herdsman_started_at > 0),
                "app_uptime_s": max(0, int(now - self._epoch_start_at)) if self._epoch_known else 0,
                "epoch_start_utc": self._epoch_start_at if self._epoch_known else 0,
                "adapter_error": error if not self._manual_stop and 0 <= now - error_at <= 180 else "",
                "ota_active": any(state == "updating" for state in self._ota.values()),
                "ota_unknown": self._ota_bootstrap_unknown or any(
                    name not in self._devices and state == "updating" for name, state in self._ota.items()),
                "manual_stop": self._manual_stop,
                "log_gap": self._log_gap,
            }


def _failure(line: str) -> str:
    for needle, code in (("SRSP - SYS - ping after", "SRSP_SYS_PING"),
                         ("SRSP - AF - register after", "SRSP_AF_REGISTER"),
                         ("SRSP - SYS - resetInd after", "SRSP_SYS_RESETIND"),
                         ("AREQ - SYS - resetInd after", "SRSP_SYS_RESETIND")):
        if needle in line:
            return code
    return ""


def start_failure_kind(log_text: str, now: float | None = None, *,
                       epoch_start: float = 0, admission_floor: float = 0) -> str:
    """Compatibility helper; runtime uses the observer's process-scoped result."""
    now = time.time() if now is None else now
    lines = [(t, line) for line in log_text.splitlines()
             if (t := timestamp(line)) is not None and _origin(line)]
    floor = max(epoch_start, admission_floor,
                max((t for t, line in lines if _BOOT in line), default=0))
    if any(t >= floor and "Stopping Zigbee2MQTT" in line and
           re.search(r"signal=SIG(?:TERM|INT)\)", line) for t, line in lines):
        return ""
    found = [(t, code) for t, line in lines if floor <= t <= now and now - t <= 180
             and (code := _failure(line))]
    return max(found)[1] if found else ""
