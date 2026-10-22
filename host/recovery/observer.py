"""Passive, non-retained MQTT and bounded Z2M log incident classifier.

Never publishes commands or opens the serial adapter. A broker connection
alone is not Zigbee evidence. Only freshly delivered non-retained MQTT device
messages count, and only current log-time SRSP errors may trigger detection.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from threading import Lock
import json
import re
import time
from zoneinfo import ZoneInfo

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

_STAMP = re.compile(r"\[(20\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\]")
_TARGET = re.compile(r"(?:Failed to (?:read state of|ping|send to|bind) )'([^']+)'")
_ZDO_ERROR = re.compile(r"SRSP - (?:AF|ZDO|UTIL|SYS) - \w+ after \d+ms")
_MAX_EVENTS = 1500
_ZONE = ZoneInfo("Europe/Prague")


def timestamp(line: str) -> float | None:
    match = _STAMP.search(line[:55])
    if not match:
        return None
    return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(
        tzinfo=_ZONE).timestamp()


class PassiveObserver:
    def __init__(self, root_topic: str = "zigbee2mqtt"):
        self.root = root_topic.rstrip("/")
        self.mutex = Lock()
        self.recent: deque[tuple[float, str]] = deque(maxlen=_MAX_EVENTS)
        self.bridge_on_at = 0.0
        self.received_at = 0.0
        self.connected = False
        self.client = None
        self.last_log_read_at = 0.0
        self.errors: deque[tuple[float, str, str]] = deque(maxlen=500)
        self._seen_logs: dict[str, float] = {}
        self._epoch_start_at = 0.0
        self._herdsman_started_at = 0.0

    def start(self, host: str, port: int, username: str, password: str):
        if mqtt is None:
            raise RuntimeError("PAHO_MQTT_NOT_INSTALLED")
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                             client_id="p7u-recovery-readonly",
                             clean_session=True)
        if username:
            client.username_pw_set(username, password)
        def on_connect(_client, _userdata, _flags, reason, _properties):
            with self.mutex:
                self.connected = int(reason) == 0
            if self.connected:
                client.subscribe(self.root + "/#", qos=0)
        def on_disconnect(_client, _userdata, _flags, _reason, _properties):
            with self.mutex:
                self.connected = False
                self.bridge_on_at = 0
                self.recent.clear()
        def on_message(_client, _userdata, msg):
            # Broker-delivered retained states are not live radio evidence.
            if msg.retain:
                return
            now = time.time()
            topic = msg.topic
            if topic == self.root + "/bridge/state":
                try:
                    state = json.loads(msg.payload).get("state")
                except (ValueError, AttributeError, TypeError):
                    return
                with self.mutex:
                    self.bridge_on_at = now if state == "online" else 0
                return
            if not topic.startswith(self.root + "/") or topic.startswith(
                self.root + "/bridge/"):
                return
            suffix = topic[len(self.root) + 1:]
            if "/" in suffix or not suffix or len(suffix) > 128:
                return
            with self.mutex:
                self.recent.append((now, suffix))
                self.received_at = now
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.on_message = on_message
        client.connect(host, port, keepalive=30)
        client.loop_start()
        self.client = client

    def close(self):
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()

    def read_log(self, raw: str, now: float | None = None):
        now = time.time() if now is None else now
        with self.mutex:
            self.last_log_read_at = now
            # Digest the event string only in transient RAM to discard duplicate
            # tail lines. Never persist IEEE, payload, or full raw logs.
            for line in raw.splitlines():
                t = timestamp(line)
                if t is None or t > now + 30 or now - t > 900:
                    continue
                if "zigbee-herdsman started" in line:
                    self._herdsman_started_at = max(self._herdsman_started_at, t)
                if "Zigbee2MQTT started!" in line:
                    self._epoch_start_at = max(self._epoch_start_at, t)
                if "SRSP -" not in line or not _ZDO_ERROR.search(line):
                    continue
                # Reject echoed MQTT responses; classify only originating errors.
                if "MQTT publish: topic" in line or "bridge/response/" in line:
                    continue
                import hashlib
                digest = hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()[:20]
                if digest in self._seen_logs:
                    continue
                self._seen_logs[digest] = t
                subsystem = (_ZDO_ERROR.search(line).group(0).split(" - ")[1])
                target = _TARGET.search(line)
                # In-memory opaque per-device key, not exportable.
                device = (target.group(1) if target else "")
                self.errors.append((t, subsystem, device))
            self._seen_logs = {k:v for k,v in self._seen_logs.items() if now-v < 900}

    def sample(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self.mutex:
            recent = {k for t,k in self.recent if 0 <= now-t <= 120}
            # Important: if no affected device can be extracted, fail closed.
            events = [(t,sub,dev) for t,sub,dev in self.errors if
                      0 <= now-t <= 120 and dev]
            subsys = [sub for t,sub,_ in self.errors if 0 <= now-t <= 120]
            startup = [name for t,name,_ in self.errors if 0 <= now-t <= 120]
            return {
                "mqtt_reachable": self.connected,
                "fresh_device_topics_120s": len(recent),
                "srsp_120s": len(events),
                "affected_devices_120s": len({dev for _,_,dev in events}),
                "health_fresh": bool(now - self.last_log_read_at <= 40 and
                                     self.connected),
                "bridge_online_fresh": bool(self.bridge_on_at > 0 and
                                            now-self.bridge_on_at < 900),
                "herdsman_started_fresh": bool(self._herdsman_started_at > 0 and
                                              now-self._herdsman_started_at < 900),
                "app_uptime_s": int(now-self._epoch_start_at) if
                    self._epoch_start_at and now >= self._epoch_start_at else 0,
                "epoch_start_utc": self._epoch_start_at,
            }


def start_failure_kind(log_text: str, now: float | None = None) -> str:
    """Inspect only recent CURRENT process startup failure signatures."""
    now = time.time() if now is None else now
    kinds = {
        "SRSP - SYS - ping after": "SRSP_SYS_PING",
        "SRSP - AF - register after": "SRSP_AF_REGISTER",
        "SRSP - SYS - resetInd after": "SRSP_SYS_RESETIND",
    }
    found: list[tuple[float,str]] = []
    for ln in log_text.splitlines():
        t = timestamp(ln)
        if t is None or not 0 <= now-t <= 180:
            continue
        for needle, code in kinds.items():
            if needle in ln:
                found.append((t,code))
    return max(found)[1] if found else ""
