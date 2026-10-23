"""Passive 180-second Zigbee serving proof over MQTT + read-only HA state.

Subscribes ONLY to explicitly pinned Zigbee2MQTT friendly-name topics.
No MQTT PUBLISH/SET, no ZCL commands, no serial/network recovery, and no
broker log of credentials. Retained and bridge status messages do NOT count.
An HA GET /api/states/<entity> is a non-actuating cached-state read; it
does not claim a physical Zigbee attribute-read transaction.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import os
import re
import threading
import time
from typing import Callable
from urllib.request import Request, urlopen

from p7u_lifecycle_core import LifecycleHold, guard

TOPIC = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{2,95}$")
ENTITY = re.compile(r"^(sensor|binary_sensor)\.[a-z0-9_]{4,100}$")


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    username: str
    password: str
    expected_topics: tuple[str, ...]
    ha_entity_id: str

    def validate(self):
        guard(isinstance(self.host, str) and re.fullmatch(r"[a-zA-Z0-9.-]{3,160}", self.host) is not None,
              "MQTT_HOST")
        guard(type(self.port) is int and 1 <= self.port <= 65535, "MQTT_PORT")
        guard(len(self.expected_topics) >= 3 and len(set(self.expected_topics)) == len(self.expected_topics)
              and all(TOPIC.fullmatch(x) for x in self.expected_topics), "PINNED_DEVICE_TOPICS")
        guard(ENTITY.fullmatch(self.ha_entity_id) is not None, "HA_NON_ACTUATING_READ_ENTITY")


def read_ha_state(entity_id: str) -> dict:
    guard(ENTITY.fullmatch(entity_id) is not None, "HA_ENTITY_SCOPE")
    token = os.environ.get("SUPERVISOR_TOKEN", "")
    guard(len(token) >= 20 and not any(c.isspace() for c in token),
          "HA_READ_TOKEN_MISSING")
    req = Request("http://supervisor/core/api/states/" + entity_id,
                  method="GET", headers={"Authorization":"Bearer "+token})
    try:
        with urlopen(req, timeout=7) as response:
            data=response.read(32*1024+1)
    except OSError as exc:
        raise LifecycleHold("P7U_HOLD_HA_READ_UNAVAILABLE") from exc
    guard(len(data)<=32*1024,"HA_READ_TOO_LARGE")
    try:
        state=json.loads(data)
    except ValueError as exc:
        raise LifecycleHold("P7U_HOLD_HA_STATE_INVALID") from exc
    guard(type(state) is dict and state.get("entity_id")==entity_id and
          type(state.get("state")) is str and state["state"] not in
          ("unknown","unavailable","none"), "HA_STATE_NOT_VALID")
    return {"entity_id":entity_id,"read_only":True,"valid":True}


class FreshMqttEvidence:
    def __init__(self, config: Config):
        config.validate()
        self.config=config
        self.started_monotonic=time.monotonic()
        self.started_utc_seconds=time.time()
        self._seen: dict[str, float]={}
        self._lock=threading.Lock()
        self._done=threading.Event()
        self.connected=False

    @staticmethod
    def _last_seen_seconds(value) -> float | None:
        try:
            if type(value) is int:
                seconds = value / 1000 if value >= 100_000_000_000 else float(value)
            elif isinstance(value, str):
                timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    return None
                seconds = timestamp.timestamp()
            else:
                return None
        except (ValueError, OverflowError, OSError):
            return None
        return seconds if math.isfinite(seconds) else None

    def observe(self, *, topic: str, payload: bytes, retained: bool, now: float) -> None:
        if retained or not topic.startswith("zigbee2mqtt/") or len(payload)>16*1024:
            return
        name=topic[len("zigbee2mqtt/"):]
        if name not in self.config.expected_topics or "/" in name or now<self.started_monotonic:
            return
        try:
            data=json.loads(payload)
        except (UnicodeError,ValueError):
            return
        if type(data) is not dict or not data or set(data)=={"availability"}:
            return
        # Z2M can republish persistent cached states as new nonretained MQTT
        # messages. Only the device's actual last Zigbee message timestamp
        # can distinguish those startup payloads from post-cutover RF traffic.
        last_seen = self._last_seen_seconds(data.get("last_seen"))
        observed_utc = self.started_utc_seconds + (now - self.started_monotonic)
        if last_seen is None or not self.started_utc_seconds <= last_seen <= observed_utc + 5:
            return
        with self._lock:
            self._seen[name]=now
            if len(self._seen)>=3:
                self._done.set()

    def result(self) -> dict:
        with self._lock:
            seen=set(self._seen)
        return {"fresh_devices":len(seen),
                "mqtt_messages_fresh":len(seen)>=3,
                "non_actuating_read":False}

    def collect(self, max_seconds: int, *,
                ha_reader: Callable[[str],dict]=read_ha_state) -> dict:
        guard(type(max_seconds) is int and max_seconds==180, "MQTT_OBSERVATION_WINDOW")
        # Imported ONLY inside the bounded passive collector. Existence of a
        # library never grants permission to publish to a Zigbee command topic.
        try:
            import paho.mqtt.client as mqtt
        except ImportError as exc:
            raise LifecycleHold("P7U_HOLD_MQTT_READER_DEPENDENCY") from exc
        try:
            client=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                               client_id="p7u-passive-serving-" + os.urandom(4).hex(),
                               clean_session=True)
            if self.config.username:
                client.username_pw_set(self.config.username,self.config.password)
            def on_connect(c, userdata, flags, reason_code, properties):
                if reason_code != 0:
                    return
                self.connected=True
                for name in self.config.expected_topics:
                    c.subscribe("zigbee2mqtt/"+name, qos=0)
            def on_message(c,userdata,message):
                self.observe(topic=message.topic,payload=message.payload,
                             retained=message.retain,now=time.monotonic())
            client.on_connect=on_connect
            client.on_message=on_message
            client.connect(self.config.host,self.config.port,keepalive=30)
            client.loop_start()
            self._done.wait(max_seconds)
        except Exception as exc:
            raise LifecycleHold("P7U_HOLD_PASSIVE_MQTT_UNAVAILABLE") from exc
        finally:
            if "client" in locals():
                try:
                    client.disconnect()
                    client.loop_stop()
                except Exception:
                    pass
        result=self.result()
        result["mqtt_messages_fresh"]=bool(self.connected and result["mqtt_messages_fresh"])
        # HA state GET is not a physical Zigbee ZCL read; the three actual
        # post-subscription MQTT payloads are the independent live evidence.
        if result["mqtt_messages_fresh"]:
            try:
                state=ha_reader(self.config.ha_entity_id)
                result["non_actuating_read"]=state.get("read_only") is True and state.get("valid") is True
            except Exception:
                result["non_actuating_read"]=False
        return result
