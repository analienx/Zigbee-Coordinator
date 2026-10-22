"""Read the existing Zigbee2MQTT EMQX connection from the HA read-only mount.

No credentials or network keys printed, saved, exported, or stored in logs.
The file must be the mounted Home Assistant configuration, not user-supplied.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml


@dataclass(frozen=True)
class Broker:
    host: str
    port: int
    username: str
    password: str


def load_broker_settings(config_file: Path) -> Broker:
    path = Path(config_file)
    if path != Path("/homeassistant/zigbee2mqtt/configuration.yaml") and not (
        path.name == "configuration.yaml" and path.parent.name == "zigbee2mqtt"
    ):
        raise ValueError("UNKNOWN_Z2M_CONFIG_LOCATION")
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    settings = data.get("mqtt") or {}
    if not isinstance(settings, dict):
        raise ValueError("INVALID_Z2M_MQTT_CONFIGURATION")
    server = settings.get("server")
    if not isinstance(server, str):
        raise ValueError("MQTT_HOST_NOT_CONFIGURED")
    url = urlsplit(server)
    if url.scheme not in ("mqtt", "tcp") or not url.hostname or url.username:
        raise ValueError("MQTT_URI_SCHEME_OR_INLINE_CREDENTIALS_NOT_ALLOWED")
    if url.path not in ("", "/") or url.query or url.fragment:
        raise ValueError("MQTT_URI_UNEXPECTED_COMPONENTS")
    port = url.port or 1883
    if not (1 <= port <= 65535):
        raise ValueError("MQTT_PORT_INVALID")
    username, password = settings.get("user") or "", settings.get("password") or ""
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("MQTT_SECRET_NOT_STRING")
    return Broker(host=url.hostname, port=port,
                  username=username, password=password)
