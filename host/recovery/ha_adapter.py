"""Home Assistant Supervisor/SMLIGHT control adapter, never owns Zigbee serial.

Scoped to existing HA service token and one pinned LAN SMLIGHT. The native HA
button is preferred; the fallback action is privately fingerprinted and never
supports arbitrary cmd, factory reset, flash or network configuration changes.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

ADDON_SLUG = "45df7312_zigbee2mqtt"
EXPECTED_BY_ID = "usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00"
_ALLOWED = {"RESET_RADIO": (1, "zigbee_button"),
            "RESTART_ESP": (3, "core_button")}


@dataclass(frozen=True)
class Configuration:
    slzb_url: str = "http://192.168.50.59"
    addon_slug: str = ADDON_SLUG
    expected_by_id: str = EXPECTED_BY_ID
    esp_restart_entity: str = ""
    zigbee_restart_entity: str = ""
    allow_private_http_fallback: bool = False


class ControlError(RuntimeError):
    pass


class SupervisorClient:
    def __init__(self, token: str, base: str = "http://supervisor"):
        if not token:
            raise ControlError("NO_SUPERVISOR_TOKEN")
        self.token, self.base = token, base.rstrip("/")

    def call(self, path: str, *, method: str = "GET",
             payload: dict | None = None, timeout: float = 8) -> Any:
        if not path.startswith("/") or path.startswith("//"):
            raise ControlError("UNSAFE_SUPERVISOR_PATH")
        body = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.base + path, data=body, method=method,
            headers={"Authorization": "Bearer " + self.token,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as res:
            data = res.read(2_000_000).decode("utf-8", "replace")
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return data

    def addon_state(self, slug: str) -> str:
        data = self.call(f"/addons/{slug}/info")
        if not isinstance(data, dict) or data.get("result") != "ok":
            raise ControlError("SUPERVISOR_INFO_NOT_OK")
        return str(data.get("data", {}).get("state", "unknown"))

    def addon_options(self, slug: str) -> dict:
        res = self.call(f"/addons/{slug}/options/config")
        if not isinstance(res, dict) or res.get("result") != "ok":
            raise ControlError("SUPERVISOR_OPTIONS_NOT_OK")
        return res.get("data") or {}

    def hardware_has_port(self, by_id: str) -> bool:
        # Supervisor hardware endpoint may include /dev/serial/by-id in an
        # alternate field; absence means UNKNOWN and blocks reset.
        res = self.call("/hardware/info")
        if not isinstance(res, dict) or res.get("result") != "ok":
            return False
        return by_id in json.dumps(res.get("data", {}))

    def service(self, slug: str, operation: str) -> bool:
        if operation not in ("start", "stop"):
            raise ControlError("UNAPPROVED_SUPERVISOR_OPERATION")
        res = self.call(f"/addons/{slug}/{operation}", method="POST",
                        payload={}, timeout=95)
        return isinstance(res, dict) and res.get("result") == "ok"

    def button(self, entity_id: str) -> bool:
        if not re.fullmatch(r"button\.[a-z0-9_]{1,100}", entity_id):
            raise ControlError("INVALID_NATIVE_BUTTON_ID")
        # Only configured exact entity IDs are used; no entity discovery action.
        state = self.call("/core/api/states/" + entity_id)
        if not isinstance(state, dict) or state.get("entity_id") != entity_id:
            raise ControlError("NATIVE_BUTTON_NOT_FOUND")
        if state.get("state") in ("unavailable", "unknown"):
            raise ControlError("NATIVE_BUTTON_UNAVAILABLE")
        r = self.call("/core/api/services/button/press", method="POST",
                      payload={"entity_id": entity_id}, timeout=15)
        return isinstance(r, list)  # HA service calls return entity list

    def log_text(self, slug: str) -> str:
        r = self.call(f"/addons/{slug}/logs/latest?lines=800", timeout=12)
        if not isinstance(r, str):
            raise ControlError("SUPERVISOR_LOGS_NOT_RAW_TEXT")
        return r


class SmlightControl:
    def __init__(self, cfg: Configuration):
        parsed = urllib.parse.urlsplit(cfg.slzb_url)
        if parsed.scheme != "http" or parsed.username or parsed.password or (
            parsed.hostname not in ("192.168.50.59",)
        ) or parsed.port not in (None, 80) or parsed.path not in ("", "/"):
            raise ControlError("SLZB_LAN_ALLOWLIST_MISMATCH")
        self.cfg = cfg

    def fetch(self, path: str, query: dict | None = None,
              *, timeout: int = 8) -> str:
        if not path.startswith("/") or ".." in path:
            raise ControlError("UNSAFE_SLZB_PATH")
        q = urllib.parse.urlencode(query or {})
        url = self.cfg.slzb_url.rstrip("/") + path + (("?" + q) if q else "")
        req = urllib.request.Request(url, method="GET")
        # Private API requests are local-only, no generic user-provided URL.
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                raise ControlError("SLZB_HTTP_NOT_200")
            return r.read(300_000).decode("utf-8", "replace")

    def identity(self) -> dict:
        d = json.loads(self.fetch("/ha_info"))
        info = d.get("Info", {})
        if (info.get("model") != "SLZB-06p7U" or
            info.get("zb_hw") != "CC2652P7" or
            info.get("coord_mode") != 2):
            raise ControlError("SLZB_MODEL_RADIO_OR_USB_MODE_MISMATCH")
        return {"model": info["model"], "zb_hw": info["zb_hw"],
                "coord_mode": info["coord_mode"],
                "sw_version": info.get("sw_version")}

    def private_restart(self, operation: str) -> bool:
        if operation not in _ALLOWED:
            raise ControlError("UNAPPROVED_SLZB_COMMAND")
        self.identity()
        js = self.fetch("/js/httpApi.js")
        # Vendor private API contracts are version-sensitive; every side
        # effect is preceded by a fresh source check. NEVER expose cmd=9.
        if not all(k in js for k in (
            'apiLink="/api2?action="', "API_CMD:4",
            "CMD_ZB_RST:1", "CMD_ESP_RES:3", "CMD_HARD_RESET:9",
        )):
            raise ControlError("UNVERIFIED_INSTALLED_SLZB_COMMAND_MAP")
        response = self.fetch("/api2", {"action": 4,
                                           "cmd": _ALLOWED[operation][0]})
        if response.strip().lower() != "ok":
            raise ControlError("SLZB_RESTART_NOT_ACKNOWLEDGED")
        return True


class HAActuator:
    """Only executable side effects: evidence, stop/start Z2M, restart radio/ESP."""

    def __init__(self, cfg: Configuration, supervisor: SupervisorClient,
                 slzb: SmlightControl, evidence_callback):
        self.cfg, self.supervisor, self.slzb = cfg, supervisor, slzb
        self.evidence_callback = evidence_callback

    def perform_once(self, action: str) -> bool:
        if action == "CAPTURE_EVIDENCE":
            return bool(self.evidence_callback())
        if action == "STOP_Z2M":
            state = self.supervisor.addon_state(self.cfg.addon_slug)
            return (state in ("error", "stopped") or
                    self.supervisor.service(self.cfg.addon_slug, "stop"))
        if action == "START_Z2M":
            if not self.supervisor.hardware_has_port(self.cfg.expected_by_id):
                raise ControlError("USB_PHYSICAL_DEVICE_NOT_ENUMERATED")
            return self.supervisor.service(self.cfg.addon_slug, "start")
        if action in _ALLOWED:
            entity = (self.cfg.esp_restart_entity if action == "RESTART_ESP"
                      else self.cfg.zigbee_restart_entity)
            if entity:
                return self.supervisor.button(entity)
            if self.cfg.allow_private_http_fallback:
                return self.slzb.private_restart(action)
            raise ControlError("NO_APPROVED_NATIVE_BUTTON_OR_VERIFIED_FALLBACK")
        raise ControlError("UNSUPPORTED_ACTION")
