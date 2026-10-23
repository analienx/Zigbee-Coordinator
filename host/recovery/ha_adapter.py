"""Home Assistant Supervisor/SMLIGHT control adapter, never owns Zigbee serial.

Scoped to existing HA service token and one pinned LAN SMLIGHT. The native HA
button is preferred; the fallback action is privately fingerprinted and never
supports arbitrary cmd, factory reset, flash or network configuration changes.
"""
from __future__ import annotations

import json
import hashlib
import gzip
import io
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ADDON_SLUG = "45df7312_zigbee2mqtt"
EXPECTED_BY_ID = "usb-SMLIGHT_SMLIGHT_SLZB-06p7U_SLZB-06p7U115236-if00"
_ALLOWED = {"RESET_RADIO": (1, "zigbee_button"),
            "RESTART_ESP": (3, "core_button")}
REVIEWED_JS_SHA256 = "2d50552d71bf55f8f87aeabece9f4dae01d589d9e2e88699ec0b15e8e8e600ed"


@dataclass(frozen=True)
class Configuration:
    slzb_url: str = "http://192.168.50.59"
    addon_slug: str = ADDON_SLUG
    expected_by_id: str = EXPECTED_BY_ID
    esp_restart_entity: str = ""
    zigbee_restart_entity: str = ""
    allow_private_http_fallback: bool = False
    expected_mac: str = ""
    expected_sw_version: str = "v3.4.3.dev1"
    expected_js_sha256: str = REVIEWED_JS_SHA256
    registry_directory: str = "/homeassistant/.storage"


class ControlError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ControlError("HTTP_REDIRECT_FORBIDDEN")


def _mac(value: str) -> str:
    compact = re.sub(r"[:.\-]", "", value).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", compact):
        raise ControlError("INVALID_PINNED_MAC")
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2))


class SupervisorClient:
    def __init__(self, token: str, base: str = "http://supervisor"):
        if not token:
            raise ControlError("NO_SUPERVISOR_TOKEN")
        self.token, self.base = token, base.rstrip("/")
        self.opener = urllib.request.build_opener(_NoRedirect())

    def _raw(self, path: str, *, method="GET", payload=None, timeout=8,
             limit=2_000_000, prefix=False) -> str:
        if not path.startswith("/") or path.startswith("//") or ".." in path:
            raise ControlError("UNSAFE_SUPERVISOR_PATH")
        body = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            self.base + path, data=body, method=method,
            headers={"Authorization": "Bearer " + self.token,
                     "Content-Type": "application/json"})
        with self.opener.open(req, timeout=timeout) as res:
            data = res.read(limit if prefix else limit + 1)
        if not prefix and len(data) > limit:
            raise ControlError("SUPERVISOR_RESPONSE_TOO_LARGE")
        if prefix:
            data = data[:data.rfind(b"\n") + 1]
        return data.decode("utf-8", "strict")

    def call(self, path: str, *, method: str = "GET",
             payload: dict | None = None, timeout: float = 8) -> Any:
        data = self._raw(path, method=method, payload=payload, timeout=timeout)
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return data

    def addon_info(self, slug: str) -> dict:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", slug):
            raise ControlError("INVALID_ADDON_SLUG")
        data = self.call(f"/addons/{slug}/info")
        if (not isinstance(data, dict) or data.get("result") != "ok" or
                not isinstance(data.get("data"), dict)):
            raise ControlError("SUPERVISOR_INFO_NOT_OK")
        return data["data"]

    def addon_state(self, slug: str) -> str:
        return str(self.addon_info(slug).get("state", "unknown"))

    def addon_options(self, slug: str) -> dict:
        options = self.addon_info(slug).get("options")
        if not isinstance(options, dict):
            raise ControlError("SUPERVISOR_OPTIONS_NOT_OK")
        return options

    def hardware_has_port(self, by_id: str) -> bool:
        res = self.call("/hardware/info")
        if not isinstance(res, dict) or res.get("result") != "ok":
            return False
        expected = "/dev/serial/by-id/" + by_id.rsplit("/", 1)[-1]
        devices = res.get("data", {}).get("devices", [])
        return isinstance(devices, list) and any(
            isinstance(device, dict) and device.get("by_id") == expected and
            device.get("subsystem") == "tty" and
            re.fullmatch(r"/dev/tty[A-Za-z0-9]+", str(device.get("dev_path", "")))
            for device in devices)

    def service(self, slug: str, operation: str) -> bool:
        if operation not in ("start", "stop"):
            raise ControlError("UNAPPROVED_SUPERVISOR_OPERATION")
        res = self.call(f"/addons/{slug}/{operation}", method="POST",
                        payload={}, timeout=95)
        return isinstance(res, dict) and res.get("result") == "ok"

    def button_available(self, entity_id: str) -> bool:
        if not re.fullmatch(r"button\.[a-z0-9_]{1,100}", entity_id):
            raise ControlError("INVALID_NATIVE_BUTTON_ID")
        # Only configured exact entity IDs are used; no entity discovery action.
        state = self.call("/core/api/states/" + entity_id)
        if not isinstance(state, dict) or state.get("entity_id") != entity_id:
            raise ControlError("NATIVE_BUTTON_NOT_FOUND")
        # A never-pressed button has state unknown (no last-pressed time).
        # The caller verifies its registry identity before reaching this API.
        if "state" not in state or state.get("state") == "unavailable":
            raise ControlError("NATIVE_BUTTON_UNAVAILABLE")
        return True

    def button(self, entity_id: str) -> bool:
        self.button_available(entity_id)
        r = self.call("/core/api/services/button/press", method="POST",
                      payload={"entity_id": entity_id}, timeout=15)
        return isinstance(r, list)  # HA service calls return entity list

    def log_text(self, slug: str) -> str:
        r = self.call(f"/addons/{slug}/logs/latest?lines=800", timeout=12)
        if not isinstance(r, str):
            raise ControlError("SUPERVISOR_LOGS_NOT_RAW_TEXT")
        return r

    def log_prefix(self, slug: str, max_bytes: int = 65536) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", slug) or not 1024 <= max_bytes <= 65536:
            raise ControlError("INVALID_LOG_PREFIX_REQUEST")
        # No lines= means FROM the beginning of the current container epoch.
        # Drop a possibly incomplete UTF-8 character/line at the bounded end.
        text = self._raw(f"/addons/{slug}/logs/latest?format=timestamp",
                         timeout=12, limit=max_bytes, prefix=True)
        complete = text.rsplit("\n", 1)[0] if "\n" in text else ""
        if not complete:
            raise ControlError("SUPERVISOR_LOG_PREFIX_INCOMPLETE")
        return complete

    def log_window(self, slug: str) -> tuple[str, str]:
        before = self.log_prefix(slug)
        tail = self.log_text(slug)
        after = self.log_prefix(slug)
        # Journal timestamp on the first line identifies the container epoch;
        # no Docker socket or inferred watcher uptime is needed.
        first = before.splitlines()[0]
        if first != after.splitlines()[0] or not re.match(r"\d{4}-\d\d-\d\d[T ]", first):
            raise ControlError("SUPERVISOR_LOG_EPOCH_UNKNOWN_OR_CHANGED")
        return before, tail


class SmlightControl:
    def __init__(self, cfg: Configuration):
        parsed = urllib.parse.urlsplit(cfg.slzb_url)
        if parsed.scheme != "http" or parsed.username or parsed.password or (
            parsed.hostname not in ("192.168.50.59",)
        ) or parsed.port not in (None, 80) or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ControlError("SLZB_LAN_ALLOWLIST_MISMATCH")
        self.cfg = cfg
        self.opener = urllib.request.build_opener(_NoRedirect())

    def fetch(self, path: str, query: dict | None = None,
              *, timeout: int = 8) -> str:
        if not path.startswith("/") or path.startswith("//") or ".." in path:
            raise ControlError("UNSAFE_SLZB_PATH")
        q = urllib.parse.urlencode(query or {})
        url = self.cfg.slzb_url.rstrip("/") + path + (("?" + q) if q else "")
        req = urllib.request.Request(url, method="GET")
        # Private API requests are local-only, no generic user-provided URL.
        with self.opener.open(req, timeout=timeout) as r:
            if r.status != 200:
                raise ControlError("SLZB_HTTP_NOT_200")
            body = r.read(300_001)
            if len(body) > 300_000:
                raise ControlError("SLZB_RESPONSE_TOO_LARGE")
            encoding = r.headers.get("Content-Encoding", "").lower()
            if encoding == "gzip" or body.startswith(b"\x1f\x8b"):
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                        body = stream.read(300_001)
                except (OSError, EOFError) as exc:
                    raise ControlError("SLZB_INVALID_GZIP_RESPONSE") from exc
                if len(body) > 300_000:
                    raise ControlError("SLZB_DECOMPRESSED_RESPONSE_TOO_LARGE")
            elif encoding not in ("", "identity"):
                raise ControlError("SLZB_UNSUPPORTED_CONTENT_ENCODING")
            return body.decode("utf-8", "strict")

    def identity(self) -> dict:
        d = json.loads(self.fetch("/ha_info"))
        info = d.get("Info", {})
        if (info.get("model") != "SLZB-06p7U" or
            info.get("zb_hw") != "CC2652P7" or
            info.get("coord_mode") != 2):
            raise ControlError("SLZB_MODEL_RADIO_OR_USB_MODE_MISMATCH")
        if info.get("sw_version") != self.cfg.expected_sw_version:
            raise ControlError("SLZB_FIRMWARE_VERSION_MISMATCH")
        mac = _mac(str(info.get("MAC", "")))
        if self.cfg.expected_mac and mac != _mac(self.cfg.expected_mac):
            raise ControlError("SLZB_MAC_MISMATCH")
        return {"model": info["model"], "zb_hw": info["zb_hw"],
                "coord_mode": info["coord_mode"],
                "sw_version": info.get("sw_version"), "MAC": mac}

    def verify_private_control(self) -> dict:
        """Read-only admission for both fixed restart opcodes."""
        if not self.cfg.expected_mac:
            raise ControlError("SLZB_MAC_NOT_PINNED")
        identity = self.identity()
        js = self.fetch("/js/httpApi.js")
        # Vendor private API contracts are version-sensitive; every side
        # effect is preceded by a fresh source check. NEVER expose cmd=9.
        digest = hashlib.sha256(js.encode("utf-8")).hexdigest()
        if not re.fullmatch(r"[0-9a-f]{64}", self.cfg.expected_js_sha256) or digest != self.cfg.expected_js_sha256:
            raise ControlError("SLZB_COMMAND_SOURCE_HASH_MISMATCH")
        required = {"API_CMD": 4, "CMD_ZB_RST": 1, "CMD_ESP_RES": 3,
                    "CMD_HARD_RESET": 9}
        valid = bool(re.search(r'''\bapiLink\s*=\s*["']/api2\?action=["']''', js))
        for key, number in required.items():
            values = re.findall(r"(?<![\w$])" + key + r"\s*:\s*(\d+)(?![\w.])", js)
            valid = valid and values == [str(number)]
        if not valid:
            raise ControlError("UNVERIFIED_INSTALLED_SLZB_COMMAND_MAP")
        return {"MAC": identity["MAC"], "sw_version": identity["sw_version"],
                "js_sha256": digest}

    def private_restart(self, operation: str) -> bool:
        if operation not in _ALLOWED:
            raise ControlError("UNAPPROVED_SLZB_COMMAND")
        self.verify_private_control()
        response = self.fetch("/api2", {"action": 4,
                                           "cmd": _ALLOWED[operation][0]})
        if response.strip().lower() != "ok":
            raise ControlError("SLZB_RESTART_NOT_ACKNOWLEDGED")
        return True


def verify_native_binding(cfg: Configuration, operation: str, entity_id: str) -> None:
    """Read HA's existing registry; never discover or press another entity."""
    if operation not in _ALLOWED:
        raise ControlError("UNAPPROVED_SLZB_COMMAND")
    expected = _mac(cfg.expected_mac)
    suffix = "core_restart" if operation == "RESTART_ESP" else "zigbee_restart"
    directory = Path(cfg.registry_directory)
    def registry(name, key):
        path = directory / name
        if path.is_symlink() or path.stat().st_size > 8_000_000:
            raise ControlError("NATIVE_REGISTRY_UNSAFE")
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = data.get("data", {}).get(key)
        if not isinstance(entries, list):
            raise ControlError("NATIVE_REGISTRY_INVALID")
        return entries
    entities = [e for e in registry("core.entity_registry", "entities")
                if isinstance(e, dict) and e.get("entity_id") == entity_id]
    if len(entities) != 1:
        raise ControlError("NATIVE_BUTTON_REGISTRY_MISSING_OR_DUPLICATE")
    entity = entities[0]
    if (entity.get("platform") != "smlight" or entity.get("disabled_by") is not None or
            entity.get("unique_id") != expected + "-" + suffix):
        raise ControlError("NATIVE_BUTTON_OPERATION_OR_MAC_MISMATCH")
    devices = [d for d in registry("core.device_registry", "devices")
               if isinstance(d, dict) and d.get("id") == entity.get("device_id")]
    if len(devices) != 1:
        raise ControlError("NATIVE_DEVICE_REGISTRY_MISSING_OR_DUPLICATE")
    device = devices[0]
    connections = device.get("connections", [])
    # HA 2026.9 device registry uses singular config_entry_id; older records
    # use config_entries. Require an explicit matching owner for both schemas.
    registered_entries = device.get("config_entries")
    if registered_entries is None:
        entry = device.get("config_entry_id")
        registered_entries = [entry] if isinstance(entry, str) else []
    if (not isinstance(registered_entries, list) or
            not entity.get("config_entry_id") or
            entity["config_entry_id"] not in registered_entries or
            ["mac", expected] not in connections):
        raise ControlError("NATIVE_BUTTON_DEVICE_BINDING_MISMATCH")


class HAActuator:
    """Only executable side effects: evidence, stop/start Z2M, restart radio/ESP."""

    def __init__(self, cfg: Configuration, supervisor: SupervisorClient,
                 slzb: SmlightControl, evidence_callback):
        self.cfg, self.supervisor, self.slzb = cfg, supervisor, slzb
        self.evidence_callback = evidence_callback

    def perform_once(self, action: str) -> bool:
        if action == "CAPTURE_EVIDENCE":
            return bool(self.evidence_callback())
        if action not in ("STOP_Z2M", "START_Z2M", *_ALLOWED):
            raise ControlError("UNSUPPORTED_ACTION")
        if not self.cfg.expected_mac:
            raise ControlError("SLZB_MAC_NOT_PINNED")
        self.slzb.identity()
        if not self.supervisor.hardware_has_port(self.cfg.expected_by_id):
            raise ControlError("USB_PHYSICAL_DEVICE_NOT_ENUMERATED")
        if action == "STOP_Z2M":
            state = self.supervisor.addon_state(self.cfg.addon_slug)
            return (state in ("error", "stopped") or
                    self.supervisor.service(self.cfg.addon_slug, "stop"))
        if action == "START_Z2M":
            if self.supervisor.addon_state(self.cfg.addon_slug) not in ("error", "stopped"):
                raise ControlError("Z2M_NOT_QUIESCENT_BEFORE_START")
            return self.supervisor.service(self.cfg.addon_slug, "start")
        if action in _ALLOWED:
            if self.supervisor.addon_state(self.cfg.addon_slug) not in ("error", "stopped"):
                raise ControlError("Z2M_NOT_QUIESCENT_BEFORE_RESET")
            entity = (self.cfg.esp_restart_entity if action == "RESTART_ESP"
                      else self.cfg.zigbee_restart_entity)
            if entity:
                verify_native_binding(self.cfg, action, entity)
                return self.supervisor.button(entity)
            if self.cfg.allow_private_http_fallback:
                return self.slzb.private_restart(action)
            raise ControlError("NO_APPROVED_NATIVE_BUTTON_OR_VERIFIED_FALLBACK")
        raise ControlError("UNSUPPORTED_ACTION")
