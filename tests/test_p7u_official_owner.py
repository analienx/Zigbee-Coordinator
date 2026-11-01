"""Official Zigbee2MQTT app as the sole P7U serial owner. Never contacts HA or serial."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "host" / "flash"))
import p7u_paired_binding as b  # noqa: E402

V54 = "20a2474a67c1d420b6614b3fcb2f7ed543b1420e"
V53 = "8ec1439786e3e98151d2796e6797675bb9ef5965"
OWNER_ID = "a" * 64


def binding(source=V54, installed=V53):
    data = {"schema": "p7u-paired-operation-v1", "source_sha": source, "installed_source": installed,
            "previous_operation": "b66de81f093ee1556fc870831e10490c",
            **{k: "1" * 64 for k in b.PIN_FIELDS}}
    raw = json.dumps(data, sort_keys=True).encode()
    return raw, hashlib.sha256(raw).hexdigest()


def official_package(**over):
    p = {"firmware_source_sha": V54, "operator_source_sha": "f" * 40,
         "paired_host_mode": b.OFFICIAL_MODE, "paired_host_slug": b.OFFICIAL_OWNER,
         "paired_host_version": b.OFFICIAL_OWNER_VERSION, "paired_host_image": b.OFFICIAL_OWNER_IMAGE,
         "paired_host_source_sha": V54, "f2_wire_contract": b.OWNED_STAGE_WIRE}
    p.update(over)
    return p


class BindingTests(unittest.TestCase):
    def test_official_package_binds_official_owner(self):
        raw, pin = binding()
        values = b.binding_values(raw, pin, official_package())
        self.assertEqual(values["OWNER"], "45df7312_zigbee2mqtt")
        self.assertEqual(values["IMAGE"], b.OFFICIAL_OWNER_IMAGE)
        self.assertEqual(values["PAIRED_HOST_VERSION"], "2.14.2-1")
        self.assertEqual(values["OWNER_IMAGE_REF"], b.OFFICIAL_OWNER_IMAGE_REF)
        self.assertTrue(values["OFFICIAL_OWNER"])
        self.assertEqual((values["SOURCE"], values["INSTALLED"]), (V54, V53))

    def test_every_official_pin_is_enforced(self):
        raw, pin = binding()
        for field, bad in (("paired_host_image", "sha256:" + "0" * 64), ("paired_host_slug", "local_p7u_r4_native_host"),
                           ("paired_host_version", "2.14.3-1"), ("paired_host_source_sha", V53),
                           ("f2_wire_contract", "R4D4_MINOR3_240_V1")):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "PAIRED_HOST"):
                b.binding_values(raw, pin, official_package(**{field: bad}))

    def test_v54_requires_v53_predecessor(self):
        raw, pin = binding(installed="a70ae24ff45e708e13969cd341c9ecb494d1570f")
        with self.assertRaisesRegex(ValueError, "SOURCES"):
            b.binding_values(raw, pin, official_package())

    def test_v54_never_pairs_with_custom_host(self):
        raw, pin = binding()
        legacy = official_package(paired_host_mode=None, paired_host_image=b.V6_STARTUP_CAPTURE_IMAGE)
        with self.assertRaisesRegex(ValueError, "PAIRED_HOST"):
            b.binding_values(raw, pin, legacy)

    def test_official_mode_rejected_for_other_firmware(self):
        raw, pin = binding(source=V53, installed="a70ae24ff45e708e13969cd341c9ecb494d1570f")
        with self.assertRaisesRegex(ValueError, "PAIRED_HOST"):
            b.binding_values(raw, pin, official_package(firmware_source_sha=V53, paired_host_source_sha=V53))


class DriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("p7u_driver_official", ROOT / "tools/p7u_ha_flash_driver.py")
        cls.d = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.d)

    def test_official_identity(self):
        self.assertEqual(self.d.host_identity(official_package(), V54),
                         (b.OFFICIAL_OWNER, b.OFFICIAL_OWNER_IMAGE))

    def test_official_identity_fails_closed(self):
        with self.assertRaises(SystemExit):
            self.d.host_identity(official_package(paired_host_image="sha256:" + "0" * 64), V54)
        with self.assertRaises(SystemExit):
            self.d.host_identity(official_package(), V53)

    def test_legacy_identity_unchanged(self):
        legacy = {"paired_host_source_sha": self.d.HOST_SOURCE, "paired_host_image": self.d.HOST_IMAGE}
        self.assertEqual(self.d.host_identity(legacy, V53), ("local_p7u_r4_native_host", self.d.HOST_IMAGE))


try:
    import fcntl  # noqa: F401  (the operator is Linux/HA only)
    HAVE_FCNTL = True
except ImportError:
    HAVE_FCNTL = False


@unittest.skipUnless(HAVE_FCNTL, "operator imports fcntl; runs in CI on Linux")
class OperatorTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("p7u_operator_official", ROOT / "host/flash/p7u_pr154_ha.py")
        self.op = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.op)
        raw, pin = binding()
        vars(self.op).update(b.binding_values(raw, pin, official_package()))

    def scan(self, rows, owner_running=True):
        inspect = json.dumps([{"Id": OWNER_ID, "Image": b.OFFICIAL_OWNER_IMAGE,
                               "State": {"Running": owner_running}}]).encode()
        def run(args, timeout=30):
            if args[:2] == ["docker", "run"]:
                self.assertIn("--pid=host", args)
                self.assertIn("none", args)
                self.assertIn(b.OFFICIAL_OWNER_IMAGE, args)
                return "\n".join(rows).encode()
            if args[:2] == ["docker", "inspect"]:
                self.assertEqual(args[2], "app_45df7312_zigbee2mqtt")
                return inspect
            raise AssertionError(args)
        return patch.multiple(self.op, run=run, SERIAL="/dev/ttyACM0")

    def test_active_proof_requires_only_owner_holders(self):
        with self.scan(["9038 MainThread /dev/ttyACM0 " + OWNER_ID, "77 getty /dev/tty1 host"]):
            p = self.op.HA().proof(True)
        self.assertEqual(p["slots"]["diagnostic"]["container_id"], OWNER_ID)
        self.assertEqual(p["tty_holders_pids"], [9038])

    def test_foreign_holder_is_refused(self):
        with self.scan(["9038 MainThread /dev/ttyACM0 " + OWNER_ID, "4242 python3 /dev/ttyACM0 " + "b" * 64]):
            with self.assertRaisesRegex(self.op.Hold, "TTY_OWNER"):
                self.op.HA().proof(True)

    def test_active_without_holder_is_refused(self):
        with self.scan([]):
            with self.assertRaisesRegex(self.op.Hold, "TTY_OWNER"):
                self.op.HA().proof(True)

    def test_quiescent_requires_no_holder(self):
        with self.scan([]):
            self.assertEqual(self.op.HA().proof(False)["tty_holders_pids"], [])
        with self.scan(["9038 MainThread /dev/ttyACM0 host"]):
            with self.assertRaisesRegex(self.op.Hold, "TTY_NOT_QUIESCENT"):
                self.op.HA().proof(False)

    def test_policy_tolerates_retired_apps_but_not_autostart(self):
        owner = {"version": "2.14.2-1", "boot": "manual", "watchdog": False, "auto_update": False}
        infos = {"45df7312_zigbee2mqtt": owner,
                 "local_p7u_r4_native_host": {"state": "stopped", "boot": "manual"},
                 "local_p7u_r4_owner_inspector": {"installed": False},
                 "local_p7u_recovery": {"installed": False},
                 "local_p7u_r4_lifecycle_manager": {"installed": False}}
        def info(self, slug):
            if slug not in infos: raise self_op.Hold("ADDON_INFO")
            return infos[slug]
        self_op = self.op
        states = lambda self, url, payload=None: {"entity_id": url.rsplit("/", 1)[1], "state": "off"}
        with patch.object(self.op.HA, "info", info), patch.object(self.op.HA, "request", states):
            self.op.HA().policy()
            infos["local_p7u_r4_native_host"] = {"state": "stopped", "boot": "auto"}
            with self.assertRaisesRegex(self.op.Hold, "LEGACY_APP_POLICY"):
                self.op.HA().policy()
            infos["local_p7u_r4_native_host"] = {"installed": False}
            infos["45df7312_zigbee2mqtt"] = dict(owner, version="2.14.3-1")
            with self.assertRaisesRegex(self.op.Hold, "HOST_POLICY"):
                self.op.HA().policy()

    def test_device_bound_admits_200(self):
        self.assertEqual((self.op.PEERS_MIN, self.op.PEERS_MAX), (100, 200))


if __name__ == "__main__":
    unittest.main()
