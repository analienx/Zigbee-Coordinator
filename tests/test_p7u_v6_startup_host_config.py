"""Offline configuration migration mutation checks; no hardware or service APIs."""
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

p=Path(__file__).resolve().parents[1]/"host/flash/p7u_v6_startup_host_config.py"
spec=importlib.util.spec_from_file_location("p7u_v6_startup_host_config",p)
config=importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)

BASE=b"name: P7U\nversion: 0.2.1-2c2d96d6334b\nenvironment:\n  P7U_B4_COLLECTOR: '1'\n  P7U_B4_STARTUP_CAPTURE: '0'\n  P7U_APPROVED_DB_MANIFEST: /config/zigbee2mqtt/.p7u-approved.json\n"
OLD=BASE.replace(b"0.2.1-2c2d96d6334b",b"0.2.1-66ed700c2818").replace(
    config.SOURCE_STARTUP,config.OLD_FLAGS)


class ConfigTests(unittest.TestCase):
    def render(self,old=OLD,release=BASE):
        with patch.object(config,"OLD_SHA256",config.sha256(OLD)),patch.object(
            config,"SOURCE_SHA256",config.sha256(BASE)):
            return config.render(old,release)

    def test_exact_expected_difference_only(self):
        result=self.render()
        self.assertIn(b"P7U_B4_STARTUP_CAPTURE: '1'",result)
        self.assertIn(config.OLD_FLAGS,result)
        self.assertEqual(result.count(b"P7U_B4_STARTUP_CAPTURE"),1)
        self.assertIn(b"version: 0.2.1-2c2d96d6334b",result)

    def test_changed_installed_baseline_holds(self):
        for change in (OLD+b"unexpected\n",OLD.replace(b"COLLECTOR: '1'",b"COLLECTOR: '0'")):
            with self.assertRaisesRegex(ValueError,"INSTALLED_CONFIG_DRIFT"):
                self.render(change)

    def test_wrong_source_candidate_holds(self):
        for change in (BASE.replace(b"'0'",b"'1'"),BASE+b"extra: true\n"):
            with self.assertRaisesRegex(ValueError,"QUALIFIED_SOURCE_CONFIG_DRIFT"):
                self.render(release=change)

    def test_no_other_diff_even_when_hashes_rebound(self):
        candidate=BASE.replace(b"name: P7U",b"name: DIFFERENT")
        with patch.object(config,"OLD_SHA256",config.sha256(OLD)),patch.object(
            config,"SOURCE_SHA256",config.sha256(candidate)):
            with self.assertRaisesRegex(ValueError,"CONFIG_UNEXPECTED_DIFFERENCE"):
                config.render(OLD,candidate)

    def test_disabled_or_missing_startup_optin_holds(self):
        candidate=BASE.replace(config.SOURCE_STARTUP,b"")
        with patch.object(config,"OLD_SHA256",config.sha256(OLD)),patch.object(
            config,"SOURCE_SHA256",config.sha256(candidate)):
            with self.assertRaisesRegex(ValueError,"CONFIG_EXPECTED_SHAPE"):
                config.render(OLD,candidate)


if __name__=="__main__":
    unittest.main()
