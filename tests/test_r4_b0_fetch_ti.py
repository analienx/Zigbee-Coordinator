"""TI download trust guardrails: no network requests in unit tests."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
p = ROOT / "firmware/slzb-06p7u/r4/b0/tools/b0_fetch_ti.py"
spec = importlib.util.spec_from_file_location("b0_fetch_ti", p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class FetchTests(unittest.TestCase):
    def test_all_sources_are_version_specific_ti_https(self):
        from urllib.parse import urlparse
        for key, (version, filename, url) in mod.ARTIFACTS.items():
            parsed = urlparse(url)
            self.assertEqual(parsed.hostname, "dr-download.ti.com")
            self.assertEqual(parsed.scheme, "https")
            self.assertIn(version.split(".")[0], url)
            self.assertTrue(parsed.path.endswith("/" + filename))

    def test_exact_vendor_pins_are_present_and_distinct(self):
        self.assertEqual(set(mod.VENDOR_SHA256), set(mod.ARTIFACTS))
        self.assertEqual(len(set(mod.VENDOR_SHA256.values())), 3)
        for key, digest in mod.VENDOR_SHA256.items():
            self.assertTrue(mod.valid_digest(digest), key)
            self.assertTrue(mod.PUBLISHER_PAGES[key].startswith("https://www.ti.com/tool/download/"))

    def test_missing_or_invalid_sha_blocks_before_network(self):
        with tempfile.TemporaryDirectory() as folder:
            for bad in ("UNKNOWN", "", "0" * 63, "G" * 64):
                with self.assertRaisesRegex(ValueError, "publisher SHA-256"):
                    mod.acquire("ccs", bad, Path(folder))
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_unknown_component_blocks(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "unknown TI component"):
                mod.acquire("not-a-tool", "0" * 64, Path(folder))


if __name__ == "__main__":
    unittest.main()
