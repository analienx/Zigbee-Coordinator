"""Offline adversarial tests for R4-00 upstream attester; no network or hardware.

These tests are run on standard GitHub-hosted Actions. They do not claim
an independent protected policy root or native firmware qualification.
"""
import copy
import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "firmware" / "slzb-06p7u" / "r4"
TOOL = BASE / "tools" / "r4_upstream_attest.py"
spec = importlib.util.spec_from_file_location("r4_attester", TOOL)
att = importlib.util.module_from_spec(spec)
spec.loader.exec_module(att)
manifest = json.loads((BASE / "SOURCE_PROVENANCE.json").read_text())

ENV = {
    "EXPECT_TI_SDK_SHA": "3615ad5d3f4f271258d18a2f5ce1785064ff9a58",
    "EXPECT_TI_EXAMPLES_SHA": "87ff5b638b632050228a7504f35cf3b95581c278",
    "EXPECT_HERDSMAN_SHA": "0968f979d558874b17396c96b66382d4236bbdcd",
    "EXPECT_KOENKK_SHA": "5e4db67e550d41ea6dc6cd86ceeb04d82ffe1bfb",
    "EXPECT_KOENKK_PATCH_BLOB": "e015d9a9020e08d049515664693b22a9ce0e1fdb",
    "EXPECT_KOENKK_CHANGELOG_BLOB": "25f8bb3fb3bafe22b860d9a00134a2d722272650",
    "EXPECT_TI_RELEASE": "lpf2-8.33.00.16",
    "EXPECT_HERDSMAN_VERSION": "10.9.1",
    "EXPECT_VENDOR_20260310_SHA256": "f18011d2652651e36d5e1e7e1cb1f7cbcb99e9493eacbbf8e404a036c626afbe",
    "EXPECT_VENDOR_20240710_SHA256": "1e257bc066e7a8db9c12e0b826791cc81d8744b9453355af0f4efce194060d6b",
    "EXPECT_TI_SDK_REPO": "TexasInstruments/simplelink-lowpower-f2-sdk",
    "EXPECT_TI_EXAMPLES_REPO": "TexasInstruments/simplelink-zstack-examples",
    "EXPECT_HERDSMAN_REPO": "Koenkk/zigbee-herdsman",
    "EXPECT_KOENKK_REPO": "Koenkk/Z-Stack-firmware",
    "EXPECT_KOENKK_PATCH_PATH": "coordinator/Z-Stack_3.x.0/firmware.patch",
    "EXPECT_KOENKK_CHANGELOG_PATH": "coordinator/Z-Stack_3.x.0/CHANGELOG.md",
    "EXPECT_SDK_VERSION": "8.33",
    "EXPECT_CCS_VERSION": "12.8.0.00012",
    "EXPECT_TI_ARM_CLANG_VERSION": "3.2.2.LTS",
    "EXPECT_SYSCONFIG_VERSION": "1.21.1.3772",
}

class Response:
    def __init__(self, data=b"abcd", final=None, length=None, status=200):
        self.data = data
        self.url = final or "https://updates.smlight.tech/firmware/release.bin"
        self.headers = {} if length is None else {"Content-Length": str(length)}
        self.status = status
        self.pos = 0

    def __enter__(self): return self
    def __exit__(self, *args): return None
    def geturl(self): return self.url
    def read(self, n):
        chunk = self.data[self.pos:self.pos+n]
        self.pos += len(chunk)
        return chunk

class AttesterHostileTests(unittest.TestCase):
    def test_complete_expectations_pass(self):
        self.assertEqual(att._check_pin_identity(manifest, ENV), [])

    def test_missing_or_empty_each_expectation_fails_closed(self):
        for key in ENV:
            for value in (None, ""):
                with self.subTest(key=key, value=value):
                    env = dict(ENV)
                    if value is None:env.pop(key)
                    else:env[key] = value
                    self.assertTrue(any(key in e for e in
                        att._check_pin_identity(manifest, env)))

    def test_canonical_origins_and_paths_cannot_repoint(self):
        tests = [
            ("ti_lowpower_f2_sdk", "repo", "someone/fork"),
            ("zstack_examples", "repo", "TexasInstruments/fork"),
            ("zigbee_herdsman", "repo", "Koenkk/untrusted"),
            ("koenkk_zstack_firmware", "repo", "attacker/Z-Stack-firmware"),
            ("koenkk_zstack_firmware", "patch", "arbitrary/file.patch"),
            ("koenkk_zstack_firmware", "changelog", "arbitrary/CHANGELOG.md"),
        ]
        for donor, field, wrong in tests:
            with self.subTest(donor=donor, field=field):
                doc = copy.deepcopy(manifest)
                doc["donors"][donor][field] = wrong
                self.assertTrue(att._check_pin_identity(doc, ENV))

    def test_toolchain_and_sdk_version_are_bound(self):
        for field in ("ccs", "ti_arm_clang", "sysconfig"):
            doc = copy.deepcopy(manifest)
            doc["toolchain"][field] = "fake"
            self.assertTrue(att._check_pin_identity(doc, ENV))
        doc = copy.deepcopy(manifest)
        doc["sdk_version"] = "8.32"
        self.assertTrue(att._check_pin_identity(doc, ENV))

    def test_git_object_type_and_fetched_sha(self):
        sha = "a" * 40
        responses = [(0,""), (0,""), (0,""),(0,sha),(0,"commit")]
        with patch.object(att, "_run_git", side_effect=responses) as git:
            self.assertIsNone(att._fetch_exact(Path("."),"Koenkk/zigbee-herdsman",sha,"herdsman"))
            self.assertEqual(git.call_count, 5)
        responses[-1] = (0,"tree")
        with patch.object(att,"_run_git",side_effect=responses):
            self.assertIn("not a commit",att._fetch_exact(Path("."),"Koenkk/zigbee-herdsman",sha,"herdsman"))
        responses[-1] = (0,"commit")
        responses[-2] = (0,"b"*40)
        with patch.object(att,"_run_git",side_effect=responses):
            self.assertIn("exact SHA",att._fetch_exact(Path("."),"Koenkk/zigbee-herdsman",sha,"herdsman"))

    def test_vendor_redirect_size_status(self):
        url = "https://updates.smlight.tech/firmware/release.bin"
        cases=[
            (Response(final="https://evil.example/b.bin"),"unexpected redirect"),
            (Response(final="http://updates.smlight.tech/firmware/release.bin"),"unexpected redirect"),
            (Response(length=3),"Content-Length"),
            (Response(data=b"abcde"),"downloaded bytes"),
            (Response(status=404),"HTTP status"),
        ]
        for resp, label in cases:
            with self.subTest(label=label):
                with patch.object(att.urllib.request,"urlopen",return_value=resp):
                    digest, err=att._download_sha256(url,4)
                self.assertIsNone(digest)
                self.assertIn(label,err)
        with patch.object(att.urllib.request,"urlopen",return_value=Response(length=4)):
            digest,err=att._download_sha256(url,4)
        self.assertIsNone(err)
        self.assertEqual(len(digest),64)

    def test_malformed_numeric_manifest_tuple_fails(self):
        spec = importlib.util.spec_from_file_location("val_r4",BASE/"tools"/"r4_provenance_validate.py")
        val=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(val)
        for field in ("baud","container_bytes_observed"):
            doc=copy.deepcopy(manifest)
            doc["vendor_images"][0][field]=float(doc["vendor_images"][0][field])
            self.assertTrue(any("must be an integer" in e for e in val.validate_provenance(doc)))

    def test_source_anchor_must_bind_same_repo_commit_and_path(self):
        spec=importlib.util.spec_from_file_location("val_r4",BASE/"tools"/"r4_provenance_validate.py")
        val=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(val)
        good=("Koenkk/Z-Stack-firmware@5e4db67e550d41ea6dc6cd86ceeb04d82ffe1bfb "
              "coordinator/Z-Stack_3.x.0/firmware.patch")
        self.assertTrue(val._bound_source_anchor(good))
        self.assertFalse(val._bound_source_anchor(
            "Koenkk/Z-Stack-firmware@"+ENV["EXPECT_KOENKK_SHA"]+
            " elsewhere/file.c coordinator/Z-Stack_3.x.0/firmware.patch"))

if __name__=="__main__":
    unittest.main()
