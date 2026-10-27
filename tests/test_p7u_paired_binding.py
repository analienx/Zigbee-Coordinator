"""Typed release binding tests; no serial, service or private data access."""
import importlib.util
import hashlib
import json
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/"host/flash/p7u_paired_binding.py"
spec=importlib.util.spec_from_file_location("paired_binding",path)
binding=importlib.util.module_from_spec(spec);spec.loader.exec_module(binding)


class Binding(unittest.TestCase):
    def fixture(self):
        value={"schema":"p7u-paired-operation-v1","source_sha":"a"*40,
               "installed_source":binding.INSTALLED,"previous_operation":"1"*32,
               **{key:"b"*64 for key in binding.PIN_FIELDS}}
        package={"firmware_source_sha":"a"*40,"operator_source_sha":"a"*40,
                 "paired_host_image":"sha256:"+"c"*64,"paired_host_source_sha":"a"*40}
        return value,package

    def call(self,value,package,pin=None):
        raw=binding.canonical(value)
        return binding.binding_values(raw,pin or hashlib.sha256(raw).hexdigest(),package)

    def test_fixed_device_paths_and_matched_host(self):
        data,package=self.fixture();result=self.call(data,package)
        self.assertEqual(result["INSTALLED"],binding.INSTALLED)
        self.assertEqual(str(result["INPUT"]),"/share/p7u-paired-input-"+"a"*12)
        self.assertEqual(result["IMAGE"],package["paired_host_image"])
        self.assertNotIn("SERIAL",result)

    def test_changed_binding_or_package_source_is_denied(self):
        data,package=self.fixture()
        with self.assertRaisesRegex(ValueError,"PIN"):self.call(data,package,"d"*64)
        package["operator_source_sha"]="d"*40
        with self.assertRaisesRegex(ValueError,"PACKAGE_SOURCE"):self.call(data,package)

    def test_no_arbitrary_path_command_or_installed_image(self):
        for key,value in (("previous_operation","../../etc"),("source_sha","a"*39+";"),
                          ("installed_source","d"*40),("SERIAL","/dev/other")):
            data,package=self.fixture();data[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.call(data,package)

    def test_only_sealed_hashes_and_image_digests(self):
        data,package=self.fixture();data["candidate_pin"]="not-a-pin"
        with self.assertRaisesRegex(ValueError,"HASH_FIELDS"):self.call(data,package)
        data,package=self.fixture();package["paired_host_image"]="arbitrary:latest"
        with self.assertRaisesRegex(ValueError,"PAIRED_HOST"):self.call(data,package)
        data,package=self.fixture();package["paired_host_source_sha"]="d"*40
        with self.assertRaisesRegex(ValueError,"PAIRED_HOST"):self.call(data,package)
