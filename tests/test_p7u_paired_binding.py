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
        package["operator_source_sha"]="not-a-source"
        with self.assertRaisesRegex(ValueError,"PACKAGE_SOURCE"):self.call(data,package)

    def test_independently_qualified_operator_keeps_firmware_and_host_paired(self):
        data,package=self.fixture();package['operator_source_sha']='d'*40
        self.assertEqual(self.call(data,package)['SOURCE'],data['source_sha'])
        data.update(readonly_hold_operation='2'*32,readonly_hold_plan_pin='e'*64,readonly_hold_pin='f'*64)
        result=self.call(data,package)
        self.assertEqual(str(result['HELD_ROM']),'/share/p7u-r4-firmware-operations/'+'2'*32)
        data.update(readonly_attach_operation='3'*32,readonly_attach_plan_pin='1'*64,readonly_attach_pin='2'*64)
        self.assertEqual(self.call(data,package)['FAILED_ATTACH'].name,'3'*32)
        data['readonly_attach_operation']='not-an-id'
        with self.assertRaisesRegex(ValueError,'READONLY_ATTACH_FIELDS'):self.call(data,package)
        data['readonly_attach_operation']='3'*32
        data['readonly_hold_operation']='../arbitrary'
        with self.assertRaisesRegex(ValueError,'READONLY_HOLD_FIELDS'):self.call(data,package)

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

    def test_qualified_host_repair_requires_explicit_known_v43_wire_contract(self):
        data,package=self.fixture();data['source_sha']='899f179031aae74db2e48699900f1cf5722bb4de'
        package['firmware_source_sha']=data['source_sha'];package['paired_host_source_sha']='d'*40
        with self.assertRaisesRegex(ValueError,'PAIRED_HOST'):self.call(data,package)
        package['f2_wire_contract']='R4D4_MINOR3_240_V1'
        self.assertEqual(self.call(data,package)['PAIRED_HOST_VERSION'],'0.2.1-'+'d'*12)
        package['f2_wire_contract']='unknown'
        with self.assertRaisesRegex(ValueError,'PAIRED_HOST'):self.call(data,package)
        data,package=self.fixture();package["paired_host_source_sha"]="d"*40
        with self.assertRaisesRegex(ValueError,"PAIRED_HOST"):self.call(data,package)
