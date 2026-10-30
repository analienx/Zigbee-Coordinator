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
    def test_owned_stage_pair_requires_exact_predecessor_host_and_wire(self):
        data,package=self.fixture();data['source_sha']=binding.OWNED_STAGE_PAIR[0]
        data['installed_source']=binding.QUALIFIED_SUCCESSORS[data['source_sha']]
        package.update(firmware_source_sha=data['source_sha'],paired_host_source_sha=binding.OWNED_STAGE_PAIR[1],f2_wire_contract=binding.OWNED_STAGE_WIRE)
        self.assertEqual(self.call(data,package)['INSTALLED'],data['installed_source'])
        for key,value in (('paired_host_source_sha','d'*40),('f2_wire_contract','unknown')):
            bad={**package,key:value}
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'PAIRED_HOST'):self.call(data,bad)
        data['installed_source']=binding.INSTALLED
        with self.assertRaisesRegex(ValueError,'SOURCES'):self.call(data,package)
    def test_v6_startup_capture_requires_exact_host_image_and_wire(self):
        data, package = self.fixture()
        data['source_sha'] = binding.OWNED_STAGE_PAIR[0]
        data['installed_source'] = binding.QUALIFIED_SUCCESSORS[data['source_sha']]
        package.update(firmware_source_sha=data['source_sha'],
                       paired_host_source_sha=binding.V6_STARTUP_CAPTURE_HOST,
                       paired_host_image=binding.V6_STARTUP_CAPTURE_IMAGE,
                       f2_wire_contract=binding.OWNED_STAGE_WIRE)
        result = self.call(data, package)
        self.assertEqual(result['SOURCE'], data['source_sha'])
        self.assertEqual(result['PAIRED_HOST_VERSION'],
                         '0.2.1-' + binding.V6_STARTUP_CAPTURE_HOST[:12])
        self.assertEqual(result['IMAGE'], binding.V6_STARTUP_CAPTURE_IMAGE)
        for field, bad in (('paired_host_image','sha256:'+'0'*64),
                           ('paired_host_source_sha','2'*40),
                           ('f2_wire_contract','R4D4_MINOR4_AND_R4D5_PAGED_V1')):
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'PAIRED_HOST'):
                self.call(data,{**package,field:bad})
        data['source_sha']='e3a0f3b7726adf1f6c182973f135665a5c3857e0'
        data['installed_source']=binding.QUALIFIED_SUCCESSORS[data['source_sha']]
        # Incompatible firmware is rejected at the stricter package-source gate.
        with self.assertRaisesRegex(ValueError,'PACKAGE_SOURCE'):
            self.call(data,package)

    def test_v48_exact_successor_to_v47_reuses_instrumented_host(self):
        data,package=self.fixture()
        data.update(source_sha='250441cd17c55e25c78d97e041f056574355ade7',
                    installed_source='391d7a5b24d459f347a8ff2378c751ebcc7eec4b')
        package.update(firmware_source_sha=data['source_sha'],
                       paired_host_source_sha=binding.V6_STARTUP_CAPTURE_HOST,
                       paired_host_image=binding.V6_STARTUP_CAPTURE_IMAGE,
                       f2_wire_contract=binding.OWNED_STAGE_WIRE)
        self.assertEqual(self.call(data,package)['INSTALLED'],data['installed_source'])
        for key,wrong in (('paired_host_image','sha256:'+'0'*64),
                          ('paired_host_source_sha','f'*40),
                          ('f2_wire_contract','unknown')):
            with self.subTest(field=key),self.assertRaisesRegex(ValueError,'PAIRED_HOST'):
                self.call(data,{**package,key:wrong})
        with self.assertRaisesRegex(ValueError,'SOURCES'):
            self.call({**data,'installed_source':'66ed700c2818c7a0963dad9160d55109009bbaac'},package)

    def test_v50_exact_successor_to_v48_reuses_instrumented_host(self):
        data,package=self.fixture()
        data.update(source_sha='540d75a23d11587fb45fd892c5e9ae01ec0aab15',
                    installed_source='250441cd17c55e25c78d97e041f056574355ade7')
        package.update(firmware_source_sha=data['source_sha'],
                       paired_host_source_sha=binding.V6_STARTUP_CAPTURE_HOST,
                       paired_host_image=binding.V6_STARTUP_CAPTURE_IMAGE,
                       f2_wire_contract=binding.OWNED_STAGE_WIRE)
        self.assertEqual(self.call(data,package)['INSTALLED'],data['installed_source'])
        for key,wrong in (('paired_host_image','sha256:'+'0'*64),
                          ('paired_host_source_sha','f'*40),
                          ('f2_wire_contract','unknown')):
            with self.subTest(field=key),self.assertRaisesRegex(ValueError,'PAIRED_HOST'):
                self.call(data,{**package,key:wrong})
        with self.assertRaisesRegex(ValueError,'SOURCES'):
            self.call({**data,'installed_source':'66ed700c2818c7a0963dad9160d55109009bbaac'},package)

    def test_v50_ready_observer_priority_is_exact_source_not_bypassed(self):
        import ast
        path=Path(__file__).resolve().parents[1]/"firmware/slzb-06p7u/r4/release/p7u_r4_startup_observer.py"
        src=path.read_text()
        tree=ast.parse(src)
        names=("V50_SOURCES","expected_ready_npi_priority","stack_evidence_supported")
        nodes=[n for n in tree.body if
               (isinstance(n,ast.FunctionDef) and n.name in names) or
               (isinstance(n,ast.Assign) and any(getattr(t,"id",None) in names for t in n.targets))]
        self.assertEqual(len(nodes),3)
        scope={}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),"exec"),scope)
        self.assertEqual(scope["V50_SOURCES"],frozenset({"540d75a23d11587fb45fd892c5e9ae01ec0aab15"}))
        self.assertEqual(scope["expected_ready_npi_priority"]("540d75a23d11587fb45fd892c5e9ae01ec0aab15"),6)
        self.assertEqual(scope["expected_ready_npi_priority"]("250441cd17c55e25c78d97e041f056574355ade7"),4)
        self.assertEqual(scope["expected_ready_npi_priority"]("0"*40),4)
        self.assertTrue(scope["stack_evidence_supported"]("540d75a23d11587fb45fd892c5e9ae01ec0aab15"))
        self.assertFalse(scope["stack_evidence_supported"]("250441cd17c55e25c78d97e041f056574355ade7"))
        self.assertIn('info["npi_priority"]==expected_ready_npi_priority(source)',src)
        for gate in ("UTIL_NOT_COORDINATOR_STATE9","CONFIGURED_MARKER_NOT_VERIFIED",
                     "RETAINED_TRANSACTION_MILESTONES_INCOMPLETE"):
            self.assertIn(gate,src)

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

class RuntimePrioritySuccessorBinding(unittest.TestCase):
    def test_only_exact_successor_and_unchanged_v5_host_pair(self):
        helper=Binding(); data,package=helper.fixture()
        data.update(source_sha="e3a0f3b7726adf1f6c182973f135665a5c3857e0",installed_source="85ce37c24802b0f16fec0afd00a1a0457656cd80")
        package.update(firmware_source_sha="e3a0f3b7726adf1f6c182973f135665a5c3857e0",paired_host_source_sha="85ce37c24802b0f16fec0afd00a1a0457656cd80",
                       f2_wire_contract="R4D4_MINOR4_AND_R4D5_PAGED_V1")
        result=helper.call(data,package)
        self.assertEqual(result['INSTALLED'],"85ce37c24802b0f16fec0afd00a1a0457656cd80")
        self.assertEqual(result['SOURCE'],"e3a0f3b7726adf1f6c182973f135665a5c3857e0")
        self.assertEqual(result['PAIRED_HOST_VERSION'],"0.2.1-85ce37c24802")
        for field,bad in (('installed_source',binding.INSTALLED),('source_sha','f'*40)):
            changed=dict(data);changed[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):helper.call(changed,package)
        for field,bad in (('paired_host_source_sha','e'*40),('f2_wire_contract',None)):
            changed=dict(package);changed[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):helper.call(data,changed)
