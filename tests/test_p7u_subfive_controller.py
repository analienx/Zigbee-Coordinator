"""No-radio regression for exact-source preparation and USB/ZNP transport."""
from pathlib import Path
import copy
import hashlib
import json
import socket
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
for p in (ROOT/"tools",ROOT/"firmware/slzb-06p7u/r4/release"):
    sys.path.insert(0,str(p))
import p7u_build_flash as b
import p7u_prepared_deps as deps
from p7u_usb_startup_serial import UsbStartupTransport
from p7u_r4_startup_transport import FramedZnp


class FakeSerial:
    def __init__(self,frames=()):
        self.rx=list(frames)
        self.tx=[]
        self.timeout=None
        self.write_timeout=None
        self.closed=False
    def read(self,n):
        return self.rx.pop(0) if self.rx else b""
    def write(self,x):
        self.tx.append(x)
        return len(x)
    def flush(self):pass
    def close(self):self.closed=True


class SubfiveContractTests(unittest.TestCase):
    def test_source_tests_cannot_be_runtime_noop(self):
        self.assertEqual(len(b.REQUIRED_SOURCE_TESTS),1)
        self.assertGreaterEqual(len(b.REQUIRED_SOURCE_TESTS[0]),12)
        self.assertIn("tests/test_p7u_known_r4_fastpath.py",b.REQUIRED_SOURCE_TESTS[0])

    def test_execute_stops_before_any_build_or_hardware_operation(self):
        with self.assertRaisesRegex(b.Hold,"HA_HARDWARE_EXECUTOR_NOT_YET_QUALIFIED"):
            b.run({},execute=True)

    def test_arg_value_requires_single_value_and_out_path(self):
        self.assertIsNone(b.argv_value(["python","--source"],"--source"))
        self.assertIsNone(b.argv_value(["python","--source","x","--source","y"],"--source"))
        self.assertEqual(b.argv_value(["python","--source","abc"],"--source"),"abc")

    def test_real_budget_includes_build_boot_traffic_and_margin(self):
        self.assertEqual(sum(b.BUDGET.values()),290.)
        self.assertEqual(b.TARGET_SECONDS,290.)

    def test_one_clean_source_bound_build_is_required(self):
        h={k:"a"*64 for k in ("app","handoff","elf","source_manifest")}
        a={"worker":"build-1","clean_app_build":True,
           "dependency_identity":"b"*64,"artifact_hashes":h}
        self.assertEqual(b.check_clean_build(a),h)
        for invalid in (dict(a,clean_app_build=False),
                        dict(a,worker="replica-2"),
                        dict(a,dependency_identity="wrong"),
                        dict(a,artifact_hashes={**h,"elf":"wrong"})):
            with self.assertRaisesRegex(b.Hold,
                                        "FRESH_CLEAN_APP_BUILD_REQUIRED|BUILT_ARTIFACT_HASHES_REQUIRED"):
                b.check_clean_build(invalid)

    def test_live_receipt_must_include_full_sha_real_owner_and_traffic(self):
        s={"schema":"p7u-sub5-live-result-v1","source_sha":"1"*40,
           "installed_source_sha":"1"*40,"flash_verification":"ALL88_ROM_SHA",
           "protected_nv_writes":0,"ccfg_writes":0,"state":9,
           "owner":"ORIGINAL_Z2M","exclusive_uart_owner":True,
           "fresh_nonretained_device_reports":1,"observation_seconds":10,
           "startup_errors":0,"owner_start_attempts":1}
        self.assertTrue(b.verify_operation_result(s,"1"*40))
        for key,val in [("flash_verification","WRITTEN_PLUS_CRC"),
                        ("state",8),("fresh_nonretained_device_reports",0),
                        ("protected_nv_writes",1),("owner_start_attempts",2)]:
            fail=dict(s,**{key:val})
            with self.assertRaisesRegex(b.Hold,"END_TO_END_ACCEPTANCE_INCOMPLETE"):
                b.verify_operation_result(fail,"1"*40)

    def test_immutable_deps_reject_changed_library_and_source_pins(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/"sdk").mkdir()
            (root/"sdk/lib1.a").write_bytes(b"alpha")
            (root/"sdk/lib2.a").write_bytes(b"beta")
            d={"schema":"p7u-prepared-ti-deps-v1",
               "pins":dict(deps.REQUIRED_PINS),"immutable_root":str(root/"sdk"),
               "verified_files":{"lib1.a":deps.digest(b"alpha"),
                                 "lib2.a":deps.digest(b"beta")},
               "qualified_sdk_library_sets":1,
               "clean_app_objects_required":True,"reuse_app_objects":False,
               "provisioned":True,"immutable_mount":True,
               "container_digest_pinned":True}
            d.update({k:"a"*64 for k in deps.CONTROL_FIELDS})
            d["identity_sha256"]=deps.digest(deps.canonical(d))
            path=root/"manifest.json"
            path.write_bytes(deps.canonical(d))
            self.assertEqual(deps.verify_manifest(path)["identity_sha256"],
                             d["identity_sha256"])
            (root/"sdk/lib1.a").write_bytes(b"tampered")
            with self.assertRaisesRegex(deps.DependencyHold,"SHA_MISMATCH"):
                deps.verify_manifest(path)
            (root/"sdk/lib1.a").write_bytes(b"alpha")
            d["pins"]["ccs"]="12.9.0"
            d["identity_sha256"]=deps.digest(deps.canonical({k:v for k,v in d.items()
                                                              if k!="identity_sha256"}))
            path.write_bytes(deps.canonical(d))
            with self.assertRaisesRegex(deps.DependencyHold,"PINS_CHANGED"):
                deps.verify_manifest(path)

    def test_single_build_candidate_is_source_and_file_bound(self):
        from p7u_r4_operator import candidate_verify_fast_single,sha as file_sha
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)
            (base/"app.hex").write_bytes(b":00000001FF\n")
            (base/"handoff.bin").write_bytes(b"h"*8192)
            (base/"app.elf").write_bytes(b"elf")
            (base/"source-manifest.json").write_bytes(b"{}")
            h={name:file_sha((base/name).read_bytes()) for name in
               ("app.hex","handoff.bin","app.elf","source-manifest.json")}
            output={"app":h["app.hex"],"handoff":h["handoff.bin"],
                    "elf":h["app.elf"],"source_manifest":h["source-manifest.json"]}
            report={"worker":"build-1","source_sha":"1"*40,
                    "dependency_identity":"c"*64,"artifact_hashes":output,
                    "clean_app_build":True,"reused_app_objects":False}
            c={"schema":"p7u-stock20260311-candidate-v1",
               "build_mode":"SINGLE_CLEAN_APP_PINNED_DEPENDENCIES","build_count":1,
               "source_sha":"1"*40,"prepared_identity_sha256":"c"*64,
               "board":"SLZB-06P7U-r1.73-CC2652P7",
               "boot_contract":"APP0_REQUIRES_SEPARATE_AC000_HANDOFF",
               "private_current_capture_and_security_preflight_required":True,
               "flash_authorized":False,"hardware_boot_qualified":False,
               "replicas":[report],"app_hex_sha256":output["app"],
               "handoff_sha256":output["handoff"],"files":h}
            (base/"candidate.json").write_text(json.dumps(c))
            self.assertEqual(candidate_verify_fast_single(base,"1"*40,output,"c"*64),c)
            with self.assertRaisesRegex(Exception,"SINGLE_BUILD_CONTRACT_CHANGED"):
                candidate_verify_fast_single(base,"2"*40,output,"c"*64)
            c["replicas"][0]["reused_app_objects"]=True
            (base/"candidate.json").write_text(json.dumps(c))
            with self.assertRaisesRegex(Exception,"NOT_ACTUALLY_CLEAN"):
                candidate_verify_fast_single(base,"1"*40,output,"c"*64)
            c["replicas"][0]["reused_app_objects"]=False
            (base/"candidate.json").write_text(json.dumps(c))
            (base/"app.hex").write_bytes(b"tampered")
            with self.assertRaisesRegex(Exception,"FILE_HASH_MISMATCH"):
                candidate_verify_fast_single(base,"1"*40,output,"c"*64)

    def test_znp_uart_is_existing_parser_with_strict_partial_write(self):
        # SRSP subsystem 7, command 0, empty payload.
        wire=b"\xfe\x00\x67\x00\x67"
        fake=FakeSerial([wire])
        transport=UsbStartupTransport(fake)
        znp=FramedZnp(transport)
        import time
        self.assertEqual(znp.request(7,0,deadline=time.monotonic()+.8),b"")
        self.assertEqual(len(fake.tx),1)
        transport.close()
        self.assertTrue(fake.closed)
        with self.assertRaises(OSError):
            transport.recv(20)

    def test_uart_empty_read_is_timeout_not_false_disconnect(self):
        port=UsbStartupTransport(FakeSerial())
        with self.assertRaises(socket.timeout):
            port.recv(32)

if __name__=="__main__":
    unittest.main()
