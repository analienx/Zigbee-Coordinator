"""Real atomic single-build package controls; no hardware, no fake permits."""
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7u/r4/release"))
from p7u_single_candidate_packager import (package,PackagingHold,FILES,EXTRA,
                                          sha,canonical)
from p7u_r4_operator import candidate_verify_fast_single


class PackagerTests(unittest.TestCase):
    def create_inputs(self,path):
        in_dir=path/"in"
        in_dir.mkdir()
        raw={"app":b":00000001FF\n","handoff":b"h"*8192,
             "elf":b"ELF","source_manifest":json.dumps({"schema":"r4-p7u-final-ti-source-snapshot-v1",
              "firmware_source_sha":"1"*40,
              "compiled_source_unchanged_after_snapshot":True,
              "flash_authorized":False}).encode(),
             "profile":b'{"profile":"stock-nv4"}'}
        raw["native_manifest"]=json.dumps({"schema":"r4-b0-artifact-manifest-v1",
                                           "files":{},"provenance":{}}).encode()
        raw["handoff_receipt"]=json.dumps({
            "schema":"r4-p7u-stock20260311-compiled-handoff-v1",
            "status":"COMPILED_M4F_SINGLE_SECTOR_TRANSFER_AUDITED",
            "sector_sha256":sha(raw["handoff"]),
            "profile_sha256":sha(raw["profile"]),
            "source_native_manifest_sha256":sha(raw["native_manifest"])}).encode()
        paths={}
        for name,data in raw.items():
            q=in_dir/(name+".blob")
            q.write_bytes(data)
            paths[name]=q
        hashes={key:sha(raw[key]) for key in FILES}
        receipt={"worker":"build-1","source_sha":"1"*40,
                 "dependency_identity":"2"*64,
                 "artifact_hashes":hashes,
                 "clean_app_build":True,"reused_app_objects":False}
        return paths,receipt,hashes

    def test_exact_clean_one_build_bundle_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            inputs,report,hashes=self.create_inputs(base)
            out=base/"candidate"
            r=package(source_sha="1"*40,prepared_identity="2"*64,
                     files=inputs,worker_receipt=report,out_dir=out)
            self.assertIn("NOT_FLASH_APPROVED",r["status"])
            self.assertEqual(r["files"],len(FILES)+len(EXTRA))
            verified=candidate_verify_fast_single(out,"1"*40,hashes,"2"*64)
            self.assertEqual(verified["build_count"],1)
            self.assertEqual(verified["replicas"],[report])
            with self.assertRaisesRegex(PackagingHold,"NEW_DIRECTORY"):
                package(source_sha="1"*40,prepared_identity="2"*64,
                        files=inputs,worker_receipt=report,out_dir=out)

    def test_tamper_source_or_handoff_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            paths,receipt,_=self.create_inputs(root)
            for label,value in [("wrong_source","3"*40),("wrong_pin","4"*64)]:
                with self.assertRaises(PackagingHold):
                    package(source_sha=value if label=="wrong_source" else "1"*40,
                        prepared_identity=value if label=="wrong_pin" else "2"*64,
                        files=paths,worker_receipt=receipt,out_dir=root/label)
            paths["handoff"].write_bytes(b"X"*8192)
            with self.assertRaisesRegex(PackagingHold,"COMPILER_OUTPUT_HASHES_CHANGED"):
                package(source_sha="1"*40,prepared_identity="2"*64,
                     files=paths,worker_receipt=receipt,out_dir=root/"bad-handoff")
            self.assertFalse((root/"bad-handoff").exists())

    def test_unproven_compilation_or_handoff_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            paths,receipt,_=self.create_inputs(root)
            receipt["reused_app_objects"]=True
            with self.assertRaisesRegex(PackagingHold,"ONE_CLEAN_NATIVE_BUILD"):
                package(source_sha="1"*40,prepared_identity="2"*64,
                     files=paths,worker_receipt=receipt,out_dir=root/"bad")
            receipt["reused_app_objects"]=False
            bad=json.loads(paths["handoff_receipt"].read_bytes())
            bad["sector_sha256"]="0"*64
            paths["handoff_receipt"].write_bytes(canonical(bad))
            with self.assertRaisesRegex(PackagingHold,"HANDOFF_MUST_BE_COMPILED"):
                package(source_sha="1"*40,prepared_identity="2"*64,
                     files=paths,worker_receipt=receipt,out_dir=root/"bad2")

if __name__=="__main__":unittest.main()
