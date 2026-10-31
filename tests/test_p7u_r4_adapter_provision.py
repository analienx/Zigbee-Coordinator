"""Offline one-use adapter provisioning regression (no network or hardware)."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7u/r4/release"))
import p7u_r4_adapter_provision as provision
import p7u_r4_operator as op


class AdapterProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.template=self.root/"templates"
        self.template.mkdir()
        self.private=self.root/"private"
        self.private.mkdir()
        self.source="d"*40
        self.candidate={"source_sha":self.source,"github_run_id":"12345"}
        self.recipe=self.root/"reviewed-private-recipe.json"
        entries={}
        for stage,name in provision.NAMES.items():
            body=('"""read-only fixture"""\nSOURCE="previous"\n'
                  'CANDIDATE="original"\n# '+stage+'\n').encode()
            new=body.decode().replace("previous",self.source).replace("original","current").encode()
            (self.template/name).write_bytes(body)
            entries[stage]={
                "template_sha256":provision.digest(body),
                "output_sha256":provision.digest(new),
                "replacements":[
                    {"old":"previous","new":self.source,"count":1},
                    {"old":"original","new":"current","count":1},
                ]}
        self.manifest={
            "schema":"p7u-r4-one-use-adapters-v1",
            "source_sha":self.source,
            "github_run_id":"12345",
            "candidate_sha256":provision.digest(provision.canonical(self.candidate)),
            "stages":entries}
        self.write_manifest()

    def write_manifest(self):
        blob=provision.canonical(self.manifest)
        self.recipe.write_bytes(blob)
        return provision.digest(blob)

    def run_provision(self, *, sha=None):
        return provision.provision(self.private,self.template,self.recipe,
                                   sha or self.write_manifest(),
                                   self.source,self.candidate)

    def test_all_four_scripts_are_sealed_and_source_bound(self):
        seal=self.run_provision()
        self.assertEqual(len(seal["scripts_sha256"]),4)
        self.assertTrue((self.private/"operator-adapters.json").is_file())
        self.assertIsNotNone(provision.verify_seal(self.private,self.source,self.candidate))
        for name in provision.NAMES.values():
            self.assertIn(self.source,(self.private/name).read_text())

    def test_no_second_provision_over_existing_scripts(self):
        self.run_provision()
        with self.assertRaisesRegex(provision.ProvisionHold,"ALREADY_EXISTS"):
            self.run_provision()

    def test_tampered_template_refused_before_any_output(self):
        target=self.template/"flash_upgrade_once.py"
        target.write_text(target.read_text()+"# stealth change\n")
        with self.assertRaisesRegex(provision.ProvisionHold,"TEMPLATE_SHA256_CHANGED"):
            self.run_provision()
        self.assertFalse((self.private/"operator-adapters.json").exists())

    def test_unreviewed_replacement_fails_digest(self):
        self.manifest["stages"]["flash"]["replacements"][1]["new"]="tampered"
        with self.assertRaisesRegex(provision.ProvisionHold,"REVIEWED_ADAPTER_OUTPUT_MISMATCH"):
            self.run_provision()

    def test_transaction_sentinel_blocks_provision(self):
        (self.private/"flash-journal.jsonl").write_text("")
        with self.assertRaisesRegex(provision.ProvisionHold,"PRIVATE_TRANSACTION"):
            self.run_provision()

    def test_recipe_pin_fails_on_modified_manifest(self):
        pin=self.write_manifest()
        self.manifest["source_sha"]="f"*40
        self.write_manifest()
        with self.assertRaisesRegex(provision.ProvisionHold,"REVIEWED_RECIPE_CHANGED"):
            self.run_provision(sha=pin)

    def test_sealed_script_mutation_blocks_run(self):
        self.run_provision()
        (self.private/"startup_once.py").write_text("source changed")
        with self.assertRaisesRegex(provision.ProvisionHold,"REVIEWED_ONE_SHOT_SCRIPT_CHANGED"):
            provision.verify_seal(self.private,self.source,self.candidate)

    def test_status_journal_is_readonly_and_does_not_claim_flash_pass(self):
        (self.private/"flash-journal.jsonl").write_text(
           '{"event":"BEFORE_ERASE","address":704512}\n')
        snapshot=op.journal_progress(self.private)
        self.assertEqual(snapshot["verified_sectors"],0)
        self.assertEqual(snapshot["last_sector"],"0xac000")
        self.assertFalse(snapshot["verified_flash_receipt_present"])


if __name__=="__main__":
    unittest.main()
