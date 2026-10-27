"""Read-only continuation admission; no real HA, serial or firmware mutation."""
import importlib.util,json,tempfile
from pathlib import Path
from unittest.mock import Mock
import unittest
from types import SimpleNamespace
from tests.test_p7u_ha_local_deploy import op

p=Path(__file__).resolve().parents[1]/'host/flash/p7u_paired_hold.py'
spec=importlib.util.spec_from_file_location('paired_hold',p)
hold=importlib.util.module_from_spec(spec);spec.loader.exec_module(hold)

class ReadonlyHold(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/('1'*32);self.root.mkdir(mode=0o700)
        self.owner={'id':'owner','image':'sha256:'+'a'*64,'started_at':'time','running':False}
        self.plan={'source':'2'*40,'installed':'3'*40,'operation_id':self.root.name,
                   'candidate_pin':'b'*64,'input_pin':'c'*64,'owner':dict(self.owner,running=True)}
        self.pin=op.sha(op.canonical(self.plan));snapshot=bytes(720896)
        values={n:{} for n in hold.NAMES if n.endswith('.json')}
        values.update({'plan.json':self.plan,'execute-intent.json':{'plan_sha256':self.pin},
          'bsl-entry-intent.json':{'attempts':1,'plan_sha256':self.pin},
          'hold.json':{'automatic_boot':False,'automatic_retry':False,'error_type':'Hold',
                       'plan_sha256':self.pin,'safe_code':'P7U_DEPLOY_HOLD_NATIVE_SECURITY'},
          'security-receipt.json':{'status':'HOLD','reason_codes':['ADDRESS_MANAGER_RETAINED_ROWS_CHANGED_NO_MIGRATION_AUTHORIZED'],
             'write_attempts':0,'erase_attempts':0,'compaction_attempts':0,'capture_sha256':op.sha(snapshot)},
          'sparse-receipt.json':{'status':'SPARSE_ROM_CRC_WITH_FRESH_NV_READ_ONLY_NOT_FLASH_ADMISSION',
             'rom_crc32_sector_checks':88,'live_reconstructed_sha256':op.sha(snapshot)},
          'cold-backup.json':{'bytes':4,'sha256':op.sha(b'cold')}})
        for name,value in values.items():(self.root/name).write_bytes(op.canonical(value))
        (self.root/'fresh-sparse-snapshot.bin').write_bytes(snapshot)
        (self.root/'cold-before-flash.tar').write_bytes(b'cold')
        self.ns={name:getattr(op,name) for name in ('need','load','read','private_root','sha','canonical','file_sha')}
        self.ns.update(HELD_ROM=self.root,SOURCE=self.plan['source'],INSTALLED=self.plan['installed'],
           CANDIDATE_PIN=self.plan['candidate_pin'],PREVIOUS_INPUT_PIN=self.plan['input_pin'],
           IMAGE=self.owner['image'],PAIRED_ROM_HOLD_PLAN_PIN=self.pin)
        self.seal();self.ha=Mock()
    def seal(self):self.ns['PAIRED_ROM_HOLD_PIN']=hold.fingerprint(self.root,self.owner,self.plan['source'])
    def test_exact_zero_write_hold_can_prepare_a_new_rom_session(self):
        self.assertEqual(hold.provenance(self.ns,self.ha,self.owner),self.ns['PAIRED_ROM_HOLD_PIN'])
        self.ha.proof.assert_called_once_with(False)
    def test_admission_or_write_artifact_prevents_continuation(self):
        for name in ('admission.json','mutation-journal.jsonl','frozen-plan.json'):
            p=self.root/name;p.write_text('{}')
            with self.assertRaisesRegex(ValueError,'FILE_SET'):hold.provenance(self.ns,self.ha,self.owner)
            p.unlink()
        self.ha.proof.assert_not_called()
    def test_changed_capture_or_intent_pin_is_rejected(self):
        (self.root/'fresh-sparse-snapshot.bin').write_bytes(bytes(720895)+b'x')
        with self.assertRaisesRegex(op.Hold,'HOLD_PIN'):hold.provenance(self.ns,self.ha,self.owner)
        self.seal()
        with self.assertRaisesRegex(op.Hold,'HOLD_SECURITY'):hold.provenance(self.ns,self.ha,self.owner)
    def test_write_attempt_or_unknown_hold_never_becomes_readonly(self):
        p=self.root/'security-receipt.json';v=json.loads(p.read_bytes());v['erase_attempts']=1
        p.write_bytes(op.canonical(v));self.seal()
        with self.assertRaisesRegex(op.Hold,'HOLD_SECURITY'):hold.provenance(self.ns,self.ha,self.owner)
    def test_replaced_or_running_owner_is_rejected(self):
        for owner in (dict(self.owner,id='other'),dict(self.owner,running=True)):
            with self.assertRaisesRegex(op.Hold,'HOLD_PIN'):hold.provenance(self.ns,self.ha,owner)
        self.ha.proof.assert_not_called()
    def test_supervisor_removed_container_requires_exact_absence_and_pinned_image(self):
        ns=dict(self.ns,OWNER='local_p7u_r4_native_host',PAIRED_HOST_VERSION='0.2.1-'+'2'*12)
        proc=Mock(return_value=SimpleNamespace(returncode=1,stdout='[]',stderr='error: no such object: app_local_p7u_r4_native_host'))
        ns['subprocess']=SimpleNamespace(run=proc)
        ns['run']=Mock(return_value=json.dumps([{'Id':self.owner['image']}]).encode())
        self.ha.info.return_value={'state':'error','version':ns['PAIRED_HOST_VERSION'],'build':False,'boot':'manual','watchdog':False}
        owner=hold.absent_owner(ns,self.ha)
        self.ns['PAIRED_ROM_HOLD_PIN']=hold.fingerprint(self.root,owner,self.plan['source'])
        self.assertEqual(hold.provenance(self.ns,self.ha,owner),self.ns['PAIRED_ROM_HOLD_PIN'])
        proc.return_value.stderr='Cannot connect to Docker daemon'
        with self.assertRaisesRegex(op.Hold,'ABSENCE_NOT_PROVEN'):hold.absent_owner(ns,self.ha)
        proc.return_value.stderr='error: no such object: app_local_p7u_r4_native_host'
        ns['run'].return_value=json.dumps([{'Id':'wrong-image'}]).encode()
        with self.assertRaisesRegex(op.Hold,'ABSENT_OWNER_IMAGE'):hold.absent_owner(ns,self.ha)

    def attach_fixture(self):
        operations=Path(self.tmp.name)/'operations';operations.mkdir(mode=0o700)
        attach=operations/('4'*32);attach.mkdir(mode=0o700)
        p=dict(self.plan,operation_id=attach.name,owner=self.owner,
               rom_continuation_sha256=self.ns['PAIRED_ROM_HOLD_PIN'],bounded_reentry_sha256=None)
        pin=op.sha(op.canonical(p))
        values={n:{} for n in hold.ATTACH_NAMES if n.endswith('.json')}
        values.update({'plan.json':p,'execute-intent.json':{'plan_sha256':pin},
          'rom-reattach-intent.json':{'plan_sha256':pin,'provenance':self.ns['PAIRED_ROM_HOLD_PIN']},
          'hold.json':{'automatic_boot':False,'automatic_retry':False,'error_type':'RomWireError',
                       'plan_sha256':pin,'safe_code':'BSL_ACK_TIMEOUT_OR_DISCONNECTED'},
          'cold-backup.json':{'bytes':4,'sha256':op.sha(b'cold')}})
        for name,value in values.items():(attach/name).write_bytes(op.canonical(value))
        (attach/'cold-before-flash.tar').write_bytes(b'cold')
        self.ns.update(FAILED_ATTACH=attach,OPERATIONS=operations,PRIVATE=operations/('5'*32),durable=op.durable,
             PAIRED_ROM_REENTRY_PLAN_PIN=pin,
             PAIRED_ROM_REENTRY_PIN=hold.fingerprint(attach,self.owner,self.plan['source'],hold.ATTACH_NAMES))
        return attach

    def test_exact_readonly_attach_can_consume_only_one_fresh_bsl_entry(self):
        attach=self.attach_fixture()
        digest=hold.reentry_provenance(self.ns,self.ha,self.owner)
        self.assertEqual(len(digest),64)
        hold.consume_reentry(self.ns,'new-plan-pin')
        marker=self.ns['OPERATIONS']/('readonly-reentry-'+attach.name)/'intent.json'
        self.assertEqual(json.loads(marker.read_bytes())['attempts'],1)
        with self.assertRaisesRegex(op.Hold,'ALREADY_CONSUMED'):hold.consume_reentry(self.ns,'new-plan-pin')
        with self.assertRaisesRegex(op.Hold,'ALREADY_CONSUMED'):hold.reentry_provenance(self.ns,self.ha,self.owner)

    def test_attach_with_bsl_capture_or_write_admission_cannot_authorize_reentry(self):
        attach=self.attach_fixture()
        for name in ('bsl-entry-intent.json','fresh-sparse-snapshot.bin','admission.json','mutation-journal.jsonl'):
            path=attach/name;path.write_bytes(b'x')
            with self.assertRaisesRegex(ValueError,'FILE_SET'):hold.reentry_provenance(self.ns,self.ha,self.owner)
            path.unlink()
