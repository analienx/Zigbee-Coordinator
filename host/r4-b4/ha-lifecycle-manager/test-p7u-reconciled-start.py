"""Hosted adversarial checks for the explicit post-HOLD continuation."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

HERE=Path(__file__).parent
sys.path[:0]=[str(HERE),str(HERE.parent/'ha-addon'),str(HERE.parent)]
import p7u_lifecycle_main as main
import p7u_reconciled_start as m
from p7u_lifecycle_core import Journal, LifecycleHold
from p7u_lifecycle_machine import Presence


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.old=self.root/'old';self.new=self.root/'new'
        self.old.mkdir(mode=0o700);self.new.mkdir(mode=0o700)
        self.jd=self.old/'journal';self.jd.mkdir(mode=0o700)
        patcher=patch.object(main,'PRIVATE_ROOT',self.root);patcher.start();self.addCleanup(patcher.stop)
        self.op='b2660c95-38f5-40b2-9589-6864ed178210'
        self.plan={key:None for key in main.PLAN_FIELDS}
        self.plan.update(schema='p7u-one-shot-plan-v1',operation_id=self.op,source_sha='a'*40,
                         original_slot='official',target_slot='diagnostic',serial_by_id='/dev/serial/by-id/usb-P7U',
                         original_owner={'identity':'preserved'},diagnostic_image_sha256='b'*64)
        self.oldpath=self.old/'plan.json';oldhash=self.write(self.oldpath,self.plan)
        self.write(self.root/'active-operation.json',{'schema':'p7u-active-operation-v1',
            'operation_id':self.op,'source_sha':'a'*40,'plan_sha256':oldhash})
        cold=self.old/'cold-host-data.tar';cold.write_bytes(b'private original host data')
        approval={'generation':'original-generation','inventory_sha256':'d'*64,
                  'cold_backup':{'archive':cold.name,'sha256':hashlib.sha256(cold.read_bytes()).hexdigest()}}
        with Journal(self.jd) as j:
            for phase in ['PREFLIGHT','STOP_INTENT','OWNER_ABSENT','DB_APPROVED','START_INTENT','HOLD']:
                j.append(phase,approval if phase=='DB_APPROVED' else
                         {'reason':'post-start evidence incomplete'} if phase=='HOLD' else {})
        log=self.old/'failed.log';log.write_bytes(b'P7U HOLD_EXISTING_NV: ping unavailable; no bootloader magic or line toggles');log.chmod(0o600)
        now=time.time();stamp=lambda t:datetime.fromtimestamp(t,timezone.utc).isoformat()
        common={'incident_id':self.op.replace('-',''),'action_key':self.op.replace('-','')+':ESP_RESET_PENDING:RESTART_ESP',
                'phase':'ESP_RESET_PENDING','action':'RESTART_ESP'}
        attempt=self.new/'reset.attempt.json';result=self.new/'reset.result.json'
        ah=self.write(attempt,{**common,'schema':'p7u-shared-recovery-attempt-v2','sent_after_receipt':True,'recorded_utc':stamp(now-2)})
        rh=self.write(result,{**common,'schema':'p7u-shared-recovery-result-v2','status':'COMMAND_ACCEPTED_NOT_YET_VERIFIED','recorded_utc':stamp(now-1)})
        r={'previous_plan_path':str(self.oldpath),'previous_plan_sha256':oldhash,
           'previous_journal_sha256':hashlib.sha256((self.jd/'events.jsonl').read_bytes()).hexdigest(),
           'failed_container_id':'c'*64,'failed_log_path':str(log),'failed_log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),
           'reset_attempt_path':str(attempt),'reset_attempt_sha256':ah,'reset_result_path':str(result),'reset_result_sha256':rh}
        self.plan={**self.plan,'source_sha':'e'*40,'reconciliation':r}
        self.failed={'Id':'c'*64,'Image':'sha256:'+'b'*64,'State':{'Running':False,'Status':'exited','ExitCode':1,'FinishedAt':stamp(now-10)}}
        self.port=MagicMock();self.port.artifact_directory=self.new
        self.port.inspect.return_value=Presence(False,None)
        self.port.preflight_database.return_value={'existing_approval':{'generation':'original-generation'},'inventory_sha256':'d'*64}
        for target,kwargs in [(m,{'inspect_docker':lambda slot:self.failed}), (main,{'validate_service_bundle':lambda *a:None})]:
            for key,value in kwargs.items():
                p=patch.object(target,key,side_effect=value);p.start();self.addCleanup(p.stop)
        p=patch.object(m,'zero_tty_three_times');p.start();self.addCleanup(p.stop)

    def write(self,path,obj):
        raw=(json.dumps(obj,sort_keys=True)+'\n').encode();path.write_bytes(raw);path.chmod(0o600)
        return hashlib.sha256(raw).hexdigest()

    def validate(self):return m.validate_reconciliation(self.plan,self.port)

    def test_exact_terminal_failure_and_current_approval_admitted_without_side_effect(self):
        self.assertTrue(self.validate()['prior_hold_verified'])
        self.port.client.call.assert_not_called()
        self.assertTrue((self.root/'active-operation.json').exists())

    def test_changed_old_journal_or_database_generation_is_rejected(self):
        self.port.preflight_database.return_value={'existing_approval':{'generation':'foreign'},'inventory_sha256':'d'*64}
        with self.assertRaisesRegex(LifecycleHold,'DATABASE_GENERATION_CHANGED'):self.validate()
        (self.jd/'events.jsonl').write_bytes((self.jd/'events.jsonl').read_bytes()+b' ')
        with self.assertRaisesRegex(LifecycleHold,'FILE_CHANGED'):self.validate()

    def test_new_operation_id_cannot_hide_the_prior_intent(self):
        self.plan['operation_id']='f'*32
        with self.assertRaisesRegex(LifecycleHold,'OPERATION_CHANGED'):self.validate()

    def test_running_or_replaced_failed_container_is_rejected(self):
        self.failed['State']['Running']=True
        with self.assertRaisesRegex(LifecycleHold,'FAILED_CONTAINER_CHANGED'):self.validate()
        self.failed['State']['Running']=False;self.failed['Id']='f'*64
        with self.assertRaisesRegex(LifecycleHold,'FAILED_CONTAINER_CHANGED'):self.validate()

    def test_ambiguous_reset_is_never_accepted(self):
        r=self.plan['reconciliation'];path=Path(r['reset_result_path']);doc=json.loads(path.read_text())
        doc['status']='AMBIGUOUS_NO_RETRY';r['reset_result_sha256']=self.write(path,doc)
        with self.assertRaisesRegex(LifecycleHold,'RESET_NOT_ACKNOWLEDGED'):self.validate()

    def test_stale_or_wrong_incident_reset_is_rejected(self):
        r=self.plan['reconciliation'];path=Path(r['reset_result_path']);doc=json.loads(path.read_text())
        doc['recorded_utc']='2020-01-01T00:00:00+00:00';r['reset_result_sha256']=self.write(path,doc)
        with self.assertRaisesRegex(LifecycleHold,'RESET_STALE'):self.validate()
        doc['incident_id']='e'*32;r['reset_result_sha256']=self.write(path,doc)
        with self.assertRaisesRegex(LifecycleHold,'RESET_IDENTITY'):self.validate()

    def test_continuation_claim_is_exclusive_and_preserves_prior_pointer(self):
        evidence=self.validate();pointer=(self.root/'active-operation.json').read_bytes()
        m.claim_continuation(self.plan,'e'*64,evidence)
        self.assertEqual((self.root/'active-operation.json').read_bytes(),pointer)
        with self.assertRaisesRegex(LifecycleHold,'ALREADY_ATTEMPTED'):self.validate()
        with self.assertRaises(FileExistsError):m.claim_continuation(self.plan,'e'*64,evidence)

    def test_readonly_preflight_does_not_claim_clean_or_start(self):
        with patch.object(main,'global_operation_lock'),patch.object(m,'validate_reconciliation',return_value={'prior_hold_verified':True}),patch.object(m,'claim_continuation') as claim:
            result=m.run_reconciled({'execute':False,'plan_sha256':'e'*64},self.plan,self.port)
        self.assertEqual(result['status'],'PREFLIGHT_PASS');claim.assert_not_called();self.port.client.call.assert_not_called()

    def test_execution_claims_before_cleaning_only_the_exact_stopped_generation(self):
        events=[];self.port.client.call.side_effect=lambda **kw:events.append(('cleanup',kw))
        self.port.cold_receipt={'sha256':'f'*64}
        evidence={'prior_hold_verified':True,'failed_container_id':'c'*64}
        with patch.object(main,'global_operation_lock'), \
             patch.object(m,'validate_reconciliation',return_value=evidence), \
             patch.object(m,'claim_continuation',side_effect=lambda *a:events.append(('claim',))), \
             patch.object(m,'inspect_docker',side_effect=[self.failed,None]), \
             patch.object(m,'Manager') as manager:
            manager.return_value.start_quiescent_once.return_value='COMMITTED'
            result=m.run_reconciled({'execute':True,'plan_sha256':'e'*64},self.plan,self.port)
        self.assertEqual(result['status'],'COMMITTED')
        self.assertEqual([e[0] for e in events],['claim','cleanup'])
        self.assertEqual(events[1][1],{'method':'POST','slot':'diagnostic','action':'stop','timeout_seconds':30})
        manager.return_value.start_quiescent_once.assert_called_once()


if __name__=='__main__':unittest.main()
