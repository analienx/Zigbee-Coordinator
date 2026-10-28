"""Real progress framing and finish-only service-admission fault controls."""
import sys,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch,call
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'host/r4-b4'),str(ROOT/'host/flash'),str(ROOT/'firmware/slzb-06p7u/r4/release')]
from tests.test_p7u_ha_local_deploy import op
from tests.test_p7u_r4_startup_observer import evidence,SOURCE,terminal
import p7u_paired_finish as finish
import p7u_paired_hold as hold
import p7u_r4_startup_transport as transport
from p7u_r4_startup_observer import verify_success_frames

def wire(nonce):
    d=bytearray(240);d[:5]=b'R4D4\x04';d[6:8]=b'\xf0\x00';d[157]=3;d[132:140]=nonce
    d[28:32]=(1).to_bytes(4,'little');values=[0]*20;values[-1]=10
    d[160:]=struct.pack('<20I',*values)
    return bytes(d)

class Finish(unittest.TestCase):
    def test_serial_recv_returns_available_bytes_without_waiting_for_512(self):
        serial=object.__new__(op.StartupSerial);serial.port=Mock(in_waiting=3)
        serial.port.read.side_effect=[b'a',b'bcd']
        self.assertEqual(serial.recv(512),b'abcd')
        self.assertEqual(serial.port.read.call_args_list,[call(1),call(3)])
        serial.port.read.side_effect=[b'']
        with self.assertRaises(TimeoutError):serial.recv(512)
    def test_progress_requires_exact_length_nonce_and_valid_scalars(self):
        nonce=b'12345678';d=wire(nonce)
        self.assertEqual(finish.capture_progress(d,nonce)['uartProgress']['tickPeriodUs'],10)
        for raw in (d[:160],wire(b'87654321'),d[:236]+bytes(4)):
            with self.assertRaises(ValueError):finish.capture_progress(raw,nonce)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        old=self.root/'guarded-startup-recovery';old.mkdir(mode=0o700)
        self.failed={'id':'failed','image':'sha256:'+'a'*64,'running':False,'started_at':'old'}
        op.durable(old,'startup-result.json',{'status':'FAILED_STOP_NO_RETRY','ready_observed':True,
           'failure_category':'READY_OBSERVED_VERIFICATION_INCOMPLETE','frames':{'B1E1':evidence().hex()}})
        op.durable(old,'intent.json',{'failed_owner':self.failed})
        self.ns={k:getattr(op,k) for k in ('need','load','read','private_root','durable','file_sha')}
        self.port=Mock();self.ns.update(PRIVATE=self.root,SOURCE=SOURCE,IMAGE=self.failed['image'],
           sealed_tree=Mock(),verified_write=Mock(return_value={'management_sha256':'board'}),
           modules=Mock(),StartupSerial=Mock(return_value=self.port))
        self.ha=Mock();self.ha.management.return_value='board'
        self.ha.inspect.side_effect=[self.failed,dict(self.failed,id='new',running=True)]
        self.z=Mock();self.z.request.side_effect=lambda sub,cmd,nonce,**kw:wire(nonce)
    def invoke(self,result):
        with patch.object(hold,'verified_pair_package',return_value=self.root), \
             patch.object(transport,'FramedZnp',return_value=self.z), \
             patch.object(transport,'observe_after_srsp',return_value=result):
            return finish.finish(self.ns,self.root,'package','plan',self.ha)
    def test_finish_starts_only_after_fresh_f2_and_original_terminal_proof(self):
        verify_success_frames(terminal(),SOURCE)
        value=self.invoke({'status':'COORDINATOR_STATE9_MARKER_PASS','frames':terminal()})
        self.assertEqual(value['status'],'NATIVE_STATE9_AND_F2_V43_VERIFIED_HOST_STARTED_PENDING_SERVING')
        self.ha.restart_radio.assert_not_called();self.ha.owner_action.assert_called_once_with('start')
        self.assertEqual(self.z.request.call_args.args[:2],(1,242))
        self.port.close.assert_called_once()
        self.assertFalse((self.root/'terminal-readonly-finish/retained-startup-intent.json').exists())
    def test_failed_terminal_proof_never_starts_or_resets(self):
        with self.assertRaisesRegex(op.Hold,'TERMINAL_NOT_PROVEN'):self.invoke({'status':'FAILED_STOP_NO_RETRY'})
        self.ha.owner_action.assert_not_called();self.ha.restart_radio.assert_not_called()
        self.port.close.assert_called_once()
    def test_stale_f2_nonce_never_starts_and_closes_owner(self):
        self.z.request.side_effect=lambda *a,**k:wire(b'oldnonce')
        with self.assertRaisesRegex(ValueError,'NONCE'):self.invoke({'status':'COORDINATOR_STATE9_MARKER_PASS'})
        self.ha.owner_action.assert_not_called();self.ha.restart_radio.assert_not_called()
        self.port.close.assert_called_once()
