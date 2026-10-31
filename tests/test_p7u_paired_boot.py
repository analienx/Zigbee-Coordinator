"""Offline ordering and failure controls for one native boot, no live I/O."""
import struct,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'host/r4-b4'),str(ROOT/'host/flash'),
             str(ROOT/'firmware/slzb-06p7u/r4/release')]
from tests.test_p7u_ha_local_deploy import op
import p7u_paired_boot as boot
import p7u_paired_finish as finish
import p7u_r4_startup_transport as transport

def wire(nonce):
    b=bytearray(248);b[:5]=b'R4D4\x04';b[6:8]=(248).to_bytes(2,'little')
    b[12:16]=(0x1ffffff).to_bytes(4,'little');b[28:32]=(1).to_bytes(4,'little')
    b[132:140]=nonce;b[157]=4;values=[0]*20;values[-1]=10
    b[160:240]=struct.pack('<20I',*values)
    return bytes(b)

class NativeBoot(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700);self.events=[]
        self.old=dict(id=None,image='sha256:'+'a'*64,running=False,started_at=None)
        self.new=dict(self.old,id='new',running=True,started_at='now')
        self.ha=Mock();self.ha.inspect.side_effect=[self.old,self.new]
        self.ha.management.return_value='board';self.ha.boot_binding.return_value='button'
        self.ha.restart_radio.side_effect=lambda:self.events.append('boot')
        self.ha.owner_action.side_effect=lambda action:self.events.append(action)
        self.port=Mock();self.port.close.side_effect=lambda:self.events.append('close')
        self.ns={k:getattr(op,k) for k in ('need','load','durable','file_sha')}
        self.ns.update(PRIVATE=self.root,SOURCE='98b882c49cdef2cb422822b8845bee3a4045765f',
            IMAGE=self.old['image'],sealed_tree=Mock(),verified_write=Mock(return_value={'management_sha256':'board'}),
            modules=Mock(),StartupSerial=Mock(side_effect=lambda:(self.events.append('open') or self.port)),
            resume_pristine=Mock(side_effect=lambda *a:(self.events.append('ready') or
                {'status':'COORDINATOR_STATE9_MARKER_PASS'})))
        op.durable(self.root,'owner-backup-before-stop.json',{})
        self.z=Mock();self.z._next.return_value=(0x41,0x80,bytes(6))
        self.z.preboot_bad_fcs=0
        self.z.request.side_effect=lambda s,c,n,**kw:(self.events.append('f2') or wire(n))
    def invoke(self):
        with patch.object(transport,'FramedZnp',return_value=self.z):
            return boot.boot_native(self.ns,self.root,'package','plan',self.ha)
    def test_open_before_boot_ready_before_host_and_once_only(self):
        r=self.invoke();self.assertTrue(r['host_api_ack'])
        self.assertEqual(self.events,['open','boot','ready','f2','close','start'])
        self.assertEqual(self.ha.owner_action.call_count,1)
        self.assertEqual(self.z.request.call_args.args[:2],(1,242))
        with self.assertRaisesRegex(op.Hold,'CONSUMED'):self.invoke()
        self.assertEqual(self.ha.restart_radio.call_count,1)
    def test_uncertain_start_is_inspected_without_retry(self):
        self.ha.owner_action.side_effect=TimeoutError()
        r=self.invoke();self.assertFalse(r['host_api_ack'])
        self.ha.owner_action.assert_called_once_with('start')
    def test_single_corrupt_preboot_frame_is_bounded_and_never_accepted(self):
        # One corrupt unsolicited frame must not consume an otherwise valid
        # reset indication in the *same* boot. No reset/retry is performed.
        class Socket:
            def __init__(self, wire):
                self.wire=wire
            def settimeout(self, value):
                pass
            def recv(self, size):
                result=self.wire;self.wire=b''
                return result
        payload=bytes(range(6))
        raw=bytes((6,0x41,0x80))+payload
        fcs=0
        for value in raw:
            fcs^=value
        good=b'\xfe'+raw+bytes((fcs,))
        bad=good[:-1]+bytes((fcs^1,))
        import time
        z=transport.FramedZnp(Socket(bad+good))
        self.assertEqual(z._next(time.monotonic()+1,
            allow_preboot_fcs_resync=True),(0x41,0x80,payload))
        self.assertEqual(z.preboot_bad_fcs,1)
        strict=transport.FramedZnp(Socket(bad+good))
        with self.assertRaises(RuntimeError):
            strict._next(time.monotonic()+1)
        double=transport.FramedZnp(Socket(bad+bad+good))
        with self.assertRaises(RuntimeError):
            double._next(time.monotonic()+1,allow_preboot_fcs_resync=True)
        self.assertEqual(double.preboot_bad_fcs,2)

    def test_bad_reset_shape_closes_uart_never_starts(self):
        self.z._next.return_value=(0x41,0x80,bytes(5))
        with self.assertRaisesRegex(op.Hold,'RESET_IND_SHAPE'):self.invoke()
        self.ha.owner_action.assert_not_called();self.port.close.assert_called_once()
        self.ns['resume_pristine'].assert_not_called()
    def test_failed_native_ready_never_starts(self):
        self.ns['resume_pristine'].return_value={'status':'FAILED'}
        self.ns['resume_pristine'].side_effect=None
        with self.assertRaisesRegex(op.Hold,'STATE9'):self.invoke()
        self.ha.owner_action.assert_not_called();self.port.close.assert_called_once()
    def test_stale_nonce_never_starts(self):
        self.z.request.side_effect=lambda *a,**kw:wire(b'oldnonce')
        with self.assertRaisesRegex(ValueError,'NONCE'):self.invoke()
        self.ha.owner_action.assert_not_called();self.port.close.assert_called_once()
    def test_minor4_wire_bounds_and_congestion_validity(self):
        n=b'12345678';b=wire(n)
        self.assertEqual(finish.capture_progress(b,n)['minor'],4)
        for offset,value in ((6,0),(15,0),(157,3),(236,0)):
            bad=bytearray(b);bad[offset]=value
            with self.subTest(offset=offset),self.assertRaises(ValueError):finish.capture_progress(bytes(bad),n)
        bad=bytearray(b);bad[140:144]=(1).to_bytes(4,'little')
        with self.assertRaisesRegex(ValueError,'CONGESTION'):finish.capture_progress(bytes(bad),n)
