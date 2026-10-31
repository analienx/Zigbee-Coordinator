"""Read-only hang evidence: owner/TTY gates first, B1Q1 only, no reset or host start."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'host/r4-b4'), str(ROOT / 'host/flash'),
                str(ROOT / 'firmware/slzb-06p7u/r4/release')]
from tests.test_p7u_ha_local_deploy import op
from tests.test_p7u_v50_stack_evidence import V50, e2, e3, e6
import p7u_hang_evidence_once as hang
import p7u_paired_hold as hold
import p7u_r4_startup_transport as transport
from p7u_r4_startup_observer import Q0, Q3, Q4, Q5, Q6, Q7, Q8
from tests.test_p7u_v50_stack_evidence import e1


def b1s1(source):
    s = bytearray(24); s[:6] = b'B1S1\x01\x18'; s[6] = 5; s[9] = 8
    s[12:16] = bytes.fromhex(source[:8])
    return bytes(s)


class Znp:
    """Scripted one-outstanding-request owner; a failure latches it unusable."""
    def __init__(self, *, fail_at=None, stuck=False, busy=True, backlog=0):
        self.sent, self.history, self.unsolicited = [], [], []
        self.fail_at, self.stuck, self.busy, self.e2 = fail_at, stuck, busy, 0
        self.backlog = backlog
        self.unusable = False

    def request(self, sub, cmd, payload=b'', *, deadline):
        assert not self.unusable
        self.sent.append((sub, cmd, payload))
        self.history.append({'operation': payload.hex() if payload else f'{sub:02x}:{cmd:02x}',
                             'result': 'COMPLETE'})
        if self.fail_at is not None and len(self.sent) - 1 == self.fail_at:
            self.unusable = True
            raise TimeoutError('ZNP_OUTSTANDING_RESPONSE_DEADLINE')
        if payload == Q5:
            return e3(V50, ready=True, onset=True, long=True)
        if payload == Q4:
            self.e2 += 1
            raw = bytearray(e2(V50, now=1000 + 100000 * self.e2,
                               busy=(95000 if self.busy else 1000) * self.e2, nwk=75 * self.e2))
            if self.stuck:
                raw[44] = 3; raw[40:44] = (700000).to_bytes(4, 'little')
            return bytes(raw)
        if payload == Q8:
            return e6(V50, deferred=self.backlog, stuck_ms=7000 if self.stuck else 0)
        if payload in (Q6, Q7):
            t = bytearray(248); t[:6] = (b'B1E4' if payload == Q6 else b'B1E5') + b'\x01\xf8'
            t[6] = 2; t[7] = 5 if payload == Q6 else 60; t[8:12] = bytes.fromhex(V50[:8])
            t[16] = 2; t[36:38] = (950).to_bytes(2, 'little'); t[38] = 3
            t[44:46] = (2500).to_bytes(2, 'little'); t[48:50] = (990).to_bytes(2, 'little')
            t[50] = 3; t[56:58] = (2400).to_bytes(2, 'little')
            return bytes(t)
        if payload == Q3:
            return e1(V50, 4, 6)
        if payload == Q0:
            return b1s1(V50)
        if (sub, cmd) == (1, 1):
            return b'\x79\x01'
        raise AssertionError((sub, cmd, payload))


class HangEvidence(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name); self.root.chmod(0o700)
        op.durable(self.root, 'started-pending-serving.json', {'source': V50})
        self.owner = {'id': 'stopped', 'image': 'sha256:' + 'a' * 64, 'running': False,
                      'started_at': 'old'}
        self.ns = {k: getattr(op, k) for k in ('need', 'load', 'read', 'durable', 'file_sha')}
        self.port = Mock()
        self.ns.update(PRIVATE=self.root, SOURCE=V50, IMAGE=self.owner['image'],
                       verified_write=Mock(return_value={'management_sha256': 'board'}),
                       modules=Mock(), StartupSerial=Mock(return_value=self.port))
        self.ha = Mock(); self.ha.management.return_value = 'board'
        self.ha.inspect.return_value = self.owner

    def invoke(self, znp):
        with patch.object(hold, 'verified_pair_package', return_value=self.root), \
             patch.object(transport, 'FramedZnp', return_value=znp), \
             patch.object(hang.time, 'sleep'):
            return hang.capture(self.ns, self.root, 'package', 'plan', self.ha)

    def stored(self, value):
        return json.loads((self.root / value['evidence_dir'] / 'result.json').read_text())

    def assert_read_only(self):
        for name in ('owner_action', 'restart_radio', 'enter_bsl', 'boot_binding'):
            getattr(self.ha, name).assert_not_called()
        self.port.close.assert_called_once()

    def test_full_capture_reads_onset_first_then_pings_mt(self):
        znp = Znp()
        value = self.invoke(znp)
        self.assertEqual(value['status'], 'HANG_EVIDENCE_CAPTURED')
        self.assertEqual(value['classification'], 'STACK_SATURATED')
        self.assertEqual(value['mt_ping'], 'RESPONDED')
        self.assertEqual(znp.sent, [(1, 241, Q5), (1, 241, Q8), (1, 241, Q4), (1, 241, Q7),
                                    (1, 241, Q6), (1, 241, Q3), (1, 241, Q0), (1, 241, Q4),
                                    (1, 241, Q8), (1, 1, b'')])
        self.assertEqual(value['labels'], ['STACK_SATURATED'])
        stored = self.stored(value)
        self.assertEqual(stored['onset_record']['summary']['onset_top_service'], 2)
        self.assertGreater(stored['stack_profile']['stack_busy_percent'], 90)
        coarse = stored['trend']['coarse_60min']
        self.assertEqual([e['heap_low'] for e in coarse['entries']], [40000, 38400])
        self.assertEqual(coarse['entries'][1]['busy_permille'], 990)
        self.assertEqual(stored['trend']['fine_5min']['period_min'], 5)
        lines = (self.root / value['evidence_dir'] / 'evidence.jsonl').read_text().splitlines()
        self.assertEqual([json.loads(x)['response'] for x in lines],
                         ['B1E3', 'B1E6', 'B1E2', 'B1E5', 'B1E4', 'B1E1', 'B1S1',
                          'B1E2_LATER', 'B1E6_LATER', 'SYS_PING'])
        self.assertEqual(stored['pipeline']['later']['timers']['probe_task'], 2)
        intent = json.loads((self.root / value['evidence_dir'] / 'intent.json').read_text())
        self.assertFalse(intent['reset_authorized'] or intent['host_start_authorized'])
        self.ha.proof.assert_called_once_with(False)
        self.assert_read_only()

    def test_unresponsive_npi_stops_after_first_query(self):
        znp = Znp(fail_at=0)
        value = self.invoke(znp)
        self.assertEqual(value['status'], 'HANG_EVIDENCE_PARTIAL')
        self.assertEqual(value['classification'], 'NPI_OWNER_UNRESPONSIVE')
        self.assertEqual(len(znp.sent), 1)
        self.assertEqual(value['mt_ping'], 'NOT_ATTEMPTED')
        self.assert_read_only()

    def test_stuck_dispatch_and_dead_mt_are_distinguished(self):
        self.assertEqual(self.invoke(Znp(stuck=True))['classification'], 'STACK_DISPATCH_STUCK')
        self.port.close.reset_mock()
        value = self.invoke(Znp(fail_at=9, busy=False))
        self.assertEqual(value['classification'], 'MT_PATH_UNRESPONSIVE')
        self.assertEqual(value['mt_ping'], 'NO_RESPONSE')
        self.assert_read_only()

    def test_timer_backlog_is_reported_alongside_saturation(self):
        value = self.invoke(Znp(backlog=300))
        self.assertEqual(value['labels'], ['TIMER_FREE_BACKLOG', 'STACK_SATURATED'])
        self.assert_read_only()

    def test_running_owner_never_opens_the_port(self):
        self.ha.inspect.return_value = dict(self.owner, running=True)
        with self.assertRaisesRegex(op.Hold, 'HANG_EVIDENCE_OWNER_RUNNING'):
            self.invoke(Znp())
        self.ns['StartupSerial'].assert_not_called()
        self.ha.proof.assert_not_called()

    def test_other_installed_source_or_board_is_refused(self):
        (self.root / 'started-pending-serving.json').unlink()
        op.durable(self.root, 'started-pending-serving.json', {'source': '0' * 40})
        with self.assertRaisesRegex(op.Hold, 'HANG_EVIDENCE_SOURCE_NOT_INSTALLED'):
            self.invoke(Znp())
        (self.root / 'started-pending-serving.json').unlink()
        op.durable(self.root, 'started-pending-serving.json', {'source': V50})
        self.ha.management.return_value = 'other'
        with self.assertRaisesRegex(op.Hold, 'HANG_EVIDENCE_BOARD'):
            self.invoke(Znp())
        self.ns['StartupSerial'].assert_not_called()


if __name__ == '__main__':
    unittest.main()
