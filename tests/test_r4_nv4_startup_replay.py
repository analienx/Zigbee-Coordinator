"""Exact startup append workload through genuine TI NV4 APIs, public data only."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.test_r4_nv4_readonly_admission import PAGE_SIZE, encoded_record, stock_like

ROOT = Path(__file__).resolve().parents[1]
QUAL = ROOT / 'firmware/slzb-06p7u/r4/qualification'
sys.path.insert(0, str(QUAL))
import nv4_startup_replay as replay


def startup_fixture():
    """779 live rows plus dead history: exactly the stock capacity profile.

    Every identity/key is synthetic. Dead versions exhaust free append space
    so the 98 creates + 107 updates must exercise genuine compaction.
    """
    media = bytearray(stock_like())
    for page, state in enumerate((0x78,0x78,0x7c,0xfe)):
        base = page*PAGE_SIZE
        media[base] = state
        media[base+2] = 0x0c
        media[base+16:base+PAGE_SIZE] = b'\xff'*(PAGE_SIZE-16)
    parts = [encoded_record(i,itemid=4,active=False,data=bytes(20)) for i in range(200)]
    for table,count,width in ((1,357,12),(2,1,14),(3,51,16),(4,300,20),(6,3,24),(7,5,12)):
        for index in range(count):
            row = bytearray(b'\xff'*width)
            if table in (4,6,7):
                row[:] = bytes(width)
                row[:4] = (100000+index).to_bytes(4,'little')
                row[8:12] = (index+1).to_bytes(4,'little')
            parts.append(encoded_record(index,itemid=table,data=bytes(row)))
    for index in (*range(60),0x55,0x87):
        row = bytes([(index*17+3)&255])*16
        if index == 0x21:
            row = bytes(range(1,117))
        elif index in (3,0x55,0x87):
            row = bytes([int(index==0x55)])
        parts.append(encoded_record(index,itemid=0,data=row))
    assert len(parts)==979
    page,cursor=0,16
    for part in parts:
        if cursor+len(part)>PAGE_SIZE:
            page+=1;cursor=16
        assert page<3
        at=page*PAGE_SIZE+cursor
        media[at:at+len(part)]=part;cursor+=len(part)
    assert page==2
    return bytes(media)


class StartupReplayPins(unittest.TestCase):
    def test_unpinned_driver_cannot_be_extracted(self):
        with self.assertRaisesRegex(ValueError,'STARTUP_REPLAY_TI_SOURCE_MISMATCH'):
            replay.transform(b'wrong source',b'wrong CRC',b'wrong interface')


@unittest.skipUnless(os.environ.get('GITHUB_ACTIONS')=='true' and shutil.which('gcc') and
                     all(os.environ.get(x) for x in ('R4_TI_NVOCMP_SOURCE','R4_TI_CRC_SOURCE',
                                                    'R4_TI_NVINTF_SOURCE')),
                     'exact public TI sources and compiler on GitHub hosted runner required')
class GenuineStartupReplay(unittest.TestCase):
    def test_capacity_counters_compaction_and_interruption(self):
        generated=replay.transform(*(Path(os.environ[x]).read_bytes() for x in
                                    ('R4_TI_NVOCMP_SOURCE','R4_TI_CRC_SOURCE','R4_TI_NVINTF_SOURCE')))
        with tempfile.TemporaryDirectory(prefix='r4-startup-replay-') as task_dir:
            source=Path(task_dir)/'replay.c';binary=Path(task_dir)/'replay'
            source.write_text(generated)
            compile_result=subprocess.run(['gcc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                '-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter','-Wno-sign-compare',
                '-fsanitize=undefined','-fno-sanitize-recover=all',
                '-I',str(ROOT/'firmware/slzb-06p7u/r4/b1'),'-I',str(QUAL),
                str(source),'-o',str(binary)],capture_output=True,text=True,timeout=60)
            self.assertEqual(compile_result.returncode,0,compile_result.stderr)
            result=subprocess.run([str(binary)],input=startup_fixture(),capture_output=True,timeout=120)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertIn(b'P7U_TI_NV4_STARTUP_REPLAY_PASS',result.stdout)
            print(result.stdout.decode(),end='')


if __name__=='__main__':
    unittest.main()
