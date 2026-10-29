"""Cross-language projection of the actual compiled-owner warning fixture."""
import copy,importlib.util,json,os,unittest
from pathlib import Path
p=Path(__file__).with_name('p7u_halfhour_export.py')
spec=importlib.util.spec_from_file_location('exporter',p);exporter=importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)

class WarningExport(unittest.TestCase):
    def setUp(self):
        p=Path(os.environ['B4_FIRST_WARNING_FIXTURE']);self.assertTrue(str(p).startswith('/tmp/'))
        self.row=json.loads(p.read_bytes())
    def test_first_warning_remains_a_warning_and_not_a_native_sample(self):
        end=((self.row['utc']//1800000)+1)*1800000
        report=exporter.analyze([(1,self.row)],end-1800000,end)
        self.assertEqual(report['summary']['hostFirstWarnings'],1)
        self.assertEqual(report['summary']['nativeF2Valid'],0)
        self.assertEqual(report['summary']['nativeV5Flights'],0)
        self.assertIn('HOST_FIRST_WARNING_CAPTURED',report['summary']['issues'])
        self.assertEqual(report['events'][0]['firstWarning']['operation']['operation'],'ping')
    def test_unknown_raw_fields_are_never_exported(self):
        row=copy.deepcopy(self.row);w=row['firstWarning'];w['rawPayload']='PRIVATE_SECRET'
        w['operation']['device']='PRIVATE_SECRET';w['recentOperations'][0]['key']='PRIVATE_SECRET'
        self.assertNotIn('PRIVATE_SECRET',json.dumps(exporter.project(row)))
    def test_unbounded_or_noncanonical_history_is_rejected(self):
        for change in ('oversized','operation'):
            with self.subTest(change=change):
                row=copy.deepcopy(self.row)
                if change=='oversized':row['firstWarning']['recentOperations']*=17
                else:row['firstWarning']['operation']['operation']='device-secret'
                with self.assertRaises(ValueError):exporter.project(row)

if __name__=='__main__':unittest.main()
