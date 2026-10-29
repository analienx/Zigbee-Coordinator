"""Project the actual compiled-owner V6 fixture, without promoting it to VALID."""
import importlib.util,json,os,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('export',Path(__file__).with_name('p7u_halfhour_export.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Export(unittest.TestCase):
 def test_actual_record_and_unknown_fields(self):
  fixture=Path(os.environ['B4_V6_FIXTURE']);row=json.loads(fixture.read_text());v=m.project(row)
  self.assertEqual(v['stageV6']['fault']['stageId'],7);self.assertEqual(v['stageV6']['fault']['operation'],'dataRequest')
  self.assertNotIn('radioBootId',json.dumps(v));self.assertNotIn('command',json.dumps(v))
  a=m.analyze([(1,row)],row['utc']-1,row['utc']+1)
  self.assertEqual(a['summary']['nativeF2Valid'],0);self.assertEqual(a['summary']['nativeV6Stages'],1)
  self.assertEqual(a['summary']['overdueStagesObserved'],[1])
  row['stageV6']['fault']['key']='forbidden'
  with self.assertRaises(ValueError):m.project(row)
if __name__=='__main__':unittest.main()
