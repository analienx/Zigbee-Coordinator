import unittest
from nv_contract import budget,check_macros,check_generated,check_map

class Tests(unittest.TestCase):
    def test_five_pages_cannot_fit_four_hundred_security_records(self):
        c=budget('capacity-400')
        self.assertGreater(c['costs']['tclk'],5*2048)
        self.assertGreater(c['nvs_pages'],5)
        self.assertEqual(c['nvs_base']+c['nvs_bytes'],1048576)
    def test_production_reserve_is_explicit_and_compaction_is_not_live_capacity(self):
        c=budget('production-demand');p=c['capacities']
        self.assertEqual(p['tc_devices'],p['current_link_keys']+p['declared_key_reserve'])
        self.assertGreaterEqual((c['nvs_pages']-c['compaction_reserve_pages'])*2032,c['live_bytes']+c['growth_bytes'])
    def test_compiler_capacity_and_recovery_policy_mismatch_fail_closed(self):
        c=budget('production-demand')
        text='\n'.join(f'#define {k} {v}' for k,v in {'ZDSECMGR_TC_DEVICE_MAX':128,'NWK_MAX_DEVICE_LIST':75,'NWK_MAX_ADDRESSES':256,'NVOCMP_NVPAGES':c['nvs_pages'],'NVOCMP_NVS_INDEX':0}.items())
        check_macros(text,c)
        for changed in (text.replace('MAX 128','MAX 400'),text+'\n#define NVOCMP_RECOVER_FROM_COMPACT_FAILURE 1'):
            with self.assertRaises(ValueError):check_macros(changed,c)
    def test_generated_backend_and_map_must_match_budget(self):
        c=budget('production-demand');size=hex(c['nvs_bytes']);base=hex(c['nvs_base'])
        text=f'''static char flashBuf0[{size}] __attribute__((location({base})));
NVSCC26XX_HWAttrs nvsCC26XXHWAttrs[1] = {{ /* internal */ {{ .regionBase = (void *) flashBuf0, .regionSize = {size} }} }};
const NVS_Config NVS_config[1] = {{
{{ .fxnTablePtr = &NVSCC26XX_fxnTable, .object = &nvsCC26XXObjects[0], .hwAttrs = &nvsCC26XXHWAttrs[0] }}
}};'''
        check_generated(text,c)
        with self.assertRaises(ValueError):check_generated(text.replace('NVSCC26XX_fxnTable','NVSSPI25X_fxnTable'),c)
        check_map(f' FLASH_NV 0 {c["nvs_base"]:08x} {c["nvs_bytes"]:08x}',c)
        with self.assertRaises(ValueError):check_map(' FLASH_NV 0 000fd800 00002800',c)

if __name__=='__main__':unittest.main()
