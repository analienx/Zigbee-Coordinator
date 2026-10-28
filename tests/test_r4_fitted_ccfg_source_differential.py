"""Pure generated TI source proof for actual fitted P7U power profile."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]/"firmware/slzb-06p7u/r4/release"
spec=importlib.util.spec_from_file_location("fitted_ccfg_source",ROOT/"r4_fitted_ccfg_source_differential.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def source():
    return (
        "#define CCFG_FORCE_VDDR_HH                              0x0\n"
        "#define SET_CCFG_MODE_CONF_DCDC_RECHARGE                0x1\n"
        "#define SET_CCFG_MODE_CONF_DCDC_ACTIVE                  0x1\n"
        "#define SET_CCFG_IMAGE_VALID_CONF_IMAGE_VALID           0x00000000\n"
        "#include DeviceFamily_constructPath(startup_files/ccfg.c)\n"
    )
class FittedSourceTests(unittest.TestCase):
    def test_three_board_power_macros_change_only(self):
        inp=source()
        out=m.transform(inp)
        self.assertEqual(len(inp),len(out))
        self.assertEqual(sum(x!=y for x,y in zip(inp,out)),3)
        self.assertIn("CCFG_FORCE_VDDR_HH                              0x1",out)
        self.assertIn("MODE_CONF_DCDC_ACTIVE                  0x0",out)
        self.assertIn("MODE_CONF_DCDC_RECHARGE                0x0",out)
        self.assertIn("IMAGE_VALID_CONF_IMAGE_VALID           0x00000000",out)
        self.assertNotEqual(inp,out)

    def test_patched_or_missing_or_ambiguous_inputs_denied(self):
        x=source()
        for candidate in (
            x.replace("0x0\n","0x1\n",1),
            x.replace("DCDC_ACTIVE","DCDC_ACTIVEX"),
            x+x,
            x.replace("IMAGE_VALID_CONF_IMAGE_VALID","IMAGE_VALID_UNKNOWN"),
            x.replace("DeviceFamily_constructPath(startup_files/ccfg.c)","wrong"),
        ):
            with self.subTest(text=candidate[:80]),self.assertRaisesRegex(ValueError,"FITTED_P7U_CCFG_SOURCE_BLOCKED"):
                m.transform(candidate)

    def test_entrypoint_pins_actual_ti_source_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);i=d/"ti_devices_config.c";o=d/"fitted.c";r=d/"receipt.json"
            i.write_text(source())
            with self.assertRaisesRegex(ValueError,"REAL_TI833_GENERATED_SOURCE_SHA_PIN"):
                m.prepare(i,o,r)
            self.assertFalse(o.exists())
            with patch.object(m,"KNOWN_TI833_GENERATED_SHA",m.hashlib.sha256(i.read_bytes()).hexdigest()):
                receipt=m.prepare(i,o,r)
                self.assertTrue(receipt["sets_CCFG_FORCE_VDDR_HH_1"])
                self.assertFalse(receipt["compiled_into_native_R4"])
                self.assertFalse(receipt["flash_authorized"])
                with self.assertRaisesRegex(ValueError,"NO_OVERWRITE"):
                    m.prepare(i,o,r)

if __name__=="__main__":
    unittest.main()
