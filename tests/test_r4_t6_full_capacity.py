"""Synthetic capacity audit controls; genuine ELF evidence remains hosted-only."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "r4_full_capacity", ROOT / "tools/r4_t6_full_capacity.py")
capacity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capacity)


def native_symbols():
    # Actual TI 8.33 Cortex-M4F extents and scalar widths. These literals
    # deliberately do not derive widths/strides from the audit's tables.
    arrays = {
        "TCLinkKeyRAMEntry": 3600, "ApsLinkKeyRAMEntry": 36,
        "AssociatedDevList": 3492, "rtgSrcTable": 1536,
        "neighborTable": 1792, "rtgTable": 1024, "BindingTable": 56,
    }
    scalars = {
        "gZDSECMGR_TC_DEVICE_MAX": (2, 300),
        "gZDSECMGR_ENTRY_MAX": (2, 3),
        "gNWK_MAX_DEVICE_LIST": (1, 97),
        "gMAX_RTG_SRC_ENTRIES": (1, 192),
        "gMAX_NEIGHBOR_ENTRIES": (1, 64),
        "gMAX_RTG_ENTRIES": (1, 128),
        "gNWK_MAX_BINDING_ENTRIES": (1, 4),
    }
    symbols = {name: [{"size_bytes": size, "section_type": 8,
                       "section": ".bss"}] for name, size in arrays.items()}
    symbols.update({name: [{"size_bytes": width, "initializer": value}]
                    for name, (width, value) in scalars.items()})
    symbols.update({name: [{"address": value}] for name, value in (
        ("__STACK_SIZE", 4096), ("heapStart", 0x20009000),
        ("heapEnd", 0x20023000))})
    return symbols


class FullCapacityAuditTests(unittest.TestCase):
    def audit(self, symbols, *, aps_define=3):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            opts = root / "znp_cnf.opts"
            defines = {**capacity.ROUTING, **capacity.DEFINES,
                       "ZDSECMGR_DEVICE_MAX": aps_define}
            opts.write_text("".join(f"-D{name}={value}\n"
                                    for name, value in defines.items()))
            admitted = {
                "schema": "r4-r05-full-native-capacity-opts-v1",
                "profile_sha256": capacity.digest(
                    capacity.full.DEFAULT_PROFILE.read_bytes()),
                "result_sha256": capacity.digest(opts.read_bytes()),
                "new_compiler_defines": capacity.DEFINES,
            }
            opts_receipt = root / "opts.json"
            opts_receipt.write_text(json.dumps(admitted))
            xml = root / "native.xml"
            xml.write_text(
                '<link_info><banner>TI ARM Clang 3.2.2</banner>'
                '<placement_map><memory_area><name>SRAM</name>'
                '<origin>0x20000000</origin><length>0x24000</length>'
                '</memory_area></placement_map></link_info>')

            def one_symbol(found, name):
                options = found.get(name, [])
                return options[0] if len(options) == 1 else None

            collector = SimpleNamespace(
                load_manifest=lambda _: {
                    "elf": {"path": root / "native.out", "sha256": "e" * 64},
                    "xml": {"path": xml, "sha256": capacity.digest(xml.read_bytes())},
                },
                parse_elf=lambda _: (b"", [], symbols),
                one_symbol=one_symbol,
                initializer_value=lambda _, item: item.get("initializer") if item else None,
                MAX_XML=2 * 1024 * 1024,
            )
            with patch.object(capacity, "load_collector", return_value=collector):
                return capacity.audit_native(
                    root, opts, opts_receipt, capacity.full.DEFAULT_PROFILE,
                    root / "collector.py", root / "receipt.json")

    def test_pinned_ti_scalar_widths_and_array_extents(self):
        linked = self.audit(native_symbols())["linked_capacity_symbols"]
        self.assertEqual(linked["trust_center_devices"]["capacity_scalar_width_bytes"], 2)
        for domain in ("associated_devices_slots", "source_routes", "neighbors", "nwk_routes"):
            self.assertEqual(linked[domain]["capacity_scalar_width_bytes"], 1)
        self.assertEqual(linked["aps_table_entries"]["capacity_proof"],
                         "LINKED_SCALAR_AND_ARRAY_EXTENT")

    def test_absent_unused_aps_scalar_requires_exact_pinned_array(self):
        symbols = native_symbols()
        del symbols["gZDSECMGR_ENTRY_MAX"]
        aps = self.audit(symbols)["linked_capacity_symbols"]["aps_table_entries"]
        self.assertEqual((aps["linked_count"], aps["array_bytes"], aps["entry_bytes"]),
                         (3, 36, 12))
        self.assertFalse(aps["capacity_scalar_present"])
        self.assertIsNone(aps["capacity_scalar_width_bytes"])
        self.assertEqual(aps["capacity_proof"], "ARRAY_EXTENT_AND_PINNED_TI_ABI")
        for size in (24, 35, 48):
            with self.subTest(size=size):
                altered = copy.deepcopy(symbols)
                altered["ApsLinkKeyRAMEntry"][0]["size_bytes"] = size
                with self.assertRaisesRegex(ValueError, "MISMATCH_aps_table_entries|ABI_DRIFT_aps_table_entries"):
                    self.audit(altered)

    def test_absent_aps_scalar_cannot_bypass_effective_compiler_count(self):
        symbols = native_symbols()
        del symbols["gZDSECMGR_ENTRY_MAX"]
        with self.assertRaisesRegex(ValueError, "EFFECTIVE_COMPILER_DEFINE_DRIFT_ZDSECMGR_DEVICE_MAX"):
            self.audit(symbols, aps_define=2)

    def test_present_wrong_or_ambiguous_aps_scalar_is_rejected(self):
        for scalar in ({"size_bytes": 2, "initializer": 2},
                       {"size_bytes": 1, "initializer": 3},
                       {"size_bytes": 2, "initializer": None}):
            with self.subTest(scalar=scalar):
                symbols = native_symbols()
                symbols["gZDSECMGR_ENTRY_MAX"] = [scalar]
                with self.assertRaisesRegex(ValueError, "MISMATCH_aps_table_entries"):
                    self.audit(symbols)
        symbols = native_symbols()
        symbols["gZDSECMGR_ENTRY_MAX"] *= 2
        with self.assertRaisesRegex(ValueError, "MISMATCH_aps_table_entries"):
            self.audit(symbols)

    def test_other_missing_scalars_and_wrong_routing_width_still_fail(self):
        for domain, name in (("trust_center_devices", "gZDSECMGR_TC_DEVICE_MAX"),
                             ("associated_devices_slots", "gNWK_MAX_DEVICE_LIST"),
                             ("source_routes", "gMAX_RTG_SRC_ENTRIES"),
                             ("neighbors", "gMAX_NEIGHBOR_ENTRIES"),
                             ("nwk_routes", "gMAX_RTG_ENTRIES")):
            with self.subTest(domain=domain):
                symbols = native_symbols()
                del symbols[name]
                with self.assertRaisesRegex(ValueError, "MISMATCH_" + domain):
                    self.audit(symbols)
        symbols = native_symbols()
        symbols["gMAX_RTG_SRC_ENTRIES"][0]["size_bytes"] = 2
        with self.assertRaisesRegex(ValueError, "MISMATCH_source_routes"):
            self.audit(symbols)


if __name__ == "__main__":
    unittest.main()
