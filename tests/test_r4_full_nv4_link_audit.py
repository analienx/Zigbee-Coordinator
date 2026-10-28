"""Full-NV4 TI linker XML must prove geometry and 4096-byte C/IRQ stack."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "firmware/slzb-06p7u/r4/b0/tools/b0_image_audit.py"
spec = importlib.util.spec_from_file_location("r4_native_audit", SOURCE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def linker_xml(*, nv_base=0xA6000, nv_size=0x8000, cirq=4096):
    root = ET.Element("link_info")
    ET.SubElement(root, "banner").text = "TI ARM Clang 3.2.2 (native link)"
    ET.SubElement(root, "output_file").text = "znp.out"
    entry = ET.SubElement(root, "entry_point")
    ET.SubElement(entry, "address").text = "0x101"
    placement = ET.SubElement(root, "placement_map")
    for name, origin, length in (
        ("FLASH", 0, 0xA0000), ("FLASH_NV", nv_base, nv_size),
        ("FLASH_LAST", 0xAE000, 0x2000),
        ("SRAM", 0x20000000, 0x24000),
    ):
        node = ET.SubElement(placement, "memory_area")
        for tag, value in (("name", name), ("origin", hex(origin)), ("length", hex(length))):
            ET.SubElement(node, tag).text = value
    groups = ET.SubElement(root, "logical_group_list")
    for name, addr, size in (
        (".resetVecs", 0, 0x3C), (".ccfg", 0xAFFA8, 0x58),
        (".stack", 0x20020000, cirq),
    ):
        node = ET.SubElement(groups, "logical_group")
        for tag, value in (("name", name), ("load_address", hex(addr)), ("size", hex(size))):
            ET.SubElement(node, tag).text = value
    return ET.tostring(root, encoding="unicode")


class FullNv4LinkedAuditTests(unittest.TestCase):
    def test_full_nv4_geometry_and_real_cirq_stack_required(self):
        evidence, error = audit._parse_link_xml(
            linker_xml(), "znp.out", 0x101, full_nv4=True)
        self.assertIsNone(error)
        self.assertEqual(evidence["areas"]["FLASH"], (0, 0xA0000))
        self.assertEqual(evidence["areas"]["FLASH_NV"], (0xA6000, 0x8000))
        self.assertEqual(evidence["sections"][".stack"][1], 4096)

    def test_old_nv2_profile_cannot_masquerade_as_full_nv4(self):
        _, error = audit._parse_link_xml(
            linker_xml(nv_base=0xA0000, nv_size=0x4000),
            "znp.out", 0x101, full_nv4=True)
        self.assertIn("geometry mismatch", error)

    def test_cirq_donor_1024_not_accepted_as_4096(self):
        _, error = audit._parse_link_xml(
            linker_xml(cirq=1024), "znp.out", 0x101, full_nv4=True)
        self.assertIn("want 4096 linked bytes", error)

    def test_incompatible_link_profiles_refused(self):
        _, error = audit._parse_link_xml(
            linker_xml(), "znp.out", 0x101,
            direct_rom_boot=True, full_nv4=True)
        self.assertIn("mutually exclusive", error)

    def test_old_direct_profile_still_rejects_nv4_geometry(self):
        _, error = audit._parse_link_xml(
            linker_xml(), "znp.out", 0x101, direct_rom_boot=True)
        self.assertIn("geometry mismatch", error)


if __name__ == "__main__":
    unittest.main()
