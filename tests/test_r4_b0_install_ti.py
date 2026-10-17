"""Offline assurance for the hosted TI toolchain installer."""
import importlib.util
import pathlib
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "firmware/slzb-06p7u/r4/b0/tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("b0_install_ti", TOOLS / "b0_install_ti.py")
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


class HostedInstallerTests(unittest.TestCase):
    def test_empty_installer_archive(self):
        with tempfile.TemporaryDirectory() as root:
            base = pathlib.Path(root)
            archive = base / "empty.tar.gz"
            with tarfile.open(archive, "w:gz"):
                pass
            dest = base / "safe"
            dest.mkdir()
            install.contained_extract(archive, dest)
            self.assertEqual(list(dest.iterdir()), [])

    def test_archive_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            base = pathlib.Path(root)
            archive = base / "link.tar.gz"
            info = tarfile.TarInfo("escape")
            info.type = tarfile.SYMTYPE
            info.linkname = "../outside"
            with tarfile.open(archive, "w:gz") as tf:
                tf.addfile(info)
            dest = base / "safe"
            dest.mkdir()
            with self.assertRaisesRegex(RuntimeError, "link/device"):
                install.contained_extract(archive, dest)

    def test_archive_parent_escape_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            base = pathlib.Path(root)
            archive = base / "traversal.tar.gz"
            info = tarfile.TarInfo("../outside")
            info.size = 0
            with tarfile.open(archive, "w:gz") as tf:
                tf.addfile(info)
            dest = base / "safe"
            dest.mkdir()
            with self.assertRaisesRegex(RuntimeError, "traversal"):
                install.contained_extract(archive, dest)


if __name__ == "__main__":
    unittest.main()
