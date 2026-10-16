"""Collect actual CCS ZNP outputs, never synthetic fixture artifacts."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def one(root, suffix):
    files = [p for p in root.rglob("*") if p.is_file() and p.name.lower().endswith(suffix)]
    files = [p for p in files if "znp" in p.name.lower()]
    if len(files) != 1:
        raise RuntimeError("expected exactly one ZNP %s, found %d: %s" %
                           (suffix, len(files), [str(x) for x in files[:10]]))
    return files[0]


def collect(workspace, out, clang_dir, build_log):
    out.mkdir(parents=True, exist_ok=True)
    elf = one(workspace, ".out")
    xml = one(workspace, "linkinfo.xml")
    hexfile = one(workspace, ".hex")
    if not build_log.is_file():
        raise RuntimeError("missing actual CCS build log")
    tool = clang_dir / "bin" / "tiarmobjcopy"
    if not tool.is_file():
        raise RuntimeError("missing TI tiarmobjcopy")
    items = {"elf": elf, "xml": xml, "hex": hexfile}
    for kind, origin in items.items():
        shutil.copyfile(origin, out / ("znp" + {"elf": ".out", "xml": "_linkInfo.xml", "hex": ".hex"}[kind]))
    subprocess.run([str(tool), "-O", "binary", str(elf), str(out / "znp.bin")], check=True)
    shutil.copyfile(build_log, out / "build.log")
    items = {"elf": "znp.out", "xml": "znp_linkInfo.xml", "hex": "znp.hex", "bin": "znp.bin"}
    manifest = {
        "schema": "r4-b0-artifact-manifest-v1",
        "build_log": "build.log",
        "files": {key: {"file": name, "sha256": hashlib.sha256((out / name).read_bytes()).hexdigest()}
                  for key, name in items.items()},
        "provenance": {"elf_source": str(elf), "xml_source": str(xml),
                       "hex_source": str(hexfile), "kind": "NATIVE_DONOR_UNQUALIFIED"},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--build-log", type=Path, required=True)
    args = parser.parse_args()
    collect(args.workspace, args.out, args.clang, args.build_log)


if __name__ == "__main__":
    main()
