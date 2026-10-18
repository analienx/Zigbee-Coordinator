#!/usr/bin/env python3
"""Pinned-source-only stock P7U NV4 geometry overlay; NEVER authorizes flash.

Input files are throwaway copies of TI 8.33.00.16's znp.syscfg, P7 linker
command file, and TICLANG projectspec. The fitted stock application's binary
NVSCC26XX attributes show a four-page region at A6000..ADFFF.  This operation
cannot validate existing network keys, runtime initialization, or CCFG boot.

TI explicitly requires a matching NVOCMP_NVPAGES define in both compiler and
linker options, plus matching SysConfig and linker flash ranges. Every anchor
is exact and verified before returning any changed text.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

STOCK_BASE = 0xA6000
STOCK_SIZE = 0x8000
STOCK_PAGES = 4
STOCK_END = 0xAE000
SECTOR = 0x2000
UPSTREAM_GIT_BLOBS = (
    "463216ecaa895654cbfb85bd3becd838e49ae5bf",  # znp.syscfg
    "1e5777c21f354566e6479c3cb7d97bb51637159b",  # P7 TI-RTOS7 linker
    "4d05569e6a4164ce3c1d682b4ee9865f6a1d23be",  # TICLANG projectspec
)

P7_SYSCFG_OLD = (
    'if (deviceName.includes("R7") || deviceName.includes("P7"))\n'
    '{\n'
    '    NVS1.internalFlash.regionBase = 0xAA000;\n'
    '    NVS1.internalFlash.regionSize = 0x4000;\n'
    '}'
)
P7_SYSCFG_NEW = (
    'if (deviceName.includes("R7") || deviceName.includes("P7"))\n'
    '{\n'
    '    // P7U_R4_STOCK_NV4: existing fitted stock pages; no NV writes\n'
    '    NVS1.internalFlash.regionBase = 0xA6000;\n'
    '    NVS1.internalFlash.regionSize = 0x8000;\n'
    '}'
)
LINKER_EDITS = (
    ('#define FLASH_SIZE              0xAA000',
     '#define FLASH_SIZE              0xA6000'),
    ('#define FLASH_NV_BASE           0xAA000',
     '#define FLASH_NV_BASE           0xA6000'),
    ('#define FLASH_NV_SIZE           0x4000',
     '#define FLASH_NV_SIZE           0x8000'),
)
PROJECT_EDITS = (
    ('-DNVOCMP_NVPAGES=2', '-DNVOCMP_NVPAGES=4'),
    ('--define=NVOCMP_NVPAGES=2', '--define=NVOCMP_NVPAGES=4'),
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def replace_one(source: str, before: str, after: str, label: str) -> str:
    if source.count(before) != 1 or after in source:
        raise ValueError(f"P7U_NV4_{label}_ANCHOR_DRIFT")
    return source.replace(before, after, 1)


def transform(syscfg: str, linker: str, projectspec: str) -> tuple[str, str, str]:
    """Return three rewrites atomically, or raise before any file mutation."""
    if not all(isinstance(x, str) for x in (syscfg, linker, projectspec)):
        raise TypeError("P7U_NV4_SOURCE_TEXT_REQUIRED")
    sc, ld, project = (x.replace("\r\n", "\n") for x in (syscfg, linker, projectspec))
    # Fitted device is P7, not P10. Preserve CCFG sector and boot fields.
    if (sc.count('NVS1.$name                    = "CONFIG_NVSINTERNAL";') != 1 or
            ld.count('#define FLASH_LAST_BASE         0xAE000') != 1 or
            ld.count('#define FLASH_LAST_SIZE         0x2000') != 1 or
            ld.count('#define FLASH_BASE              0x00000000') != 1 or
            'Cortex M.CC1352P7' not in project):
        raise ValueError("P7U_NV4_PINNED_BOARD_OR_CCFG_MISMATCH")
    sc = replace_one(sc, P7_SYSCFG_OLD, P7_SYSCFG_NEW, "SYSCFG")
    for i, (old, new) in enumerate(LINKER_EDITS):
        ld = replace_one(ld, old, new, f"LINKER_{i}")
    for i, (old, new) in enumerate(PROJECT_EDITS):
        project = replace_one(project, old, new, f"PROJECT_{i}")
    return sc, ld, project


def apply(syscfg: Path, linker: Path, projectspec: Path, receipt: Path) -> dict:
    if any(p.is_symlink() for p in (syscfg, linker, projectspec, receipt)):
        raise ValueError("P7U_NV4_SOURCE_SYMLINK_REFUSED")
    paths = [syscfg.resolve(), linker.resolve(), projectspec.resolve(), receipt.resolve()]
    if len(set(paths)) != len(paths):
        raise ValueError("P7U_NV4_INPUT_OR_RECEIPT_ALIAS")
    if receipt.exists() or receipt.is_symlink():
        raise ValueError("P7U_NV4_RECEIPT_MUST_NOT_OVERWRITE")
    old = [p.read_bytes() for p in (syscfg, linker, projectspec)]
    if tuple(git_blob(x) for x in old) != UPSTREAM_GIT_BLOBS:
        raise ValueError("P7U_NV4_UPSTREAM_BLOB_PIN_MISMATCH")
    new = transform(*(x.decode("utf-8") for x in old))
    report = {
        "schema": "r4-stock-p7u-nv4-source-overlay-v1",
        "stock_nvs_range": ["0xA6000", "0xAE000"],
        "stock_nvs_sector_bytes": SECTOR,
        "stock_nvs_page_count": STOCK_PAGES,
        "linker_app_end_exclusive": "0xA6000",
        "ccfg_sector": ["0xAE000", "0xB0000"],
        "source_before_sha256": [sha256(x) for x in old],
        "upstream_git_blobs": list(UPSTREAM_GIT_BLOBS),
        "source_after_sha256": [sha256(x.encode("utf-8")) for x in new],
        "mode": "SOURCE_ONLY_NATIVE_AND_CLONE_UNVERIFIED",
        "native_image_qualified": False,
        "existing_nv_readonly_clone_passed": False,
        "security_counter_continuity_verified": False,
        "hardware_contact": False,
        "flash_authorized": False,
    }
    # Stage *all* outputs on their destination filesystems before replacing
    # any pinned inputs. If a replacement raises, restore the original bytes
    # from pre-staged copies. A killed process still requires reconstructing
    # the disposable SDK from the pinned donor (multi-file rename is not an
    # atomic crash transaction).
    originals = (syscfg, linker, projectspec)
    payloads = [value.encode("utf-8") for value in new]
    receipt_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    staged: list[Path] = []
    backups: list[Path] = []
    replaced: list[int] = []
    rollback_complete = True

    def stage(path: Path, contents: bytes, *, mode: int) -> Path:
        with tempfile.NamedTemporaryFile(prefix=".r4-nv4-stage-", dir=path.parent,
                                         delete=False) as stream:
            temporary = Path(stream.name)
            staged.append(temporary)
            os.fchmod(stream.fileno(), mode)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary

    try:
        outputs = [stage(path, data, mode=stat.S_IMODE(path.stat().st_mode))
                   for path, data in zip(originals, payloads)]
        receipt_stage = stage(receipt, receipt_bytes, mode=0o600)
        for path, raw in zip(originals, old):
            backups.append(stage(path, raw, mode=stat.S_IMODE(path.stat().st_mode)))
        for index, (path, temporary) in enumerate(zip(originals, outputs)):
            os.replace(temporary, path)
            replaced.append(index)
        os.replace(receipt_stage, receipt)
    except Exception:
        for index in reversed(replaced):
            try:
                os.replace(backups[index], originals[index])
            except OSError as exc:
                rollback_complete = False
                raise RuntimeError("P7U_NV4_OVERLAY_ROLLBACK_FAILED") from exc
        raise
    finally:
        # Keep donor copies for manual recovery if the rollback itself fails.
        if rollback_complete:
            for temporary in staged:
                temporary.unlink(missing_ok=True)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("syscfg", "linker", "projectspec", "receipt"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.syscfg, args.linker, args.projectspec, args.receipt),
                     sort_keys=True))


if __name__ == "__main__":
    main()
