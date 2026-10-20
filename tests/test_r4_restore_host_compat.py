"""R4 host restore contract against TI's legacy ZNP version/key-read gates."""
from pathlib import Path
import sys

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "firmware" / "slzb-06p7u" / "r4" / "b1" / "tools"
sys.path.insert(0, str(TOOLS))
from patch_restore_host import patch_restore_host  # noqa: E402


def fixtures():
    mt_sys = (
        '#include "mt_version.h"\n'
        '#if !MT_SYS_OSAL_NV_READ_CERTIFICATE_DATA\n'
        '  /* private certificate reads still denied */\n'
        '#endif\n'
        '#if !MT_SYS_KEY_MANAGEMENT\n'
        '  if ( (nvId == ZCD_NV_NWK_ACTIVE_KEY_INFO) ||\n'
        '       (nvId == ZCD_NV_NWK_ALTERN_KEY_INFO) ||\n'
        '       (nvId == ZCD_NV_PRECFGKEY) )\n'
        '  { return ZInvalidParameter; }\n'
        '#endif\n'
    )
    mt_version = (
        'const uint8_t MTVersionString[] = {\n'
        '  2,  /* Transport protocol revision */\n'
        '                                   0,  /* Product ID */\n'
        '};\n'
    )
    return mt_sys, mt_version


def test_modern_product_and_keys_while_preserving_certificate_guard():
    mt_sys, mt_version = patch_restore_host(*fixtures())
    assert '1,  /* Z-Stack 3.x: extended NV tables */' in mt_version
    assert '0,  /* Product ID */' not in mt_version
    assert '#define B1_RESTORE_ALLOW_NETWORK_KEY_READ 1' in mt_sys
    assert '#if !MT_SYS_KEY_MANAGEMENT && !B1_RESTORE_ALLOW_NETWORK_KEY_READ' in mt_sys
    assert '#if !MT_SYS_OSAL_NV_READ_CERTIFICATE_DATA' in mt_sys
    assert 'ZCD_NV_PRECFGKEY' in mt_sys
    assert 'NWKKEY' not in mt_sys  # does not alter the logical NWK key record


def test_unknown_or_twice_patched_donor_fails_closed():
    source = fixtures()
    transformed = patch_restore_host(*source)
    with pytest.raises(RuntimeError, match="SOURCE_DRIFT"):
        patch_restore_host(*transformed)
    with pytest.raises(RuntimeError, match="SOURCE_DRIFT"):
        patch_restore_host(source[0].replace('MT_SYS_KEY_MANAGEMENT', 'UNKNOWN'), source[1])
    with pytest.raises(RuntimeError, match="SOURCE_DRIFT"):
        patch_restore_host(source[0], source[1].replace('0,  /* Product ID */', '2,  /* Product ID */'))


def test_overlay_requires_pinned_mt_sources_and_receipts():
    apply = (TOOLS / "apply_b1.py").read_text()
    hosted = (TOOLS / "run_hosted_tests.py").read_text()
    assert 'SDK_MT_VERSION,  # do not shift existing SOURCE_PATHS harness indices' in hosted
    for required in (
        'SDK_MT_SYS', 'SDK_MT_VERSION', 'SHA_MT_SYS', 'SHA_MT_VERSION',
        'git_blob_sha(mt_sys) != SHA_MT_SYS',
        'git_blob_sha(mt_version) != SHA_MT_VERSION',
        'mt_sys, mt_version = patch_restore_host(mt_sys, mt_version)',
        'src_mt_sys.write_text(mt_sys',
        'src_mt_version.write_text(mt_version',
        '"modified_mt_sys_sha256": SDK_MT_SYS',
        '"modified_mt_version_sha256": SDK_MT_VERSION',
    ):
        assert required in apply


def test_composite_b4_accepts_only_attested_b1_mt_sys():
    stage = (Path(__file__).resolve().parents[1] / "tools"
             / "r4_b0_b4_composite_stage.py").read_text()
    assert stage.count("for name in (TASK,UART,SYS):") == 2
    assert 'hashlib.sha256((sdk/name).read_bytes()).hexdigest()!=v' in stage
    assert 'bindings=b1.get("additional_source_bindings",{})' in stage
    assert 'B1 source changed before B4 overlay:' in stage
