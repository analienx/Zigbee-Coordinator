"""Hosted R11-DIAG audit: extension-frame/RAM/startup-observer gates.

Run only in GitHub-hosted Actions as part of audit_source.py. No radio,
flash, or device access. All checks are fail-closed exact or numeric.
"""
import subprocess

R11_MT_FILES = ('r11_startup.h', 'r11_ext_export.inc')
R11_TI_FILES = ('source/ti/zstack/startup/main.c',
                'source/ti/zstack/stack/zdo/zd_app.c',
                'source/ti/zstack/stack/bdb/bdb.c')


def audit_r11(a):
    mt = a.sdk / 'source/ti/zstack/mt'
    variant = getattr(a, 'variant', 'DIAG')
    if variant != 'DIAG':
        # BASE never installs DIAG-only observer headers: assert absence
        # and zero startup hooks (variant-aware audit; BASE stays pristine).
        for name in R11_MT_FILES:
            if (mt / name).exists():
                raise ValueError('BASE must not install DIAG-only %s' % name)
        for path in R11_TI_FILES:
            diff = subprocess.check_output(
                ['git', '-C', str(a.sdk), 'diff', '--', path], text=True)
            for line in diff.splitlines():
                if not line.startswith('+') or line.startswith('+++'):
                    continue
                if 'T832R11_' in line or 'r11_startup.h' in line:
                    raise ValueError('BASE carries startup observer delta in %s: %s' % (path, line[1:].strip()[:80]))
        return {'r11_observer_only': True, 'retention_bit_clear': True,
                'variant': variant, 'r11_absent': True}
    for name in R11_MT_FILES:
        text = (mt / name).read_text()
        for forbidden in ('ClockP_', 'malloc(', 'printf(', 'NVOCMP_read(',
                          'NVS_', 'Memory_getStats('):
            if forbidden in text:
                raise ValueError('heavy R11 observer %s: %s' % (name, forbidden))
    impl = (mt / 't832_diag_impl.inc').read_text()
    for marker in ('T832R11Ext_tryExport(now64,now)',
                   'T832R11Ext_noteLegacyAccepted()',
                   'T832R11Ext_sample(now)',
                   'T832_DIAG_CAP_R11_EXT'):
        if marker not in impl:
            raise ValueError('R11 export wiring missing: ' + marker)
    header = (mt / 't832_diag.h').read_text()
    for marker in ('T832_DIAG_EV_NV_FIRST_V1 = 51',
                   'T832_DIAG_EV_STARTUP_V1 = 52',
                   'T832_DIAG_EV_RUNTIME_V1 = 53',
                   'T832_DIAG_CAP_R11_EXT        (1u << 30)'):
        if marker not in header:
            raise ValueError('R11 header contract missing: ' + marker)
    if '(1u << 31)' in header or '<< 31' in header:
        raise ValueError('retention bit31 must stay clear')
    # Startup POD patches observe only: every added line is an observer
    # call, its include, a bare re-brace of an observed return, or the
    # re-emitted observed return itself. No branch condition, call target,
    # or return value may change.
    for path in R11_TI_FILES:
        diff = subprocess.check_output(
            ['git', '-C', str(a.sdk), 'diff', '--', path], text=True)
        for line in diff.splitlines():
            if not line.startswith('+') or line.startswith('+++'):
                continue
            body = line[1:].strip()
            if path == R11_TI_FILES[0] and body in (
                    'uint8_t t832r11InitStatus;',
                    't832r11InitStatus=zstack_user0Cfg.nvFps.initNV(NULL);'):
                continue
            if path == R11_TI_FILES[1] and body == 'nvStat = NV_ITEM_UNINIT;':
                # Existing else assignment, re-braced solely to observe NLME.
                continue
            if body in ('{', '}'):
                continue
            if body.startswith('return ( ZDO_INITDEV_'):
                continue
            if ('T832R11_' in line or 'r11_startup.h' in line or
                    'T832Diag_' in line or body == '#include "t832_diag.h"'):
                continue
            raise ValueError('non-observer delta in %s: %s' % (path, body[:80]))
    return {'r11_observer_only': True, 'retention_bit_clear': True}
