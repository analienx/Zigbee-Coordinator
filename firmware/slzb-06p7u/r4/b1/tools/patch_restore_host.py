"""Pinned TI 8.33 ZNP compatibility for restoring an existing Zigbee network.

The unmodified donor presents itself as legacy Z-Stack 1.2 even though it
implements the extended NV tables. Its MT SYS key-read gate rejects the
active and alternate key IDs needed by zigbee-herdsman restore strategy.
This change does not mutate NV, rotate keys, or adjust frame counters.
"""
from patch_zdapp import replace_once


def patch_restore_host(mt_sys: str, mt_version: str) -> tuple[str, str]:
    mt_version = replace_once(
        mt_version,
        "                                   0,  /* Product ID */",
        "                                   1,  /* Z-Stack 3.x: extended NV tables */",
        "pinned MT SYS_VERSION product for ZStack3x0")

    # ZCD_NV_NWKKEY (key plus counter) is already readable via the same
    # transport, so this guard does not create a new confidentiality boundary.
    # Leave the separate certificate/private-key read denial untouched.
    mt_sys = replace_once(
        mt_sys,
        '#include "mt_version.h"',
        '#include "mt_version.h"\n'
        '#define B1_RESTORE_ALLOW_NETWORK_KEY_READ 1',
        "bounded read compatibility declaration")
    mt_sys = replace_once(
        mt_sys,
        '#if !MT_SYS_KEY_MANAGEMENT\n  if ( (nvId == ZCD_NV_NWK_ACTIVE_KEY_INFO)',
        '#if !MT_SYS_KEY_MANAGEMENT && !B1_RESTORE_ALLOW_NETWORK_KEY_READ\n'
        '  if ( (nvId == ZCD_NV_NWK_ACTIVE_KEY_INFO)',
        "host-read protection compatible with 3.x restore")
    return mt_sys, mt_version
