# Application writer and stock cleanup contract v2

The diagnostic follow-up uses one fixed **24-sector application envelope**:
8 KiB sectors at `0x00000..0x2E000`, ending before `0x30000`. This remains well
below NV5 at `0xA4000`; NV and the complete CCFG sector at `0xAE000` stay excluded.
This is an explicit reviewed envelope, not an unrestricted flash-size guard.

The candidate plan contains its actual contiguous occupied sectors (23 through
24 for these coordinator profiles), derived from the native image. A candidate
does not gain artificial trailing HEX bytes to fit the envelope. The low-level
adapter, core writer, offline plan, live CLI and package all enforce the limit.
Sector zero remains last, each programmed sector is CRC checked, and installed
CCFG/IEEE checks remain unchanged. No bank erase or reset operation is added.

The paired official-stock rollback covers **all 24 sectors**. Manufacturer APP
bytes remain exact. Each sector from `0x2C000` through `0x2E000` is explicitly
represented as FF-only cleanup. The full tail is verified, not just its last
sector. This removes custom diagnostics code even when it extends beyond the
old `0x2E000` boundary. Stock application-only HEX SHA-256 is now
`b1d63aea8201203064a501b8af13ecf230ae130b952fd920617aa88e138da1b7`.
The manufacturer container SHA and its application bytes are unchanged.

`test_application_contract.py` writes the top sector, rolls back a populated
custom tail, checks all bytes outside the envelope unchanged, and rejects the
next sector. Protocol tests independently reject NV and out-of-envelope
addresses. Native packaging rejects mismatched coverage and altered tail bytes.

The workbench package version is `0.1.0-rc2`; historical `p7u_rc1_*` script and
manifest filenames are retained for tooling continuity. No release/tag is
published by these scripts. The original RC1 tag, 23-sector kit and later e9
private archive remain immutable historical artifacts; they require their own
matching source/tool version and are not the new candidate.

NV preparation/restore is a different tool with exactly five NV sectors and
cannot write application/CCFG. See [NV5_RECOVERY.md](NV5_RECOVERY.md). This updated
software contract still needs actual one-unit ROM write/stock rollback proof.
