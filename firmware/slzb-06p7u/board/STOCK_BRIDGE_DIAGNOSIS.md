# Stock P7U USB/ZNP evidence — unresolved

The current user-supplied dashboard identifies USB Device/coordinator mode,
corev3.2.6.dev3, AP-only networking, stock metadata20240316 and the label HW & SW.
This does not state UART baud or establish line-control behavior. Earlier HA
enumeration and a single115200 SYS_PING timeout are historical observations;
no new serial session has been opened for this implementation.

Read-only HTTP attempts from the executor on2026-10-14 could not resolve the
user-supplied console hostname; the user-supplied AP address timed out. Those
are management-path failures from this host, not radio-health evidence. No
settings, USB controls, radio reset, service or network state was changed.

The [manufacturer mode manual](https://smlight.tech/support/manuals/books/slzb-os/page/mode)
defines USB mode as direct serial to the automation host. The separate USB to
Ethernet passthrough feature concerns attached USB peripherals. The
[SLZB-OS3.2.0 changelog](https://smlight.tech/support/manuals/books/slzb-os/page/changelog-slzb-os)
documents a selectable alternative USB driver for U-series devices. The exact
selection on this3.2.6.dev3 unit remains unknown; no later Berry API is assumed.

The [documented status endpoints](https://smlight.tech/support/manuals/books/slzb-os/page/slzb-os-api-endpoints)
are `/ha_info`, `/ha_sensors` and `/metrics`; other UI endpoints are explicitly
undocumented and version-dependent. Respect at most one request per second.
Next evidence: reachable management status and read-only USB/mode settings,
actual baud/driver/flow/line-control contract, then fresh one-owner exclusion.
Only after those are confirmed: one bounded SYS_PING and conditional SYS_VERSION.
Do not respond to another timeout with baud/control/reset loops.

Z2M's historical Supervisor error is a separate operational observation. No
production service intervention is included in this board-source package.
