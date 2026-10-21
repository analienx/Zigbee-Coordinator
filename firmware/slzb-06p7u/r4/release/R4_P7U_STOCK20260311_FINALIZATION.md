# Current stock 20260311 P7U candidate

Target: the single SLZB-06P7U R1.73 / CC2652P7, with the retained107-device
network. This supersedes historical A6000/direct-ROM APP-only instructions.
It grants no hardware access, BSL entry, flash, reset or production start.

**Reliability candidate, 2026-10-21:** the `828b1b5` image booted and answered
ZNP, but an automatic herdsman restore deleted NIB and left startup option 3;
its subsequent NV HOLD was correct. This revision prevents destructive raw
MT NV changes on an admitted network, blocks pending destructive startup
flags, accepts the valid mixed FULL/INACTIVE page rotation, adds precise
read-only NV4 diagnostics, and includes protected herdsman startup in the host
bundle. Internal Zigbee counter/routing persistence remains enabled.
After successful globals initialization, the ZNP profile enables direct ZDO
callbacks in RAM so a retained disabled callback setting cannot suppress
host responses. The stored callback setting remains unchanged; initialization
failure latches HOLD before enabling the runtime switch.

Deploy the firmware with its matching protected host bundle. This is a
retained-network candidate; it does not authorize or implement an automatic
blank-NV backup restore. An intentional backup restore may use the separately
qualified stock bootstrap followed by an NV-preserving R4 reflash. Incident
specific inactive-NIB repair is outside this candidate. Hardware operations
and installed HA changes remain separate from preparing/building this image.
See the [NV HOLD evidence](P7U_NV_HOLD_FORENSICS_20261020.md).

Operational transport/mode decision: [P7U Ethernet-versus-HA-USB quickstart](P7U_TRANSPORT_AND_FLASH_QUICKSTART.md). The USB cable is connected to **Home Assistant**, not Zephyrus. The last approved operation captured full flash twice over Ethernet/ROM BSL, without an app-return command. Firmware work after that operation does not contact or restart the unit. The earlier APP+AC000 operation and readback succeeded; another write still requires new frozen admission and separate owner confirmation of AC000.

## Accepted evidence and exact layout

The existing private full capture and genuine pinned TI8.33 RAM initializer
reported init_code0, 892 parsed records, 779 active records, four pages and
zero write, erase or compaction attempts. That is successful retained-store
initialization, not coordinator boot or restored security/RF acceptance.
This was an earlier retained snapshot, distinct from the 952-record preflash
pair accepted by the exact C observer on 2026-10-20; do not conflate them.
Reuse that evidence; do not repeat restore, add a counter margin or re-pair.

| Range | Role and transition rule |
|---|---|
| 00000..9FFFF | Conservative APP envelope; actual sector list comes from linked image |
| A0000..A3FFF | Reserved gap, unchanged |
| A4000..ABFFF | Four retained NVOCMP pages, unchanged by the writer |
| AC000..ADFFF | Factory ROM-selected boot stage; separate explicit approval required |
| AE000..AFFFF | Whole top/CCFG sector, unchanged |

The separate build profile is `profiles/p7u-r4-stock20260311-nv4.json`.
`P7U CURRENT stock20260311 B0-B4 dual native` builds two real TI images and
joins them with the pinned B4 host source. Current native audits require
A4000 NVS, TC300/APS3/association97/routing192-64-128/CIRQ4096 and factory
CCFG IMAGE_VALID_CONF=AC000. A raw APP vector at0 is intentionally not declared
bootable through the unchanged factory signed loader.

## Concrete boot route

The candidate includes a new TI-clang-compiled Cortex-M4F stage for the single
AC000 sector, not the historical fixed-opcode trampoline. Its full54-entry
vector table handles NMI/faults with local HOLD. It checks the exact audited
APP SP/reset pair, clears SysTick/NVIC/pending state, restores privileged MSP
and interrupt-mask state, sets VTOR0 with barriers, and enters TI's real reset
handler. Hosted execution checks actual compiled instructions/registers/MMIO.
It does not model TI ROM, analog hardware or asynchronous fault timing.

Replacing this stage changes the manufacturer signing trust boundary. The
new stage does not claim to be a manufacturer-signed MCUboot image or to
reproduce the stock loader's signature policy. There is no matching private
manufacturer key available for an authenticated stock-loader route.

## Private preflight and bounded operation

The public candidate holds APP-only HEX, the8192-byte handoff, original native
audit inputs, final TI source patch/manifest, linked security ABI and host
receipts. Its `candidate.json` is exact-head evidence, not a flash grant.
`profile.json` is a build profile, not a private live-board identity.

1. Use the existing approved same-unit duplicate capture/ROM CRC procedure in
   the hardware lane. Preserve that unit's original APP and AC000 bytes offline.
   Confirm current Ethernet ownership; leave stopped USB-configured Z2M, MQTT
   and transport settings unchanged.
2. Run `qualification/stock20260311_security_preflight.py` privately with its
   externally pinned capture, known baseline and candidate native ABI. It uses
   genuine TI logical reads and emits only sanitized booleans/counts/reasons.
   An aggregate scanner count cannot supply its PASS. Any unresolved identity,
   key, TCLK/index, native layout or persisted counter check remains HOLD.
3. `r4_stock20260311_transition.prepare` binds the exact public candidate,
   APP/handoff bytes, both identical captures, full CCFG and the private
   security receipt. Dict/plan/capture receipt pins in this API use canonical
   JSON (sorted keys, compact separators); file/native manifest pins use raw
   bytes as stated in their receipts. Keep all generated transition material
   private. No hardware adapter or live CLI is constructed by this module.
4. Review the generated exact sector list and hashes, then obtain separate
   owner approval explicitly naming APP plus the single AC000 boot sector.
   Earlier APP-only permission is insufficient. Never erase CCFG, NV or bank.
5. Admission reads SHA plus device ROM CRC for all88 sectors and binds live
   management identity. The bounded executor journals each erase, programs
   nonzero APP sectors then APP vector sector0, and verifies all APP before
   AC000. It programs AC008..ADFFF first, verifies code/tail and all flash,
   then writes AC000's first8 vector bytes last. It independently verifies all
   sectors before returning still in BSL. Reset is a separate operator action.

The operation is not interruption-atomic. Any timeout/uncertain packet stops
without retry, reset or automatic restore. Reenter the independently preserved
DIO15-low ROM BSL path and read/CRC the actual interrupted state before a new
approved recovery plan. Recovery restores only exact stock APP (sector0last)
and original AC000 (vectors last), preserves current NV/top, and verifies all
flash before reset. After firmware has run, do not replay an old NV snapshot;
current committed security/counter state must be retained and re-admitted.

Physical acceptance has two ordered phases. First, after a controlled verified
boot, obtain read-only B1/F1 and ZNP SYS/UTIL responses, confirm no HOLD and
match persisted identity/security against the qualified backup. Second, let
the owner select HA-attached USB and start exactly one matching protected
Herdsman/Zigbee2MQTT instance. Only **after protected host startup** may
coordinator state 9 and representative router/end-device traffic be required;
do not deadlock acceptance by demanding state 9 before its host can run.
Stop on any restore/commissioning request or security mismatch; never
fall through to normal Herdsman recovery against ambiguous retained NV.
The incident's current inactive NIB and STARTUP_OPTION=3 are not repaired by
APP/AC000 reflashing. Backup-led, intentionally blank NV restoration remains
a distinct unimplemented one-time protocol, not a permitted auto-restore.
NWK key UPDATE/SWITCH and B5 stay disabled. FULL_B0_B4 remains unsealed until
actual persistence/RF acceptance; native linking is not live300-device fit.

Primary boot references: [TI ROM/CCFG boot chain](https://www.ti.com/lit/an/swra651/swra651.pdf),
[TI ROM BSL](https://www.ti.com/lit/an/swra466e/swra466e.pdf),
[ARM core register/reset state](https://arm-software.github.io/CMSIS_6/latest/Core/group__Core__Register__gr.html),
[MCUboot signing](https://docs.mcuboot.com/signed_images.html).

## P0 retained-only runtime boundary (2026-10-21)

The TI MT SYS raw-NV handler never interprets missing/ambiguous B1 NV
admission as permission for virgin commissioning, deletion, creation,
compaction or write. It permits *only* exact byte-identical legacy no-op
writes against an admitted retained store with no runtime HOLD; ordinary
internal stack security-counter persistence remains intact. The read-only
NV4 observer limits total historical records by the physical four-page
capacity rather than a lower arbitrary wear/churn count. These are narrow
non-destructive startup reliability fixes, not a new restore implementation.

Reuse the previously versioned P7U stock/Herdsman restore sequence from
`skills/p7u-zstack-restore-recovery/SKILL.md` if recovery is approved after
private backup, identity and counter continuity checks. Historical stock
restore wrote the original network NV, but **did not establish coordinator
state 9**. Do not repeat that write operation to cure a startup timeout,
replay an older backup over newer counters, invent a custom NVOCMP repair,
or interpret a successful GitHub build as hardware acceptance.
