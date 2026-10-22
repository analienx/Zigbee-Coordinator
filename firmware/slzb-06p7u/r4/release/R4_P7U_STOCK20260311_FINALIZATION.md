# Current stock 20260311 P7U candidate

Target: the single SLZB-06P7U R1.73 / CC2652P7, with the retained107-device
network. This supersedes historical A6000/direct-ROM APP-only instructions.
It grants no hardware access, BSL entry, flash, reset or production start.

**Current incident, 2026-10-22:** installed source `e298709` returned the
retained-startup SRSP but failed before state 9. Its independent B1P1 snapshot
reported FAILED, phase 13 NETWORK_START, NV operation item 0/subindex 96,
status 10. The real coordinator-transition publisher initializes legacy
marker `0x60=0x55`, which maps to exactly that extended-NV item/subindex.
The tails-only initializer rejected the missing marker and latched HOLD.

The correction permits that exact one-byte creation only while the internal
publisher holds a scoped capability, with retained NV, validated security and
durable NWK counter reservation. It independently proves absence and verifies
the created bytes; arbitrary legacy/security creation remains blocked. HOLD
now records a nonzero first startup failure. Hosted coverage composes the
actual publisher, legacy wrapper and extended initializer, with production B1
state, including controls that recreate the old rejection and reject an
unscoped exception. Native qualification and physical state-9 acceptance
remain required. Keep the failed installed image's startup attempt consumed;
preserve its newest persisted counters for any admitted upgrade.

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

Production targets ordinary Zigbee2MQTT / unmodified Herdsman. The bundled
protected host profile is optional diagnostic tooling, not a maintained HA
dependency. At the actual coordinator transition, after complete security
validation and durable counter reservation, firmware creates the missing
one-byte Herdsman configured marker (0x60=0x55) with checked readback. An
existing correct marker is untouched; a one-byte unconfigured marker is
completed without restoring network data. Malformed length or a failed
read/commit holds startup. This retained-network candidate does not implement an automatic
blank-NV backup restore. An intentional backup restore may use the separately
qualified stock bootstrap followed by an NV-preserving R4 reflash. Incident
specific inactive-NIB repair is outside this candidate. Hardware operations
and installed HA changes remain separate from preparing/building this image.
See the [NV HOLD evidence](P7U_NV_HOLD_FORENSICS_20261020.md).

Operational transport/mode decision: [P7U Ethernet-versus-HA-USB quickstart](P7U_TRANSPORT_AND_FLASH_QUICKSTART.md). The USB cable is connected to **Home Assistant**, not Zephyrus. The latest owner report has stock firmware responding over Ethernet, original NV restored, and coordinator state 0 after two failed starts. Firmware work does not contact or restart the unit. Another write requires new frozen admission and separate owner confirmation of AC000.

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

Physical acceptance starts on the existing Ethernet path: verify healthy
B1/F1 and SYS/UTIL, admitted retained NV, identity, keys and current counter
floors. A separately approved one-time retained ZDO startup uses the guarded
non-forming BDB0 path. Require actual state 9, continuous ZNP responses and
the verified configured marker before the deliberate USB return and ordinary
Zigbee2MQTT startup. The marker is not a substitute for identity/key agreement;
configuration mismatch must stop, and raw NV mutation remains blocked.
The earlier missing-NIB incident has since been restored by the owner; do
not repeat that restore. Backup-led, intentionally blank NV restoration
remains separate from this retained-only image.
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

## R4 NV flash brownout guard (TI 8.33)

The current-stock P7U native response file explicitly compiles
`NVOCMP_MIN_VDD_FLASH_MV=2000`. This activates the genuine TI
`NVOCMP_checkVoltage` / AONBatMon low-voltage refusal in `initNV`
for normal flash writes and erase/compaction work, rather than adding
a proprietary voltage algorithm. The native CCS options receipt
and post-link audit bind the exact define. It does not eliminate
instantaneous power cuts or authorize unknown NV journal repairs.

The pinned multi-page TI driver retains `RECOVER_COMPACT` and
`RECOVER_ERASE` for legitimate interrupted states. The strict R4
read-only pre-init classifier still HOLDs unrecognized/torn journals;
no auto-reformat or unconditional TI recovery bypass is introduced.

## R4 native journal recovery boundary

R4 allows the pinned TI 8.33 `RECOVER_COMPACT` when one CRC-verified
formed-network PGXSRC source survives and the destination is either
an XDST (possibly partially written and discardable) or a formatted
empty NACT page. TI recovers the original records; R4 then requires
a fully settled CRC-valid formed ring and zero sticky NV backend errors
before Zigbee starts. No new flash copy or restore algorithm is used.

`RECOVER_ERASE` is authorized only after the exact single-page source
has **already been erased** and formatted NACT, the completed PGCDST
journal identifies that same source and the remaining destination
records independently prove the coordinator's formed state.
A still-live source with a destination journal is **NOT** authority to
erase source content: without explicit bit-for-bit record equivalence
that would risk losing security material or rolling back counters.
These undecidable cuts remain HOLD and require the already-proven
stock recovery playbook. Automatic FORCE_CLEAN/virgin commissioning
remain denied. Native compilation and hardware boot still need to pass
before considering the device image deployable.

### Logical-state continuity during TI journal replay

For admitted interrupted compaction, the read-only NV4 source now
computes two order-independent 64-bit accumulators over each CRC-valid
active item (compressed identity, payload length and payload bytes,
excluding mutable status and CRC bits). Native TI recovery may relocate
records across pages but cannot change the resulting logical inventory.
Before allowing Zigbee startup, the R4 B1 init bridge requires matching
active record count AND both full logical accumulators, followed by
normal stock Z-Stack security restoration. This comparison does not
authorize arbitrary source erasure and does not replace the host's
PAN/E-PAN/key identity checks or confidential flash backup.

### No destructive TI initialization fallback in retained R4

The exact TI 8.33 `NVOCMP_scanPage` invalid page/header fallback
previously erased its corrupted sector; the >2-page `NVOCMP_initNv`
`FORCE_CLEAN` erased all four sectors, and `NORMAL_INIT` created a
new empty NV journal. The pinned source bridge replaces all three
paths with sticky runtime HOLD **without NVS_erase or NVS_write**.
All real TI `NORMAL_RESUME`, `RECOVER_COMPACT` and narrow
`RECOVER_ERASE` cases remain unchanged; only the proven preflight
permits those recovery paths. Exact body preimage validation prevents
a future unreviewed SDK version from silently re-enabling formatting.
