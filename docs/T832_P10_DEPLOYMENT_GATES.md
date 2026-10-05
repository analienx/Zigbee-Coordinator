# T832 R5 P10 deployment gates

This addendum applies issue #73's [scope/readiness clarification](https://github.com/analienx/home-assistant-stack/issues/73#issuecomment-5998837901).
It supersedes the combined hardware-release sequence in the original R5
closure. It changes deployment documentation only; the validated firmware
candidate remains pinned below. **Current status: candidate validated,
FLASH-READY not established, flash_authorized=false.** No live deployment is
claimed or authorized by this document.

## Target and immutable candidate

| Item | Pin / scope |
|---|---|
| Only firmware target | MR4U **CC2674P10**, through the existing management radio-upload path |
| ESP32-S3 / SLZB-OS | Unchanged; existing management/reset/bridge interfaces provide independent evidence |
| EFR32MG26 / Ember | Unchanged; no update, reconfiguration or repurposing |
| Firmware repository commit | `1f08f3c1e5da067a1db144e07dc71fd7e155a217` |
| Hosted validation | [37339066099](https://github.com/analienx/Zigbee-Coordinator/actions/runs/37339066099), all seven jobs green |
| DIAG image | `T832-DIAG-R0.hex`, 558808 bytes |
| Image SHA256 | `773dcbb100353005ea8f86faf261d4e25c350ffac715c3dcb08aeeca8b69e15c` |
| Matching OUT SHA256 | `6f06cfab0c131afaac2390abd2cbb75da62bcc01deedf7006881700757251bca` |
| Expected live identity | SYS_VERSION revision `8320002`; DEBUG build `0x1f08f3c1`, capabilities `0x0ffbffff` |

R5-11 is host-side observation/correlation around existing interfaces. It
does not require a new SLZB-OS build. R5-12's producer/scheduler remains an
undeployed integration seam. Neither requirement expands the flash target.
Installing the recovery automation is a separate live change; it is not
implicitly authorized by a P10 upload permit.

## Image extent does not establish erase semantics

The issue clarification reports inspection of this exact hosted HEX:
application records approximately `0x00000000..0x00030770`, CCFG records
`0x50000000..0x5000007c`, and no records in FLASH_NV starting `0x000FD800`.
The linker reserves 10240 NV bytes; reservation is different from HEX content.
This is image-content evidence, **not proof that the uploader preserves NV**.

The public SMLIGHT flasher at commit
[`9a1d33571c1cdaedc9dfcdcf2df5b5a5fece0b1c`](https://github.com/smlight-tech/smlight-cc-flasher/tree/9a1d33571c1cdaedc9dfcdcf2df5b5a5fece0b1c)
calls erase before programming in
[`Flasher.flash`](https://github.com/smlight-tech/smlight-cc-flasher/blob/9a1d33571c1cdaedc9dfcdcf2df5b5a5fece0b1c/smlight_cc_flasher/flasher.py).
[`CC26xx.erase`](https://github.com/smlight-tech/smlight-cc-flasher/blob/9a1d33571c1cdaedc9dfcdcf2df5b5a5fece0b1c/smlight_cc_flasher/device.py)
performs main-bank erase and, for M33, CCFG erase. These sources do not prove
the installed MR4U management UI uses that implementation or configuration.

Record the installed management version, positively identified P10 upload
route, and version-specific erase evidence. If semantics remain unknown,
record that explicitly, assume NV may be lost, and require a verified restore
plan. Do not infer preservation from a progress message, successful upload,
or absence of NV records. Do not substitute this CLI for the intended UI path.

## A. FLASH-READY: before one upload

Each item needs dated evidence in a private operator record. Unknown evidence
does not count as passed, except erase semantics may remain explicitly unknown
with the potentially NV-destructive upload/restore plan acknowledged.

- [ ] Pin the exact firmware SHA, image hash/size, manifest, OUT and maps above.
  Re-hash the local file actually selected for upload.
- [ ] Positively identify **CC2674P10** and its management upload target;
  ambiguous radio/interface numbers alone are insufficient. Record the device
  identity and installed management version privately.
- [ ] Record ESP32/SLZB-OS and EFR32MG26/Ember as unchanged and out of scope.
- [ ] Verify a fresh private coordinator backup plus Z2M database/config
  snapshot, taken with a consistent final pre-upload state. Preserve coordinator
  IEEE/network identity, PAN/extPAN/channel, security/key material and current
  frame-counter evidence. Keep secrets in the private backup, not issue/PR text.
  Verify the files and the restore procedure, not just that an export was requested.
- [ ] Have a known-good **P10** rollback image available locally and hashed.
  Verify its compatibility with the backup and intended management upload path.
- [ ] Establish recovery independent of a functioning candidate application.
  Management access alone does not prove BSL entry after replacing CCFG.
  Record the actual reset/BSL path and a way to recover if application boot fails.
- [ ] Review this exact image's generated CCFG against MR4U board wiring and
  recovery requirements: bootloader/backdoor enable, DIO/polarity, protection
  and relevant clock/pin settings. Verify memory/HEX extents and no unexpected
  application/NV overlap. Hosted layout checks do not close the board-specific
  [CCFG/BSL checklist](TI_ZNP_CC2674P10_MR4U_PORTING_CHECKLIST.md).
- [ ] Document selective-sector versus whole-bank erase evidence, or explicitly
  accept possible NV loss with the verified backup/restore plan above.
- [ ] Stop Z2M and prevent restart/serial ownership through the upload and
  initial smoke. Verify no other client owns the P10 transport. Suspend any
  watchdog that could interfere during this planned window; preserve its
  previous state for restoration after smoke.
- [ ] Stage the bound collector/decoder and private destination before first
  boot. With Z2M stopped, specify the **single** initial ZNP/log owner and how
  records reach the file-only collector. The collector does not open serial.
  Account for automatic boot at the end of a UI upload: either establish a
  recording/buffering path before that boot, or keep this gate unresolved.
  Starting a reader afterward cannot be claimed to capture the first boot.
- [ ] Record explicit operator authorization for **one** upload of this exact
  device/target/file/hash tuple. An attempt consumes the permit even if upload
  fails; no automatic retry, second flash or rollback flash is covered.

The built manifest remains `flash_authorized=false`; do not edit or repackage
it to manufacture approval. A separate private operator permit may authorize
only the exact tuple once all pre-upload gates are satisfied. This permit is
also separate from the incident latch's one-reset permit.

Task_stat/NWK sampling cost, real UART timing, AF/ZDO/SYS load and candidate
reset behavior require running the candidate. They are post-upload gates,
not prerequisites that demand testing an uninstalled image.

## B. POST-FLASH SMOKE: before production traffic

Keep production startup and automatic recovery inhibited while checking:

1. P10 boots without a loop. DEBUG identity, SYS_VERSION, image binding and
   live decoded T832 records match the pinned tuple. Preserve early boot logs.
2. Repeated SYS_PING/SYS_VERSION succeed through the sole test owner. Record
   normal ZNP synchronization/priority and UART callback behavior.
3. One separately authorized controlled reset still reaches P10; correlate
   independent reset evidence with the next BOOT and recheck identity/NV.
   A flash permit does not itself grant a control-line/reset operation.
4. Read and compare coordinator/NV state before production startup. If NV was
   lost, perform one separately authorized controlled restore from the verified
   fresh backup using the documented existing-owner procedure. If that needs
   Z2M running, restrict it to the restore sequence; do not start normal traffic
   or form a new network. No automatic restore retry.
5. Verify coordinator IEEE, PAN/extPAN/channel, network-key fingerprints,
   security state and frame-counter safety under that restore procedure.
   Identity mismatch or unsafe/unknown counter continuity inhibits production.
6. Measure Task/NWK/critical-section cost and real UART timing under controlled
   load. Preserve values and criteria; subjective apparent responsiveness is
   insufficient evidence of observer cost.
7. Hand off the single transport owner to Z2M, then verify real AF/ZDO/SYS,
   device reports and control, and no observer-induced transport regression.
   SYS responsiveness alone does not establish mesh recovery.

Failure keeps production startup inhibited. Preserve evidence and use the
prepared recovery plan under its own scoped authorization; no blind flash loop.

## C. PRODUCTION-SOAK-READY

After smoke passes, a separately authorized observation window may begin with
manual incident handling while the producer/scheduler is still pending. Before
enabling automatic recovery, complete separate review/installation of the
existing-owner observer and capture barrier. Prove capture
before reset, private permissions, missing/stale evidence refusal, stuck-owner
handling, restart replay refusal and the persisted single-reset latch. Restore
only the reviewed watchdog configuration after this ordering is proven.

Run the authorized 72 h/until-reproduction window and preserve incident
bundles. Read fatal RAM by SWD before reset if available; retention remains
unproven. Matched KCTRL comparison is a separately authorized trial/image,
not a second flash permitted by this record. KCTRL TX/NV/resource changes
remain confounders; a clean soak is not proof of the original fault's cause.

## Private operator record (documentation template)

This is a checklist record, not input to a flashing tool or an automated permit
validator. Keep evidence references private; publish only redacted dispositions.

```yaml
state: NOT_FLASH_READY
flash_authorized: false
firmware_sha: 1f08f3c1e5da067a1db144e07dc71fd7e155a217
image_sha256: 773dcbb100353005ea8f86faf261d4e25c350ffac715c3dcb08aeeca8b69e15c
target: CC2674P10
device_identity_ref: null
management_version: null
upload_route_evidence_ref: null
erase_semantics: unknown
possible_nv_loss_acknowledged: false
backup_restore_evidence_ref: null
rollback_image_hash: null
ccfg_bsl_recovery_evidence_ref: null
exclusive_owner_evidence_ref: null
first_boot_capture_evidence_ref: null
operator_authorization_ref: null
authorized_upload_attempts: 0
upload_attempt_consumed: false
post_flash_smoke_evidence_ref: null
production_soak_ready: false
```
