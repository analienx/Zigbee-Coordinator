"""Pinned offline 10.9.1 Z-Stack startup safety overlay. Never deploy to HA."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from safe_checkout_files import read_source_bytes, write_source_text, validate_sources

PIN = "0968f979d558874b17396c96b66382d4236bbdcd"
PATH = "src/adapter/z-stack/adapter/manager.ts"
MARKER = "P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD"


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("herdsman 10.9.1 manager source anchor drift")
    return source.replace(old, new, 1)


def plan(checkout):
    validate_sources(checkout, (PATH,))
    def git(*arguments):
        return subprocess.check_output(
            ["git", "-C", str(checkout), *arguments], stderr=subprocess.DEVNULL
        )
    if git("rev-parse", "HEAD").decode().strip() != PIN:
        raise ValueError("wrong upstream herdsman commit")
    original = read_source_bytes(checkout, PATH)
    if original != git("show", f"{PIN}:{PATH}"):
        raise ValueError("dirty or substituted upstream manager")
    source = original.decode("utf-8")
    if MARKER in source:
        raise ValueError("already patched")

    source = once(
        source,
        "    private znp: Znp;\n",
        """    // P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD: one-shot virgin admission.
    private p7uVirginCommissioningAdmitted = false;
    private p7uClearAdapterAuthorized = false;
    private p7uAutomaticRestoreDisabled = true;
    private znp: Znp;
""",
    )
    source = once(
        source,
        "        await this.nv.init();\n",
        """        this.p7uVirginCommissioningAdmitted = false;
        this.p7uClearAdapterAuthorized = false;
        await this.nv.init();
""",
    )
    source = once(
        source,
        "        /* Determine startup strategy */\n",
        """        /* P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD: incomplete state is HOLD,
         * not permission to commission. A matching backup does not authorize
         * automatic restore: beginRestore first commissions a RANDOM network.
         */
        const p7uStartupOption = await this.nv.readItem(NvItemsIds.STARTUP_OPTION);
        if (
            p7uStartupOption &&
            (p7uStartupOption.length !== 1 || (p7uStartupOption[0] & 0x83) !== 0)
        ) {
            throw new Error("P7U HOLD_EXISTING_NV: pending startup clear or counter-reset flag");
        }
        const p7uTrustCenter = await this.nv.readItem(NvItemsIds.TRUSTCENTER_ADDR);
        const p7uBdbState = await this.nv.readItem(NvItemsIds.BDBNODEISONANETWORK);
        const p7uTclkSeed = await this.nv.readItem(NvItemsIds.TCLK_SEED);
        const p7uNonEmpty = (raw: Buffer): boolean =>
            raw.length > 0 && !raw.every((byte) => byte === 0) &&
            !raw.every((byte) => byte === 0xff);
        const p7uKeyEvidence = (info: {key: Buffer} | null | undefined): boolean =>
            Boolean(info && Buffer.isBuffer(info.key) && p7uNonEmpty(info.key));
        const p7uProvablyVirgin =
            !backup && !nib && !hasConfigured &&
            !p7uKeyEvidence(activeKeyInfo) &&
            !p7uKeyEvidence(alternateKeyInfo) &&
            !(p7uTrustCenter && p7uNonEmpty(p7uTrustCenter)) &&
            !(p7uBdbState && p7uNonEmpty(p7uBdbState)) &&
            !(p7uTclkSeed && p7uNonEmpty(p7uTclkSeed));

        /* Determine startup strategy */
""",
    )
    if source.count('return "restoreBackup";') != 2:
        raise ValueError("unexpected restore branch count")
    source = source.replace(
        'return "restoreBackup";',
        'throw new Error("P7U HOLD_EXISTING_NV: automatic restore requires checked offline recovery");',
    )
    if source.count('return "startCommissioning";') != 3:
        raise ValueError("unexpected commissioning branch count")
    source = source.replace(
        'return "startCommissioning";',
        """if (!p7uProvablyVirgin) {
                throw new Error("P7U HOLD_EXISTING_NV: commissioning refused for retained or ambiguous NV");
            }
            this.p7uVirginCommissioningAdmitted = true;
            return "startCommissioning";""",
    )
    source = once(
        source,
        """    private async beginRestore(): Promise<void> {
        const backup = this.backup.getStoredBackup();""",
        """    private async beginRestore(): Promise<void> {
        // P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD: never create a random
        // provisioning network before the original NV security is proven.
        if (this.p7uAutomaticRestoreDisabled) {
            throw new Error("P7U HOLD_EXISTING_NV: automatic backup replay disabled");
        }
        const backup = this.backup.getStoredBackup();""",
    )
    source = once(
        source,
        """        /* clear and reset the adapter */
        await this.nv.deleteItem(NvItemsIds.NIB);
        await this.clearAdapter();""",
        """        /* P7U_P0_NONDESTRUCTIVE_STARTUP_HOLD: one-use virgin admission. */
        if (!this.p7uVirginCommissioningAdmitted) {
            throw new Error("P7U HOLD_EXISTING_NV: destructive commissioning not admitted");
        }
        this.p7uVirginCommissioningAdmitted = false;
        await this.nv.deleteItem(NvItemsIds.NIB);
        this.p7uClearAdapterAuthorized = true;
        await this.clearAdapter();""",
    )
    source = once(
        source,
        """    private async clearAdapter(): Promise<void> {
        logger.debug("clearing adapter using startup option 3", NS);""",
        """    private async clearAdapter(): Promise<void> {
        if (!this.p7uClearAdapterAuthorized) {
            throw new Error("P7U HOLD_EXISTING_NV: clearAdapter requires virgin admission");
        }
        this.p7uClearAdapterAuthorized = false;
        logger.debug("clearing adapter using startup option 3", NS);""",
    )
    assert source.count(MARKER) >= 3
    return original, source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    before, after = plan(args.checkout)
    write_source_text(args.checkout, PATH, after)
    receipt = {
        "schema": "p7u-herdsman10.9.1-startup-hold-v1",
        "pinned_head": PIN,
        "file": PATH,
        "upstream_sha256": hashlib.sha256(before).hexdigest(),
        "patched_sha256": hashlib.sha256(after.encode()).hexdigest(),
        "installed": False,
        "network_recovered": False,
        "radio_access": False,
        "restore_automatically_allowed": False,
        "virgin_commissioning_allowed": True,
    }
    args.receipt.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
