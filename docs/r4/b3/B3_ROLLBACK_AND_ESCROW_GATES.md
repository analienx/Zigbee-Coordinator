# B3 rollback and escrow boundary

Source-only. Original escrow holds *private* identity and security data, never public files. Copy neither keys, raw NV, IEEE/PAN/extPAN identifiers nor private backups into GitHub, Actions caches, PRs or logs. No production device access or flash implied.

Before future separately owner-approved R4-07: independently hash-verified same-device pre-image in private escrow; prove source/target page formats read-only, cross-check trustworthy multiple backup epochs and TX high-water, isolate original/same-IEEE radios (never simultaneously active), record exact app/NV/CCFG allowed sectors and immutable rollback image, qualify physical power-cut recovery. Unknown format or untrusted snapshots block migration. B3 evaluator output is offline only; all mutation authorities remain false.

Explicitly excluded: uploading actual archives to the GitHub workflow, generating patched images/keys, writing NV, advising a live factory reset, and automatic rollover from mismatched backups.
