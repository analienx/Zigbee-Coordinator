"""R4-00 upstream attestation (hosted-network job only, never unittest).

Given a base dir, loads that dir's SOURCE_PROVENANCE.json (parsed with
that dir's validator.loads_strict, so duplicate keys fail here exactly
as in the production consistency gate) AND imports that dir's
tools/r4_provenance_validate.py for the EXPECTED pins, then verifies
every pin against upstream over the network:

- reviewer-visible identity tripwire FIRST (before any network use):
  manifest pins are compared against the EXPECT_* literals the
  workflow passes in the environment (see
  .github/workflows/test-r4-00-provenance.yml). A coherent
  manifest+validator repoint to another REAL upstream commit passes
  manifest-consistency and every existence check below, so without
  this gate it would attest green; here it fails closed with a `pin
  identity mismatch` line. Missing/empty env also fails closed (never
  default-accepts). These literals live in-PR: any repoint must edit
  manifest + validator + workflow env (+ test canaries) consistently,
  all visible in the diff. They are tripwires, not external proof;
- git fetch the exact zstack-examples SHA from
  TexasInstruments/simplelink-zstack-examples, then `git ls-tree` the
  cc13xx_cc26xx_sdk gitlink: mode must be 160000 and the SHA must equal
  the manifest SDK pin;
- git fetch the exact lowpower-f2-sdk SHA from
  TexasInstruments/simplelink-lowpower-f2-sdk and check the commit
  message names the manifest release (lpf2-8.33.00.16);
- git fetch the herdsman and koenkk pins from their repos
  (existence = fetch success);
- `git ls-tree` of coordinator/Z-Stack_3.x.0/firmware.patch and
  CHANGELOG.md at the fetched koenkk commit: mode must be 100644 blob
  and each SHA must equal the manifest blob pin;
- bounded download of both vendor image URLs taken from the manifest,
  with sha256 compared to the manifest pin.

Vendor-URL limit stated honestly: no external catalog root exists for
URL identity. The gates are exact-tuple consistency (validator: the
URL is bound to rev/model/filename/bytes/sha) plus
URL-actually-fetched-and-content-matches here (the positive step
downloads img["url"] from the manifest and compares bytes to the pin).
This never proves URL authenticity beyond that; never claim it does.

Fail-closed: on ANY unavailable external check (no git, no network,
fetch refused, download error, oversize body, malformed ls-tree)
exit nonzero with an explicit `external proof unavailable` line. On
pin/content mismatch exit nonzero with an `upstream mismatch` line.
All output is clean single lines on stdout; this script never emits
a traceback.
"""
import hashlib
import json
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from pathlib import Path

GIT_TIMEOUT_S = 180
HTTP_TIMEOUT_S = 60
# Vendor containers are < 300 KiB; 8 MiB bounds the download while
# staying far above any legitimate R4-00 artifact.
MAX_IMAGE_BYTES = 8 * 1024 * 1024


def _load_manifest(base, loads_strict):
    """Parse with the validator's loads_strict (duplicate-key parity
    with the production gate): a duplicate-key manifest the validator
    rejects is rejected here too, never silently deduped."""
    path = base / "SOURCE_PROVENANCE.json"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return loads_strict(handle.read()), None
    except (OSError, ValueError) as exc:
        return None, "attest: unreadable manifest %s (%s)" % (path, exc)


def _dig(donors, key, field):
    entry = donors.get(key)
    if isinstance(entry, dict):
        return entry.get(field)
    return None


def _check_pin_identity(manifest, environ):
    """Reviewer-visible identity tripwire (issue #85 R4-R1): compare
    manifest pin values against the EXPECT_* environment literals
    BEFORE any network use. Mismatch (or missing/empty env, which
    never default-accepts) yields `pin identity mismatch` lines.
    Never raises: malformed shapes fail closed as mismatch lines."""
    problems = []

    def want(name):
        value = environ.get(name)
        if not value:
            problems.append(
                "pin identity mismatch (reviewed expectation %s "
                "missing or empty; refusing to default-accept)" % name)
            return None
        return value

    def check(manifest_field, got, env_name):
        expected = want(env_name)
        if expected is None:
            return
        if got != expected:
            problems.append(
                "pin identity mismatch (manifest %s != reviewed expectation)"
                % manifest_field)

    try:
        donors = manifest.get("donors")
        if not isinstance(donors, dict):
            donors = {}
        check("donors.ti_lowpower_f2_sdk.sha",
              _dig(donors, "ti_lowpower_f2_sdk", "sha"), "EXPECT_TI_SDK_SHA")
        check("donors.zstack_examples.sha",
              _dig(donors, "zstack_examples", "sha"), "EXPECT_TI_EXAMPLES_SHA")
        check("donors.zigbee_herdsman.sha",
              _dig(donors, "zigbee_herdsman", "sha"), "EXPECT_HERDSMAN_SHA")
        check("donors.koenkk_zstack_firmware.commit",
              _dig(donors, "koenkk_zstack_firmware", "commit"), "EXPECT_KOENKK_SHA")
        check("donors.koenkk_zstack_firmware.patch_blob",
              _dig(donors, "koenkk_zstack_firmware", "patch_blob"),
              "EXPECT_KOENKK_PATCH_BLOB")
        check("donors.koenkk_zstack_firmware.changelog_blob",
              _dig(donors, "koenkk_zstack_firmware", "changelog_blob"),
              "EXPECT_KOENKK_CHANGELOG_BLOB")
        check("donors.ti_lowpower_f2_sdk.release",
              _dig(donors, "ti_lowpower_f2_sdk", "release"), "EXPECT_TI_RELEASE")
        check("donors.zstack_examples.release",
              _dig(donors, "zstack_examples", "release"), "EXPECT_TI_RELEASE")
        check("donors.zigbee_herdsman.version",
              _dig(donors, "zigbee_herdsman", "version"), "EXPECT_HERDSMAN_VERSION")
        by_rev = {}
        images = manifest.get("vendor_images")
        if isinstance(images, list):
            for img in images:
                if isinstance(img, dict) and isinstance(img.get("rev"), str):
                    by_rev.setdefault(img["rev"], img)
        for key, name in (
                ("ti_lowpower_f2_sdk", "EXPECT_TI_SDK_REPO"),
                ("zstack_examples", "EXPECT_TI_EXAMPLES_REPO"),
                ("zigbee_herdsman", "EXPECT_HERDSMAN_REPO"),
                ("koenkk_zstack_firmware", "EXPECT_KOENKK_REPO")):
            check("donors.%s.repo" % key, _dig(donors, key, "repo"), name)
        check("donors.koenkk_zstack_firmware.patch",
              _dig(donors, "koenkk_zstack_firmware", "patch"),
              "EXPECT_KOENKK_PATCH_PATH")
        check("donors.koenkk_zstack_firmware.changelog",
              _dig(donors, "koenkk_zstack_firmware", "changelog"),
              "EXPECT_KOENKK_CHANGELOG_PATH")
        check("sdk_version", manifest.get("sdk_version"), "EXPECT_SDK_VERSION")
        tool = manifest.get("toolchain")
        if not isinstance(tool, dict):tool = {}
        for field, envname in (
                ("ccs", "EXPECT_CCS_VERSION"),
                ("sysconfig", "EXPECT_SYSCONFIG_VERSION"),
                ("ti_arm_clang", "EXPECT_TI_ARM_CLANG_VERSION")):
            check("toolchain.%s" % field, tool.get(field), envname)
        for rev, env_name in (("20260310", "EXPECT_VENDOR_20260310_SHA256"),
                              ("20240710", "EXPECT_VENDOR_20240710_SHA256")):
            img = by_rev.get(rev)
            check("vendor %s sha256" % rev,
                  img.get("sha256") if isinstance(img, dict) else None,
                  env_name)
    except Exception as exc:  # noqa: BLE001 -- fail closed, never traceback
        problems.append("pin identity mismatch (identity check error: %s)" % exc)
    return problems


def _check_koenkk_blob(clone, sha, relpath, want, display):
    """ls-tree one koenkk path at the fetched commit; returns
    (ok_line, None) on match or (None, error_line). Malformed output
    (nonzero ls-tree, empty, non-100644-blob) is `external proof
    unavailable`; a SHA that differs from the manifest pin is
    `upstream mismatch`."""
    code, out = _run_git(clone, ["ls-tree", sha, relpath])
    if code != 0 or not out.strip():
        return None, ("attest: external proof unavailable "
                      "(ls-tree of koenkk %s failed)" % display)
    parts = out.split()
    if len(parts) < 3 or parts[0] != "100644" or parts[1] != "blob":
        return None, ("attest: external proof unavailable "
                      "(ls-tree of koenkk %s malformed: %r)"
                      % (display, out.strip()[:120]))
    if len(parts) != 4 or parts[3] != relpath:
        return None, ("attest: upstream mismatch (koenkk %s path differs "
                      "from reviewed path)" % display)
    if parts[2] != want:
        return None, ("attest: upstream mismatch (koenkk %s blob %s "
                      "!= manifest %s)" % (display, parts[2], want))
    return ("upstream OK: koenkk %s blob equals manifest %s"
            % (display, want)), None


def _load_validator(base):
    tool_path = base / "tools" / "r4_provenance_validate.py"
    try:
        spec = importlib.util.spec_from_file_location(
            "r4_attest_validator", tool_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, None
    except (OSError, ValueError) as exc:
        return None, "attest: unreadable validator %s (%s)" % (tool_path, exc)


def _run_git(work, args):
    proc = subprocess.run(
        ["git"] + args, cwd=str(work), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=GIT_TIMEOUT_S, check=False)
    try:
        out = proc.stdout.decode("utf-8", "replace")
    except ValueError:
        out = ""
    return proc.returncode, out


def _fetch_exact(work, repo, sha, label):
    """Fetch one exact SHA; any failure is reported as external proof
    unavailable by the caller."""
    url = "https://github.com/%s.git" % repo
    code, _ = _run_git(work, ["init", "-q"])
    if code != 0:
        return "git init failed for %s" % label
    code, _ = _run_git(work, ["remote", "add", "origin", url])
    if code != 0:
        return "git remote add failed for %s" % label
    code, _ = _run_git(work, ["fetch", "--depth", "1", "origin", sha])
    if code != 0:
        return "fetch of %s %s from %s failed" % (label, sha, repo)
    code, resolved = _run_git(work, ["rev-parse", "FETCH_HEAD"])
    if code != 0 or resolved.strip() != sha:
        return "fetched %s object does not resolve to exact SHA" % label
    code, objtype = _run_git(work, ["cat-file", "-t", sha])
    if code != 0 or objtype.strip() != "commit":
        return "fetched %s object is not a commit" % label
    return None


def _download_sha256(url, expected_bytes):
    """Verify digest, byte size and exact HTTPS final URL separately."""
    if (not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool)
            or expected_bytes <= 0):
        return None, "origin mismatch (approved byte length is invalid)"
    if urlsplit(url).scheme != "https" or urlsplit(url).hostname != "updates.smlight.tech":
        return None, "origin mismatch (unapproved initial URL)"
    digest = hashlib.sha256()
    total = 0
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_S) as resp:
            final = urlsplit(resp.geturl())
            if (final.scheme != "https" or final.hostname != "updates.smlight.tech"
                    or resp.geturl() != url):
                return None, "origin mismatch (unexpected redirect/final URL)"
            if getattr(resp, "status", None) != 200:
                return None, "origin mismatch (HTTP status not 200)"
            header = resp.headers.get("Content-Length")
            if header is not None and (not header.isdecimal() or int(header) != expected_bytes):
                return None, "origin mismatch (Content-Length differs from approved bytes)"
            while True:
                chunk = resp.read(65536)
                if not chunk:break
                total += len(chunk)
                if total > MAX_IMAGE_BYTES:
                    return None, "origin mismatch (oversize body)"
                digest.update(chunk)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, "download failed (%s)" % exc
    if total != expected_bytes:
        return None, "origin mismatch (downloaded bytes differ from approved bytes)"
    return digest.hexdigest(), None


def attest(base):
    """Returns (exit_code, lines). Never raises."""
    lines = []
    validator, err = _load_validator(base)
    if err is not None:
        return 1, [err]
    try:
        repos = validator.EXPECTED_DONOR_REPOS
        loads_strict = validator.loads_strict
    except AttributeError as exc:
        return 1, ["attest: validator missing EXPECTED constants (%s)" % exc]
    manifest, err = _load_manifest(base, loads_strict)
    if err is not None:
        return 1, [err]
    # Manifest-consistency first (strict production gate): a doc that
    # fails its own constants is rejected before any network use.
    try:
        consistency = validator.validate_provenance(manifest, allow_fixture=False)
    except Exception as exc:  # noqa: BLE001 -- fail closed, never traceback
        return 1, ["attest: external proof unavailable "
                   "(manifest-consistency check error: %s)" % exc]
    if consistency:
        lines.append("attest: manifest-consistency failed: %s" % consistency[0])
        return 1, lines
    # Identity tripwire BEFORE any network use (issue #85 R4-R1): the
    # manifest pins must equal the reviewed EXPECT_* env literals.
    try:
        identity = _check_pin_identity(manifest, os.environ)
    except Exception as exc:  # noqa: BLE001 -- fail closed, never traceback
        return 1, ["attest: external proof unavailable "
                   "(identity check error: %s)" % exc]
    if identity:
        for problem in identity:
            lines.append("attest: " + problem)
        return 1, lines
    try:
        donors = manifest["donors"]
        ti_sdk_sha = donors["ti_lowpower_f2_sdk"]["sha"]
        ti_release = donors["ti_lowpower_f2_sdk"]["release"]
        examples_sha = donors["zstack_examples"]["sha"]
        herdsman_sha = donors["zigbee_herdsman"]["sha"]
        koenkk_sha = donors["koenkk_zstack_firmware"]["commit"]
        koenkk_patch_blob = donors["koenkk_zstack_firmware"]["patch_blob"]
        koenkk_changelog_blob = donors["koenkk_zstack_firmware"]["changelog_blob"]
        koenkk_patch_path = validator.KOENKK_PATCH_PATH
        koenkk_changelog_path = validator.KOENKK_CHANGELOG_PATH
        images = manifest["vendor_images"]
    except (KeyError, TypeError, AttributeError) as exc:
        return 1, ["attest: manifest missing attestation fields (%s)" % exc]
    if shutil.which("git") is None:
        return 1, ["attest: external proof unavailable (no git binary)"]
    work = Path(tempfile.mkdtemp(prefix="r4_attest_"))
    try:
        # One clone dir per repo: reusing a single dir would collide on
        # the `origin` remote name across fetches.
        clone_dirs = {}
        for repo_key, sha, label in (
                (repos["zstack_examples"], examples_sha, "zstack-examples"),
                (repos["ti_lowpower_f2_sdk"], ti_sdk_sha, "lowpower-f2-sdk"),
                (repos["zigbee_herdsman"], herdsman_sha, "zigbee-herdsman"),
                (repos["koenkk_zstack_firmware"], koenkk_sha, "koenkk-firmware")):
            clone = work / label
            try:
                clone.mkdir(parents=False, exist_ok=False)
            except OSError as exc:
                return 1, ["attest: external proof unavailable "
                           "(clone dir: %s)" % exc]
            problem = _fetch_exact(clone, repo_key, sha, label)
            if problem is not None:
                return 1, ["attest: external proof unavailable (%s)" % problem]
            clone_dirs[label] = clone
            lines.append("upstream OK: fetched %s %s" % (label, sha))
        code, tree_out = _run_git(
            clone_dirs["zstack-examples"],
            ["ls-tree", examples_sha, "cc13xx_cc26xx_sdk"])
        if code != 0 or not tree_out.strip():
            return 1, ["attest: external proof unavailable "
                       "(ls-tree of cc13xx_cc26xx_sdk failed)"]
        parts = tree_out.split()
        if (len(parts) < 4 or parts[0] != "160000" or parts[1] != "commit"
                or parts[2] != ti_sdk_sha):
            return 1, ["attest: upstream mismatch (cc13xx_cc26xx_sdk gitlink "
                       "%r != mode 160000 commit + SDK pin %s)"
                       % (tree_out.strip(), ti_sdk_sha)]
        lines.append("upstream OK: cc13xx_cc26xx_sdk gitlink mode 160000 "
                     "equals SDK pin %s" % ti_sdk_sha)
        code, log_out = _run_git(
            clone_dirs["lowpower-f2-sdk"],
            ["log", "-1", "--format=%s%n%b", ti_sdk_sha])
        if code != 0:
            return 1, ["attest: external proof unavailable "
                       "(SDK commit message unreadable)"]
        if ti_release not in log_out:
            return 1, ["attest: upstream mismatch (SDK commit message does "
                       "not name release %s)" % ti_release]
        lines.append("upstream OK: SDK commit message names %s" % ti_release)
        code, examples_log = _run_git(
            clone_dirs["zstack-examples"],
            ["log", "-1", "--format=%s%n%b", examples_sha])
        if code != 0 or ti_release.split("lpf2-")[-1] not in examples_log:
            return 1, ["attest: upstream mismatch (examples release message)"]
        lines.append("upstream OK: examples commit message names release")
        code, package_text = _run_git(
            clone_dirs["zigbee-herdsman"], ["show", herdsman_sha + ":package.json"])
        if code != 0:
            return 1, ["attest: external proof unavailable (herdsman package.json)"]
        try:herd_version = json.loads(package_text)["version"]
        except (ValueError, KeyError, TypeError):
            return 1, ["attest: upstream mismatch (herdsman package.json version malformed)"]
        if herd_version != donors["zigbee_herdsman"]["version"]:
            return 1, ["attest: upstream mismatch (herdsman version differs from package.json)"]
        lines.append("upstream OK: herdsman package.json version matches")
        # Koenkk blob pins re-verified upstream (issue #85 R4-R2): the
        # manifest patch_blob/changelog_blob must equal the ls-tree
        # blob SHAs at the fetched koenkk commit.
        for relpath, want_blob, display in (
                (koenkk_patch_path, koenkk_patch_blob, "firmware.patch"),
                (koenkk_changelog_path, koenkk_changelog_blob, "CHANGELOG.md")):
            ok_line, blob_err = _check_koenkk_blob(
                clone_dirs["koenkk-firmware"], koenkk_sha,
                relpath, want_blob, display)
            if blob_err is not None:
                return 1, [blob_err]
            lines.append(ok_line)
        if not isinstance(images, list) or not images:
            return 1, ["attest: manifest vendor_images missing"]
        for img in images:
            try:
                url = img["url"]
                want = img["sha256"]
                rev = img.get("rev", "?")
            except (KeyError, TypeError, AttributeError) as exc:
                return 1, ["attest: manifest vendor entry malformed (%s)" % exc]
            got, problem = _download_sha256(url, img.get("container_bytes_observed"))
            if problem is not None:
                kind = ("upstream mismatch" if problem.startswith("origin mismatch")
                        else "external proof unavailable")
                return 1, ["attest: %s (vendor %s image: %s)" % (kind, rev, problem)]
            if got != want:
                return 1, ["attest: upstream mismatch (vendor %s sha256 "
                           "%s != manifest %s)" % (rev, got, want)]
            lines.append("upstream OK: vendor %s content sha256 matches" % rev)
    except Exception as exc:  # noqa: BLE001 -- fail closed, never traceback
        return 1, ["attest: external proof unavailable (internal error: %s)" % exc]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    lines.append("upstream attestation OK")
    return 0, lines


def main(argv):
    base = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[1]
    try:
        code, lines = attest(base)
    except Exception as exc:  # noqa: BLE001 -- last-resort fail closed
        code, lines = 1, ["attest: external proof unavailable (%s)" % exc]
    sys.stdout.write("\n".join(lines) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
