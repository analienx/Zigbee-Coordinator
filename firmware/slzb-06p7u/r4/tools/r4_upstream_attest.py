"""R4-00 upstream attestation (hosted-network job only, never unittest).

Given a base dir, loads that dir's SOURCE_PROVENANCE.json AND imports
that dir's tools/r4_provenance_validate.py for the EXPECTED pins, then
independently verifies every pin against upstream over the network:

- git fetch the exact zstack-examples SHA from
  TexasInstruments/simplelink-zstack-examples, then `git ls-tree` the
  cc13xx_cc26xx_sdk gitlink: mode must be 160000 and the SHA must equal
  the manifest SDK pin;
- git fetch the exact lowpower-f2-sdk SHA from
  TexasInstruments/simplelink-lowpower-f2-sdk and check the commit
  message names the manifest release (lpf2-8.33.00.16);
- git fetch the herdsman and koenkk pins from their repos
  (existence = fetch success);
- bounded download of both vendor image URLs with sha256 compared to
  the manifest (content identity only, never source proof).

Fail-closed: on ANY unavailable external check (no git, no network,
fetch refused, download error, oversize body) exit nonzero with an
explicit `external proof unavailable` line. On pin/content mismatch
exit nonzero with an `upstream mismatch` line. All output is clean
single lines on stdout; this script never emits a traceback.
"""
import hashlib
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

GIT_TIMEOUT_S = 180
HTTP_TIMEOUT_S = 60
# Vendor containers are < 300 KiB; 8 MiB bounds the download while
# staying far above any legitimate R4-00 artifact.
MAX_IMAGE_BYTES = 8 * 1024 * 1024


def _load_manifest(base):
    path = base / "SOURCE_PROVENANCE.json"
    try:
        import json
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle), None
    except (OSError, ValueError) as exc:
        return None, "attest: unreadable manifest %s (%s)" % (path, exc)


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
    return None


def _download_sha256(url):
    digest = hashlib.sha256()
    total = 0
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_S) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_IMAGE_BYTES:
                    return None, "oversize body (> %d bytes)" % MAX_IMAGE_BYTES
                digest.update(chunk)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, "download failed (%s)" % exc
    return digest.hexdigest(), None


def attest(base):
    """Returns (exit_code, lines). Never raises."""
    lines = []
    manifest, err = _load_manifest(base)
    if err is not None:
        return 1, [err]
    validator, err = _load_validator(base)
    if err is not None:
        return 1, [err]
    try:
        repos = validator.EXPECTED_DONOR_REPOS
    except AttributeError as exc:
        return 1, ["attest: validator missing EXPECTED constants (%s)" % exc]
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
    try:
        donors = manifest["donors"]
        ti_sdk_sha = donors["ti_lowpower_f2_sdk"]["sha"]
        ti_release = donors["ti_lowpower_f2_sdk"]["release"]
        examples_sha = donors["zstack_examples"]["sha"]
        herdsman_sha = donors["zigbee_herdsman"]["sha"]
        koenkk_sha = donors["koenkk_zstack_firmware"]["commit"]
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
        if len(parts) < 3 or parts[0] != "160000" or parts[2].split("\t")[0] != ti_sdk_sha:
            return 1, ["attest: upstream mismatch (cc13xx_cc26xx_sdk gitlink "
                       "%r != mode 160000 + SDK pin %s)"
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
        if not isinstance(images, list) or not images:
            return 1, ["attest: manifest vendor_images missing"]
        for img in images:
            try:
                url = img["url"]
                want = img["sha256"]
                rev = img.get("rev", "?")
            except (KeyError, TypeError, AttributeError) as exc:
                return 1, ["attest: manifest vendor entry malformed (%s)" % exc]
            got, problem = _download_sha256(url)
            if problem is not None:
                return 1, ["attest: external proof unavailable "
                           "(vendor %s image: %s)" % (rev, problem)]
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
