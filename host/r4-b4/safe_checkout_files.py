"""Confine B4 source overlays to regular files in disposable pinned checkouts.

Validation covers every path component, not only the leaf. Writes re-open each
directory with O_NOFOLLOW relative to its verified parent, so a symlink swap
between source planning and output cannot redirect a source mutation.
No installed host, package cache, device or operational data is touched.
"""
import os
from pathlib import Path
import stat

_TMP = Path("/tmp")


def _checkout_root(root):
    supplied = Path(root)
    if not supplied.is_dir() or supplied.is_symlink():
        raise ValueError("B4 checkout must be a real disposable directory")
    # Do not allow symlink ancestors below /tmp to redirect the checkout.
    absolute = Path(os.path.abspath(supplied))
    if absolute == _TMP or _TMP not in absolute.parents:
        raise ValueError("B4 checkout must reside below /tmp")
    for part in (absolute, *absolute.parents):
        if part == _TMP:
            break
        if part.is_symlink():
            raise ValueError("B4 checkout ancestor symlink")
    resolved = absolute.resolve(strict=True)
    if resolved == _TMP or _TMP not in resolved.parents:
        raise ValueError("B4 checkout escapes /tmp")
    return resolved


def _source(root, relative):
    checkout = _checkout_root(root)
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or any(p in ("..", ".") for p in rel.parts):
        raise ValueError("B4 invalid relative source path")
    cursor = checkout
    for part in rel.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError("B4 symlink in source path: " + str(relative))
    if not cursor.is_file() or not cursor.resolve(strict=True).is_relative_to(checkout):
        raise ValueError("B4 source missing or escaped checkout: " + str(relative))
    return checkout, rel, cursor


def validate_sources(root, relatives):
    for relative in relatives:
        _source(root, relative)


def write_source_text(root, relative, content):
    """Write through no-follow directory descriptors, never a symlink/hardlink."""
    checkout, rel, _ = _source(root, relative)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(checkout, flags)
    try:
        for component in rel.parts[:-1]:
            next_fd = os.open(component, flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        leaf_fd = os.open(rel.parts[-1], os.O_WRONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            metadata = os.fstat(leaf_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("B4 source is not an unshared regular file")
            with os.fdopen(leaf_fd, "w", encoding="utf-8", newline="") as output:
                leaf_fd = -1
                output.write(content)
                output.truncate()
        finally:
            if leaf_fd >= 0:
                os.close(leaf_fd)
    finally:
        os.close(parent_fd)
