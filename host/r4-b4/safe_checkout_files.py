"""Confine B4 source overlays to regular files in disposable pinned checkouts.

Every read and write walks from a trusted /tmp directory descriptor with
O_NOFOLLOW. Preflight validation alone cannot prevent a symlink replacement
between planning and I/O. Never use a pathname to reopen a source file.
"""

import os
from pathlib import Path
import stat


_TMP = Path("/tmp")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _components(root, relative):
    supplied = Path(root)
    if supplied.is_symlink():
        raise ValueError("B4 checkout must be a real disposable directory")
    checkout = Path(os.path.abspath(supplied))
    if checkout == _TMP or _TMP not in checkout.parents:
        raise ValueError("B4 checkout must reside below /tmp")
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or any(p in ("..", ".") for p in rel.parts):
        raise ValueError("B4 invalid relative source path")
    return checkout.relative_to(_TMP).parts + rel.parts


def _open_source(root, relative, access):
    """Open an unshared regular file relative to /tmp, rejecting every symlink.

    Each open uses the already-verified parent descriptor, so a concurrent
    ancestor replacement cannot redirect a read or write outside that inode.
    The caller owns the returned descriptor.
    """
    parts = _components(root, relative)
    parent_fd = os.open(_TMP, _DIR_FLAGS)
    try:
        try:
            for component in parts[:-1]:
                next_fd = os.open(component, _DIR_FLAGS, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
            # O_NONBLOCK also denies an attacker-induced FIFO stall before fstat.
            leaf_fd = os.open(parts[-1], access | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=parent_fd)
        except OSError as exc:
            raise ValueError("B4 symlink, missing or unsafe source path: " + str(relative)) from exc
        try:
            metadata = os.fstat(leaf_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("B4 source is not an unshared regular file")
        except BaseException:
            os.close(leaf_fd)
            raise
        return leaf_fd
    finally:
        os.close(parent_fd)


def validate_sources(root, relatives):
    for relative in relatives:
        os.close(_open_source(root, relative, os.O_RDONLY))


def read_source_bytes(root, relative):
    """Read the pinned source through an already-confined, no-follow FD."""
    fd = _open_source(root, relative, os.O_RDONLY)
    with os.fdopen(fd, "rb") as source:
        return source.read()


def read_source_text(root, relative):
    return read_source_bytes(root, relative).decode("utf-8")


def write_source_text(root, relative, content):
    """Rewrite an unshared regular source file without pathname reopening."""
    fd = _open_source(root, relative, os.O_WRONLY)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as output:
        output.write(content)
        output.truncate()
