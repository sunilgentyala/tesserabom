"""Shared safety helpers: bounded reads, atomic private writes, hashing."""

import hashlib
import json
import os
import tempfile
from typing import Any, Iterator, Optional

MAX_CONFIG_BYTES = 1_000_000
MAX_CERT_FILE_BYTES = 2_000_000


def read_bounded(path: str, limit: int) -> Optional[bytes]:
    """Read at most `limit` bytes; return None if the file is larger or unreadable."""
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return None
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as fh:
            return fh.read(limit + 1)
    except OSError:
        return None


def load_json_file(path: str) -> Optional[Any]:
    raw = read_bounded(path, MAX_CONFIG_BYTES)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return None


def sha256_file(path: str, max_bytes: int) -> Optional[str]:
    """Stream a file hash; skip files over max_bytes so scans stay bounded."""
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def walk_files(root: str, max_depth: int = 6, max_files: int = 20000) -> Iterator[str]:
    """Walk a tree without following symlinks, with depth and count caps."""
    root = os.path.abspath(root)
    base_depth = root.count(os.sep)
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if dirpath.count(os.sep) - base_depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            seen += 1
            if seen > max_files:
                return
            yield os.path.join(dirpath, name)


def atomic_write_private(path: str, data: str) -> None:
    """Write via temp file + rename, mode 0600 where the OS supports it."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-cryptoai-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
