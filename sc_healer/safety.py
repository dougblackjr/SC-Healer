"""Path, evidence, and atomic-write primitives. Linux/POSIX only."""

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def root_path(value):
    root = Path(value).absolute()
    # Reject symlinks in every component, including the supplied root.
    for part in [root, *root.parents]:
        if part.is_symlink():
            raise ValueError(f"Symlink in root: {part}")
    if not root.is_dir() or root == Path('/'):
        raise ValueError("Root must be an existing site directory, not /")
    return root.resolve()


def safe_path(root, relative, *, missing=False):
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or any(p in ('.', '..') for p in rel.parts):
        raise ValueError(f"Expected a relative path inside the site: {relative}")
    path = root
    for i, part in enumerate(rel.parts):
        path = path / part
        if path.is_symlink():
            raise ValueError(f"Refusing symlink: {relative}")
        if not path.exists():
            if missing and i == len(rel.parts) - 1:
                return path
            raise ValueError(f"Missing path: {relative}")
    if not path.is_file():
        raise ValueError(f"Not a regular file: {relative}")
    return path


def read_regular(path, *, single_link=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"Not a regular file: {path}")
        if single_link and info.st_nlink != 1:
            raise ValueError(f"Refusing multiply-linked file: {path}")
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read()
        after = os.fstat(fd)
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError(f"File changed while reading: {path}")
        return data, info
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, data, mode=0o600, owner=None):
    fd, temp = tempfile.mkstemp(prefix='.sc-healer-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            if owner is not None:
                current = os.fstat(stream.fileno())
                if (current.st_uid, current.st_gid) != owner:
                    os.fchown(stream.fileno(), *owner)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def write_json(path, value, *, exclusive=False):
    path = Path(path).absolute()
    payload = (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode()
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        sync_dir(path.parent)
    else:
        atomic_write(path, payload)


def load_json(path):
    data, _ = read_regular(Path(path))
    return json.loads(data)


def outside(root, destination):
    path = Path(destination).absolute()
    if path.resolve().is_relative_to(root):
        raise ValueError("Reports, plans, and evidence must be outside the site root")
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise ValueError(f"Symlink in output path: {part}")
    return path
