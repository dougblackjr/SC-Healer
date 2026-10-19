"""Explicit selections only. Evidence first; fail closed on stale plans."""

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import stat

from .safety import (atomic_write, digest, load_json, outside, read_regular,
                     root_path, safe_path, sync_dir, write_json)

STUB = b'<?php /* SC Healer: inert prepend placeholder; retained for cached PHP settings. */\n'


@contextmanager
def site_lock(root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def make_plan(root, quarantine=(), neutralize=(), replacements=()):
    root = root_path(root)
    entries = []
    selections = [(p, 'neutralize', STUB) for p in neutralize]
    selections += [(p, 'replace', read_regular(Path(source))[0]) for p, source in replacements]
    selections += [(p, 'quarantine', None) for p in quarantine]
    seen = set()
    for relative, action, replacement in selections:
        path = safe_path(root, relative)
        relative = path.relative_to(root).as_posix()
        if relative in seen:
            raise ValueError(f'Duplicate action: {relative}')
        seen.add(relative)
        data, info = read_regular(path, single_link=True)
        if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise ValueError(f'Refusing set-ID file: {relative}')
        entries.append({'path': relative, 'action': action, 'before_sha256': digest(data),
                        'after_sha256': digest(replacement) if replacement is not None else None,
                        'replacement_b64': base64.b64encode(replacement).decode() if replacement is not None else None})
    if not entries:
        raise ValueError('Select at least one file; scan findings never authorize deletion')
    return {'schema': 1, 'kind': 'file-plan', 'root': str(root), 'actions': entries}


def validate_plan(plan):
    if plan.get('schema') != 1 or plan.get('kind') != 'file-plan':
        raise ValueError('Unsupported file plan')
    root = root_path(plan['root'])
    seen, originals = set(), []
    if not plan.get('actions'):
        raise ValueError('Empty plan')
    for action in plan['actions']:
        path = safe_path(root, action['path'])
        if path in seen:
            raise ValueError('Duplicate action')
        seen.add(path)
        data, info = read_regular(path, single_link=True)
        if digest(data) != action['before_sha256']:
            raise ValueError(f"Stale plan; changed file: {action['path']}")
        kind = action['action']
        if kind not in ('neutralize', 'replace', 'quarantine'):
            raise ValueError('Unknown action')
        replacement = None
        if kind != 'quarantine':
            replacement = base64.b64decode(action['replacement_b64'], validate=True)
            if digest(replacement) != action['after_sha256']:
                raise ValueError('Replacement hash mismatch')
            if kind == 'neutralize' and replacement != STUB:
                raise ValueError('Invalid neutralization stub')
        elif action.get('replacement_b64') is not None or action.get('after_sha256') is not None:
            raise ValueError('Invalid quarantine action')
        originals.append((action, path, data, info, replacement))
    return root, originals


def apply_plan(plan_file, evidence_dir):
    plan = load_json(plan_file)
    root = root_path(plan['root'])
    outside(root, plan_file)
    with site_lock(root):
        root, originals = validate_plan(plan)
        evidence = outside(root, evidence_dir)
        evidence.mkdir(mode=0o700, parents=False, exist_ok=False)
        journal = {'schema': 1, 'kind': 'file-journal', 'root': str(root),
                   'created_at': datetime.now(timezone.utc).isoformat(),
                   'state': 'backing-up', 'actions': []}
        journal_path = evidence / 'journal.json'
        write_json(journal_path, journal)
        for index, (action, path, data, info, replacement) in enumerate(originals):
            backup = f'{index:06d}.bin'
            atomic_write(evidence / backup, data)
            journal['actions'].append({**action, 'backup': backup, 'mode': stat.S_IMODE(info.st_mode),
                                       'uid': info.st_uid, 'gid': info.st_gid,
                                       'mtime_ns': info.st_mtime_ns, 'atime_ns': info.st_atime_ns})
        journal['state'] = 'prepared'
        write_json(journal_path, journal)
        # All originals and the recovery journal are durable before any site mutation.
        try:
            journal['state'] = 'applying'
            write_json(journal_path, journal)
            for action, path, data, info, replacement in originals:
                current = safe_path(root, action['path'])
                latest, latest_info = read_regular(current, single_link=True)
                if digest(latest) != action['before_sha256'] or latest_info.st_ino != info.st_ino:
                    raise ValueError(f"File changed during apply: {action['path']}")
                if replacement is None:
                    path.unlink()
                    sync_dir(path.parent)
                else:
                    atomic_write(path, replacement, stat.S_IMODE(info.st_mode), (info.st_uid, info.st_gid))
            journal['state'] = 'applied'
            write_json(journal_path, journal)
        except BaseException:
            journal['state'] = 'interrupted'
            write_json(journal_path, journal)
            raise
    return {'state': 'applied', 'actions': len(originals), 'journal': str(journal_path),
            'next': 'Keep execution stopped; rescan and finish off-disk/browser recovery before reopening.'}


def restore(journal_file):
    journal = load_json(journal_file)
    if journal.get('schema') != 1 or journal.get('kind') != 'file-journal':
        raise ValueError('Unsupported recovery journal')
    if journal.get('state') == 'backing-up':
        raise ValueError('Backup did not finish; no site changes were started')
    root = root_path(journal['root'])
    evidence = outside(root, Path(journal_file).absolute().parent)
    pending, seen = [], set()
    with site_lock(root):
        # Preflight every destination and backup before restoring anything.
        for entry in journal['actions']:
            path = safe_path(root, entry['path'], missing=True)
            if path in seen:
                raise ValueError('Duplicate recovery path')
            seen.add(path)
            backup = safe_path(evidence, entry['backup'])
            data, _ = read_regular(backup, single_link=True)
            if digest(data) != entry['before_sha256']:
                raise ValueError(f"Backup hash mismatch: {entry['path']}")
            current = digest(read_regular(path, single_link=True)[0]) if path.exists() else None
            if current == entry['before_sha256']:
                continue
            if current != entry['after_sha256']:
                raise ValueError(f"Changed since cleanup; refusing to overwrite: {entry['path']}")
            pending.append((entry, path, data))
        for entry, path, data in reversed(pending):
            safe_path(root, entry['path'], missing=True)
            current = digest(read_regular(path, single_link=True)[0]) if path.exists() else None
            if current != entry['after_sha256']:
                raise ValueError(f"Changed during restore: {entry['path']}")
            atomic_write(path, data, entry['mode'], (entry['uid'], entry['gid']))
            os.utime(path, ns=(entry['atime_ns'], entry['mtime_ns']), follow_symlinks=False)
        journal['state'] = 'restored'
        write_json(Path(journal_file), journal)
    return {'state': 'restored', 'actions': len(pending), 'warning': 'Original potentially malicious content restored. Keep PHP stopped.'}
