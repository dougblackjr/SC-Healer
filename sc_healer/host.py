"""Read-only Linux inventory. No process killing, IPC deletion, or service control."""

import os
from pathlib import Path
import subprocess

from .safety import digest, root_path


def inventory(root):
    root = root_path(root)
    uid = root.stat().st_uid
    result = {'kind': 'host-inventory', 'root': str(root), 'site_owner_uid': uid,
              'processes': [], 'shared_memory': [], 'cron_references': [], 'coverage_gaps': [],
              'notes': ['Processes and IPC entries are candidates, not malware verdicts.',
                        'Container/PID/IPC namespaces and permissions limit visibility.',
                        'No process memory, IPC payloads, systemd timers, or external schedulers inspected.']}
    proc = Path('/proc')
    if not proc.is_dir():
        result['coverage_gaps'].append('Linux /proc is unavailable')
        return result
    inaccessible = 0
    for path in proc.iterdir():
        if not path.name.isdigit() or int(path.name) == os.getpid():
            continue
        try:
            process_uid = path.stat().st_uid
            argv = (path / 'cmdline').read_bytes().split(b'\0')
            exe = os.readlink(path / 'exe')
            cwd = os.readlink(path / 'cwd')
            inside = cwd == str(root) or cwd.startswith(str(root) + '/')
            referenced = any(arg.startswith(str(root).encode() + b'/') for arg in argv)
            php = 'php' in Path(exe).name.lower() or 'lsphp' in Path(exe).name.lower()
            if inside or referenced or (process_uid == uid and php):
                result['processes'].append({'pid': int(path.name), 'uid': process_uid,
                                            'executable': exe, 'cwd': cwd,
                                            'site_reference': inside or referenced,
                                            'same_owner_php': process_uid == uid and php})
        except FileNotFoundError:
            pass  # Process exited, kernel thread, or no cwd/exe.
        except PermissionError:
            inaccessible += 1
    if inaccessible:
        result['coverage_gaps'].append(f'{inaccessible} processes could not be inspected with current permissions')
    try:
        lines = Path('/proc/sysvipc/shm').read_text().splitlines()
        keys = lines[0].split()
        for line in lines[1:]:
            row = dict(zip(keys, line.split()))
            row['same_owner'] = row.get('uid') == str(uid)
            result['shared_memory'].append(row)
    except (OSError, IndexError) as error:
        result['coverage_gaps'].append(f'IPC inventory unavailable: {type(error).__name__}')

    def inspect_cron(label, data):
        for number, line in enumerate(data.splitlines(), 1):
            if line.lstrip().startswith(b'#'):
                continue
            if str(root).encode() in line or b'wp-cron' in line or b'auto_prepend_file' in line:
                result['cron_references'].append({'source': label, 'line': number,
                                                  'sha256': digest(line),
                                                  'review': 'Inspect the command locally; command text omitted to avoid leaking credentials.'})
    paths = [Path('/etc/crontab')]
    for folder in ('/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/var/spool/cron/crontabs', '/var/spool/cron'):
        try:
            paths.extend(p for p in Path(folder).iterdir() if p.is_file() and not p.is_symlink())
        except OSError:
            result['coverage_gaps'].append(f'Cannot enumerate {folder}')
    for path in paths:
        try:
            if path.is_symlink():
                result['coverage_gaps'].append(f'Cron symlink not followed: {path}')
                continue
            inspect_cron(str(path), path.read_bytes())
        except OSError:
            result['coverage_gaps'].append(f'Cannot read {path}')
    try:
        process = subprocess.run(['crontab', '-l'], capture_output=True, timeout=5, check=False)
        if process.returncode == 0:
            inspect_cron('current-user crontab', process.stdout)
        else:
            result['coverage_gaps'].append('Current-user crontab unavailable or empty; verify with host')
    except (OSError, subprocess.TimeoutExpired):
        result['coverage_gaps'].append('Current-user crontab command unavailable')
    return result
