"""Static, bounded decoding only; no PHP, JavaScript, pickle, or shell execution."""

import base64
import hashlib
import os
from pathlib import Path
import re
import stat
import zipfile
import zlib

from .safety import root_path
from .blockchain import ChainIndicators

CHUNK = 1024 * 1024
OVERLAP = 65536
DECODE_LIMIT = 4 * CHUNK
ARCHIVE_LIMIT = 32 * CHUNK
RULESET = "2026-10-16.2"

# Markers are clues, never sufficient authorization to delete a file.
PATTERNS = {
    "sc-marker": rb"\bSC_(?:AUTO_PREPEND|(?:[A-Z0-9_]*_)?(?:BEGIN|END)(?:_[A-Z0-9_]+)?|CORE|VERSION)\b",
    "prepend-setting": rb"\bauto_(?:prepend|append)_file\b",
    "php-code": rb"<\?(?:php|=)",
    "encoded-loader": rb"\b(?:gzdecode|gzinflate|gzuncompress|base64_decode)\s*\(",
    "file-write": rb"\b(?:file_put_contents|fwrite|copy|rename)\s*\(",
    "mu-plugin-reference": rb"mu-plugins",
    "shared-memory": rb"\b(?:shmop_open|shmop_read|shm_attach|shm_get_var)\s*\(",
    "opcode-invalidation": rb"\bopcache_invalidate\s*\(",
    "ethereum-rpc": rb"\b(?:eth_call|eth_getStorageAt|eth_getCode)\b",
    "plugin-hiding": rb"(?:all_plugins|pre_current_active_plugins|views_users|pre_user_query)",
    "service-worker": rb"(?:serviceWorker\s*\.\s*register|self\s*\.\s*addEventListener\s*\(\s*['\"](?:fetch|push))",
    "admin-write": rb"(?:plugin-editor\.php|theme-editor\.php|wp_ajax_edit_theme_plugin_file|edit-theme-plugin-file)",
    "php-execution": rb"\b(?:eval|assert)\s*\(",
    "string-table": rb"\b(?:strtr|str_rot13|chr)\s*\(",
}
COMPILED = {k: re.compile(v, re.I) for k, v in PATTERNS.items()}
B64 = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}")


def signals(data):
    return {name for name, pattern in COMPILED.items() if pattern.search(data)}


def decoded_signals(data, budget=None, depth=0, observer=None):
    """Share a decoding budget across a whole file; report every limit reached."""
    if budget is None:
        budget = [64, 16 * CHUNK]
    found, gaps = set(), set()
    if depth >= 3:
        return found, gaps
    for match in B64.finditer(data):
        token = match.group()
        if len(token) > DECODE_LIMIT or budget[0] <= 0 or budget[1] <= 0:
            gaps.add("Encoded-content decoding budget reached")
            break
        budget[0] -= 1
        try:
            raw = base64.b64decode(token, validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        candidates = [raw]
        # Gzip and zlib; raw DEFLATE is attempted only when the source names it.
        modes = [31, 15] + ([-15] if b'gzinflate' in data.lower() else [])
        for mode in modes:
            try:
                decoder = zlib.decompressobj(mode)
                unpacked = decoder.decompress(raw, min(DECODE_LIMIT, budget[1]) + 1)
                if len(unpacked) > min(DECODE_LIMIT, budget[1]) or decoder.unconsumed_tail:
                    gaps.add("Compressed payload exceeds decoding budget")
                elif decoder.eof:
                    candidates.append(unpacked)
            except zlib.error:
                pass
        for candidate in candidates:
            if len(candidate) > budget[1]:
                gaps.add("Encoded-content decoding budget reached")
                break
            budget[1] -= len(candidate)
            found.update(signals(candidate))
            if observer is not None:
                observer(candidate, 'decoded')
            if depth < 2:
                nested, limits = decoded_signals(candidate, budget, depth + 1, observer)
                found.update(nested)
                gaps.update(limits)
    return found, gaps


def classify(raw, decoded):
    all_signals = raw | decoded
    reasons = []
    if 'sc-marker' in all_signals:
        reasons.append(("high", "SC family marker; confirm the surrounding code"))
    if {'file-write', 'mu-plugin-reference'} <= all_signals and all_signals & {
            'encoded-loader', 'shared-memory', 'opcode-invalidation'}:
        reasons.append(("high", "Loader combines plugin restoration and persistence behavior"))
    if {'ethereum-rpc', 'plugin-hiding'} <= all_signals:
        reasons.append(("high", "Ethereum RPC combined with WordPress hiding hooks"))
    if {'service-worker', 'admin-write'} <= all_signals:
        reasons.append(("high", "Service worker code references administrative file editing"))
    if 'php-code' in decoded:
        reasons.append(("review", "Encoded data decodes to PHP"))
    for signal, explanation in (
        ('prepend-setting', 'PHP prepend/append setting requires target review'),
        ('shared-memory', 'Shared-memory API usage requires review'),
        ('ethereum-rpc', 'Ethereum RPC usage requires review'),
        ('service-worker', 'Browser service worker requires review'),
    ):
        if signal in all_signals:
            reasons.append(("review", explanation))
    return reasons


def inspect_data(data):
    chain = ChainIndicators()
    chain.observe(data)
    raw = signals(data)
    decoded, gaps = decoded_signals(data, observer=chain.observe)
    return {'signals': sorted(raw | decoded), 'decoded_signals': sorted(decoded),
            'reasons': classify(raw, decoded), 'gaps': sorted(gaps | chain.coverage_gaps),
            'blockchain': chain.report()}


def scan(root, max_file_bytes=None):
    root = root_path(root)
    findings, gaps, inventory = [], [], {}
    total = 0

    def gap(path, reason):
        gaps.append({'path': str(path), 'reason': reason})

    def walk_error(error):
        gap(error.filename, f"Directory unreadable: {error.strerror}")

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in list(dirs):
            path = Path(directory) / name
            if path.is_symlink():
                gap(path.relative_to(root), 'Symlink directory not followed')
                dirs.remove(name)
        for name in sorted(files):
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    gap(rel, 'Symlink or special file not followed')
                    continue
                if max_file_bytes is not None and info.st_size > max_file_bytes:
                    gap(rel, 'File exceeds explicitly configured size limit')
                    continue
                raw, decoded, limits = set(), set(), set()
                chain = ChainIndicators()
                sha = hashlib.sha256()
                budget = [64, 16 * CHUNK]
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        gap(rel, 'File changed to a special file')
                        continue
                    tail = b''
                    magic = b''
                    while block := stream.read(CHUNK):
                        if not magic:
                            magic = block[:4]
                        sha.update(block)
                        total += len(block)
                        window = tail + block
                        raw.update(signals(window))
                        chain.observe(window)
                        decoded_part, decode_limits = decoded_signals(window, budget, observer=chain.observe)
                        decoded.update(decoded_part)
                        limits.update(decode_limits)
                        # A long token may cross the window boundary; don't claim full decoding.
                        if len(window) >= OVERLAP and all(c in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' for c in window[-OVERLAP:]):
                            limits.add('Long encoded token crosses scan window; manual decoding needed')
                        tail = window[-OVERLAP:]
                    after = os.fstat(stream.fileno())
                if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    gap(rel, 'File changed during scan')
                inventory[rel] = {'sha256': sha.hexdigest(), 'size': after.st_size}
                for limit in sorted(limits | chain.coverage_gaps):
                    gap(rel, limit)
                reasons = classify(raw, decoded)
                php_name = bool(re.search(r'\.(?:php\d*|phtml|inc)$', name, re.I))
                if name.startswith('.') and php_name:
                    reasons.append(('review', 'Hidden PHP file'))
                if name in ('db.php', 'advanced-cache.php', 'object-cache.php', 'sunrise.php',
                            'fatal-error-handler.php', 'maintenance.php', 'db-error.php') and path.parent.name == 'wp-content':
                    reasons.append(('review', 'Early-loading WordPress drop-in; verify provenance even without readable indicators'))
                if {'string-table', 'php-execution'} <= raw:
                    reasons.append(('review', 'String decoding combined with dynamic PHP execution'))
                if php_name and info.st_size > 8 * CHUNK:
                    reasons.append(('review', 'Oversized PHP file; all raw bytes were scanned'))
                if 'php-code' in raw and ('uploads' in path.parts or not php_name):
                    reasons.append(('review', 'PHP content in uploads or a non-PHP extension'))
                if re.fullmatch(r'[a-f0-9]{8,}\.zip', name, re.I):
                    reasons.append(('review', 'Hex-named archive may be a restore bundle'))
                if reasons:
                    findings.append({'path': rel, **inventory[rel],
                                     'signals': sorted(raw | decoded),
                                     'decoded_signals': sorted(decoded),
                                     'blockchain': chain.report(),
                                     'reasons': reasons})
                if magic.startswith(b'PK\x03\x04') or path.suffix.lower() == '.zip':
                    inspect_archive(path, rel, findings, gap)
            except (OSError, ValueError) as error:
                gap(rel, f"Unable to scan: {error}")

    # Duplicate placement is useful even when a new obfuscator hides all strings.
    mu_hashes = {}
    for rel, metadata in inventory.items():
        if '/mu-plugins/' in '/' + rel and rel.endswith('.php'):
            mu_hashes.setdefault(metadata['sha256'], []).append(rel)
    for rel, metadata in inventory.items():
        if '/plugins/' in '/' + rel and metadata['sha256'] in mu_hashes:
            findings.append({'path': rel, **metadata, 'signals': [], 'decoded_signals': [],
                             'reasons': [('review', 'Identical normal/MU plugin copies')],
                             'related_paths': mu_hashes[metadata['sha256']]})
    return {'schema': 1, 'kind': 'scan', 'ruleset': RULESET, 'root': str(root),
            'files_scanned': len(inventory), 'bytes_scanned': total,
            'findings': findings, 'coverage_gaps': gaps, 'inventory': inventory,
            'verdict': 'review-required' if findings or gaps else 'no-known-indicators',
            'unassessed': ['live database', 'process memory and shared memory',
                           'host and database scheduled tasks', 'browser profiles',
                           'parent/server PHP configuration', 'unknown obfuscated variants']}


def inspect_archive(path, relative, findings, gap):
    """Read members in memory; never extract archive paths or execute members."""
    try:
        with zipfile.ZipFile(path) as archive:
            remaining = ARCHIVE_LIMIT
            members = archive.infolist()
            if len(members) > 2000:
                gap(relative, 'Archive member count exceeds inspection budget')
            for member in members[:2000]:
                if member.is_dir():
                    continue
                label = relative + '::' + member.filename
                if member.file_size > min(DECODE_LIMIT, remaining):
                    gap(label, 'Archive member exceeds inspection budget')
                    continue
                if member.flag_bits & 1:
                    gap(label, 'Encrypted archive member')
                    continue
                with archive.open(member) as stream:
                    data = stream.read(min(DECODE_LIMIT, remaining) + 1)
                remaining -= len(data)
                if remaining < 0 or len(data) > DECODE_LIMIT:
                    gap(label, 'Archive expanded beyond inspection budget')
                    break
                result = inspect_data(data)
                for limit in result.pop('gaps'):
                    gap(label, limit)
                if data.startswith(b'PK\x03\x04'):
                    gap(label, 'Nested archive not inspected')
                if result['reasons']:
                    findings.append({'path': label, 'container': relative,
                                     'sha256': hashlib.sha256(data).hexdigest(), **result})
    except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as error:
        gap(relative, f'Archive inspection failed: {error}')
