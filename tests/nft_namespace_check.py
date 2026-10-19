"""Only invoke through unshare --user --map-current-user --net.

No host-network writes or external traffic. Uses local sockets in a fresh netns.
"""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sc_healer.blockchain import containment_plan

# Refuse to run without namespace isolation from the parent launching unshare.
if len(sys.argv) != 2:
    raise SystemExit('An inherited host network-namespace FD is required')
host_fd = int(sys.argv[1])
if os.stat('/proc/self/ns/net').st_ino == os.fstat(host_fd).st_ino:
    raise SystemExit('Refusing kernel test outside a separate network namespace')
os.close(host_fd)
uid = os.getuid()
if uid == 0:
    raise SystemExit('Run the test from a non-root account with --map-current-user')
subprocess.run(['ip', 'link', 'set', 'dev', 'lo', 'up'], check=True)


def nft(*args):
    return subprocess.run(['nft', *map(str, args)], check=True, capture_output=True, text=True)


with tempfile.TemporaryDirectory() as directory:
    rules = Path(directory) / 'apply.nft'
    sockets = []
    try:
        # Both IP families, plus a connection established before containment.
        for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            receiver = socket.socket(family, socket.SOCK_DGRAM)
            receiver.bind((host, 0))
            receiver.settimeout(0.2)
            sender = socket.socket(family, socket.SOCK_DGRAM)
            sockets.append((sender, receiver, host))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(1)
        client.connect(listener.getsockname())
        peer, _ = listener.accept()
        peer.settimeout(0.2)
        client.sendall(b'before')
        assert peer.recv(6) == b'before'

        # Nonmatching UID traffic must pass through this table.
        other = containment_plan(uid + 1)
        rules.write_text(other['apply_nft'])
        nft('--check', '--file', rules)
        nft('--file', rules)
        for sender, receiver, host in sockets:
            sender.sendto(b'allowed', receiver.getsockname())
            assert receiver.recv(20) == b'allowed'
        nft('delete', 'table', 'inet', other['table'])

        blocked = containment_plan(uid)
        rules.write_text(blocked['apply_nft'])
        nft('--check', '--file', rules)
        nft('--file', rules)
        for sender, receiver, host in sockets:
            try:
                sender.sendto(b'blocked', receiver.getsockname())
            except PermissionError:
                pass  # Local output drop may be returned synchronously as EPERM.
            try:
                receiver.recv(20)
                raise AssertionError('UDP containment failed')
            except socket.timeout:
                pass
        try:
            client.sendall(b'after')
        except PermissionError:
            pass
        try:
            peer.recv(5)
            raise AssertionError('Existing TCP connection was not contained')
        except socket.timeout:
            pass
        counters = json.loads(nft('--json', 'list', 'table', 'inet', blocked['table']).stdout)
        counts = [expr['counter']['packets'] for item in counters['nftables'] if 'rule' in item
                  for expr in item['rule']['expr'] if 'counter' in expr]
        assert sum(counts) >= 3
        # Refuse duplicate table application rather than accidentally widening it.
        duplicate = subprocess.run(['nft', '--file', str(rules)], capture_output=True)
        assert duplicate.returncode != 0
        rollback = Path(directory) / 'rollback.nft'
        rollback.write_text(blocked['rollback_nft'])
        nft('--file', rollback)

        # Explicit destination/port exceptions allow only the reviewed local endpoints.
        exceptions = [('udp', host, receiver.getsockname()[1]) for _, receiver, host in sockets]
        allowed = containment_plan(uid, exceptions)
        rules.write_text(allowed['apply_nft'])
        nft('--check', '--file', rules)
        nft('--file', rules)
        for sender, receiver, host in sockets:
            sender.sendto(b'exception', receiver.getsockname())
            assert receiver.recv(20) == b'exception'
        nft('--file', rollback)
        for sender, receiver, host in sockets:
            sender.sendto(b'restored', receiver.getsockname())
            assert receiver.recv(20) == b'restored'
        print('kernel containment checks passed: IPv4, IPv6, existing TCP, nonmatching UID, exceptions, duplicate refusal, rollback')
    finally:
        for sender, receiver, _ in sockets:
            sender.close()
            receiver.close()
        for name in ('listener', 'client', 'peer'):
            if name in locals():
                locals()[name].close()
