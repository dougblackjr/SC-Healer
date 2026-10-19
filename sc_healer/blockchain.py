"""Offline blockchain indicator collection and scoped containment generation.

Never resolves domains, calls an RPC endpoint, submits transactions, or changes
the host firewall. Public RPC services and addresses are not inherently malicious.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from .safety import atomic_write, outside, root_path, write_json

RPC = re.compile(rb'\b(?:eth_call|eth_getStorageAt|eth_getCode)\b')
ADDRESS = re.compile(rb'(?<![A-Za-z0-9_])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])')
SELECTOR = re.compile(rb'''["'](0x[0-9a-fA-F]{8})["']''')
CALLDATA = re.compile(rb'''["']data["']\s*(?::|=>)\s*["'](0x[0-9a-fA-F]{8})(?:[0-9a-fA-F]{2})*["']''')
URL = re.compile(rb'''\b(?:https?|wss?)://[^\s<>"'\\]{1,2048}''', re.I)


class ChainIndicators:
    """Co-located clues, not inferred call edges. Bounded per artifact."""

    def __init__(self):
        self.items = {key: {} for key in ('rpc_methods', 'address_candidates', 'selector_candidates', 'endpoint_origins')}
        self.gaps = set()

    def add(self, field, value, representation):
        entries = self.items[field]
        if value not in entries and len(entries) >= 256:
            self.gaps.add('Blockchain indicator count limit reached')
            return
        entries.setdefault(value, set()).add(representation)

    def observe(self, data, representation='raw'):
        # JSON-escaped slashes are literal data; no source-language evaluation.
        data = data.replace(b'\\/', b'/')
        for match in RPC.finditer(data):
            self.add('rpc_methods', match.group().decode(), representation)
        for match in ADDRESS.finditer(data):
            self.add('address_candidates', match.group().decode().lower(), representation)
        for pattern in (SELECTOR, CALLDATA):
            for match in pattern.finditer(data):
                self.add('selector_candidates', match.group(1).decode().lower(), representation)
        for match in URL.finditer(data):
            try:
                if len(match.group()) >= 2048:
                    self.gaps.add('Long URL candidate requires manual review')
                    continue
                url = urlsplit(match.group().decode('utf-8'))
                host = url.hostname
                if not host:
                    continue
                try:
                    address = ipaddress.ip_address(host)
                    host = f'[{address}]' if address.version == 6 else str(address)
                except ValueError:
                    host = host.encode('idna').decode().lower()
                    if not re.fullmatch(r'[a-z0-9.-]+', host) or len(host) > 253:
                        continue
                port = f':{url.port}' if url.port is not None else ''
                # Credentials, paths, query strings, and fragments may contain API keys.
                self.add('endpoint_origins', f'{url.scheme.lower()}://{host}{port}', representation)
            except (ValueError, UnicodeError):
                continue

    def report(self):
        if not self.items['rpc_methods']:
            return None
        return {**{field: [{'value': value, 'representations': sorted(representations)}
                           for value, representations in sorted(entries.items())]
                   for field, entries in self.items.items()},
                'interpretation': 'Co-located candidates only. Addresses may be accounts, URLs may be unrelated, and selectors are not verified contract methods. No chain/network requests made.'}

    @property
    def coverage_gaps(self):
        return self.gaps if self.items['rpc_methods'] else set()


def parse_exception(protocol, destination, port):
    if protocol not in ('tcp', 'udp'):
        raise ValueError('Exception protocol must be tcp or udp')
    # Literal addresses only; avoid DNS rebinding, shell injection, or broad CIDRs.
    if '%' in destination:
        raise ValueError('Scoped IP addresses are not supported')
    address = ipaddress.ip_address(destination)
    if address.is_unspecified or address.is_multicast:
        raise ValueError('Exception must name a unicast destination')
    if not str(port).isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('Exception port must be 1..65535')
    return {'protocol': protocol, 'destination': str(address), 'port': int(port), 'family': address.version}


def containment_plan(uid, exceptions=()):
    if type(uid) is not int or not 1 <= uid < 4294967295:
        raise ValueError('Select a non-root numeric PHP socket-owner UID (1..4294967294)')
    allowed = [parse_exception(*entry) for entry in exceptions]
    if len({(a['protocol'], a['destination'], a['port']) for a in allowed}) != len(allowed):
        raise ValueError('Duplicate egress exception')
    table = f'sc_healer_uid_{uid}'
    # create, not add: fail if this table already exists instead of merging rules.
    lines = [
        '# SC Healer temporary containment. Review plan.json before applying.',
        '# Affects all IP traffic from sockets owned by the selected UID, including replies.',
        f'create table inet {table}',
        f'add chain inet {table} output {{ type filter hook output priority -10; policy accept; }}',
    ]
    for entry in allowed:
        family = 'ip' if entry['family'] == 4 else 'ip6'
        lines.append(f'add rule inet {table} output meta skuid {uid} {family} daddr {entry["destination"]} {entry["protocol"]} dport {entry["port"]} counter accept')
    lines.append(f'add rule inet {table} output meta skuid {uid} counter drop')
    return {
        'schema': 1, 'kind': 'egress-plan', 'uid': uid, 'table': table,
        'status': 'generated-not-applied', 'exceptions': allowed,
        'apply_nft': '\n'.join(lines) + '\n',
        'rollback_nft': f'delete table inet {table}\n',
        'scope': 'IPv4/IPv6 local output in the namespace where installed, matched by socket-owner UID.',
        'impact': [
            'Blocks all IP output for that socket UID unless explicitly allowed, including DNS, loopback, existing connections, and HTTP replies.',
            'All sites, SSH sessions, jobs and services using the UID can be disrupted. Use a dedicated site/PHP identity and a separate recovery account.',
            'Other UIDs are not dropped by this table; pre-existing firewall policy still applies.',
        ],
        'limits': [
            'Containment does not erase contract state, remove local persistence, or prove infection is gone.',
            'Unix-domain sockets and proxies/delegates under other UIDs can bypass this boundary; stop execution and audit delegates.',
            'Root/capability escalation, inherited sockets, container forwarding and different network namespaces require separate controls.',
            'Allowed destinations can carry command traffic if they are compromised or offer forwarding/proxy services.',
            'Remote administrator browsers are outside this policy.',
            'Rules are temporary and may be lost on reboot or firewall-manager reload; coordinate with the host firewall owner.',
        ],
        'validation': [
            'Confirm actual PHP/background socket-owner UID and the network namespace; do not infer it from file ownership.',
            'Check apply.nft with nft --check --file in that namespace before applying.',
            'From an unprivileged process with that UID, test a controlled reachable endpoint with short timeouts over both IPv4 and IPv6; never test against attacker infrastructure.',
            'Compare drop counters before/after the test with nft list table inet ' + table + '; verify another UID is unaffected.',
            'Use nft --file rollback.nft to remove only this containment table after recovery.',
        ],
    }


def write_containment(root, output_dir, uid, exceptions=()):
    root = root_path(root)
    plan = containment_plan(uid, exceptions)
    destination = outside(root, output_dir)
    destination.mkdir(mode=0o700, exist_ok=False)
    # Write into a new private directory; nothing here executes nft or requires root.
    atomic_write(destination / 'apply.nft', plan['apply_nft'].encode())
    atomic_write(destination / 'rollback.nft', plan['rollback_nft'].encode())
    write_json(destination / 'plan.json', {**plan, 'site_root': str(root)}, exclusive=True)
    return {'kind': 'egress-plan', 'status': plan['status'], 'directory': str(destination), 'uid': uid,
            'next': 'Review plan.json, check the UID/namespace and operational impact, then have the host operator validate/apply the rules.'}
