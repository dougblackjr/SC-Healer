import base64
from contextlib import redirect_stdout, redirect_stderr
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from sc_healer.blockchain import ChainIndicators, containment_plan, write_containment
from sc_healer.cli import main
from sc_healer.scanner import inspect_data, scan

# Invented test values; not attributed to SC or any real contract.
PAYLOAD = (b'eth_call "to":"0x' + b'1' * 40 + b'" "data":"0x1234abcd' + b'0' * 64 +
           b'" https://user:password@rpc.example.invalid:443/private-api-key?key=secret')


class BlockchainTest(unittest.TestCase):
    def test_collects_candidates_and_redacts_endpoint_credentials(self):
        report = inspect_data(PAYLOAD)['blockchain']
        self.assertEqual(report['rpc_methods'][0]['value'], 'eth_call')
        self.assertEqual(report['address_candidates'][0]['value'], '0x' + '1' * 40)
        self.assertEqual(report['selector_candidates'][0]['value'], '0x1234abcd')
        self.assertEqual(report['endpoint_origins'][0]['value'], 'https://rpc.example.invalid:443')
        serialized = json.dumps(report)
        for secret in ('password', 'private-api-key', 'secret'):
            self.assertNotIn(secret, serialized)

    def test_encoded_payload_and_archive_keep_indicator_provenance(self):
        encoded = base64.b64encode(gzip.compress(PAYLOAD))
        report = inspect_data(encoded)['blockchain']
        self.assertEqual(report['rpc_methods'][0]['representations'], ['decoded'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'loader.php').write_bytes(encoded)
            with zipfile.ZipFile(root / 'bundle.zip', 'w') as archive:
                archive.writestr('candidate.php', encoded)
            scan_report = scan(root)
            relevant = [f for f in scan_report['findings'] if f.get('blockchain')]
            self.assertEqual(len(relevant), 2)
            self.assertTrue(any('::candidate.php' in f['path'] for f in relevant))

    def test_address_does_not_imply_blockchain_malware(self):
        self.assertIsNone(inspect_data(b'address="0x' + b'a' * 40 + b'"')['blockchain'])
        report = inspect_data(PAYLOAD)
        self.assertFalse(any(reason[0] == 'high' for reason in report['reasons']))

    def test_json_escaped_slashes_ipv6_and_storage_method(self):
        report = inspect_data(b'eth_getStorageAt "https:\\/\\/[2001:db8::1]:443/token"')['blockchain']
        self.assertEqual(report['endpoint_origins'][0]['value'], 'https://[2001:db8::1]:443')

    def test_indicator_budget_is_visible_only_with_rpc_context(self):
        data = b' '.join(f'0x{n:040x}'.encode() for n in range(260))
        collector = ChainIndicators()
        collector.observe(data)
        self.assertFalse(collector.coverage_gaps)
        collector.observe(b'eth_call')
        self.assertTrue(collector.coverage_gaps)
        self.assertEqual(len(collector.report()['address_candidates']), 256)

    def test_default_policy_is_uid_scoped_dual_stack_and_has_no_exemptions(self):
        plan = containment_plan(1201)
        rules = plan['apply_nft']
        self.assertIn('create table inet sc_healer_uid_1201', rules)
        self.assertIn('hook output priority -10; policy accept;', rules)
        self.assertIn('meta skuid 1201 counter drop', rules)
        self.assertNotIn('ct state', rules)
        self.assertNotIn('flush', rules)
        self.assertNotIn('counter accept', rules)
        self.assertEqual(plan['rollback_nft'], 'delete table inet sc_healer_uid_1201\n')

    def test_explicit_exceptions_are_precise_and_before_drop(self):
        plan = containment_plan(1201, [('tcp', '192.0.2.2', '3306'), ('udp', '2001:db8::2', '53')])
        rules = plan['apply_nft']
        self.assertIn('meta skuid 1201 ip daddr 192.0.2.2 tcp dport 3306 counter accept', rules)
        self.assertIn('meta skuid 1201 ip6 daddr 2001:db8::2 udp dport 53 counter accept', rules)
        self.assertTrue(rules.rstrip().endswith('meta skuid 1201 counter drop'))

    def test_root_uid_bad_exceptions_and_injection_are_rejected(self):
        for uid in (0, -1, 4294967295, True, '1000; flush ruleset'):
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                containment_plan(uid)
        for entry in [('tcp', 'example.com', '443'), ('tcp', '0.0.0.0/0', '443'),
                      ('tcp', '127.0.0.1; flush ruleset', '443'), ('tcp', '127.0.0.1', '0'),
                      ('udp', '::', '53'), ('udp', 'ff02::1', '53'), ('tcp', '::1', '65536'),
                      ('tcp; drop', '127.0.0.1', '443'), ('udp', 'fe80::1%lo', '53')]:
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                containment_plan(1201, [entry])

    def test_bundle_is_private_external_exclusive_and_never_executes_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'site'
            root.mkdir()
            output = Path(directory) / 'egress'
            with patch('subprocess.run', side_effect=AssertionError('No commands permitted')):
                result = write_containment(root, output, 1201)
            self.assertEqual(result['status'], 'generated-not-applied')
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / 'apply.nft').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_containment(root, output, 1201)
            with self.assertRaises(ValueError):
                write_containment(root, root / 'egress', 1201)

    def test_cli_requires_dedicated_uid_and_generates_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'site'
            root.mkdir()
            output = Path(directory) / 'egress'
            args = ['egress-plan', str(root), '--uid', '1201', '--output-dir', str(output)]
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 2)
            self.assertFalse(output.exists())
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(main(args + ['--dedicated-uid']), 0)
            self.assertEqual(json.loads(stream.getvalue())['status'], 'generated-not-applied')
            self.assertTrue((output / 'rollback.nft').is_file())

    @unittest.skipUnless(sys.platform == 'linux', 'Linux namespace guard')
    def test_kernel_helper_refuses_to_modify_host_namespace(self):
        helper = Path(__file__).with_name('nft_namespace_check.py')
        with open('/proc/self/ns/net', 'rb') as host_namespace:
            result = subprocess.run([sys.executable, str(helper), str(host_namespace.fileno())],
                                    pass_fds=(host_namespace.fileno(),), text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Refusing kernel test', result.stderr)


@unittest.skipUnless(os.environ.get('SC_HEALER_NFT_TEST') == '1', 'Opt-in isolated nftables kernel test')
class NftNamespaceTest(unittest.TestCase):
    def test_nft_rules_in_disposable_user_and_network_namespace(self):
        for binary in ('unshare', 'ip', 'nft'):
            if not shutil.which(binary):
                self.skipTest(f'{binary} is unavailable')
        helper = Path(__file__).with_name('nft_namespace_check.py')
        with open('/proc/self/ns/net', 'rb') as host_namespace:
            result = subprocess.run(['unshare', '--user', '--map-current-user', '--keep-caps', '--net',
                                     sys.executable, str(helper), str(host_namespace.fileno())],
                                    pass_fds=(host_namespace.fileno(),), text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('kernel containment checks passed', result.stdout)
