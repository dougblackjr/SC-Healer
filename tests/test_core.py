import base64
import gzip
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from sc_healer import phpserialize
from sc_healer.cli import main
from sc_healer.remediation import STUB, apply_plan, make_plan, restore
from sc_healer.safety import load_json, safe_path, write_json
from sc_healer.scanner import CHUNK, inspect_data, scan

# Inert strings only: no functional malicious code is included in test fixtures.
INDICATORS = b'<?php /* SC_AUTO_PREPEND mu-plugins file_put_contents( gzdecode( */'


class SiteTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.site = self.base / 'site'
        self.site.mkdir()

    def put(self, name, data):
        path = self.site / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_padded_29mb_file_is_scanned_to_end(self):
        self.put('wp-content/.hidden.php', b' ' * (29 * CHUNK) + INDICATORS)
        result = scan(self.site)
        self.assertEqual(result['files_scanned'], 1)
        self.assertEqual(result['bytes_scanned'], 29 * CHUNK + len(INDICATORS))
        self.assertIn('sc-marker', result['findings'][0]['signals'])
        self.assertFalse(result['coverage_gaps'])

    def test_signal_crosses_chunk_boundary(self):
        self.put('test.php', b' ' * (CHUNK - 4) + b'SC_AUTO_PREPEND')
        self.assertIn('sc-marker', scan(self.site)['findings'][0]['signals'])

    def test_encoded_gzip_payload(self):
        result = inspect_data(base64.b64encode(gzip.compress(INDICATORS)))
        self.assertIn('php-code', result['decoded_signals'])
        self.assertIn('sc-marker', result['decoded_signals'])

    def test_zip_never_extracts_paths(self):
        with zipfile.ZipFile(self.site / 'abcde1234.zip', 'w') as archive:
            archive.writestr('../../escape.php', INDICATORS)
        result = scan(self.site)
        self.assertTrue(any('::../../escape.php' in f['path'] for f in result['findings']))
        self.assertFalse((self.base / 'escape.php').exists())

    def test_decompression_bomb_is_a_coverage_gap(self):
        result = inspect_data(base64.b64encode(gzip.compress(b'x' * (5 * CHUNK))))
        self.assertTrue(result['gaps'])

    def test_duplicate_normal_and_mu_plugins_are_review_findings(self):
        self.put('wp-content/mu-plugins/random.php', b'<?php /* inert */')
        self.put('wp-content/plugins/random/random.php', b'<?php /* inert */')
        self.assertTrue(any(f.get('related_paths') for f in scan(self.site)['findings']))

    def test_benign_cache_is_not_a_high_confidence_detection(self):
        self.put('wp-content/advanced-cache.php', b'<?php /* legitimate cache */ file_put_contents("cache", "data");')
        self.put('.user.ini', b'auto_prepend_file = wordfence-waf.php\n')
        report = scan(self.site)
        self.assertFalse(any(reason[0] == 'high' for item in report['findings'] for reason in item['reasons']))

    def test_symlinks_and_size_limits_are_visible_gaps(self):
        self.put('large.php', b'x' * 50)
        (self.site / 'link.php').symlink_to('/etc/passwd')
        report = scan(self.site, max_file_bytes=20)
        self.assertEqual(len(report['coverage_gaps']), 2)

    def test_read_only_scan_does_not_change_content(self):
        path = self.put('test.php', INDICATORS)
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        scan(self.site)
        self.assertEqual(before, (path.read_bytes(), path.stat().st_mtime_ns))

    def test_apply_and_restore_all_operations(self):
        original = self.put('shim.php', INDICATORS)
        self.put('loader.php', INDICATORS)
        theme = self.put('theme.php', b'<?php /* edited theme */')
        theme.chmod(0o640)
        trusted = self.base / 'clean.php'
        trusted.write_bytes(b'<?php /* reviewed clean theme */')
        plan = make_plan(self.site, ['loader.php'], ['shim.php'], [('theme.php', trusted)])
        plan_path = self.base / 'plan.json'
        write_json(plan_path, plan)
        result = apply_plan(plan_path, self.base / 'evidence')
        self.assertEqual(original.read_bytes(), STUB)
        self.assertFalse((self.site / 'loader.php').exists())
        self.assertEqual(theme.read_bytes(), trusted.read_bytes())
        self.assertEqual(theme.stat().st_mode & 0o777, 0o640)
        evidence = self.base / 'evidence'
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
        self.assertEqual((evidence / '000000.bin').stat().st_mode & 0o777, 0o600)
        restore(result['journal'])
        self.assertEqual(original.read_bytes(), INDICATORS)
        self.assertEqual((self.site / 'loader.php').read_bytes(), INDICATORS)
        self.assertEqual(theme.read_bytes(), b'<?php /* edited theme */')
        self.assertEqual(restore(result['journal'])['actions'], 0)

    def test_stale_plan_rejects_before_any_mutation(self):
        first = self.put('a.php', INDICATORS)
        second = self.put('b.php', INDICATORS)
        plan = make_plan(self.site, ['a.php', 'b.php'])
        second.write_bytes(b'changed')
        plan_path = self.base / 'plan.json'
        write_json(plan_path, plan)
        with self.assertRaisesRegex(ValueError, 'Stale'):
            apply_plan(plan_path, self.base / 'evidence')
        self.assertEqual(first.read_bytes(), INDICATORS)
        self.assertFalse((self.base / 'evidence').exists())

    def test_restore_refuses_new_content(self):
        file = self.put('test.php', INDICATORS)
        plan_path = self.base / 'plan.json'
        write_json(plan_path, make_plan(self.site, ['test.php']))
        applied = apply_plan(plan_path, self.base / 'evidence')
        file.write_bytes(b'new legitimate content')
        with self.assertRaisesRegex(ValueError, 'Changed since cleanup'):
            restore(applied['journal'])
        self.assertEqual(file.read_bytes(), b'new legitimate content')

    def test_corrupt_backup_prevents_restore(self):
        self.put('test.php', INDICATORS)
        plan_path = self.base / 'plan.json'
        write_json(plan_path, make_plan(self.site, ['test.php']))
        result = apply_plan(plan_path, self.base / 'evidence')
        (self.base / 'evidence' / '000000.bin').write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'Backup hash'):
            restore(result['journal'])

    def test_interrupted_apply_can_be_restored(self):
        self.put('a.php', INDICATORS)
        self.put('b.php', INDICATORS)
        plan_path = self.base / 'plan.json'
        write_json(plan_path, make_plan(self.site, ['a.php', 'b.php']))
        real_unlink = Path.unlink

        def fail_on_second(path, *args, **kwargs):
            if path == self.site / 'b.php':
                raise OSError('simulated disk failure')
            return real_unlink(path, *args, **kwargs)

        with patch.object(Path, 'unlink', fail_on_second):
            with self.assertRaises(OSError):
                apply_plan(plan_path, self.base / 'evidence')
        journal = self.base / 'evidence' / 'journal.json'
        self.assertEqual(load_json(journal)['state'], 'interrupted')
        restore(journal)
        self.assertEqual((self.site / 'a.php').read_bytes(), INDICATORS)
        self.assertEqual((self.site / 'b.php').read_bytes(), INDICATORS)

    def test_escape_symlink_and_hardlink_rejected(self):
        self.put('a.php', INDICATORS)
        with self.assertRaises(ValueError):
            safe_path(self.site, '../outside')
        (self.site / 'link').symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError):
            safe_path(self.site, 'link/something')
        os.link(self.site / 'a.php', self.site / 'b.php')
        with self.assertRaisesRegex(ValueError, 'multiply-linked'):
            make_plan(self.site, ['a.php'])

    def test_evidence_inside_site_rejected(self):
        self.put('a.php', INDICATORS)
        plan = self.base / 'plan.json'
        write_json(plan, make_plan(self.site, ['a.php']))
        with self.assertRaisesRegex(ValueError, 'outside'):
            apply_plan(plan, self.site / 'evidence')

    def test_missing_execution_acknowledgment_prevents_apply(self):
        self.assertEqual(main(['apply', 'missing.json', '--evidence-dir', '/tmp/unused']), 2)

    def test_json_outputs_are_exclusive(self):
        path = self.base / 'report.json'
        write_json(path, {'original': 1}, exclusive=True)
        with self.assertRaises(FileExistsError):
            write_json(path, {'replacement': 2}, exclusive=True)
        self.assertEqual(json.loads(path.read_text()), {'original': 1})


class SerializationTest(unittest.TestCase):
    CRON = b'a:2:{i:1720000000;a:2:{s:8:"bad_hook";a:0:{}s:9:"good_hook";a:1:{s:2:"id";a:1:{s:4:"args";a:1:{i:0;s:2:"\xc3\xa9";}}}}s:7:"version";i:2;}'

    def test_roundtrip_and_selective_removal(self):
        self.assertEqual(phpserialize.dumps(phpserialize.loads(self.CRON)), self.CRON)
        cleaned = phpserialize.remove_hooks(self.CRON, ['bad_hook'])
        self.assertEqual(phpserialize.cron_hooks(cleaned), ['good_hook'])
        self.assertIn(b's:2:"\xc3\xa9"', cleaned)

    def test_objects_references_malformed_and_deep_arrays_rejected(self):
        for payload in (b'O:4:"Evil":0:{}', b'R:1;', b's:3:"hi";', b'a:1:{i:0;N;}junk',
                        b'a:1:{i:0;' * 66 + b'N;' + b'}' * 66):
            with self.subTest(payload=payload[:20]), self.assertRaises(ValueError):
                phpserialize.loads(payload)

    def test_unknown_hook_is_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            phpserialize.remove_hooks(self.CRON, ['missing'])


if __name__ == '__main__':
    unittest.main()
