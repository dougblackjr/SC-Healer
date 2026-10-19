"""Opt-in integration tests start a disposable local MySQL server, never the host DB.

Run: SC_HEALER_MYSQL_TEST=1 .venv/bin/python -m unittest discover -s tests -v
Requires MySQL 8's mysqld and the mysql extra. Socket only; networking is disabled.
"""

import base64
import gzip
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from sc_healer.database import Database
from sc_healer.safety import write_json
import test_core as fixtures


@unittest.skipUnless(os.environ.get('SC_HEALER_MYSQL_TEST') == '1', 'Opt-in isolated MySQL integration test')
class DatabaseIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pymysql
        binary = shutil.which('mysqld')
        if not binary:
            raise unittest.SkipTest('mysqld not installed')
        cls.temp = tempfile.TemporaryDirectory(prefix='sc-healer-mysql-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name)
        datadir = cls.base / 'data'
        datadir.mkdir()
        cls.socket = str(cls.base / 'mysql.sock')
        log = cls.base / 'mysql.log'
        user = pwd.getpwuid(os.getuid()).pw_name
        init = subprocess.run([binary, '--no-defaults', '--initialize-insecure', f'--user={user}',
                               f'--datadir={datadir}', f'--log-error={log}'], capture_output=True, timeout=60)
        if init.returncode:
            raise RuntimeError('Disposable MySQL initialization failed: ' + init.stderr.decode())
        cls.server = subprocess.Popen([binary, '--no-defaults', f'--user={user}', f'--datadir={datadir}',
                                       f'--socket={cls.socket}', f'--pid-file={cls.base / "mysql.pid"}',
                                       f'--log-error={log}', '--skip-networking', '--mysqlx=0',
                                       '--innodb-buffer-pool-size=32M', '--performance-schema=OFF'],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def stop():
            cls.server.terminate()
            try:
                cls.server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                cls.server.kill()
                cls.server.wait()

        cls.addClassCleanup(stop)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                # Check readiness with a context-managed socket before asking the
                # driver to connect; some driver releases leak failed-connect sockets.
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as readiness:
                    readiness.settimeout(0.2)
                    readiness.connect(cls.socket)
                cls.admin = pymysql.connect(user='root', unix_socket=cls.socket, autocommit=True)
                cls.addClassCleanup(cls.admin.close)
                return
            except (pymysql.Error, OSError):
                if cls.server.poll() is not None:
                    break
                time.sleep(0.1)
        raise RuntimeError('Disposable MySQL startup failed: ' + log.read_text())

    def setUp(self):
        with self.admin.cursor() as cursor:
            cursor.execute('DROP DATABASE IF EXISTS sc_healer_test')
            cursor.execute('CREATE DATABASE sc_healer_test CHARACTER SET utf8mb4')
        self.case_temp = tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(self.case_temp.cleanup)
        self.case = Path(self.case_temp.name)
        config = self.case / 'config.json'
        write_json(config, {'user': 'root', 'unix_socket': self.socket, 'database': 'sc_healer_test', 'prefix': 'site_'})
        self.db = Database(config)
        self.addCleanup(self.db.close)
        self.db.execute('CREATE TABLE site_options (option_id BIGINT PRIMARY KEY AUTO_INCREMENT, option_name VARCHAR(191) UNIQUE, option_value LONGTEXT, autoload VARCHAR(20)) ENGINE=InnoDB')
        self.db.execute('CREATE TABLE site_2_options LIKE site_options')
        self.db.execute('CREATE TABLE site_usermeta (umeta_id BIGINT PRIMARY KEY AUTO_INCREMENT, user_id BIGINT, meta_key VARCHAR(191), meta_value LONGTEXT) ENGINE=InnoDB')
        self.db.execute('INSERT INTO site_options VALUES (1,%s,%s,%s)', ('random_payload', base64.b64encode(gzip.compress(fixtures.INDICATORS)), 'no'))
        self.db.execute('INSERT INTO site_options VALUES (2,%s,%s,%s)', ('cron', fixtures.SerializationTest.CRON, 'yes'))
        self.db.execute('INSERT INTO site_options VALUES (3,%s,%s,%s)', ('home', 'https://example.invalid', 'yes'))
        self.db.execute('INSERT INTO site_2_options VALUES (1,%s,%s,%s)', ('sc_review', 'inert', 'no'))
        self.db.execute('INSERT INTO site_usermeta VALUES (1,1,%s,%s)', ('session_tokens', 'dummy session data'))
        self.db.execute('INSERT INTO site_usermeta VALUES (2,1,%s,%s)', ('wp_capabilities', 'a:1:{s:13:"administrator";b:1;}'))
        self.db.connection.commit()

    def write_plan(self, **kwargs):
        path = self.case / 'plan.json'
        write_json(path, self.db.plan(**kwargs))
        return path

    def test_audit_finds_encoded_payload_multisite_cron_and_hidden_admin_candidate(self):
        rpc_fixture = fixtures.INDICATORS + b' /* eth_call https://rpc.example.invalid/key */'
        self.db.execute('UPDATE site_options SET option_value=%s WHERE option_id=1',
                        (base64.b64encode(gzip.compress(rpc_fixture)),))
        self.db.connection.commit()
        self.db.execute('CREATE TRIGGER test_trigger BEFORE INSERT ON site_options FOR EACH ROW SET NEW.autoload = NEW.autoload')
        report = self.db.audit()
        self.assertTrue(any('sc-marker' in f['signals'] for f in report['findings']))
        self.assertTrue(any(f.get('blockchain') and f['blockchain']['rpc_methods'][0]['value'] == 'eth_call'
                            for f in report['findings']))
        self.assertTrue(any(f['table'] == 'site_2_options' for f in report['findings']))
        self.assertEqual(report['cron'][0]['hooks'], ['bad_hook', 'good_hook'])
        self.assertEqual(report['administrators'][0]['meta_key'], 'wp_capabilities')
        self.assertEqual(report['triggers'][0]['name'], 'test_trigger')
        self.assertFalse(report['coverage_gaps'])

    def test_apply_and_restore_database_transaction(self):
        plan = self.write_plan(deletions=[('site_options', 1)],
                               hook_selections=[('site_options', 'bad_hook')], invalidate_sessions=True)
        backup = self.case / 'backup.json'
        self.assertEqual(self.db.apply(plan, backup)['actions'], 3)
        self.assertFalse(self.db.query('SELECT * FROM site_options WHERE option_id=1'))
        self.assertNotIn(b'bad_hook', self.db.get_row('site_options', 'option_id', 2)['option_value'])
        self.assertFalse(self.db.query('SELECT * FROM site_usermeta WHERE umeta_id=1'))
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.db.restore(backup)['actions'], 3)
        self.assertEqual(self.db.get_row('site_options', 'option_id', 2)['option_value'], fixtures.SerializationTest.CRON)
        self.assertEqual(self.db.restore(backup)['actions'], 0)

    def test_stale_row_refuses_all_changes(self):
        plan = self.write_plan(deletions=[('site_options', 1)], invalidate_sessions=True)
        self.db.execute('UPDATE site_usermeta SET meta_value=%s WHERE umeta_id=1', ('changed',))
        self.db.connection.commit()
        with self.assertRaisesRegex(ValueError, 'Stale'):
            self.db.apply(plan, self.case / 'backup.json')
        self.assertTrue(self.db.query('SELECT * FROM site_options WHERE option_id=1'))
        self.assertFalse((self.case / 'backup.json').exists())

    def test_transaction_rolls_back_on_mid_apply_error(self):
        plan = self.write_plan(deletions=[('site_options', 1)], invalidate_sessions=True)
        execute = self.db.execute

        def fail(sql, params=()):
            if sql.startswith('DELETE FROM `site_usermeta`'):
                raise ValueError('Simulated failure')
            return execute(sql, params)

        backup = self.case / 'backup.json'
        with patch.object(self.db, 'execute', fail), self.assertRaisesRegex(ValueError, 'Simulated'):
            self.db.apply(plan, backup)
        self.assertTrue(self.db.query('SELECT * FROM site_options WHERE option_id=1'))
        self.assertEqual(self.db.restore(backup)['actions'], 0)

    def test_changed_row_prevents_entire_restore(self):
        plan = self.write_plan(deletions=[('site_options', 1)], hook_selections=[('site_options', 'bad_hook')])
        backup = self.case / 'backup.json'
        self.db.apply(plan, backup)
        self.db.execute('UPDATE site_options SET option_value=%s WHERE option_id=2', ('changed',))
        self.db.connection.commit()
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.db.restore(backup)
        self.assertFalse(self.db.query('SELECT * FROM site_options WHERE option_id=1'))

    def test_nontransactional_table_is_rejected(self):
        plan = self.write_plan(deletions=[('site_options', 1)])
        self.db.execute('ALTER TABLE site_options ENGINE=MyISAM')
        with self.assertRaisesRegex(ValueError, 'InnoDB'):
            self.db.apply(plan, self.case / 'backup.json')

    def test_structural_options_and_foreign_tables_rejected(self):
        with self.assertRaises(ValueError):
            self.db.plan(deletions=[('site_options', 3)])
        with self.assertRaises(ValueError):
            self.db.plan(deletions=[('other_options', 1)])
        with self.assertRaises(ValueError):
            self.db.plan(deletions=[('site_options; DROP DATABASE anything', 1)])


if __name__ == '__main__':
    unittest.main()
