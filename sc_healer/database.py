"""Direct MySQL access. Never bootstrap WordPress or evaluate wp-config.php."""

import base64
import json
import os
from pathlib import Path
import re

from . import phpserialize
from .safety import digest, load_json, read_regular, write_json
from .scanner import inspect_data

ROW_LIMIT = 16 * 1024 * 1024


def identifier(name):
    if not re.fullmatch(r'[A-Za-z0-9_]+', name):
        raise ValueError('Invalid database identifier')
    return '`' + name + '`'


def text(value):
    return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value


def encode_row(row):
    return {text(k): {'b64': base64.b64encode(v).decode()} if isinstance(v, bytes) else v
            for k, v in row.items()}


def decode_row(row):
    return {k: base64.b64decode(v['b64'], validate=True) if isinstance(v, dict) else v
            for k, v in row.items()}


def row_hash(row):
    return digest(json.dumps(encode_row(row), sort_keys=True, separators=(',', ':')).encode())


class Database:
    def __init__(self, config_file):
        data, info = read_regular(Path(config_file))
        if info.st_mode & 0o077:
            raise ValueError('Database config must be private (chmod 600)')
        config = json.loads(data)
        self.prefix = config.pop('prefix', 'wp_')
        identifier(self.prefix)
        allowed = {'host', 'port', 'user', 'password', 'database', 'unix_socket', 'ssl_ca'}
        if set(config) - allowed:
            raise ValueError('Unknown database configuration keys')
        self.name = config['database']
        identifier(self.name)
        host = config.get('host', 'localhost')
        if not config.get('unix_socket') and host not in ('localhost', '127.0.0.1', '::1') and not config.get('ssl_ca'):
            raise ValueError('Remote database connections require ssl_ca with certificate/identity verification')
        try:
            import pymysql
        except ImportError as error:
            raise ValueError('Install MySQL support: pip install -e ".[mysql]"') from error
        if config.get('ssl_ca'):
            config.update(ssl_verify_cert=True, ssl_verify_identity=True)
        self.connection = pymysql.connect(**config, charset='utf8mb4', use_unicode=False,
                                          autocommit=False, connect_timeout=10,
                                          read_timeout=30, write_timeout=30,
                                          cursorclass=pymysql.cursors.DictCursor)
        self.identity = {'database': self.name, 'prefix': self.prefix,
                         'host': host, 'port': config.get('port', 3306),
                         'unix_socket': config.get('unix_socket')}

    def close(self):
        self.connection.close()

    def query(self, sql, params=()):
        with self.connection.cursor() as cursor:
            cursor.execute(sql, params)
            return cursor.fetchall()

    def execute(self, sql, params=()):
        with self.connection.cursor() as cursor:
            return cursor.execute(sql, params)

    def option_table(self, table):
        if not re.fullmatch(re.escape(self.prefix) + r'(?:[0-9]+_)?options', table):
            raise ValueError('Expected an options table belonging to the configured prefix')
        return identifier(table)

    def tables(self):
        rows = self.query('SELECT TABLE_NAME AS name, ENGINE AS engine FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s', (self.name,))
        return {text(row['name']): text(row['engine']) for row in rows}

    def audit(self):
        tables = self.tables()
        report = {'kind': 'database-scan', 'schema': 1, 'identity': self.identity,
                  'findings': [], 'cron': [], 'administrators': [], 'triggers': [], 'events': [],
                  'coverage_gaps': [], 'notes': [
                      'Trigger/event visibility depends on database privileges; absence is not proof.',
                      'Administrator and sc_ option listings require review; names are not verdicts.',
                      'Only options, sitemeta, capabilities, cron, triggers and events are inspected; other tables may contain payloads.']}
        for table in sorted(tables):
            if re.fullmatch(re.escape(self.prefix) + r'(?:[0-9]+_)?options', table):
                self.audit_values(table, 'option_id', 'option_name', 'option_value', report)
            elif table == self.prefix + 'sitemeta':
                self.audit_values(table, 'meta_id', 'meta_key', 'meta_value', report)
        usermeta = self.prefix + 'usermeta'
        if usermeta in tables:
            # Any capabilities key, including wp_capabilities on a custom-prefix install.
            rows = self.query(f'SELECT user_id, meta_key, meta_value FROM {identifier(usermeta)} WHERE RIGHT(meta_key, 12)=%s', ('capabilities',))
            for row in rows:
                if b'administrator' in row['meta_value']:
                    report['administrators'].append({'user_id': row['user_id'], 'meta_key': text(row['meta_key']),
                                                      'review': 'Verify this user directly in the database; WordPress lists may be filtered.'})
        else:
            report['coverage_gaps'].append(f'Missing usermeta table: {usermeta}')
        if self.prefix + 'options' not in tables:
            report['coverage_gaps'].append('Base options table not found; verify prefix/database')
        for label, query in (
            ('triggers', 'SELECT TRIGGER_NAME AS name, EVENT_OBJECT_TABLE AS target, ACTION_STATEMENT AS statement FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=%s'),
            ('events', 'SELECT EVENT_NAME AS name, STATUS AS status, EVENT_DEFINITION AS statement FROM information_schema.EVENTS WHERE EVENT_SCHEMA=%s'),
        ):
            try:
                for row in self.query(query, (self.name,)):
                    report[label].append({k: text(v) for k, v in row.items()})
            except Exception as error:
                report['coverage_gaps'].append(f'{label} inspection failed: {type(error).__name__}')
        self.connection.rollback()
        return report

    def audit_values(self, table, pk, name, value, report):
        last = -1
        while True:
            # Do not fetch huge values merely to find out they were too large.
            rows = self.query(f'SELECT {identifier(pk)} AS id, {identifier(name)} AS name, OCTET_LENGTH({identifier(value)}) AS size FROM {identifier(table)} WHERE {identifier(pk)}>%s ORDER BY {identifier(pk)} LIMIT 200', (last,))
            if not rows:
                break
            for row in rows:
                last = row['id']
                label = {'table': table, 'id': last, 'name': text(row['name'])}
                if row['size'] > ROW_LIMIT:
                    report['coverage_gaps'].append({**label, 'reason': 'Database value exceeds 16 MiB inspection budget'})
                    continue
                values = self.query(f'SELECT {identifier(value)} AS value FROM {identifier(table)} WHERE {identifier(pk)}=%s AND OCTET_LENGTH({identifier(value)})<=%s', (last, ROW_LIMIT))
                if not values:
                    report['coverage_gaps'].append({**label, 'reason': 'Row changed during scan'})
                    continue
                data = values[0]['value']
                result = inspect_data(data)
                if re.match(r'^(?:(?:_site)?_transient_(?:timeout_)?)?sc_', label['name'], re.I):
                    result['reasons'].append(('review', 'SC-style option name; may be legitimate'))
                if result['reasons']:
                    report['findings'].append({**label, 'sha256': digest(data), **result})
                for limit in result['gaps']:
                    report['coverage_gaps'].append({**label, 'reason': limit})
                if label['name'] == 'cron':
                    try:
                        report['cron'].append({**label, 'hooks': phpserialize.cron_hooks(data)})
                    except ValueError as error:
                        report['coverage_gaps'].append({**label, 'reason': str(error)})

    def get_row(self, table, pk, row_id, lock=False):
        rows = self.query(f'SELECT * FROM {identifier(table)} WHERE {identifier(pk)}=%s' + (' FOR UPDATE' if lock else ''), (row_id,))
        if len(rows) != 1:
            raise ValueError(f'Expected one row: {table}:{row_id}')
        return rows[0]

    def plan(self, deletions=(), hook_selections=(), invalidate_sessions=False):
        actions, seen = [], set()

        def add(table, pk, row, after):
            key = (table, row[pk])
            if key in seen:
                raise ValueError(f'Duplicate database action: {key}')
            seen.add(key)
            actions.append({'table': table, 'pk': pk, 'id': row[pk],
                            'before_sha256': row_hash(row), 'before': encode_row(row),
                            'after': encode_row(after) if after is not None else None})

        for table, row_id in deletions:
            self.option_table(table)
            row = self.get_row(table, 'option_id', int(row_id))
            if row['option_name'] in (b'cron', b'siteurl', b'home', b'active_plugins'):
                raise ValueError('Refusing to delete a structural WordPress option')
            add(table, 'option_id', row, None)
        grouped = {}
        for table, hook in hook_selections:
            self.option_table(table)
            grouped.setdefault(table, []).append(hook)
        for table, hooks in grouped.items():
            rows = self.query(f'SELECT * FROM {identifier(table)} WHERE option_name=%s', ('cron',))
            if len(rows) != 1:
                raise ValueError('Expected one cron option')
            row = rows[0]
            after = {**row, 'option_value': phpserialize.remove_hooks(row['option_value'], hooks)}
            add(table, 'option_id', row, after)
        if invalidate_sessions:
            table = self.prefix + 'usermeta'
            for row in self.query(f'SELECT * FROM {identifier(table)} WHERE meta_key=%s', ('session_tokens',)):
                add(table, 'umeta_id', row, None)
        self.connection.rollback()
        if not actions:
            raise ValueError('No database actions selected/found')
        return {'schema': 1, 'kind': 'database-plan', 'identity': self.identity, 'actions': actions}

    def validate_action(self, action, tables):
        table, pk = action['table'], action['pk']
        before = decode_row(action['before'])
        after = decode_row(action['after']) if action['after'] is not None else None
        if tables.get(table, '').upper() != 'INNODB':
            raise ValueError('Database mutations require InnoDB transactional tables')
        if row_hash(before) != action['before_sha256'] or before[pk] != action['id']:
            raise ValueError('Database plan integrity mismatch')
        if table == self.prefix + 'usermeta':
            if pk != 'umeta_id' or before['meta_key'] != b'session_tokens' or after is not None:
                raise ValueError('Only explicit session invalidation is supported in usermeta')
        else:
            self.option_table(table)
            if pk != 'option_id':
                raise ValueError('Invalid option primary key')
            if after is not None:
                if before['option_name'] != b'cron' or set(after) != set(before):
                    raise ValueError('Only cron values can be updated')
                if any(before[k] != after[k] for k in before if k != 'option_value'):
                    raise ValueError('Only the cron value may change')
                phpserialize.cron_hooks(after['option_value'])
            elif before['option_name'] in (b'cron', b'siteurl', b'home', b'active_plugins'):
                raise ValueError('Refusing deletion of structural option')
        return before, after

    def apply(self, plan_file, backup_file):
        plan = load_json(plan_file)
        if plan.get('schema') != 1 or plan.get('kind') != 'database-plan' or plan['identity'] != self.identity:
            raise ValueError('Database plan belongs to a different connection/prefix or schema')
        tables = self.tables()
        self.connection.rollback()
        seen = set()
        try:
            self.connection.begin()
            for action in plan['actions']:
                key = (action['table'], action['id'])
                if key in seen:
                    raise ValueError('Duplicate database action')
                seen.add(key)
                self.validate_action(action, tables)
                row = self.get_row(action['table'], action['pk'], action['id'], lock=True)
                if row_hash(row) != action['before_sha256']:
                    raise ValueError(f'Stale database plan: {key}')
            # Private, durable backup before issuing any modifying statement.
            backup = {**plan, 'kind': 'database-backup', 'state': 'prepared'}
            write_json(backup_file, backup, exclusive=True)
            for action in plan['actions']:
                table, pk = identifier(action['table']), identifier(action['pk'])
                if action['after'] is None:
                    affected = self.execute(f'DELETE FROM {table} WHERE {pk}=%s', (action['id'],))
                else:
                    after = decode_row(action['after'])
                    affected = self.execute(f'UPDATE {table} SET option_value=%s WHERE {pk}=%s', (after['option_value'], action['id']))
                if affected != 1:
                    raise ValueError('Unexpected number of modified rows; rolling back')
            self.connection.commit()
            backup['state'] = 'committed'
            write_json(backup_file, backup)
        except BaseException:
            self.connection.rollback()
            raise
        return {'state': 'committed', 'actions': len(plan['actions']), 'backup': str(backup_file)}

    def restore(self, backup_file):
        backup = load_json(backup_file)
        if backup.get('schema') != 1 or backup.get('kind') != 'database-backup' or backup['identity'] != self.identity:
            raise ValueError('Wrong database backup')
        tables = self.tables()
        self.connection.rollback()
        restored = 0
        try:
            self.connection.begin()
            for action in reversed(backup['actions']):
                before, after = self.validate_action(action, tables)
                table, pk = identifier(action['table']), identifier(action['pk'])
                rows = self.query(f'SELECT * FROM {table} WHERE {pk}=%s FOR UPDATE', (action['id'],))
                if rows and row_hash(rows[0]) == action['before_sha256']:
                    continue
                if (after is None and rows) or (after is not None and (not rows or row_hash(rows[0]) != row_hash(after))):
                    raise ValueError('Row changed since cleanup; refusing database restore')
                if after is None:
                    columns = ','.join(identifier(k) for k in before)
                    placeholders = ','.join(['%s'] * len(before))
                    self.execute(f'INSERT INTO {table} ({columns}) VALUES ({placeholders})', tuple(before.values()))
                else:
                    self.execute(f'UPDATE {table} SET option_value=%s WHERE {pk}=%s', (before['option_value'], action['id']))
                restored += 1
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise
        return {'state': 'restored', 'actions': restored, 'warning': 'Potentially malicious rows/session tokens restored; keep execution stopped.'}
