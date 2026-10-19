import argparse
import json
from pathlib import Path
import sys
import time

from . import __version__
from .host import inventory
from .remediation import apply_plan, make_plan, restore
from .safety import load_json, outside, root_path, write_json
from .scanner import scan


def emit(value, output=None, root=None):
    if output:
        path = outside(root_path(root), output) if root else Path(output)
        write_json(path, value, exclusive=True)
        print(json.dumps({'report': str(path), 'kind': value.get('kind'),
                          'findings': len(value.get('findings', [])),
                          'coverage_gaps': len(value.get('coverage_gaps', []))}))
    else:
        print(json.dumps(value, indent=2, ensure_ascii=True))


def stopped(args):
    if not args.execution_stopped:
        raise ValueError('Stop PHP/web execution, cron, and background writers, then pass --execution-stopped. WordPress maintenance mode is insufficient.')


def split_pair(value):
    if ':' not in value:
        raise argparse.ArgumentTypeError('Expected TABLE:VALUE')
    return value.split(':', 1)


def parser():
    p = argparse.ArgumentParser(description='SC Healer: offline-first WordPress incident recovery. Never executes site code.')
    p.add_argument('--version', action='version', version=__version__)
    commands = p.add_subparsers(dest='command', required=True)
    s = commands.add_parser('scan', help='Read-only recursive file and ZIP inspection')
    s.add_argument('root')
    s.add_argument('--output')
    s.add_argument('--max-file-bytes', type=int, help='Optional limit; skipped files become coverage gaps')
    h = commands.add_parser('host-audit', help='Read-only Linux process, IPC, and cron inventory')
    h.add_argument('root')
    h.add_argument('--output')
    egress = commands.add_parser('egress-plan', help='Generate a UID-scoped nftables containment bundle; never applies rules')
    egress.add_argument('root')
    egress.add_argument('--uid', type=int, required=True, help='Confirmed dedicated PHP socket-owner UID, not file owner')
    egress.add_argument('--dedicated-uid', action='store_true', help='Acknowledge the UID is dedicated and its traffic can be interrupted')
    egress.add_argument('--allow', nargs=3, action='append', default=[], metavar=('PROTOCOL', 'IP', 'PORT'))
    egress.add_argument('--output-dir', required=True, help='New private directory outside all web roots')
    plan = commands.add_parser('plan', help='Build a plan from explicit file selections')
    plan.add_argument('root')
    plan.add_argument('--quarantine', action='append', default=[], metavar='RELATIVE_PATH')
    plan.add_argument('--neutralize-prepend', action='append', default=[], metavar='RELATIVE_PATH')
    plan.add_argument('--replace', nargs=2, action='append', default=[], metavar=('RELATIVE_PATH', 'TRUSTED_FILE'))
    plan.add_argument('--output', required=True)
    apply = commands.add_parser('apply', help='Back up and apply a reviewed file plan')
    apply.add_argument('plan')
    apply.add_argument('--evidence-dir', required=True, help='New private directory outside every web root')
    apply.add_argument('--execution-stopped', action='store_true')
    apply.add_argument('--off-disk-reviewed', action='store_true')
    undo = commands.add_parser('restore', help='Restore original files while execution stays stopped')
    undo.add_argument('journal')
    undo.add_argument('--execution-stopped', action='store_true')
    w = commands.add_parser('watch', help='Compare repeated scans against a post-cleanup inventory')
    w.add_argument('root')
    w.add_argument('--baseline', required=True)
    w.add_argument('--interval', type=float, default=30)
    w.add_argument('--iterations', type=int, default=10)
    for command in ('db-scan', 'db-plan', 'db-apply', 'db-restore'):
        db = commands.add_parser(command, help='Direct MySQL operation; requires optional mysql dependency')
        db.add_argument('--config', required=True, help='Private JSON connection file; never wp-config.php')
        db.add_argument('--root', required=True, help='Site root, used to keep artifacts outside the web tree')
        if command in ('db-scan', 'db-plan'):
            db.add_argument('--output', required=True)
        if command == 'db-plan':
            db.add_argument('--delete-option', action='append', type=split_pair, default=[], metavar='TABLE:OPTION_ID')
            db.add_argument('--remove-cron-hook', action='append', type=split_pair, default=[], metavar='TABLE:HOOK')
            db.add_argument('--invalidate-sessions', action='store_true')
        if command in ('db-apply', 'db-restore'):
            db.add_argument('plan' if command == 'db-apply' else 'backup')
            db.add_argument('--execution-stopped', action='store_true')
            db.add_argument('--triggers-reviewed', action='store_true')
        if command == 'db-apply':
            db.add_argument('--backup', required=True)
    return p


def run(args):
    if args.command == 'scan':
        if args.max_file_bytes is not None and args.max_file_bytes <= 0:
            raise ValueError('Size limit must be positive')
        report = scan(args.root, args.max_file_bytes)
        emit(report, args.output, args.root)
        return 2 if report['coverage_gaps'] else int(bool(report['findings']))
    if args.command == 'host-audit':
        report = inventory(args.root)
        emit(report, args.output, args.root)
        return 2 if report['coverage_gaps'] else 0
    if args.command == 'egress-plan':
        from .blockchain import write_containment
        if not args.dedicated_uid:
            raise ValueError('Confirm a dedicated PHP/socket UID and the interruption scope, then pass --dedicated-uid. Shared www-data accounts are not site-isolated.')
        emit(write_containment(args.root, args.output_dir, args.uid, args.allow))
    elif args.command == 'plan':
        output = outside(root_path(args.root), args.output)
        plan = make_plan(args.root, args.quarantine, args.neutralize_prepend, args.replace)
        emit(plan, output, args.root)
    elif args.command == 'apply':
        stopped(args)
        if not args.off_disk_reviewed:
            raise ValueError('Review/clear database, IPC, and schedulers before applying; pass --off-disk-reviewed after doing so')
        emit(apply_plan(args.plan, args.evidence_dir))
    elif args.command == 'restore':
        stopped(args)
        emit(restore(args.journal))
    elif args.command.startswith('db-'):
        from .database import Database
        root = root_path(args.root)
        outside(root, args.config)
        if args.command in ('db-apply', 'db-restore'):
            stopped(args)
            if not args.triggers_reviewed:
                raise ValueError('Review database triggers before mutations; pass --triggers-reviewed after doing so')
            outside(root, args.backup)
        if args.command == 'db-apply':
            outside(root, args.plan)
        if args.command in ('db-scan', 'db-plan'):
            outside(root, args.output)
        db = Database(args.config)
        try:
            if args.command == 'db-scan':
                report = db.audit()
                emit(report, args.output, args.root)
                return 2 if report['coverage_gaps'] else int(bool(report['findings']))
            elif args.command == 'db-plan':
                emit(db.plan(args.delete_option, args.remove_cron_hook, args.invalidate_sessions), args.output, args.root)
            elif args.command == 'db-apply':
                emit(db.apply(args.plan, args.backup))
            else:
                emit(db.restore(args.backup))
        finally:
            db.close()
    elif args.command == 'watch':
        if args.interval < 1 or args.iterations < 1:
            raise ValueError('Interval and iterations must be positive (interval >= 1 second)')
        baseline = load_json(args.baseline)
        if baseline.get('kind') != 'scan' or baseline['root'] != str(root_path(args.root)):
            raise ValueError('Baseline must be a scan of the same root')
        if baseline['coverage_gaps']:
            raise ValueError('Baseline has coverage gaps; resolve them before monitoring')
        for iteration in range(args.iterations):
            if iteration:
                time.sleep(args.interval)
            current = scan(args.root)
            previous, now = baseline['inventory'], current['inventory']
            added = sorted(set(now) - set(previous))
            removed = sorted(set(previous) - set(now))
            changed = sorted(p for p in set(now) & set(previous) if now[p] != previous[p])
            emit({'iteration': iteration + 1, 'added': added, 'removed': removed, 'changed': changed,
                  'coverage_gaps': current['coverage_gaps']})
            sys.stdout.flush()
            if current['coverage_gaps']:
                return 2
            if added or removed or changed:
                return 1
    return 0


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print('Interrupted. If applying, inspect the durable journal/backup before continuing.', file=sys.stderr)
        return 130
    except Exception as error:
        # Database exceptions may contain connection details or row data.
        message = str(error) if isinstance(error, (ValueError, OSError)) else type(error).__name__
        print(f'Error: {message}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
