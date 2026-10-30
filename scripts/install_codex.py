#!/usr/bin/env python3
"""Install the Codex distribution. Preview by default; --apply writes the plan.

No downloads, global configuration changes, Git commits or trust changes.
Use exclusive access to the target while installing. OS write errors may leave
partial work; all known source and destination conflicts are checked first.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import sys

sys.dont_write_bytecode = True
from install import (CONTEXT, InstallError, apply_plan, plan_install,
                     read_regular, safe_path, source_text)

REQUIRED = (
    '.codex/config.toml', '.codex/hooks/security.py', '.codex/hooks/session_start.py',
    '.codex/hooks/notify.py', '.codex/rules/starter.rules',
    '.codex/agents/researcher.toml', '.codex/agents/implementer.toml',
    '.codex/agents/reviewer.toml', '.agents/skills/start-project/SKILL.md',
    '.agents/skills/create-agent/SKILL.md', '.starter/START_HERE.md',
    '.starter/AUTOPILOT.md', 'prompts/INDEX.md', 'PROJECT.md',
)
IGNORE = ('.env', '.env.*', '!.env.example', '__pycache__/', '*.pyc', '.venv/')


def make_hooks(target, sounds=False):
    def handler(script, timeout=10):
        command = shlex.quote(sys.executable) + ' -B ' + shlex.quote(
            str(target / '.codex/hooks' / script))
        return {'type': 'command', 'command': command, 'timeout': timeout}

    hooks = {
        'PreToolUse': [{'matcher': '.*', 'hooks': [handler('security.py')]}],
        'SessionStart': [{'hooks': [handler('session_start.py')]}],
    }
    if sounds:
        for event in ('Stop', 'PermissionRequest'):
            hooks[event] = [{'hooks': [handler('notify.py', 5)]}]
    return (json.dumps({'description': 'Codex Starter: review these hooks with /hooks.',
                       'hooks': hooks}, ensure_ascii=False, indent=2) + '\n').encode()


def codex_plan(source, target, agent='codex', business=False, sounds=False):
    if os.name == 'nt':
        raise InstallError('This release supports macOS/Linux. Use WSL on Windows.')
    if any(char in str(target) for char in '\n\r\x00'):
        raise InstallError('Newlines and NUL are not supported in project paths')
    safe_path(source)
    safe_path(target)
    if source == target or source in target.parents or target in source.parents:
        raise InstallError('Starter source and target must be separate, non-overlapping directories')
    payload = source / 'payload'
    safe_path(payload)
    # Validate the entire package before touching the destination.
    assets = {name: source_text(payload / name) for name in REQUIRED}
    assets['.starter/LICENSE'] = source_text(source / 'LICENSE')
    assets['.starter/NOTICE.md'] = source_text(source / 'NOTICE.md')
    for file in sorted(payload.rglob('*')):
        safe_path(file)
        if file.is_dir():
            continue
        relative = file.relative_to(payload).as_posix()
        if '__pycache__' in file.parts or file.suffix == '.pyc':
            continue
        if file.suffix not in {'.md', '.toml', '.py', '.rules'}:
            raise InstallError(f'Unexpected payload file: {relative}')
        assets[relative] = source_text(file)

    # An existing context belongs to the owner, even if it was previously
    # created by this installer. Never expand or replace it automatically.
    had_context = any((target / name).exists() for name in CONTEXT)
    base, context = plan_install(source, target, agent)
    actions = {path: (old, data) for path, old, data in base}

    def add(relative, data, preserve=False):
        path = target / relative
        safe_path(path)
        old = read_regular(path) if path.exists() else None
        if old is not None:
            if preserve or old == data:
                return
            raise InstallError(f'Existing file differs; refusing overwrite: {relative}')
        actions[path] = (old, data)

    for name, data in assets.items():
        if name.startswith('business-template/'):
            if business and not had_context:
                add('.business/' + name[len('business-template/'):], data)
        else:
            add(name, data, preserve=name == 'PROJECT.md')
    add('.codex/hooks.json', make_hooks(target, sounds))

    ignore = target / '.gitignore'
    old_ignore, planned = actions.get(ignore, (
        read_regular(ignore) if ignore.exists() else None,
        read_regular(ignore) if ignore.exists() else b'',
    ))
    # Reuse upstream's final private-context rule and ensure all newly added
    # patterns follow existing negations, without accumulating on reruns.
    suffix = ('\n# Codex Starter local files\n' + '\n'.join(IGNORE) + '\n/.business/\n').encode()
    if not planned.endswith(suffix):
        planned += (b'\n' if planned and not planned.endswith(b'\n') else b'') + suffix
    if planned != old_ignore:
        actions[ignore] = (old_ignore, planned)
    return [(path, old, data) for path, (old, data) in actions.items()], context, had_context


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', metavar='PATH', help='existing project directory')
    parser.add_argument('--apply', action='store_true', help='write the validated plan')
    parser.add_argument('--agent', choices=('codex', 'both'), default='codex')
    parser.add_argument('--business', action='store_true', help='seven sections when no context exists')
    parser.add_argument('--sounds', action='store_true', help='optional Stop and PermissionRequest sound')
    args = parser.parse_args(argv)
    try:
        target = Path(os.path.abspath(os.path.expanduser(args.path)))
        source = Path(__file__).resolve().parent.parent
        actions, context, had_context = codex_plan(
            source, target, args.agent, args.business, args.sounds)
        print('Apply plan:' if args.apply else 'Dry-run: no files or directories written.')
        for path, old, _ in actions:
            print(f'  {"create" if old is None else "append/update"}: {path.relative_to(target)}')
        if args.business and had_context:
            print('Existing context preserved; --business expansion skipped: ' + ', '.join(context))
        if args.apply:
            apply_plan(actions)
            print(f'Applied {len(actions)} file changes to {target}.')
            print('Next: open this folder in Codex; review project trust and /hooks; read .starter/START_HERE.md.')
            print('Hooks are installed, NOT automatically trusted. No global settings or Git index changed.')
        else:
            print(f'{len(actions)} file changes planned. Add --apply to install.')
        return 0
    except (InstallError, OSError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
