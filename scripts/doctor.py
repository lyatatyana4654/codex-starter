#!/usr/bin/env python3
"""Read-only checks of installed paths and expected defaults, not hook trust."""
import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HOOK_SCRIPTS = {
    'PreToolUse': 'security.py', 'SessionStart': 'session_start.py',
    'Stop': 'notify.py', 'PermissionRequest': 'notify.py',
}


def normalized_config(text):
    """Compare the shipped default, not TOML semantics or arbitrary profiles."""
    return '\n'.join(line.strip() for line in text.splitlines()
                     if line.strip() and not line.lstrip().startswith('#'))


def check_hooks(document, target):
    problems = []
    if not isinstance(document, dict) or not isinstance(document.get('hooks'), dict):
        return ['Invalid hooks.json structure']
    hooks = document['hooks']
    for event in ('PreToolUse', 'SessionStart'):
        if not hooks.get(event):
            problems.append('Missing hook event: ' + event)
    for event, groups in hooks.items():
        if event not in HOOK_SCRIPTS:
            problems.append('Custom hook event requires manual review: ' + event)
            continue
        if not isinstance(groups, list) or not groups:
            problems.append('Hook groups must be a nonempty list: ' + event)
            continue
        for group in groups:
            if not isinstance(group, dict):
                problems.append('Invalid hook group: ' + event)
                continue
            # Defaults intentionally cover every matching event. A narrowed
            # matcher cannot be described as the shipped active guardrail.
            if group.get('matcher') not in (None, '.*'):
                problems.append('Custom hook matcher requires manual review: ' + event)
            handlers = group.get('hooks')
            if not isinstance(handlers, list) or not handlers:
                problems.append('Hook handlers must be a nonempty list: ' + event)
                continue
            for hook in handlers:
                if not isinstance(hook, dict) or hook.get('type') != 'command':
                    problems.append('Expected command hook: ' + event)
                    continue
                if hook.get('enabled') is False:
                    problems.append('Hook is disabled: ' + event)
                value = hook.get('command')
                if not isinstance(value, str) or not value.strip():
                    problems.append('Missing hook command: ' + event)
                    continue
                try:
                    command = shlex.split(value)
                except ValueError:
                    problems.append('Invalid hook command quoting: ' + event)
                    continue
                if len(command) != 3 or command[1] != '-B':
                    problems.append('Unexpected command shape: ' + event)
                    continue
                interpreter, _, script = command
                if not Path(interpreter).is_absolute() or not Path(interpreter).is_file():
                    problems.append('Python interpreter moved or missing: ' + event)
                path = Path(script)
                expected = target / '.codex/hooks' / HOOK_SCRIPTS[event]
                if (not path.is_absolute() or not path.is_file() or path.is_symlink()
                        or path.resolve() != expected.absolute()
                        or path.absolute() != expected.absolute()):
                    problems.append('Hook path missing or differs from expected script: ' + event)
    return problems


def secret_filename(name):
    base = Path(name).name
    return base == '.env' or (base.startswith('.env.') and base != '.env.example')


def check(target):
    problems = []
    required = ('AGENTS.md', 'PROJECT.md', '.starter/workflow.md',
                '.starter/AUTOPILOT.md', '.codex/config.toml',
                '.codex/hooks.json', '.codex/rules/starter.rules')
    for name in required:
        if not (target / name).is_file():
            problems.append('Missing: ' + name)
    settings = target / '.codex/config.toml'
    if settings.is_file():
        if settings.resolve() != settings.absolute():
            problems.append('Symlinked configuration requires manual review')
        else:
            try:
                text = settings.read_text(encoding='utf-8')
                reference = (ROOT / 'payload/.codex/config.toml').read_text(encoding='utf-8')
                if normalized_config(text) != normalized_config(reference):
                    problems.append('Configuration differs from shipped defaults; manual review required')
            except (OSError, UnicodeError):
                problems.append('Cannot read configuration or reference; manual review required')
    hooks_path = target / '.codex/hooks.json'
    if hooks_path.is_file():
        try:
            if hooks_path.resolve() != hooks_path.absolute():
                problems.append('Symlinked hooks.json requires manual review')
            else:
                problems.extend(check_hooks(json.loads(hooks_path.read_text(encoding='utf-8')), target))
        except (ValueError, KeyError, TypeError, AttributeError):
            problems.append('Invalid hooks.json structure')
    git = shutil.which('git')
    if git:
        probe = subprocess.run([git, '-C', str(target), 'rev-parse', '--show-toplevel'],
                               capture_output=True)
        if not probe.returncode:
            # Only index filenames are inspected; never open secret contents.
            tracked = subprocess.run([git, '-C', str(target), 'ls-files', '-z', '--cached'],
                                     capture_output=True)
            if tracked.returncode:
                problems.append('Git tracking could not be checked')
            else:
                names = [item.decode('utf-8', errors='surrogateescape')
                         for item in tracked.stdout.split(b'\x00') if item]
                if any(name == '.business' or name.startswith('.business/') for name in names):
                    problems.append('.business is tracked by Git')
                for name in names:
                    if secret_filename(name):
                        problems.append('Secret filename tracked by Git: ' + repr(name))
            for name in ('.business/INDEX.md', '.env', '.env.local'):
                ignored = subprocess.run([git, '-C', str(target), 'check-ignore', '--quiet', '--no-index', name])
                if ignored.returncode:
                    problems.append('Not ignored by Git: ' + name)
        else:
            print('INFO: no Git repository; review .gitignore when initializing Git.')
    else:
        problems.append('Git is unavailable; tracking and ignore protection cannot be checked')
    print('INFO: hooks are not executed; native trust and runtime activation are NOT checked.')
    print('INFO: config must match the shipped default apart from blank/comment lines; custom settings require manual review.')
    print('INFO: this does not validate the full Codex schema, interpreter identity or effective runtime permissions.')
    for problem in problems:
        print('FAIL: ' + problem)
    if not problems:
        print('OK: installed files, hook paths and expected defaults passed these static checks.')
    return 1 if problems else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', metavar='PATH')
    args = parser.parse_args()
    target = Path(args.path).expanduser().resolve()
    if not target.is_dir():
        print('FAIL: project directory does not exist', file=sys.stderr)
        return 1
    try:
        return check(target)
    except OSError as exc:
        print('FAIL: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
