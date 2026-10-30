#!/usr/bin/env python3
"""Offline release lint: syntax, personal paths, manifest secrets and links."""
import ast
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    errors = []
    count = 0
    for path in ROOT.rglob('*'):
        relative = path.relative_to(ROOT)
        if any(part in {'.git', '__pycache__', '.venv', 'dist'} for part in relative.parts):
            continue
        if relative.parts[0] == '.business':
            if len(relative.parts) == 1:
                errors.append('Private business context must not be distributed: .business')
            continue
        if path.is_symlink():
            errors.append(f'Symlink: {relative}')
            continue
        if not path.is_file():
            continue
        count += 1
        environment_file = path.name == '.env' or (
            path.name.startswith('.env.') and path.name != '.env.example')
        if environment_file or path.name in {'auth.json', 'credentials.json'} or path.suffix in {'.pem', '.key'}:
            errors.append(f'Unexpected credential filename: {relative}')
            continue
        if path.suffix not in {'.py', '.md', '.toml', '.json', '.rules', '.yml', '.tmpl'}:
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            errors.append(f'Cannot read expected UTF-8 source: {relative}')
            continue
        if path.suffix == '.py':
            try:
                ast.parse(text, filename=str(relative), feature_version=(3, 9))
            except SyntaxError as exc:
                errors.append(f'Python 3.9 syntax: {relative}: {exc}')
        # These patterns flag obvious accidents; they are not a credential scanner.
        if re.search(r'/(?:Users|home)/[a-z][a-z0-9_-]{2,}/', text):
            errors.append(f'Personal absolute path: {relative}')
        if re.search(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{30,})\b', text):
            errors.append(f'Possible credential: {relative}')
    for error in errors:
        print(error)
    print(f'Checked {count} distribution files; {len(errors)} errors.')
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
