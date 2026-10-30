"""Regression checks for false-green diagnostics; fixtures contain no secrets."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("starter_doctor", ROOT / "scripts/doctor.py")
doctor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctor)


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.target = Path(self.temporary.name).resolve() / "project"
        self.target.mkdir()
        for name in ('AGENTS.md', 'PROJECT.md', '.starter/workflow.md',
                     '.starter/AUTOPILOT.md', '.codex/rules/starter.rules',
                     '.codex/hooks/security.py', '.codex/hooks/session_start.py',
                     '.codex/hooks/notify.py'):
            path = self.target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('# Fixture\n')
        (self.target / '.codex/config.toml').write_bytes((ROOT / 'payload/.codex/config.toml').read_bytes())
        self.hooks = {}
        for event, script in (('PreToolUse', 'security.py'), ('SessionStart', 'session_start.py')):
            group = {'hooks': [{'type': 'command', 'command': shlex.join([
                sys.executable, '-B', str(self.target / '.codex/hooks' / script)])}]}
            if event == 'PreToolUse':
                group['matcher'] = '.*'
            self.hooks[event] = [group]
        self.write_hooks()
        (self.target / '.gitignore').write_text('/.business/\n.env\n.env.*\n!.env.example\n')

    def write_hooks(self):
        (self.target / '.codex/hooks.json').write_text(json.dumps({'hooks': self.hooks}))

    def check(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            result = doctor.check(self.target)
        return result, stream.getvalue()

    def test_stock_install_passes_but_does_not_claim_trust(self):
        result, output = self.check()
        self.assertEqual(result, 0, output)
        self.assertIn('NOT checked', output)

    def test_empty_hook_handlers_fail(self):
        self.hooks['PreToolUse'][0]['hooks'] = []
        self.hooks['SessionStart'][0]['hooks'] = []
        self.write_hooks()
        self.assertEqual(self.check()[0], 1)

    def test_nested_safe_profile_does_not_hide_unsafe_root(self):
        (self.target / '.codex/config.toml').write_text('''approval_policy = "never"
sandbox_mode = "danger-full-access"
[profiles.safe]
approval_policy = "on-request"
sandbox_mode = "workspace-write"
network_access = false
''')
        result, output = self.check()
        self.assertEqual(result, 1, output)

    def test_comments_and_blank_lines_do_not_change_stock_config(self):
        path = self.target / '.codex/config.toml'
        path.write_text('# Extra full-line comment\n\n' + path.read_text() + '\n# End\n')
        self.assertEqual(self.check()[0], 0)

    def test_custom_config_is_manual_review_not_false_green(self):
        path = self.target / '.codex/config.toml'
        path.write_text('model = "custom-model"\n' + path.read_text())
        result, output = self.check()
        self.assertEqual(result, 1)
        self.assertIn('manual review', output.lower())

    def test_wrong_known_script_mapping_fails(self):
        self.hooks['PreToolUse'][0]['hooks'][0]['command'] = shlex.join([
            sys.executable, '-B', str(self.target / '.codex/hooks/notify.py')])
        self.write_hooks()
        self.assertEqual(self.check()[0], 1)

    def test_hook_command_shape_and_type_fail(self):
        handler = self.hooks['PreToolUse'][0]['hooks'][0]
        for field, value in (('command', ''), ('command', 'python3 script.py'),
                             ('command', '"unclosed'), ('type', 'prompt'),
                             ('enabled', False)):
            with self.subTest(field=field, value=value):
                original = handler.copy()
                handler[field] = value
                self.write_hooks()
                self.assertEqual(self.check()[0], 1)
                handler.clear()
                handler.update(original)

    def test_malformed_hook_types_fail_without_crashing(self):
        bad = (None, [], 'bad', {'PreToolUse': [None]}, {'PreToolUse': 'bad'},
               {'PreToolUse': [{'hooks': 'bad'}]},
               {'PreToolUse': [{'hooks': [None]}]},
               {'PreToolUse': [{'hooks': [{'type': 'command', 'command': []}]}]})
        for value in bad:
            with self.subTest(value=value):
                self.hooks = value
                self.write_hooks()
                self.assertEqual(self.check()[0], 1)

    def test_different_matcher_is_manual_review(self):
        self.hooks['PreToolUse'][0]['matcher'] = '^never$'
        self.write_hooks()
        self.assertEqual(self.check()[0], 1)

    @unittest.skipUnless(shutil.which('git'), 'Git required')
    def test_tracked_secret_names_fail_even_when_ignored(self):
        subprocess.run(['git', 'init', '-q', str(self.target)], check=True)
        for name in ('.env', '.env.local', '.env.production', 'nested/.env.test'):
            path = self.target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('PLACEHOLDER=fixture\n')
            subprocess.run(['git', '-C', str(self.target), 'add', '-f', '--', name], check=True)
            result, output = self.check()
            self.assertEqual(result, 1, output)
            self.assertIn('tracked', output.lower())
            subprocess.run(['git', '-C', str(self.target), 'rm', '--cached', '--', name],
                           check=True, capture_output=True)

    @unittest.skipUnless(shutil.which('git'), 'Git required')
    def test_tracked_env_example_allowed(self):
        subprocess.run(['git', 'init', '-q', str(self.target)], check=True)
        (self.target / '.env.example').write_text('PLACEHOLDER=example\n')
        subprocess.run(['git', '-C', str(self.target), 'add', '--', '.env.example'], check=True)
        result, output = self.check()
        self.assertEqual(result, 0, output)


if __name__ == '__main__':
    unittest.main()
