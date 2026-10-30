import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CodexInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.target = self.root / "project with spaces and ' quote"
        self.target.mkdir()

    def run_install(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/install_codex.py'),
                               str(self.target), *args], capture_output=True, text=True)

    def snapshot(self):
        return {str(p.relative_to(self.target)): p.read_bytes()
                for p in self.target.rglob('*') if p.is_file()}

    def test_dry_run_writes_nothing(self):
        result = self.run_install('--business', '--sounds')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_source_target_overlap_refused(self):
        for target in (ROOT, ROOT / 'payload', ROOT.parent):
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/install_codex.py'),
                                     str(target)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('non-overlapping', result.stderr)

    def test_late_hook_conflict_before_any_write(self):
        (self.target / '.codex').mkdir()
        (self.target / '.codex/hooks.json').write_text('{"custom": true}\n')
        before = self.snapshot()
        result = self.run_install('--apply', '--business')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing overwrite', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_full_install_and_idempotence(self):
        result = self.run_install('--apply', '--business', '--sounds', '--agent', 'both')
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('AGENTS.md', 'CLAUDE.md', 'PROJECT.md', '.codex/config.toml',
                     '.codex/hooks/security.py', '.codex/hooks.json',
                     '.starter/workflow.md', '.starter/AUTOPILOT.md', '.starter/LICENSE',
                     '.agents/skills/start-project/SKILL.md', 'prompts/INDEX.md',
                     '.business/company/README.md'):
            self.assertTrue((self.target / name).is_file(), name)
        hooks = json.loads((self.target / '.codex/hooks.json').read_text())['hooks']
        self.assertEqual(set(hooks), {'PreToolUse', 'SessionStart', 'Stop', 'PermissionRequest'})
        before = self.snapshot()
        again = self.run_install('--apply', '--business', '--sounds', '--agent', 'both')
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(before, self.snapshot())

    def test_hook_command_works_in_nested_folder_with_quoted_path(self):
        result = self.run_install('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        nested = self.target / 'src'
        nested.mkdir()
        hooks = json.loads((self.target / '.codex/hooks.json').read_text())['hooks']
        command = hooks['PreToolUse'][0]['hooks'][0]['command']
        event = {'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                 'tool_input': {'command': 'printf CODEX_STARTER_SECURITY_TEST_DENY'}}
        check = subprocess.run(command, shell=True, cwd=nested, input=json.dumps(event),
                               capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertEqual(json.loads(check.stdout)['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_conflicting_config_no_partial_write(self):
        (self.target / '.codex').mkdir()
        (self.target / '.codex/config.toml').write_text('model = "my-model"\n')
        before = self.snapshot()
        result = self.run_install('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_symlink_asset_rejected_before_writes(self):
        (self.target / '.codex').symlink_to(self.root / 'outside', target_is_directory=True)
        result = self.run_install('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'outside').exists())
        self.assertEqual(len(list(self.target.iterdir())), 1)

    def test_existing_instructions_and_project_preserved(self):
        (self.target / 'AGENTS.md').write_text('Existing project rules\n')
        (self.target / 'PROJECT.md').write_text('Real product and architecture\n')
        result = self.run_install('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.target / 'AGENTS.md').read_text().startswith('Existing project rules\n'))
        self.assertEqual((self.target / 'PROJECT.md').read_text(), 'Real product and architecture\n')
        self.assertFalse((self.target / 'CLAUDE.md').exists())

    def test_existing_context_not_expanded_or_duplicated(self):
        (self.target / 'business').mkdir()
        (self.target / 'business/INDEX.md').write_text('Existing context')
        result = self.run_install('--business', '--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.target / '.business').exists())

    def test_privacy_ignore_rules_and_default_settings(self):
        subprocess.run(['git', 'init', '-q', str(self.target)], check=True)
        (self.target / '.gitignore').write_text('!.env\n!/.business/\n')
        result = self.run_install('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('.env', '.env.local', '.business/INDEX.md'):
            check = subprocess.run(['git', '-C', str(self.target), 'check-ignore', '--quiet', name])
            self.assertEqual(check.returncode, 0, name)
        settings = (self.target / '.codex/config.toml').read_text()
        self.assertIn('sandbox_mode = "workspace-write"', settings)
        self.assertIn('approval_policy = "on-request"', settings)
        self.assertIn('network_access = false', settings)
        hooks = json.loads((self.target / '.codex/hooks.json').read_text())['hooks']
        self.assertEqual(set(hooks), {'PreToolUse', 'SessionStart'})


if __name__ == '__main__':
    unittest.main()
