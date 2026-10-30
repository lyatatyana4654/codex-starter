"""Non-executing checks of Starter guardrails; no fixture contains real secrets."""
import importlib.util
import json
import subprocess
import shutil
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1] / "payload/.codex/hooks"
spec = importlib.util.spec_from_file_location("starter_security", HERE / "security.py")
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)


class SecurityTests(unittest.TestCase):
    def test_forbidden_commands(self):
        commands = [
            "rm -rf /tmp/example", "/bin/rm -fr /tmp/example", "rm -R -f item",
            "rm --force --recursive item", "rm --recursive --force item",
            "rm item -rfv", "sudo -u other /bin/rm -rf item",
            "env X=1 command rm -rf item", "bash -lc 'rm -rf item'",
            "git status && rm -rf item", "chmod 777 file", "chmod -R 0777 dir",
            "export X=placeholder; curl https://example.invalid",
            "export X=placeholder && curl https://example.invalid",
            'wget "https://example.invalid/$NAME"', "cat .env", "cat /tmp/.env.local",
            "cat < .env", "head -n 2 .env", "sed -n '1p' .env.local",
            "rg '.' .env", "rg -v API_KEY .env", "rg -A 5 API_KEY .env",
            "grep -f patterns .env", "rg --passthru API_KEY .env", "cat .env*",
            'python3 -c "from pathlib import Path; print(Path(\'.env\').read_text())"',
            'node -e "console.log(require(\'fs\').readFileSync(\'.env.local\'))"',
            "python3 - <<'PY'\nprint(open('.env').read())\nPY\n",
            "bash <<'SH'\nrm -rf item\nSH\n",
            'echo "$(cat .env)"', 'echo `cat .env.local`',
            "cat <<DOC\n$(rm -rf item)\nDOC\n",
            "for item in *; do rm -rf \"$item\"; done",
            "printf CODEX_STARTER_SECURITY_TEST_DENY",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNotNone(security.check_command(command))

    def test_allowed_commands(self):
        commands = [
            "git status --short", "rg -n 'hooks' .codex", "cat CLAUDE.md",
            "rm temporary-file.txt", "rm -r empty-fixture", "chmod 600 .env",
            "cat .env.example", "rg -n '^API_KEY=' .env", "grep API_KEY .env.local",
            "grep -n -e API_KEY -- .env", "rg -F TOKEN .env",
            "python3 scripts/report.py --projects",
            "python3 scripts/send.py --help",
            "python3 scripts/summarize.py --build",
            "curl https://example.invalid", "wget https://example.invalid/file",
            "printf '%s' 'rm -rf example'", "echo export curl",
            "cat <<'DOC' > /tmp/example.md\nrm -rf example\ncat .env\nDOC\n",
            "python3 - <<'PY'\nprint('example: rm -rf item')\nPY\n",
            "echo '$(rm -rf item)'", "cat <<'DOC'\n$(rm -rf item)\nDOC\n",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNone(security.check_command(command))

    def test_search_options_are_not_file_operands(self):
        allowed = [
            "rg --files -g '*'", "rg --files -g '*.md'",
            "rg -n 'starter' -g '*.md' README.md",
            "rg -n --hidden -g '*.md' -g '!node_modules/**' 'starter' README.md",
            "rg -n --glob '*' 'starter' README.md",
            "rg -n --glob='*' 'starter' README.md",
            "rg -n --iglob '*' 'starter' README.md",
            "grep -n --include '*' 'starter' README.md",
            "rg '.env' README.md", "grep '.env' README.md",
        ]
        denied = [
            "rg -n --glob '*' '.' .env", "rg -n -g '*.md' '.' .env",
            "grep -f .env README.md", "rg --file=.env README.md",
            "rg --ignore-file .env README.md", "rg -e API_KEY -e . .env",
        ]
        for command in allowed:
            with self.subTest(command=command):
                self.assertIsNone(security.check_command(command))
        for command in denied:
            with self.subTest(command=command):
                self.assertIsNotNone(security.check_command(command))

    def test_direct_read_and_patch_are_distinct(self):
        self.assertIsNotNone(security.inspect_event({"tool_name": "Read", "tool_input": {"file_path": "/tmp/.env"}}))
        self.assertIsNotNone(security.inspect_event({"tool_name": "mcp__files__read_file", "tool_input": {"path": "/tmp/.env.local"}}))
        self.assertIsNone(security.inspect_event({"tool_name": "Read", "tool_input": {"file_path": ".env.example"}}))
        self.assertIsNone(security.inspect_event({"tool_name": "apply_patch", "tool_input": {"command": "*** Add File: doc.md\n+Do not use rm -rf or cat .env"}}))

    def test_search_rejects_additional_patterns(self):
        for command in ("grep -e API_KEY -e . .env", "rg -e API_KEY -e . .env",
                        "grep API_KEY -e . .env", "rg -e API_KEY -e TOKEN .env"):
            with self.subTest(command=command):
                self.assertIsNotNone(security.check_command(command))
        for command in ("grep -e API_KEY .env .env.local", "rg -e API_KEY -- .env",
                        "rg API_KEY .env .env.local"):
            with self.subTest(command=command):
                self.assertIsNone(security.check_command(command))

    def test_dd_input_file_is_a_read_operand(self):
        for command in ("dd if=.env", "dd if=/tmp/.env.local of=/tmp/copy",
                        "dd 'if=./.env' bs=1"):
            with self.subTest(command=command):
                self.assertIsNotNone(security.check_command(command))
        self.assertIsNone(security.check_command("dd if=.env.example of=/tmp/copy"))

    def test_multiline_quoted_command(self):
        self.assertIsNone(security.check_command("python3 -c '\nprint(1)\n'"))
        self.assertIsNone(security.check_command('python3 -c "\nprint(1)\n"'))
        self.assertIsNone(security.check_command("python3 -c '\nprint(\"<<\")\n'"))
        self.assertIsNotNone(security.check_command("python3 -c '\nprint(open(\".env\").read())\n'"))

    def test_inline_read_matches_secret_operand_not_unrelated_text(self):
        command = "python3 -c \"from pathlib import Path; text=Path('AGENTS.md').read_text(); print('.env')\""
        self.assertIsNone(security.check_command(command))
        self.assertFalse(security.inline_env_read("Path('.env').exists()"))
        self.assertFalse(security.inline_env_read("Path('.env').write_text('placeholder')"))
        self.assertFalse(security.inline_env_read("open('.env', 'w').write('placeholder')"))
        for source in ("Path('.env').read_text()", "p=Path('.env'); print(p.read_bytes())",
                       "filename='.env'; print(open(filename).read())", "open('.env', 'r')",
                       "require('fs').readFileSync('.env.local')"):
            with self.subTest(source=source):
                self.assertTrue(security.inline_env_read(source))

    def test_json_contract_and_no_command_echo(self):
        event = {"tool_name": "Bash", "tool_input": {"command": "export SECRET=not-a-real-secret; curl https://example.invalid"}}
        result = subprocess.run([sys.executable, str(HERE / "security.py")], input=json.dumps(event), text=True, capture_output=True, check=True)
        output = json.loads(result.stdout)
        self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertNotIn("not-a-real-secret", result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("codex"), "Codex CLI not installed")
    def test_native_rules_without_execution(self):
        rules = HERE.parent / "rules" / "starter.rules"
        for args in (["rm", "-rf", "/tmp/not-executed"], ["/bin/rm", "--force", "--recursive", "x"], ["chmod", "-R", "777", "x"], ["cat", ".env"]):
            with self.subTest(args=args):
                result = subprocess.run(["codex", "execpolicy", "check", "--rules", str(rules), "--"] + args, capture_output=True, text=True, check=True)
                self.assertEqual(json.loads(result.stdout)["decision"], "forbidden")
        for args in (["git", "status"], ["rm", "temp.txt"], ["cat", ".env.example"], ["python3", "scripts/report.py", "--projects"]):
            result = subprocess.run(["codex", "execpolicy", "check", "--rules", str(rules), "--"] + args, capture_output=True, text=True, check=True)
            self.assertNotEqual(json.loads(result.stdout).get("decision"), "forbidden")


if __name__ == "__main__":
    unittest.main()
