"""Hooks never inspect project secrets or grant tool permissions."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "payload/.codex/hooks"


def load(name):
    spec = importlib.util.spec_from_file_location("starter_" + name, HOOKS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HookTests(unittest.TestCase):
    def test_session_start_contract(self):
        event = {"hook_event_name": "SessionStart", "source": "startup",
                 "cwd": "/nonexistent", "transcript_path": "/nonexistent/private"}
        result = subprocess.run([sys.executable, str(HOOKS / "session_start.py")],
                                input=json.dumps(event), capture_output=True, text=True, check=True)
        payload = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(payload["hookEventName"], "SessionStart")
        for path in ("AGENTS.md", ".starter/workflow.md", "PROJECT.md"):
            self.assertIn(path, payload["additionalContext"])
        self.assertLess(len(payload["additionalContext"]), 1100)
        self.assertNotIn("private", result.stdout)

    def test_notify_noop_on_unsupported_platform(self):
        module = load("notify")
        with mock.patch.object(module.subprocess, "run") as run:
            module.notify({"hook_event_name": "PermissionRequest"}, platform="unsupported")
        run.assert_not_called()

    def test_notify_uses_literal_argv_and_no_shell(self):
        module = load("notify")
        with mock.patch.object(module.Path, "is_file", return_value=True), \
                mock.patch.object(module.subprocess, "run") as run:
            module.notify({"hook_event_name": "PermissionRequest", "tool_input": "$(malicious)"}, platform="darwin")
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/afplay")
        self.assertIn("Ping", argv[1])
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        self.assertNotIn("malicious", str(argv))

    def test_linux_sound_failure_is_advisory(self):
        module = load("notify")
        with mock.patch.object(module.shutil, "which", return_value="/usr/bin/paplay"), \
                mock.patch.object(module.Path, "is_file", return_value=True), \
                mock.patch.object(module.subprocess, "run", side_effect=OSError("no audio")):
            module.notify({"hook_event_name": "Stop"}, platform="linux")

    def test_no_player_does_not_run(self):
        module = load("notify")
        with mock.patch.object(module.shutil, "which", return_value=None), \
                mock.patch.object(module.subprocess, "run") as run:
            module.notify({"hook_event_name": "Stop"}, platform="linux")
        run.assert_not_called()

    def test_notify_json_never_approves_permission_request(self):
        module = load("notify")
        with mock.patch.object(module.sys, "stdin", __import__("io").StringIO('{"hook_event_name":"PermissionRequest"}')), \
                mock.patch.object(module, "notify"), \
                mock.patch("builtins.print") as output:
            module.main()
        self.assertEqual(json.loads(output.call_args.args[0]), {})

    def test_notify_malformed_event_is_noop(self):
        module = load("notify")
        with mock.patch.object(module.sys, "stdin", __import__("io").StringIO("invalid")), \
                mock.patch.object(module, "notify") as notify, \
                mock.patch("builtins.print") as output:
            module.main()
        notify.assert_not_called()
        self.assertEqual(json.loads(output.call_args.args[0]), {})


if __name__ == "__main__":
    unittest.main()
