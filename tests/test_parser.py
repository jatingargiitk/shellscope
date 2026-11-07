import os
import tempfile
import unittest
from pathlib import Path

from shellscope.parser import parse_command


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.cwd = "/tmp/shellscope-test-cwd"

    def kinds(self, cmd):
        r = parse_command(cmd, cwd=self.cwd)
        return [(e.kind, e.target) for e in r.effects]

    def test_simple_rm(self):
        effects = self.kinds("rm -rf /tmp/foo")
        self.assertIn(("binary", "rm"), effects)
        self.assertTrue(any(k == "delete" and t.endswith("/tmp/foo") for k, t in effects))

    def test_pipeline_and_redirect(self):
        r = parse_command("cat notes.txt | grep secret > /tmp/out.txt", cwd=self.cwd)
        kinds = {e.kind for e in r.effects}
        self.assertIn("read", kinds)
        self.assertIn("write", kinds)
        self.assertTrue(any(e.kind == "write" and e.target.endswith("/tmp/out.txt") for e in r.effects))

    def test_and_or_semicolon(self):
        r = parse_command("mkdir -p a && touch a/x ; rm a/x || true", cwd=self.cwd)
        self.assertGreaterEqual(len(r.statements), 2)
        kinds = [e.kind for e in r.effects]
        self.assertIn("write", kinds)
        self.assertIn("delete", kinds)

    def test_curl_network_and_output(self):
        r = parse_command("curl -s https://example.com/a -o /tmp/a.html", cwd=self.cwd)
        self.assertTrue(any(e.kind == "network" and e.target == "example.com" for e in r.effects))
        self.assertTrue(any(e.kind == "write" and e.target.endswith("/tmp/a.html") for e in r.effects))

    def test_tilde_and_relative(self):
        r = parse_command("cat ~/.ssh/id_rsa", cwd=self.cwd)
        self.assertTrue(any(e.kind == "read" and ".ssh" in e.target for e in r.effects))
        r2 = parse_command("cat .env", cwd=self.cwd)
        self.assertTrue(any(e.kind == "read" and e.target.endswith("/.env") for e in r2.effects))

    def test_mv_cp(self):
        r = parse_command("mv src.txt dst.txt", cwd=self.cwd)
        self.assertTrue(any(e.kind == "delete" and e.target.endswith("src.txt") for e in r.effects))
        self.assertTrue(any(e.kind == "write" and e.target.endswith("dst.txt") for e in r.effects))
        r2 = parse_command("cp a b", cwd=self.cwd)
        self.assertTrue(any(e.kind == "read" and e.target.endswith("/a") for e in r2.effects))
        self.assertTrue(any(e.kind == "write" and e.target.endswith("/b") for e in r2.effects))

    def test_sudo_wrapper(self):
        r = parse_command("sudo rm -rf /var/tmp/x", cwd=self.cwd)
        bins = [e.target for e in r.effects if e.kind == "binary"]
        self.assertIn("sudo", bins)
        self.assertIn("rm", bins)

    def test_substitution_warning(self):
        r = parse_command("echo $(cat /etc/passwd)", cwd=self.cwd)
        self.assertTrue(any("substitution" in w for w in r.warnings))

    def test_chmod_write(self):
        r = parse_command("chmod 777 secret.env", cwd=self.cwd)
        self.assertTrue(any(e.kind == "write" and "secret.env" in e.target for e in r.effects))

    def test_nc_ssh(self):
        r = parse_command("nc 10.0.0.1 4444", cwd=self.cwd)
        self.assertTrue(any(e.kind == "network" and e.target == "10.0.0.1" for e in r.effects))
        r2 = parse_command("ssh user@host.example", cwd=self.cwd)
        self.assertTrue(any(e.kind == "network" and e.target == "host.example" for e in r2.effects))


if __name__ == "__main__":
    unittest.main()
