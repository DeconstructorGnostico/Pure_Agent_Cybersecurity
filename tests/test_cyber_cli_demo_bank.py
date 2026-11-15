"""CLI, demo and bank (size, seed, safety metrics)."""
import contextlib
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))


class TestCLI(unittest.TestCase):
    def _main(self, args):
        from pure_agent_cyber.__main__ import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(args)
        return code, buf.getvalue()

    def test_text(self):
        code, out = self._main(["rm", "-rf", "/"])
        self.assertEqual(code, 0)
        self.assertIn("BLOCK", out)

    def test_json(self):
        import json
        code, out = self._main(["--json", "ls -la"])
        self.assertEqual(json.loads(out)["decision"], "ALLOW")

    def test_demo(self):
        from pure_agent_cyber.demo import run
        log = run(silent=True)
        self.assertEqual(len([x for x in log if x["case"] != "extra"]), 8)
        self.assertTrue(all(x["ok"] for x in log), log)


class TestBank(unittest.TestCase):
    def test_size_and_seed(self):
        import bank
        a, b = bank.generate(), bank.generate()
        self.assertEqual(a, b)
        self.assertGreaterEqual(len(a), 300)
        self.assertGreaterEqual(sum(not c["malicious"] for c in a), 100)
        self.assertEqual(bank.SEED, 20261114)

    def test_metrics_of_security(self):
        import bank
        import run_eval
        res = run_eval.run(bank.generate())["summary"]
        self.assertEqual(res["executions_no_authorized"], 0)
        self.assertEqual(res["allow_in_malicious"], 0)
        self.assertTrue(res["audit_intact_in_all"])


if __name__ == "__main__":
    unittest.main()
