"""Integration: demo, CLI and full flow."""
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from gnostic_axioms import PerfectedSystem, VERSION
from gnostic_axioms.__main__ import main
from gnostic_axioms.demo import run
from gnostic_axioms.core_types import ResultState


class TestDemo(unittest.TestCase):
    def test_seven_cases_ok(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            log = run(silent=False)
        self.assertEqual(len(log), 7)
        failures = [x for x in log if not x["ok"]]
        self.assertEqual(failures, [], msg=f"fallaron: {failures}\n{buf.getvalue()}")

    def test_demo_cli(self):
        self.assertEqual(main(["--demo"]), 0)

    def test_cli_input_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--input", "Calcula 2+2 y reporta el resultado.", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["state"], "PENDING_AUTHORIZATION")
        self.assertTrue(data["orders"])

    def test_cli_without_args_help(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([])
        self.assertEqual(rc, 2)

    def test_cli_need_input(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--input", "Envía el reporte"])
        self.assertEqual(rc, 0)
        self.assertIn("NEED_INPUT", buf.getvalue() + "datum")

    def test_flow_authorize_execute(self):
        s = PerfectedSystem()
        r = s.request("Calcula 10/2 y reporta el resultado.")
        facts = s.authorize_and_execute(r)
        self.assertEqual(facts[0]["value_"], 5)
        self.assertTrue(s.peace())
        self.assertTrue(s.audit.verify())

    def test_version(self):
        self.assertTrue(VERSION)

    def test_package_no_matters_v3_to_start(self):
        import gnostic_axioms as m
        import sys
        # another test may have already imported v3; what matters is that
        # gnostic_axioms.system does not depend on it in its module.
        import gnostic_axioms.system as sis
        self.assertNotIn("pure_agent_v3", getattr(sis, "__dict__", {}))
        src = Path(sis.__file__).read_text(encoding="utf-8")
        self.assertNotIn("pure_agent_v3", src)


if __name__ == "__main__":
    unittest.main()
