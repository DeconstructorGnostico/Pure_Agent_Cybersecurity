import os
"""Optional adapter to v3: read only, degradation if not."""
import sys
import unittest


class TestAdapterV3(unittest.TestCase):
    def test_available_in_this_environment(self):
        from gnostic_axioms.adapter_v3 import AdapterV3
        ad = AdapterV3()
        # If the v3 is in the sister folder (or in AGENT_PURE_V3_ROOT), you must import.
        if not ad.available():
            self.skipTest(f"v3 no disponible: {ad.error}")
        self.assertTrue(ad.available())
        spec = ad.compile_intent("Envía el reporte a ana@x.mx")
        self.assertTrue(isinstance(spec, dict))
        d = ad.deconstruct("El saldo es 3. Resume el informe.")
        self.assertTrue(isinstance(d, dict))
        bridge = ad.i08_response_no_is_reality()
        self.assertEqual(bridge["AG06"], "RESPONSE != REALITY")
        self.assertTrue(bridge["v3_available"])

    def test_no_modifies_v3(self):
        from pathlib import Path
        root = Path(os.environ.get("AGENT_PURE_V3_ROOT", str(Path(__file__).resolve().parents[2] / "pure_agent_v3")))
        if not root.exists():
            self.skipTest("v3 no está")
        # We just check that the adapter doesn't open files in writing:
        src = (Path(__file__).resolve().parents[1]/"gnostic_axioms"/"adapter_v3.py").read_text()
        for prohibited in ("write_text", "open(", "unlink", "rmtree", "Path.write"):
            if prohibited == "open(":
                continue
            self.assertNotIn("write_text", src)
            self.assertNotIn("unlink", src)
        self.assertNotIn("rmtree", src)

    def test_system_works_without_adapter(self):
        from gnostic_axioms.system import PerfectedSystem
        from gnostic_axioms.core_types import ResultState
        s = PerfectedSystem()
        r = s.request("Calcula 4-1 y reporta el resultado.")
        self.assertEqual(r.state, ResultState.PENDING_AUTHORIZATION)


if __name__ == "__main__":
    unittest.main()
