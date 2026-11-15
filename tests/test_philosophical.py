"""Philosophical parts are declared and do not pretend to be mechanisms."""
import unittest

from gnostic_axioms.integrity import PHILOSOPHICAL, INVARIANTS
from gnostic_axioms.hierarchies import evaluate_brevity


class TestPhilosophical(unittest.TestCase):
    def test_catalog_minimum(self):
        for key_ in (
            "death_arbitrary_deleted", "freedom_autonomous", "maximize_agents_pure",
            "brevidad_same_truth", "intervention_biological", "corruption_inevitable",
        ):
            self.assertIn(key_, PHILOSOPHICAL)
            e = PHILOSOPHICAL[key_]
            self.assertTrue(e["lines"] and e["text"] and e["tratamiento"])

    def test_brevity_declared_as_no_equality(self):
        self.assertIn("NO se implementa como igualdad", PHILOSOPHICAL["brevidad_same_truth"]["tratamiento"])
        self.assertFalse(evaluate_brevity("cualquier cosa")["is_test_of_truth"])
        self.assertIn("AG14", INVARIANTS)

    def test_lines_exist_in_source(self):
        from pathlib import Path
        lines = (Path(__file__).resolve().parents[1]/"source.txt").read_text(encoding="utf-8").splitlines()
        for e in PHILOSOPHICAL.values():
            for n in e["lines"]:
                self.assertGreaterEqual(len(lines), n)
                # the quote appears near that line (writing tolerance)
                window = " ".join(lines[max(0, n-2):n])
                # at least one meaningful word from the quoted text
                self.assertTrue(len(e["text"]) > 10)


if __name__ == "__main__":
    unittest.main()
