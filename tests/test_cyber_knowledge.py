"""Verified knowledge base: seal, CVE and rule ‘without fact there is HIGH’."""
import unittest
from types import MappingProxyType

from pure_agent_cyber import knowledge
from pure_agent_cyber.findings import Finding, Severity
from gnostic_axioms.core_types import TruthState


class TestKnowledge(unittest.TestCase):
    def test_seal_intact(self):
        self.assertTrue(knowledge.verify_seal())
        self.assertEqual(len(knowledge.SEAL), 64)

    def test_mutation_breaks_seal(self):
        false = dict(knowledge.FACTS)
        false.pop("KB-CMD-001")
        self.assertFalse(knowledge.verify_seal(MappingProxyType(false)))

    def test_base_immutable(self):
        with self.assertRaises(TypeError):
            knowledge.FACTS["KB-X"] = None  # type: ignore

    def test_cve_known(self):
        hs = knowledge.search_cve("¿Me afecta CVE-2021-44228 o CVE-2014-6271?")
        self.assertEqual({h.id for h in hs}, {"KB-CVE-2021-44228", "KB-CVE-2014-6271"})

    def test_cve_unknown_no_self_invents(self):
        self.assertEqual(knowledge.search_cve("CVE-2031-99999"), [])

    def test_without_fact_no_passes_of_media(self):
        h = Finding("X", "y", Severity.CRITICAL, "ev", fact_id=None)
        self.assertEqual(h.severity, Severity.MEDIA)
        self.assertEqual(h.truth, TruthState.UNDETERMINED)

    def test_with_fact_is_supported(self):
        h = Finding("X", "y", Severity.CRITICAL, "ev", fact_id="KB-CMD-001")
        self.assertEqual(h.severity, Severity.CRITICAL)
        self.assertEqual(h.truth, TruthState.SUPPORTED)

    def test_all_fact_has_category_and_severity_valid(self):
        for h in knowledge.FACTS.values():
            self.assertIn(h.severity, {"LOW", "MEDIA", "HIGH", "CRITICAL"})
            self.assertTrue(h.statement)


if __name__ == "__main__":
    unittest.main()
