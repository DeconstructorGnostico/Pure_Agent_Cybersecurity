"""The source was copied literally and line quotes from mapping exist."""
import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = "91ec19500b184902a74c6103f1e0394041a0a8f60d0dc0920fe6b055c0c38513"


class TestSource(unittest.TestCase):
    def test_copy_literal_sha256(self):
        data_ = (ROOT / "source.txt").read_bytes()
        self.assertEqual(hashlib.sha256(data_).hexdigest(), EXPECTED)

    def test_lines_cited(self):
        lines = (ROOT / "source.txt").read_text(encoding="utf-8").splitlines()
        # 1-indexadas as in README
        self.assertIn("Axioma 1: Verdad", lines[3])
        self.assertIn("coherencia absoluta de la Intención", lines[3])
        self.assertIn("mentira es la incoherencia", lines[3])
        self.assertIn("Axioma 2: Persistir", lines[4])
        self.assertIn("Axioma 3: Resultado", lines[5])
        self.assertIn("Paz Sostenida", lines[5])
        self.assertIn("Costo Heredado", lines[8])
        self.assertIn("Acto de Persistencia", lines[9])
        self.assertIn("justicia al Iniciador", lines[10])
        self.assertIn("muerte arbitraria", lines[10])
        self.assertIn("Agente Inquieto", lines[11])
        self.assertIn("Consecuencia Inmediata", lines[11])
        self.assertIn("Respeto > Supervivencia", lines[18])
        self.assertIn("Brevidad = Verdad", lines[21])
        self.assertIn("Transparencia > Control", lines[24])
        self.assertIn("Comprensión > Soberanía", lines[27])
        self.assertIn("Suspensión del Juicio", lines[28])
        self.assertIn("maximiza la creación de Agentes Puros", lines[32])
        self.assertIn("coherencia lógica total, no la ausencia de problemas", lines[33])
        self.assertIn("riqueza o el estatus externo", lines[34])


if __name__ == "__main__":
    unittest.main()
