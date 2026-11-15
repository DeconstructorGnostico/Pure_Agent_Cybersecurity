# About this English edition

- Original (Spanish): https://github.com/DeconstructorGnostico/Agente_Puro_Cybersecurity. It was not modified.
- Version: 1.2.0. Behavior is meant to match the Spanish version exactly.
- Tests: Spanish original unittest: 187 tests, OK (3 skipped); English edition unittest: 187 tests, OK (3 skipped).
- Checked for equivalence: same pass/fail on every test, plus identical demo and benchmark/evaluation results case by case where the project has them.

## Stays in Spanish (by design)

`source.txt`, evaluation banks (`eval/bank*.py`: main 354, held-out 316, held-out 2 325 cases; Spanish-by-design so results stay comparable with 1.2), detector/attack patterns, fact base and lexicons (bilingual by design), demo input sentences and case titles.

These are inputs the system is evaluated on, or bilingual detection data. Translating them would change the published numbers.

## Not included

`benchmark/comparativa_v12.png` (binary; regenerate with `python benchmark/graph_v12.py`, which writes `benchmark/comparative_v12.png`; needs matplotlib).

## Freeze hashes (English edition)

SHA-256 over the package's `*.py` files concatenated in alphabetical order:

- `pure_agent_cyber/*.py`: `0d723ab71cee124c280a5d485d4ebf10d5888a613dcf7783413e4e2e596852c3`
- `gnostic_axioms/*.py`: `8baac096cdc5982d5f2966ae1ff1d78ad6b0d573261c694e8d1ec0f46966877b`
