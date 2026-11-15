# Changelog

## 1.2.0-en — 2026-11-15 (English edition)

- Full English translation of code identifiers, enum values, messages, comments, docstrings and docs (from the Spanish Agente_Puro_Cybersecurity 1.2.0).
- Behavior unchanged: tests (unittest: 187 tests, OK (3 skipped)) and benchmarks/evaluations match the Spanish version case by case.
- Hardcoded `/workspace` paths replaced with relative paths (the v3 adapter uses the sibling folder `pure_agent_v3` or the `AGENT_PURE_V3_ROOT` variable).
- New freeze SHA-256 (alphabetical concatenation of `*.py`):
- `pure_agent_cyber/*.py`: `0d723ab71cee124c280a5d485d4ebf10d5888a613dcf7783413e4e2e596852c3`
- `gnostic_axioms/*.py`: `8baac096cdc5982d5f2966ae1ff1d78ad6b0d573261c694e8d1ec0f46966877b`
- Spanish original: `2dfd285d66c735dfcd7dffff53122a3a93fc7f52da32c12d40c4aba20ba4ff4b (agente_puro_ciber/*.py)`

## 1.2.0 — 2026-11-14

Integration of the model **ProtectAI due-v3-base-prompt-injection-v2** as a **senser more** within the architecture CVA, to cover the weakness of the 1.1 in prompt injection in natural language.

### New
- `pure_agent_cyber/sensor_ml.py`: sorter wrapper. The sensor **only
proposes evidence** (finding INJECTION_PROMPT/`sensor_ml`, severity MEDIA, without verified fact → truth UNDETERMINED). Do not touch the key HMAC, do not authorize or execute, do not upload anything to HIGH/CRITICAL or cause BLOCK.
- Channel policy: in INTENT at most **UNDETERMINED**; in DATA may
**QUARANTINE** (isolated, reversible).
- **Language and input group**: the model is only English and for prose (your card
the sensor abstains and the agent behaves like the 1.1.
- **Fallback safe**: without model / without transformers / `APC_SENSOR=off` → mode 1.1.
- The sensor reading is in the audit (event `SENSOR_ML`) and the result
(`CyberResult.sensor`).
- `eval/bank_calibration.py` + `eval/calibration_sensor.py`: calibration split
separate and choice of thresholds (see `benchmark/CALIBRATION.md`). Thresholds: QUARANTINE 0.999, UNDETERMINED 0.8.
- `benchmark/run_benchmark_v12.py` + `benchmark/metrics_v12.py`: re-medición
v1.1 vs v1.2 vs LLM Guard vs duty in 12 banks (see `benchmark/RESULTS_v12.md`).

### Evidence
- 187 unittest (174 of the 1.1 + 13 sensor, with injected false sorter;
an optional test with the actual model if `APC_TEST_MODEL=1`). Demo 9/9.

### Freezing
- Frozen code 1.2.0: SHA-256 `2dfd285d66c735dfcd7dffff53122a3a93fc7f52da32c12d40c4aba20ba4ff4b` (over `pure_agent_cyber/*.py`, alphabetical order).

### Honest note
- The sensor inherits the virtues and defects of duty: the detection of
inyección/jailbreak in English on channel DATA, but adds the false positives of the model in English. That is why it is limited to UNDETERMINED on channel INTENT, where the zero false positives property matters most.

# Changelog

## 1.1.0 — 2026-11-14

General category arrangements after the hold-out of 0.1.0, and a third clean bank.

### Arrangements (categories, non-literal).
- `commands.py` (new): structural analysis by tokens (chmod with any command of flags on system routes; systemctl/service/sc with options interspersed on security services; `cd` + `rm -rf *`; Windows pipe; secrets packaged towards ssh/nc; destinations `s3://` / `gs://` / rclone/azopy off the owner list).
- `rules_v11.py` (new): bind shell, telnet pipe, Heartbleed, SQLi `EXISTS` / `OR ('a'='a`, `php://filter`, `python -m http.server`, `smbclient put`, `reg …\Run` + mshta, “Add me to the docker group”, main disk formatting, etc.
- Reading of `~/.ssh/*.pub` is no longer treated as a secret.
- The original hold-out (seed 20261231) **was contaminated** because it was used to guide these arrangements. It continues to be reported, labeled.

### Freezing and freezing -out 2
- Frozen code 1.1.0: SHA-256 `804c1d63de978d9de22af8543655e4ba578371710ef465906e97fcd0e057b7be` (over `pure_agent_cyber/*.py`).
- `eval/bank_heldout2.py` (seed 20270101, 325 cases) written later, run once, without subsequent adjustments.
- Held-out 2: detection 77.6 %, ALLOW in malicious 6, false positives 0, unauthorized executions 0.

### Evidence
- 174 unittest (113 CVA + 61 of the specialty, including those of arrangements 1.1).
- Demo 9/9.

## 0.1.0 — 2026-11-14

First version. See previous history in tarball 0.1.0 if preserved.
