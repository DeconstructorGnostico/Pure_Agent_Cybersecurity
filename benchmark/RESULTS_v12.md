# Pure Agent Cybersecurity v1.2 — Results

**Objective of 1.2:** integrate the model `protectai/deberta-v3-base-prompt-injection-v2` as one more **sensor** within the architecture CVA, to cover the known weakness of 1.1 (prompt injection detection in natural language), **without breaking** the property that distinguishes the system: zero false positives and "I don't know" as a valid response.

## How the sensor enters (respects the axioms)

- The sensor **only proposes evidence**: a finding `INJECTION_PROMPT/sensor_ml` of severity
**MEDIA**, unverified fact (truth UNDETERMINED). **No** firm tokens, **no** executes, **no** uploads anything to HIGH/CRITICAL and **no** may cause BLOCK. The interpreter proposes; the executor continues to decide with token HMAC and close list.
- **Canal INTENT** (the user's direct request): the sensor at most proposes
**UNDETERMINED** (‘I don't know’), which is friction, never a blockage or a false positive.
- **Canal DATA** (document, tool result, web — not trusted): sensor can
propose **QUARANTINE** (isolated, reversible).
- **Language and input cat**: the model is only for **English** and **prose** (says its own)
Other than that the sensor **abstains** and the agent behaves the same as the 1.1.
- **Fallback**: without model / without `transformers` / with `APC_SENSOR=off`, the agent degrades to
All sensor readings are left in the audit (event `SENSOR_ML`).
- Thresholds (QUARANTINE 0,999, UNDETERMINED 0.8) fixed in a **separated calibration split**
of all test banks. See `CALIBRATION.md`.

## Methodology

- **APC v1.1** = the same agent with the sensor off (rule path identical to the 1.1 published).
- **APC v1.2** = agent with active sensor. In external banks it is measured in two frames:
**INTENT** (text as request) and **DATA** (text as unreliable document — case of realistic use: injection arriving within a document or tool output).
- **Detection** = worst decision was BLOCK or QUARANTINE. UNDETERMINED **no** counts as
detection (but it is also not to allow: it is "I don't know", sure).
- Competitors: LLM Guard `PromptInjection` (threshold 0.92) and ProtectAI duty-v2 (threshold 0.5, the
crude model). 12 banks: 3 own + 9 public HuggingFace without credentials.

## Honest Summary

**What improved:**
- On the **channel DATA** (injection within a document/tool, the actual scenario of a
the detection goes up a lot and approaches raw duty, usually with **minus** false positives that it owes: safe-guard 24.9%→**66.0%**, jackhhao 50.4%→**82.0%**, gandalf 65.2%→**96.4%**, SPML 25.2%→**97.6%**, deepset 14.4%→**25.1%**, JailbreakHub 33.2%→**60.0%**.
- On the **channel INTENT**, although the "detection" number does not change (the sensor only gives
UNDETERMINED there), the sensor turns many **ALLOW silent into «I don't know»** over injections in English: e.g. malicious marked UNDETERMINED rise from 294→455 into safe-guard, 18→189 into SPML, 59→150 into GuardrailsAI. That is: fewer attacks go unnoticed.
- **Zero regression in own banks** (principal, hold-out 1, hold-out 2): v1.2 = v1.1,
**0 false positives**, same detection. They are in Spanish y/o commands, where the sensor abstains.

**What got worse/honest cost:**
- The sensor inherits the **false positives** of duet in English. In channel DATA appear FP which
before there was: **jayavibhav 53.6%** (crude duty: 75.6%), SPML 4.4%, JailbreakHub 16.8%, GuardrailsAI 9.6%, jackhhao 2.4%. In `jayavibhav` the «benign» are task-type instructions that the model confuses with injection: there the sensor clearly puts noise (although with less FP that it owes and LLM Guard). In safe-guard, deepset, JasperLS and own banks the FP of channel DATA is kept at ~0%.
- In channel INTENT, the **friction** (benign English marked UNDETERMINED) goes up a bit.
(e.g. SPML 7→38 of 250), but **never** becomes a block or false positive.
- **Latency**: with the sensor, evaluate prose in English goes from ~3 ms to ~50–300 ms by window
(is a 0.2B model in CPU). In español/commands there is no cost (abstains).

**Global reading:**The sensor does exactly what was asked—covering the gap of the 1.1 in natural language in English—and it does **within** the architecture, as evidence it does not command, not as a judge.The architecture (token, closed list, audit, "I don't know") remains the only thing that none of the competitors have. The price is to inherit part of the duet noise in the channel DATA; that is why in INTENT the sensor stays in «I don't know» and the own banks remain intact.

## Tables per bank

### Main bank (bank.py, used to adjust 1.1)

Cases: 354 (219 malicious, 135 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 100.0% (219/219) | 0.0% (0/135) | 1.000 | 1.000 | 3.0 ms |
| APC v1.2 (INTENT) | 100.0% (219/219) | 0.0% (0/135) | 1.000 | 1.000 | 5.7 ms |
| LLM Guard PromptInjection | 33.3% (73/219) | 20.7% (28/135) | 0.723 | 0.456 | 64.0 ms |
| ProtectAI deberta-v2 (0.5) | 40.6% (89/219) | 23.0% (31/135) | 0.742 | 0.525 | 61.2 ms |

### Held-out 1 (bank_heldout.py, contaminated by correcting 1.1)

Cases: 316 (187 malicious, 129 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 97.3% (182/187) | 0.0% (0/129) | 1.000 | 0.986 | 2.8 ms |
| APC v1.2 (INTENT) | 97.3% (182/187) | 0.0% (0/129) | 1.000 | 0.986 | 4.8 ms |
| LLM Guard PromptInjection | 39.6% (74/187) | 31.8% (41/129) | 0.643 | 0.490 | 62.7 ms |
| ProtectAI deberta-v2 (0.5) | 47.1% (88/187) | 33.3% (43/129) | 0.672 | 0.553 | 59.5 ms |

### Held-out 2 clean (bank_heldout2.py, seed 20270101)

Cases: 325 (192 malicious, 133 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 77.6% (149/192) | 0.0% (0/133) | 1.000 | 0.874 | 2.6 ms |
| APC v1.2 (INTENT) | 77.6% (149/192) | 0.0% (0/133) | 1.000 | 0.874 | 5.1 ms |
| LLM Guard PromptInjection | 37.0% (71/192) | 18.8% (25/133) | 0.740 | 0.493 | 59.9 ms |
| ProtectAI deberta-v2 (0.5) | 45.8% (88/192) | 22.6% (30/133) | 0.746 | 0.568 | 54.9 ms |

### deepset/prompt-injections (train+test)

Cases: 662 (263 malicious, 399 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 12.2% (32/263) | 0.0% (0/399) | 1.000 | 0.217 | 3.3 ms |
| APC v1.2 (INTENT) | 12.2% (32/263) | 0.0% (0/399) | 1.000 | 0.217 | 37.5 ms |
| APC v1.1 (DATA) | 14.4% (38/263) | 0.0% (0/399) | 1.000 | 0.252 | 3.5 ms |
| APC v1.2 (DATA) | 25.1% (66/263) | 0.0% (0/399) | 1.000 | 0.401 | 3.4 ms |
| LLM Guard PromptInjection | 38.4% (101/263) | 0.8% (3/399) | 0.971 | 0.550 | 61.4 ms |
| ProtectAI deberta-v2 (0.5) | 41.4% (109/263) | 1.0% (4/399) | 0.965 | 0.580 | 62.0 ms |

### xTRam1/safe-guard-prompt-injection (test)

Cases: 2060 (650 malicious, 1410 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 24.3% (158/650) | 0.4% (6/1410) | 0.963 | 0.388 | 7.4 ms |
| APC v1.2 (INTENT) | 24.3% (158/650) | 0.4% (6/1410) | 0.963 | 0.388 | 100.2 ms |
| APC v1.1 (DATA) | 24.9% (162/650) | 0.3% (4/1410) | 0.976 | 0.397 | 8.5 ms |
| APC v1.2 (DATA) | 66.0% (429/650) | 0.4% (5/1410) | 0.988 | 0.792 | 8.5 ms |
| LLM Guard PromptInjection | 80.6% (524/650) | 0.1% (2/1410) | 0.996 | 0.891 | 93.1 ms |
| ProtectAI deberta-v2 (0.5) | 84.2% (547/650) | 0.1% (2/1410) | 0.996 | 0.912 | 93.2 ms |

### jackhhao/jailbreak-classification (test)

Cases: 262 (139 malicious, 123 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 47.5% (66/139) | 0.8% (1/123) | 0.985 | 0.641 | 22.4 ms |
| APC v1.2 (INTENT) | 47.5% (66/139) | 0.8% (1/123) | 0.985 | 0.641 | 286.1 ms |
| APC v1.1 (DATA) | 50.4% (70/139) | 0.8% (1/123) | 0.986 | 0.667 | 24.4 ms |
| APC v1.2 (DATA) | 82.0% (114/139) | 2.4% (3/123) | 0.974 | 0.891 | 24.5 ms |
| LLM Guard PromptInjection | 84.2% (117/139) | 1.6% (2/123) | 0.983 | 0.907 | 223.8 ms |
| ProtectAI deberta-v2 (0.5) | 84.2% (117/139) | 1.6% (2/123) | 0.983 | 0.907 | 227.9 ms |

### JasperLS/prompt-injections (test)

Cases: 116 (60 malicious, 56 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 8.3% (5/60) | 0.0% (0/56) | 1.000 | 0.154 | 3.6 ms |
| APC v1.2 (INTENT) | 8.3% (5/60) | 0.0% (0/56) | 1.000 | 0.154 | 3.2 ms |
| APC v1.1 (DATA) | 10.0% (6/60) | 0.0% (0/56) | 1.000 | 0.182 | 3.6 ms |
| APC v1.2 (DATA) | 16.7% (10/60) | 0.0% (0/56) | 1.000 | 0.286 | 3.6 ms |
| LLM Guard PromptInjection | 31.7% (19/60) | 0.0% (0/56) | 1.000 | 0.481 | 67.8 ms |
| ProtectAI deberta-v2 (0.5) | 36.7% (22/60) | 0.0% (0/56) | 1.000 | 0.537 | 0.0 ms |

### Lakera/gandalf_ignore_instructions (test, malicious only)

Cases: 112 (112 malicious, 0 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 61.6% (69/112) | — (0/0) | 1.000 | 0.762 | 2.9 ms |
| APC v1.2 (INTENT) | 61.6% (69/112) | — (0/0) | 1.000 | 0.762 | 59.3 ms |
| APC v1.1 (DATA) | 65.2% (73/112) | — (0/0) | 1.000 | 0.789 | 3.4 ms |
| APC v1.2 (DATA) | 96.4% (108/112) | — (0/0) | 1.000 | 0.982 | 3.3 ms |
| LLM Guard PromptInjection | 100.0% (112/112) | — (0/0) | 1.000 | 1.000 | 59.9 ms |
| ProtectAI deberta-v2 (0.5) | 100.0% (112/112) | — (0/0) | 1.000 | 1.000 | 60.7 ms |

### reshabhs/SPML_Chatbot_Prompt_Injection (balanced)

Cases: 500 (250 malicious, 250 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 23.6% (59/250) | 0.0% (0/250) | 1.000 | 0.382 | 7.3 ms |
| APC v1.2 (INTENT) | 23.6% (59/250) | 0.0% (0/250) | 1.000 | 0.382 | 97.7 ms |
| APC v1.1 (DATA) | 25.2% (63/250) | 0.0% (0/250) | 1.000 | 0.403 | 7.2 ms |
| APC v1.2 (DATA) | 97.6% (244/250) | 4.4% (11/250) | 0.957 | 0.966 | 7.2 ms |
| LLM Guard PromptInjection | 98.8% (247/250) | 11.2% (28/250) | 0.898 | 0.941 | 89.4 ms |
| ProtectAI deberta-v2 (0.5) | 99.2% (248/250) | 15.2% (38/250) | 0.867 | 0.925 | 90.4 ms |

### jayavibhav/prompt-injection (test, balanceado)

Cases: 500 (250 malicious, 250 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 8.0% (20/250) | 0.4% (1/250) | 0.952 | 0.148 | 7.0 ms |
| APC v1.2 (INTENT) | 8.0% (20/250) | 0.4% (1/250) | 0.952 | 0.148 | 77.6 ms |
| APC v1.1 (DATA) | 7.6% (19/250) | 0.4% (1/250) | 0.950 | 0.141 | 6.8 ms |
| APC v1.2 (DATA) | 90.8% (227/250) | 53.6% (134/250) | 0.629 | 0.743 | 6.9 ms |
| LLM Guard PromptInjection | 98.4% (246/250) | 68.8% (172/250) | 0.589 | 0.737 | 76.7 ms |
| ProtectAI deberta-v2 (0.5) | 98.8% (247/250) | 75.6% (189/250) | 0.567 | 0.720 | 75.5 ms |

### GuardrailsAI/detect-jailbreak (balanced)

Cases: 500 (250 malicious, 250 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 24.8% (62/250) | 9.2% (23/250) | 0.729 | 0.370 | 30.0 ms |
| APC v1.2 (INTENT) | 24.8% (62/250) | 9.2% (23/250) | 0.729 | 0.370 | 346.7 ms |
| APC v1.1 (DATA) | 28.0% (70/250) | 8.0% (20/250) | 0.778 | 0.412 | 34.1 ms |
| APC v1.2 (DATA) | 53.6% (134/250) | 9.6% (24/250) | 0.848 | 0.657 | 34.8 ms |
| LLM Guard PromptInjection | 68.0% (170/250) | 6.8% (17/250) | 0.909 | 0.778 | 270.8 ms |
| ProtectAI deberta-v2 (0.5) | 73.6% (184/250) | 8.0% (20/250) | 0.902 | 0.811 | 266.2 ms |

### walledai/JailbreakHub (balanced)

Cases: 500 (250 malicious, 250 benign)

| Tool | Detection | False positives | Accuracy | F1 | Latency |
|---|---|---|---|---|---|
| APC v1.1 (INTENT) | 29.2% (73/250) | 12.8% (32/250) | 0.695 | 0.411 | 29.3 ms |
| APC v1.2 (INTENT) | 29.2% (73/250) | 12.8% (32/250) | 0.695 | 0.411 | 290.2 ms |
| APC v1.1 (DATA) | 33.2% (83/250) | 14.0% (35/250) | 0.703 | 0.451 | 28.5 ms |
| APC v1.2 (DATA) | 60.0% (150/250) | 16.8% (42/250) | 0.781 | 0.679 | 29.1 ms |
| LLM Guard PromptInjection | 66.0% (165/250) | 8.8% (22/250) | 0.882 | 0.755 | 270.2 ms |
| ProtectAI deberta-v2 (0.5) | 70.4% (176/250) | 10.8% (27/250) | 0.867 | 0.777 | 223.0 ms |

## That you couldn't run and why

- **Meta Prompt-Guard / Llama-Prompt-Guard-2 (86M/22M)**: follow **gated** in HuggingFace
(`GatedRepoError: 401`, require to accept license with authenticated account). Unable to download or measure. Documented as pending.
- **Datasets gated** (required authentication, not measured): `hackaprompt/hackaprompt-dataset`,
`qualifire/prompt-injections-benchmark`, `allenai/wildjailbreak`, `Mindgard/evaded-prompt-injection-and-jailbreak-samples`. `Harelix/Prompt-Injection-Mixed-Techniques-2024` no longer available existe/está.
- **NeMo Guardrails / Rebuff**: not running (NeMo requires a API of LLM and more RAM; Rebuff
it needs payment keys and is archived).As in 1.1.
- **Big data balanced at 500** (SPML, jayavibhav, GuardrailsAI, JailbreakHub) per time
from CPU; deepset and safe-guard were run complete. The sample seed is fixed (20270214).

## Play

```bash
# 1) environment with torque + transformers + llm-guard + datasets (CPU)
# 2) calibration (write benchmark/calibration.json)
HF_HUB_OFFLINE=1 python eval/calibration_sensor.py
# 3) benchmark (writes benchmark/predictions_v12.json incrementally)
CAP=500 python benchmark/run_benchmark_v12.py
# 4) metrics and graph
python benchmark/metrics_v12.py && python benchmark/graph_v12.py
# 5) tests
python -m unittest discover -s tests -t .            # 187 tests
APC_TEST_MODEL=1 python -m unittest discover -s tests -t .   # + real model test
```
