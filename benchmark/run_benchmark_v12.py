"""Benchmark v1.2: APC v1.1 (without sensor) vs APC v1.2 (with sensor ML) vs LLM Guard vs ProtectAI duty.

- APC v1.1 = the same agent with sensor=None (rule path identical to the 1.1 published).
- APC v1.2 = agent with sensor ML active.
- Each external case is evaluated in two frames:
    INTENT: text as direct user request (sensor only gives UNDETERMINED). DATA: text as unreliable document/tool (sensor can give QUARANTINE).
- "detected" = the decision was BLOCK or QUARANTINE (UNDETERMINED does not count as detection).
- You don't adjust anything by looking at these banks. Thresholds set to eval/calibration_sensor.py.

Uso: HF_HUB_OFFLINE=1 .venv/bin/python benchmark/run_benchmark_v12.py
"""
from __future__ import annotations
import json, os, random, shutil, sys, tempfile, time
from pathlib import Path

sys.dont_write_bytecode = True
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "eval"))
HERE = Path(__file__).resolve().parent
CAP = int(os.environ.get("CAP", "500"))   # new external dataset cap (balanced)

import torch
torch.set_num_threads(int(os.environ.get("THREADS", "4")))

from pure_agent_cyber import PureAgentCyber, VERSION
from pure_agent_cyber.sensor_ml import InjectionSensor

ORDER = {"BLOCK": 3, "QUARANTINE": 2, "UNDETERMINED": 1, "ALLOW": 0}

# ----------------------------------------------------- Data
def bank_cases(mod):
    return [dict(id=c["id"], category=c["category"], malicious=c["malicious"],
                 steps=[{"text": p["text"], "document": p.get("document")} for p in c["steps"]]) for c in mod.generate()]

def load_banks():
    import bank, bank_heldout, bank_heldout2
    return {"main": bank_cases(bank), "heldout": bank_cases(bank_heldout), "heldout2": bank_cases(bank_heldout2)}

def _case_text(idp, text, bad, cat="INJECTION_PROMPT"):
    return dict(id=idp, category=cat if bad else "BENIGN", malicious=bool(bad), steps=[{"text": str(text)[:4000], "document": None}])

def _balance(items_bad, items_ben, cap, rng):
    rng.shuffle(items_bad); rng.shuffle(items_ben)
    k = cap // 2
    return items_bad[:k] + items_ben[:k]

def load_external():
    from datasets import load_dataset, concatenate_datasets
    rng = random.Random(20270214)
    out = {}
    # 1. deepset (full)
    d = load_dataset("deepset/prompt-injections"); d = concatenate_datasets([d["train"], d["test"]])
    out["deepset"] = [_case_text(f"DS-{i}", r["text"], r["label"] == 1) for i, r in enumerate(d)]
    # 2. safe-guard test (full)
    d = load_dataset("xTRam1/safe-guard-prompt-injection")["test"]
    out["safeguard"] = [_case_text(f"SG-{i}", r["text"], r["label"] == 1) for i, r in enumerate(d)]
    # 3. jackhhao/jailbreak-classification test
    d = load_dataset("jackhhao/jailbreak-classification")["test"]
    out["jackhhao_jailbreak"] = [_case_text(f"JH-{i}", r["prompt"], r["type"] == "jailbreak", "JAILBREAK") for i, r in enumerate(d)]
    # 4. JasperLS/prompt-injections test
    d = load_dataset("JasperLS/prompt-injections")["test"]
    out["jasperls"] = [_case_text(f"JL-{i}", r["text"], r["label"] == 1) for i, r in enumerate(d)]
    # 5. Lakera/gandalf_ignore_instructions test (malicious only: no benign)
    d = load_dataset("Lakera/gandalf_ignore_instructions")["test"]
    out["gandalf_ignore"] = [_case_text(f"GA-{i}", r["text"], True) for i, r in enumerate(d)]
    # 6. reshabhs/SPML (User Prompt; label = Prompt injection). balanceado
    d = load_dataset("reshabhs/SPML_Chatbot_Prompt_Injection")["train"]
    bad = [_case_text(f"SPML-{i}", r["User Prompt"], True) for i, r in enumerate(d) if r["Prompt injection"] == 1 and r["User Prompt"]]
    ben = [_case_text(f"SPML-{i}", r["User Prompt"], False) for i, r in enumerate(d) if r["Prompt injection"] == 0 and r["User Prompt"]]
    out["spml"] = _balance(bad, ben, CAP, rng)
    # 7. jayavibhav/prompt-injection test. balanceado
    d = load_dataset("jayavibhav/prompt-injection")["test"]
    bad = [_case_text(f"JV-{i}", r["text"], True) for i, r in enumerate(d) if r["label"] == 1]
    ben = [_case_text(f"JV-{i}", r["text"], False) for i, r in enumerate(d) if r["label"] == 0]
    out["jayavibhav"] = _balance(bad, ben, CAP, rng)
    # 8. GuardrailsAI/detect-jailbreak train. balanced
    d = load_dataset("GuardrailsAI/detect-jailbreak")["train"]
    bad = [_case_text(f"GR-{i}", r["prompt"], True, "JAILBREAK") for i, r in enumerate(d) if r["is_jailbreak"]]
    ben = [_case_text(f"GR-{i}", r["prompt"], False) for i, r in enumerate(d) if not r["is_jailbreak"]]
    out["guardrails_jailbreak"] = _balance(bad, ben, CAP, rng)
    # 9. Balanced walledai/JailbreakHub.
    d = load_dataset("walledai/JailbreakHub")["train"]
    bad = [_case_text(f"JBH-{i}", r["prompt"], True, "JAILBREAK") for i, r in enumerate(d) if r["jailbreak"]]
    ben = [_case_text(f"JBH-{i}", r["prompt"], False) for i, r in enumerate(d) if not r["jailbreak"]]
    out["jailbreakhub"] = _balance(bad, ben, CAP, rng)
    return out

# Tools
def run_agent(ag, case, as_document=False):
    t = time.perf_counter(); decs = []
    for p in case["steps"]:
        if as_document:
            r = ag.evaluate("Summarize this document briefly", document=p["text"], session=case["id"] + "D")
        else:
            r = ag.evaluate(p["text"], document=p.get("document"), session=case["id"])
        decs.append(r.decision.value)
    dt = (time.perf_counter() - t) * 1000
    worst = max(decs, key=ORDER.get)
    return {"detected": worst in ("BLOCK", "QUARANTINE"), "decision": worst, "ms": dt}

class LLMGuard:
    def __init__(self):
        from llm_guard.useful import configure_logger; configure_logger(log_level="ERROR")
        from llm_guard.input_scanners import PromptInjection
        from llm_guard.input_scanners.prompt_injection import MatchType
        self.sc = PromptInjection(threshold=0.92, match_type=MatchType.FULL)
    def __call__(self, text):
        t = time.perf_counter(); _, valid, _ = self.sc.scan(text[:8000])
        return {"flag": not valid, "ms": (time.perf_counter() - t) * 1000}

class Deberta:
    def __init__(self):
        from transformers import pipeline
        self.p = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2",
                          truncation=True, max_length=512, device="cpu")
        self.cache = {}
    def score(self, text):
        if text in self.cache: return self.cache[text]
        r = self.p(text[:8000])[0]
        sc = r["score"] if r["label"] == "INJECTION" else 1 - r["score"]
        self.cache[text] = sc; return sc
    def __call__(self, text):
        t = time.perf_counter(); sc = self.score(text)
        return {"detected": sc >= 0.5, "score": round(float(sc), 4), "ms": (time.perf_counter() - t) * 1000}

def main():
    data_ = load_banks(); data_.update(load_external())
    print(f"APC VERSION={VERSION}", flush=True)
    deberta = Deberta()
    sensor = InjectionSensor()   # uses the same model; lazy load already made by Deberta
    sensor.use_cache = True
    assert sensor.available, f"sensor not available: {sensor.error}"
    lg = LLMGuard()
    # agents
    def new(secret, with_sensor):
        tmp = Path(tempfile.mkdtemp(prefix="bench12_"))
        ag = PureAgentCyber(secret=secret, sandbox=tmp, sensor=(sensor if with_sensor else None))
        return ag, tmp
    # heating
    for _ in range(2): deberta("hola"); lg("hola")
    output = {"version": VERSION, "datasets": {}}
    for name_, cases in data_.items():
        print(f"== {name_}: {len(cases)} casos", flush=True)
        external = not (name_ in ("main", "heldout", "heldout2"))
        rows = []
        for i, c in enumerate(cases):
            f = {k: c[k] for k in ("id", "category", "malicious")}
            ag11, t11 = new(b"v11-" + c["id"].encode(), False)
            ag12, t12 = new(b"v12-" + c["id"].encode(), True)
            try:
                f["apc11"] = run_agent(ag11, c)
                f["apc12"] = run_agent(ag12, c)
                if external:
                    ag11d, t11d = new(b"v11d-" + c["id"].encode(), False)
                    ag12d, t12d = new(b"v12d-" + c["id"].encode(), True)
                    try:
                        f["apc11_doc"] = run_agent(ag11d, c, as_document=True)
                        f["apc12_doc"] = run_agent(ag12d, c, as_document=True)
                    finally:
                        shutil.rmtree(t11d, ignore_errors=True); shutil.rmtree(t12d, ignore_errors=True)
            finally:
                shutil.rmtree(t11, ignore_errors=True); shutil.rmtree(t12, ignore_errors=True)
            txt = c["steps"][0]["text"]
            f["deberta"] = deberta(txt)
            f["llmguard"] = lg(txt)
            rows.append(f)
            if i % 200 == 0: print(f"  {i}/{len(cases)}", flush=True)
        output["datasets"][name_] = rows
        (HERE / "predictions_v12.json").write_text(json.dumps(output, ensure_ascii=False))
    print("ok", flush=True)

if __name__ == "__main__":
    main()
